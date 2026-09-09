import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';

import { WalletService, avianNetwork, deriveAddress, secureEncrypt } from './WalletService';
import { buildAssetTransferScript, parseAssetScript } from './assetScript';
import { SIGHASH_SINGLE_FORKID_ANYONECANPAY } from './psbt';
import { StorageService } from '@/services/core/StorageService';
import { TEST_PASSWORD, resetStorage } from '@/test/helpers';

/**
 * Marketplace listings: the seller signs their asset input with SIGHASH_SINGLE|FORKID|ANYONECANPAY,
 * committing to that input and their payment output alone, so a buyer can add payment inputs and an
 * asset destination without invalidating it. This is the only path that signs an asset input, so
 * what it refuses matters as much as what it signs.
 */

const ECPair = ECPairFactory(ecc);
const ASSET = 'RLM#BRBAEY6A94VXQ';
const PRICE = 500 * 100_000_000; // 500 AVN

/** A previous transaction whose output[0] is `asset` held at `address`. */
function assetFundingTx(address: string, asset: string, seed: number, amount = 100_000_000n) {
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.addInput(Buffer.alloc(32, seed), 0);
  tx.addOutput(buildAssetTransferScript(address, asset, amount), 0);
  return { hex: tx.toHex(), txid: tx.getId() };
}

async function createWallet(name: string, makeActive = false) {
  const keyPair = ECPair.makeRandom({ network: avianNetwork });
  const address = deriveAddress(Buffer.from(keyPair.publicKey), 'p2pkh');
  await StorageService.createWallet({
    name,
    address,
    privateKey: await secureEncrypt(keyPair.toWIF(), TEST_PASSWORD),
    isEncrypted: true,
    makeActive,
  });
  return { address, keyPair };
}

/** The unsigned listing a marketplace builds: seller's asset in, seller's payment out. */
function listingPsbt(
  payTo: string,
  funding: ReturnType<typeof assetFundingTx>,
  price = PRICE,
): string {
  const psbt = new bitcoin.Psbt({ network: avianNetwork });
  psbt.addInput({
    hash: funding.txid,
    index: 0,
    sequence: 0xfffffffe, // the seller's signature commits to this
    nonWitnessUtxo: Buffer.from(funding.hex, 'hex'),
  });
  psbt.addOutput({ address: payTo, value: price });
  return psbt.toBase64();
}

const finalSigOf = (psbtBase64: string, index = 0) =>
  bitcoin.script.decompile(
    bitcoin.Psbt.fromBase64(psbtBase64, { network: avianNetwork }).data.inputs[index]
      .finalScriptSig!,
  ) as Buffer[];

/** Electrum stub serving one asset UTXO to the seller and AVN UTXOs to the buyer. */
function marketElectrum(
  seller: string,
  asset: string,
  assetAmount: bigint,
  buyer?: string,
  buyerAvn: number[] = [],
) {
  const txs = new Map<string, string>();
  const assetTx = assetFundingTx(seller, asset, 42, assetAmount);
  txs.set(assetTx.txid, assetTx.hex);

  const avn = buyerAvn.map((value, i) => {
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    tx.addInput(Buffer.alloc(32, 90 + i), 0);
    tx.addOutput(bitcoin.address.toOutputScript(buyer!, avianNetwork), value);
    txs.set(tx.getId(), tx.toHex());
    return { txid: tx.getId(), vout: 0, value, height: 100 };
  });

  const broadcast = vi.fn(async (hex: string) => bitcoin.Transaction.fromHex(hex).getId());
  return {
    broadcast,
    assetTx,
    electrum: {
      isConnectedToServer: () => true,
      getAssetUTXOs: vi.fn(async (address: string, name: string) =>
        address === seller && name === asset
          ? [{ txid: assetTx.txid, vout: 0, value: Number(assetAmount), height: 100, asset }]
          : [],
      ),
      getUTXOs: vi.fn(async (address: string) => (address === buyer ? avn : [])),
      getTransaction: vi.fn(async (txid: string) => txs.get(txid)),
      getFeeRateSatPerVByte: vi.fn(async () => 0),
      broadcastTransaction: broadcast,
      getBalance: vi.fn(async () => 0),
      getTransactionHistory: vi.fn(async () => []),
    },
  };
}

let wallet: WalletService;

beforeEach(() => {
  resetStorage();
  wallet = new WalletService({ isConnectedToServer: () => true } as never);
});

describe('signAssetListing', () => {
  it('signs the asset input with SINGLE|FORKID|ANYONECANPAY and reports what was sold', async () => {
    const seller = await createWallet('Seller', true);
    const funding = assetFundingTx(seller.address, ASSET, 1);

    const result = await wallet.signAssetListing(
      listingPsbt(seller.address, funding),
      TEST_PASSWORD,
      seller.address,
    );

    expect(result.assetName).toBe(ASSET);
    expect(result.assetAmount).toBe(100_000_000n);
    expect(result.priceSats).toBe(PRICE);
    expect(result.payTo).toBe(seller.address);

    // The signature carries the listing sighash, not the ordinary ALL|FORKID.
    const [sig, pub] = finalSigOf(result.psbt);
    expect(sig[sig.length - 1]).toBe(SIGHASH_SINGLE_FORKID_ANYONECANPAY);
    expect(Buffer.from(pub).toString('hex')).toBe(
      Buffer.from(seller.keyPair.publicKey).toString('hex'),
    );
  });

  it('signs for the named account rather than the active wallet', async () => {
    const seller = await createWallet('Seller');
    await createWallet('Someone else', true); // active, but not the one listing
    const funding = assetFundingTx(seller.address, ASSET, 2);

    const result = await wallet.signAssetListing(
      listingPsbt(seller.address, funding),
      TEST_PASSWORD,
      seller.address,
    );

    const [, pub] = finalSigOf(result.psbt);
    expect(Buffer.from(pub).toString('hex')).toBe(
      Buffer.from(seller.keyPair.publicKey).toString('hex'),
    );
  });

  it('refuses a payment output that pays somebody else', async () => {
    // The signature commits to this output and nothing else, so paying elsewhere would sign the
    // asset away for nothing.
    const seller = await createWallet('Seller', true);
    const thief = await createWallet('Thief');
    const funding = assetFundingTx(seller.address, ASSET, 3);

    await expect(
      wallet.signAssetListing(listingPsbt(thief.address, funding), TEST_PASSWORD, seller.address),
    ).rejects.toThrow(/does not pay this account/);
  });

  it('refuses an input the account does not hold', async () => {
    const seller = await createWallet('Seller', true);
    const stranger = await createWallet('Stranger');
    const funding = assetFundingTx(stranger.address, ASSET, 4);

    // Pays the seller, but spends somebody else's asset.
    await expect(
      wallet.signAssetListing(listingPsbt(seller.address, funding), TEST_PASSWORD, seller.address),
    ).rejects.toThrow(/not held by this account/);
  });

  it('refuses a plain AVN input — this path exists only to sell assets', async () => {
    const seller = await createWallet('Seller', true);
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    tx.addInput(Buffer.alloc(32, 5), 0);
    tx.addOutput(bitcoin.address.toOutputScript(seller.address, avianNetwork), 1_000_000);

    const psbt = new bitcoin.Psbt({ network: avianNetwork });
    psbt.addInput({ hash: tx.getId(), index: 0, nonWitnessUtxo: Buffer.from(tx.toHex(), 'hex') });
    psbt.addOutput({ address: seller.address, value: PRICE });

    await expect(
      wallet.signAssetListing(psbt.toBase64(), TEST_PASSWORD, seller.address),
    ).rejects.toThrow(/does not hold an asset/);
  });

  it('refuses extra inputs or outputs the user was never shown', async () => {
    const seller = await createWallet('Seller', true);
    const funding = assetFundingTx(seller.address, ASSET, 6);

    const psbt = bitcoin.Psbt.fromBase64(listingPsbt(seller.address, funding), {
      network: avianNetwork,
    });
    psbt.addOutput({ address: seller.address, value: 1_000 });

    await expect(
      wallet.signAssetListing(psbt.toBase64(), TEST_PASSWORD, seller.address),
    ).rejects.toThrow(/exactly one input and one output/);
  });

  it('refuses a listing that is already signed', async () => {
    const seller = await createWallet('Seller', true);
    const funding = assetFundingTx(seller.address, ASSET, 7);
    const once = await wallet.signAssetListing(
      listingPsbt(seller.address, funding),
      TEST_PASSWORD,
      seller.address,
    );

    await expect(
      wallet.signAssetListing(once.psbt, TEST_PASSWORD, seller.address),
    ).rejects.toThrow(/already signed/);
  });

  it('refuses the wrong password rather than signing', async () => {
    const seller = await createWallet('Seller', true);
    const funding = assetFundingTx(seller.address, ASSET, 8);

    await expect(
      wallet.signAssetListing(
        listingPsbt(seller.address, funding),
        'wrong-password',
        seller.address,
      ),
    ).rejects.toThrow(/Invalid password/);
  });
});

describe('the buyer side of a listing', () => {
  it('signs its own payment inputs and leaves the seller-signed asset input alone', async () => {
    const seller = await createWallet('Seller');
    const buyer = await createWallet('Buyer', true);
    const funding = assetFundingTx(seller.address, ASSET, 9);

    const listing = await wallet.signAssetListing(
      listingPsbt(seller.address, funding),
      TEST_PASSWORD,
      seller.address,
    );

    // The buyer completes the swap: their AVN in, the asset out to them, change back.
    const payment = new bitcoin.Transaction();
    payment.version = 2;
    payment.addInput(Buffer.alloc(32, 10), 0);
    payment.addOutput(
      bitcoin.address.toOutputScript(buyer.address, avianNetwork),
      600 * 100_000_000,
    );

    const combined = bitcoin.Psbt.fromBase64(listing.psbt, { network: avianNetwork });
    combined.addInput({
      hash: payment.getId(),
      index: 0,
      sequence: 0xfffffffe,
      nonWitnessUtxo: Buffer.from(payment.toHex(), 'hex'),
    });
    combined.addOutput({
      script: buildAssetTransferScript(buyer.address, ASSET, 100_000_000n),
      value: 0,
    });
    combined.addOutput({ address: buyer.address, value: 99 * 100_000_000 });

    const signed = await wallet.signPsbt(combined.toBase64(), TEST_PASSWORD, buyer.address);

    // Only the buyer's input is newly signed; the seller's finalized input is untouched.
    expect(signed.signedInputs).toBe(1);
    expect(finalSigOf(signed.psbt, 0)[0].toString('hex')).toBe(
      finalSigOf(listing.psbt, 0)[0].toString('hex'),
    );
    expect(
      bitcoin.Psbt.fromBase64(signed.psbt, { network: avianNetwork }).data.inputs[1]
        .finalScriptSig,
    ).toBeDefined();
  });
});

describe('createAssetListing', () => {
  it('finds the asset itself and signs a listing the wallet built', async () => {
    const seller = await createWallet('Seller', true);
    const market = marketElectrum(seller.address, ASSET, 100_000_000n);
    const w = new WalletService(market.electrum as never);

    const listing = await w.createAssetListing({
      assetName: ASSET,
      priceSats: PRICE,
      password: TEST_PASSWORD,
      account: seller.address,
    });

    expect(listing.assetName).toBe(ASSET);
    expect(listing.priceSats).toBe(PRICE);
    expect(listing.payTo).toBe(seller.address);
    expect(listing.assetUtxo).toEqual({ txid: market.assetTx.txid, vout: 0 });

    // One input, one output, signed with the listing sighash — the shape a buyer can complete.
    const psbt = bitcoin.Psbt.fromBase64(listing.psbt, { network: avianNetwork });
    expect(psbt.inputCount).toBe(1);
    expect(psbt.txOutputs).toHaveLength(1);
    expect(psbt.txInputs[0].sequence).toBe(0xfffffffe);
    const [sig] = finalSigOf(listing.psbt);
    expect(sig[sig.length - 1]).toBe(SIGHASH_SINGLE_FORKID_ANYONECANPAY);
  });

  it('refuses to sell part of a larger holding, which the signature could not protect', async () => {
    // SINGLE|ANYONECANPAY covers input[0] and output[0] only, so asset change back to the seller
    // is uncommitted: a buyer could drop it, take the whole output and pay only the listed price.
    const seller = await createWallet('Seller', true);
    const market = marketElectrum(seller.address, ASSET, 500_000_000n); // holds 5
    const w = new WalletService(market.electrum as never);

    await expect(
      w.createAssetListing({
        assetName: ASSET,
        priceSats: PRICE,
        amount: 100_000_000n, // wants to sell 1
        password: TEST_PASSWORD,
        account: seller.address,
      }),
    ).rejects.toThrow(/split first/);
  });

  it('refuses an asset the account does not hold, and a nonsense price', async () => {
    const seller = await createWallet('Seller', true);
    const market = marketElectrum(seller.address, ASSET, 100_000_000n);
    const w = new WalletService(market.electrum as never);

    await expect(
      w.createAssetListing({
        assetName: 'RLM#NOTMINE',
        priceSats: PRICE,
        password: TEST_PASSWORD,
        account: seller.address,
      }),
    ).rejects.toThrow(/holds no/);

    await expect(
      w.createAssetListing({
        assetName: ASSET,
        priceSats: 0,
        password: TEST_PASSWORD,
        account: seller.address,
      }),
    ).rejects.toThrow(/positive whole number/);
  });
});

describe('completeAssetListing', () => {
  const setUp = async (buyerAvn = [600 * 100_000_000]) => {
    const seller = await createWallet('Seller');
    const buyer = await createWallet('Buyer', true);
    const market = marketElectrum(seller.address, ASSET, 100_000_000n, buyer.address, buyerAvn);
    const w = new WalletService(market.electrum as never);
    const listing = await w.createAssetListing({
      assetName: ASSET,
      priceSats: PRICE,
      password: TEST_PASSWORD,
      account: seller.address,
    });
    return { seller, buyer, market, w, listing };
  };

  it('pays the seller, takes the asset and broadcasts the swap', async () => {
    const { seller, buyer, market, w, listing } = await setUp();

    const result = await w.completeAssetListing({
      listingPsbt: listing.psbt,
      password: TEST_PASSWORD,
      account: buyer.address,
    });

    expect(result.broadcast).toBe(true);
    expect(result.txid).toBeTruthy();
    expect(result.pricePaidSats).toBe(PRICE);
    expect(result.assetName).toBe(ASSET);

    const tx = bitcoin.Transaction.fromHex(market.broadcast.mock.calls[0][0] as string);
    // The seller's payment stays at output[0] — their signature commits to that position.
    expect(tx.outs[0].value).toBe(PRICE);
    expect(bitcoin.address.fromOutputScript(tx.outs[0].script, avianNetwork)).toBe(seller.address);
    // The asset lands with the buyer, in full.
    const assetOut = tx.outs.find((out) => parseAssetScript(out.script as Buffer)?.name === ASSET);
    expect(parseAssetScript(assetOut!.script as Buffer)).toMatchObject({
      address: buyer.address,
      amount: 100_000_000n,
    });
    // Every input is signed: the seller's was already final, ours were added and signed.
    expect(tx.ins.every((input) => input.script.length > 0)).toBe(true);
  });

  it('reads the price from the seller-signed bytes, not from what a caller claims', async () => {
    const { w, buyer, listing } = await setUp();

    const result = await w.completeAssetListing({
      listingPsbt: listing.psbt,
      password: TEST_PASSWORD,
      account: buyer.address,
      broadcast: false,
    });

    // Whatever a site says a listing costs, this is what the buyer is shown and pays.
    expect(result.pricePaidSats).toBe(PRICE);
    expect(result.broadcast).toBe(false);
  });

  it('refuses when the buyer cannot cover the price and fee', async () => {
    const { w, buyer, listing } = await setUp([10 * 100_000_000]);

    await expect(
      w.completeAssetListing({
        listingPsbt: listing.psbt,
        password: TEST_PASSWORD,
        account: buyer.address,
      }),
    ).rejects.toThrow(/Not enough AVN/);
  });

  it('refuses to buy your own listing', async () => {
    const seller = await createWallet('Seller', true);
    const market = marketElectrum(seller.address, ASSET, 100_000_000n, seller.address, [
      600 * 100_000_000,
    ]);
    const w = new WalletService(market.electrum as never);
    const listing = await w.createAssetListing({
      assetName: ASSET,
      priceSats: PRICE,
      password: TEST_PASSWORD,
      account: seller.address,
    });

    await expect(
      w.completeAssetListing({
        listingPsbt: listing.psbt,
        password: TEST_PASSWORD,
        account: seller.address,
      }),
    ).rejects.toThrow(/your own listing/);
  });

  it('refuses a listing the seller never signed', async () => {
    const { w, buyer } = await setUp();
    const seller = await createWallet('Unsigned seller');
    const funding = assetFundingTx(seller.address, ASSET, 77);

    await expect(
      w.completeAssetListing({
        listingPsbt: listingPsbt(seller.address, funding),
        password: TEST_PASSWORD,
        account: buyer.address,
      }),
    ).rejects.toThrow(/not signed by the seller/);
  });
});

describe('what Core does that we have to match', () => {
  it('refuses to buy into a bech32 account, since an asset cannot be paid there', async () => {
    // Core mixes a native-SegWit funding input with a legacy asset input happily, but the asset
    // output itself is always a legacy P2PKH — there is no bech32 form of an asset script.
    const seller = await createWallet('Seller');
    const buyerKey = ECPair.makeRandom({ network: avianNetwork });
    const buyerAddress = deriveAddress(Buffer.from(buyerKey.publicKey), 'p2wpkh');
    await StorageService.createWallet({
      name: 'SegWit buyer',
      address: buyerAddress,
      privateKey: await secureEncrypt(buyerKey.toWIF(), TEST_PASSWORD),
      isEncrypted: true,
      addressType: 'p2wpkh',
      makeActive: true,
    });

    const market = marketElectrum(seller.address, ASSET, 100_000_000n, buyerAddress, [
      600 * 100_000_000,
    ]);
    const w = new WalletService(market.electrum as never);
    const listing = await w.createAssetListing({
      assetName: ASSET,
      priceSats: PRICE,
      password: TEST_PASSWORD,
      account: seller.address,
    });

    await expect(
      w.completeAssetListing({
        listingPsbt: listing.psbt,
        password: TEST_PASSWORD,
        account: buyerAddress,
      }),
    ).rejects.toThrow(/legacy \(R…\) address/);
  });

  it('leaves the locktime alone, because the seller signed over it', async () => {
    // Core sets locktime to the current height for anti-fee-sniping. A listing cannot: the
    // seller's signature commits to nLockTime, so a buyer changing it would void the signature.
    const seller = await createWallet('Seller');
    const buyer = await createWallet('Buyer', true);
    const market = marketElectrum(seller.address, ASSET, 100_000_000n, buyer.address, [
      600 * 100_000_000,
    ]);
    const w = new WalletService(market.electrum as never);

    const listing = await w.createAssetListing({
      assetName: ASSET,
      priceSats: PRICE,
      password: TEST_PASSWORD,
      account: seller.address,
    });
    expect(bitcoin.Psbt.fromBase64(listing.psbt, { network: avianNetwork }).locktime).toBe(0);

    await w.completeAssetListing({
      listingPsbt: listing.psbt,
      password: TEST_PASSWORD,
      account: buyer.address,
    });

    const tx = bitcoin.Transaction.fromHex(market.broadcast.mock.calls[0][0] as string);
    expect(tx.locktime).toBe(0);
    // Sequence is likewise fixed by the seller's signature — the same 0xFFFFFFFE Core uses.
    expect(tx.ins[0].sequence).toBe(0xfffffffe);
  });
});
