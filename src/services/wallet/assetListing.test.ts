import { beforeEach, describe, expect, it } from 'vitest';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';

import { WalletService, avianNetwork, deriveAddress, secureEncrypt } from './WalletService';
import { buildAssetTransferScript } from './assetScript';
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
function assetFundingTx(address: string, asset: string, seed: number) {
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.addInput(Buffer.alloc(32, seed), 0);
  tx.addOutput(buildAssetTransferScript(address, asset, 100_000_000n), 0);
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
