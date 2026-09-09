import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';

import * as bip39 from 'bip39';
import { BIP32Factory } from 'bip32';

import {
  WalletService,
  avianNetwork,
  buildDescriptorBody,
  deriveAddress,
  descriptorChecksum,
  resolveSendAmounts,
  secureEncrypt,
} from './WalletService';
import { estimateTxFee } from './fees';
import { CoinSelectionStrategy } from './UTXOSelectionService';
import { StorageService } from '@/services/core/StorageService';
import { TEST_MNEMONIC, TEST_PASSWORD, resetStorage } from '@/test/helpers';

/**
 * Transaction building against a stubbed network layer. Nothing is broadcast: the fake Electrum
 * captures the raw hex, which is then decoded and asserted on. Signature *validity* under Avian's
 * FORKID rules is deliberately out of scope (bitcoinjs-lib has no FORKID digest) — what these
 * tests protect is input selection, output construction, change handling and fee arithmetic.
 */

const ECPair = ECPairFactory(ecc);
const bip32 = BIP32Factory(ecc);

const SIGHASH_ALL_FORKID = 0x41;
const RECIPIENT = 'RJNi221gkDstBPUxeeJgtmDY4EXMEj6uvF';

interface FakeUTXO {
  txid: string;
  vout: number;
  value: number;
  height: number;
}

/** A previous transaction paying `value` to `address`, so the wallet has something to spend. */
function fundingTx(address: string, value: number, seed: number) {
  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.addInput(Buffer.alloc(32, seed), 0);
  tx.addOutput(bitcoin.address.toOutputScript(address, avianNetwork), value);
  return { hex: tx.toHex(), txid: tx.getId() };
}

function createFakeElectrum(address: string, values: number[], blockHeight = 1000) {
  const transactions = new Map<string, string>();
  const utxos: FakeUTXO[] = values.map((value, index) => {
    const { hex, txid } = fundingTx(address, value, index + 1);
    transactions.set(txid, hex);
    return { txid, vout: 0, value, height: blockHeight - 10 };
  });

  const broadcast = vi.fn(async (hex: string) => bitcoin.Transaction.fromHex(hex).getId());

  return {
    utxos,
    broadcast,
    electrum: {
      getUTXOs: vi.fn(async () => utxos),
      getCurrentBlockHeight: vi.fn(async () => blockHeight),
      getTransaction: vi.fn(async (txid: string) => transactions.get(txid)),
      broadcastTransaction: broadcast,
      // Touched by other WalletService paths but irrelevant here.
      getBalance: vi.fn(async () => values.reduce((sum, value) => sum + value, 0)),
      getTransactionHistory: vi.fn(async () => []),
      // 0 => WalletService falls back to its default rate; tests that assert fees pass an explicit
      // low feeRate so the amounts stay small and the arithmetic is easy to check.
      getFeeRateSatPerVByte: vi.fn(async () => 0),
      isConnectedToServer: vi.fn(() => true),
      connect: vi.fn(async () => {}),
      subscribeToAddress: vi.fn(async () => {}),
      unsubscribeFromAddress: vi.fn(async () => {}),
    },
  };
}

/** Registers an encrypted active wallet and returns its address. */
async function createActiveWallet(addressType: 'p2pkh' | 'p2wpkh' = 'p2pkh') {
  const keyPair = ECPair.makeRandom({ network: avianNetwork });
  const address = deriveAddress(Buffer.from(keyPair.publicKey), addressType);
  const encryptedKey = await secureEncrypt(keyPair.toWIF(), TEST_PASSWORD);

  await StorageService.createWallet({
    name: 'Spending',
    address,
    privateKey: encryptedKey,
    isEncrypted: true,
    addressType,
  });

  return { address, keyPair };
}

/** Decodes the hex handed to broadcastTransaction. */
const broadcastTx = (broadcast: ReturnType<typeof vi.fn>) =>
  bitcoin.Transaction.fromHex(broadcast.mock.calls[0][0] as string);

const outputsOf = (tx: bitcoin.Transaction) =>
  tx.outs.map((out) => ({
    value: out.value,
    address: bitcoin.address.fromOutputScript(out.script, avianNetwork),
  }));

beforeEach(() => {
  resetStorage();
});

describe('resolveSendAmounts', () => {
  const FEE = 10_000;

  it('leaves the recipient whole and takes the fee from change when the flag is off', () => {
    const { sendAmount, change } = resolveSendAmounts(100_000, FEE, 500_000, false);

    expect(sendAmount).toBe(100_000);
    expect(change).toBe(390_000);
    // Miner fee = inputs - outputs.
    expect(500_000 - sendAmount - change).toBe(FEE);
  });

  it('takes the fee from the recipient when the flag is on', () => {
    const { sendAmount, change } = resolveSendAmounts(100_000, FEE, 500_000, true);

    expect(sendAmount).toBe(90_000);
    expect(change).toBe(400_000);
    // Crucially, the miner fee is still exactly the fee rate — the flag moved who pays it, not
    // how much is paid. This is the incoherence the fix removed.
    expect(500_000 - sendAmount - change).toBe(FEE);
  });

  it('charges miners the same fee either way — the toggle only shifts who absorbs it', () => {
    const off = resolveSendAmounts(100_000, FEE, 500_000, false);
    const on = resolveSendAmounts(100_000, FEE, 500_000, true);

    const minerFeeOff = 500_000 - off.sendAmount - off.change;
    const minerFeeOn = 500_000 - on.sendAmount - on.change;
    expect(minerFeeOff).toBe(minerFeeOn);
    expect(minerFeeOn).toBe(FEE);

    // With the flag on, the sender's total outlay is exactly `amount`.
    expect(on.sendAmount + minerFeeOn).toBe(100_000);
    // With it off, the sender pays amount + fee.
    expect(off.sendAmount + minerFeeOff).toBe(110_000);
  });

  it('scales the deduction with the fee rate rather than a fixed fraction of it', () => {
    // The old code deducted feeRate/4, so the deduction did not match the fee actually paid.
    expect(resolveSendAmounts(100_000, 25_000, 500_000, true).sendAmount).toBe(75_000);
    expect(resolveSendAmounts(100_000, 4_000, 500_000, true).sendAmount).toBe(96_000);
  });

  it('never produces a negative recipient amount', () => {
    const { sendAmount } = resolveSendAmounts(3_000, FEE, 500_000, true);
    expect(sendAmount).toBe(0);
  });
});

describe('sendTransaction', () => {
  const RATE = 1; // sat/vByte — small so the test amounts and fee arithmetic stay simple
  const feeFor = (inputs: number, outputs: number) => estimateTxFee(inputs, outputs, RATE);

  it('builds, signs and broadcasts a transaction that pays the recipient', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    const txid = await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD);

    expect(broadcast).toHaveBeenCalledTimes(1);
    const tx = broadcastTx(broadcast);
    expect(txid).toBe(tx.getId());

    const outputs = outputsOf(tx);
    expect(outputs).toContainEqual({ address: RECIPIENT, value: 100_000 });
  });

  it('returns the change to the sending address', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, { feeRate: RATE });

    const outputs = outputsOf(broadcastTx(broadcast));
    expect(outputs).toContainEqual({ address, value: 500_000 - 100_000 - feeFor(1, 2) });
  });

  it('accounts for exactly the fee: inputs minus outputs is the size-based fee', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, { feeRate: RATE });

    const tx = broadcastTx(broadcast);
    const totalOut = tx.outs.reduce((sum, out) => sum + out.value, 0);
    expect(500_000 - totalOut).toBe(feeFor(1, 2)); // 1 input, recipient + change
  });

  it('scales the fee with transaction size (more inputs cost more)', async () => {
    // One input vs three: the fee must grow with the byte count, not stay flat.
    const oneIn = createFakeElectrum(
      (await createActiveWallet()).address,
      [500_000],
    );
    await new WalletService(oneIn.electrum as never).sendTransaction(
      RECIPIENT,
      100_000,
      TEST_PASSWORD,
      { feeRate: RATE },
    );
    const feeOneInput =
      500_000 - broadcastTx(oneIn.broadcast).outs.reduce((s, o) => s + o.value, 0);

    resetStorage();
    const { address } = await createActiveWallet();
    const threeIn = createFakeElectrum(address, [60_000, 60_000, 60_000]);
    await new WalletService(threeIn.electrum as never).sendTransaction(
      RECIPIENT,
      150_000, // needs all three 60k inputs
      TEST_PASSWORD,
      { feeRate: RATE, strategy: CoinSelectionStrategy.LARGEST_FIRST },
    );
    const txThree = broadcastTx(threeIn.broadcast);
    const feeThreeInputs = 180_000 - txThree.outs.reduce((s, o) => s + o.value, 0);

    expect(txThree.ins.length).toBe(3);
    expect(feeThreeInputs).toBe(feeFor(3, 2));
    expect(feeThreeInputs).toBeGreaterThan(feeOneInput);
  });

  it('honours a custom fee rate (sat/vByte)', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, { feeRate: 3 });

    const tx = broadcastTx(broadcast);
    const totalOut = tx.outs.reduce((sum, out) => sum + out.value, 0);
    expect(500_000 - totalOut).toBe(estimateTxFee(1, 2, 3));
  });

  it('pays miners the same fee with subtractFeeFromAmount on as off', async () => {
    // The built transaction is the real proof: inputs minus outputs is the miner fee, and it
    // must not depend on who absorbs it. Before the fix this dropped from 10,000 to 2,500.
    const walletFor = async () => {
      const { address } = await createActiveWallet();
      const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
      return { wallet: new WalletService(electrum as never), broadcast };
    };

    const off = await walletFor();
    await off.wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, {
      subtractFeeFromAmount: false,
      feeRate: RATE,
    });
    const txOff = broadcastTx(off.broadcast);

    resetStorage();
    const on = await walletFor();
    await on.wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, {
      subtractFeeFromAmount: true,
      feeRate: RATE,
    });
    const txOn = broadcastTx(on.broadcast);

    const feeOff = 500_000 - txOff.outs.reduce((sum, out) => sum + out.value, 0);
    const feeOn = 500_000 - txOn.outs.reduce((sum, out) => sum + out.value, 0);

    expect(feeOff).toBe(feeFor(1, 2));
    expect(feeOn).toBe(feeFor(1, 2));

    // And with the flag on, the recipient — not the sender — absorbed the fee.
    const recipientOut = (tx: bitcoin.Transaction) =>
      outputsOf(tx).find((out) => out.address === RECIPIENT)!.value;
    expect(recipientOut(txOff)).toBe(100_000);
    expect(recipientOut(txOn)).toBe(100_000 - feeFor(1, 2));
  });

  it('lets subtract-fee send the entire balance (send-max)', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    // Amount == full balance: only possible because the fee comes out of the amount.
    await wallet.sendTransaction(RECIPIENT, 500_000, TEST_PASSWORD, {
      subtractFeeFromAmount: true,
      feeRate: RATE,
    });

    const tx = broadcastTx(broadcast);
    const outputs = outputsOf(tx);
    // Everything goes to the recipient minus the fee; no change output. (The fee is still sized for
    // a 2-output tx, which is the conservative estimate the planner uses.)
    expect(outputs).toHaveLength(1);
    expect(outputs[0]).toEqual({ address: RECIPIENT, value: 500_000 - feeFor(1, 2) });
  });

  it('folds sub-dust change into the fee instead of emitting a dust output', async () => {
    const { address } = await createActiveWallet();
    // Leave a few hundred sats of change — below the dust threshold — so it must be folded.
    const funding = 100_000 + feeFor(1, 2) + 300;
    const { electrum, broadcast } = createFakeElectrum(address, [funding]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, { feeRate: RATE });

    const tx = broadcastTx(broadcast);
    expect(tx.outs).toHaveLength(1); // no dust change output
    expect(outputsOf(tx)[0]).toEqual({ address: RECIPIENT, value: 100_000 });
    // The 300 sats of would-be dust went to the miner, not to a rejected output.
    expect(funding - 100_000).toBe(feeFor(1, 2) + 300);
  });

  it('sends change to a custom change address when one is given', async () => {
    const { address } = await createActiveWallet();
    const changeAddress = 'RMBnRfw6tV7dC7LS4Lr8JBWvocokzHQNeG';
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, { changeAddress, feeRate: RATE });

    const outputs = outputsOf(broadcastTx(broadcast));
    expect(outputs).toContainEqual({ address: changeAddress, value: 500_000 - 100_000 - feeFor(1, 2) });
    expect(outputs.map((out) => out.address)).not.toContain(address);
  });

  it('ignores a blank custom change address and falls back to the sender', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, {
      changeAddress: '   ',
      feeRate: RATE,
    });

    const outputs = outputsOf(broadcastTx(broadcast));
    expect(outputs.map((out) => out.address)).toContain(address);
  });

  it('spends several UTXOs when one is not enough', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [60_000, 70_000, 80_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 150_000, TEST_PASSWORD, {
      strategy: CoinSelectionStrategy.LARGEST_FIRST,
      feeRate: RATE,
    });

    const tx = broadcastTx(broadcast);
    expect(tx.ins.length).toBeGreaterThan(1);
  });

  it('signs every input it spends', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [60_000, 70_000, 80_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 150_000, TEST_PASSWORD, {
      strategy: CoinSelectionStrategy.LARGEST_FIRST,
      feeRate: RATE,
    });

    const tx = broadcastTx(broadcast);
    for (const input of tx.ins) {
      expect(input.script.length + (input.witness?.length ?? 0)).toBeGreaterThan(0);
    }
  });

  it('stamps the Avian FORKID sighash byte onto legacy signatures', async () => {
    const { address, keyPair } = await createActiveWallet('p2pkh');
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD);

    const tx = broadcastTx(broadcast);
    const [signature, pubkey] = bitcoin.script.decompile(tx.ins[0].script) as Buffer[];

    // Last byte of a scriptSig signature is the sighash flag: SIGHASH_ALL | SIGHASH_FORKID.
    expect(signature[signature.length - 1]).toBe(SIGHASH_ALL_FORKID);
    expect(Buffer.from(pubkey).toString('hex')).toBe(
      Buffer.from(keyPair.publicKey).toString('hex'),
    );
  });

  it('records the send in local history, in AVN rather than satoshis', async () => {
    const { address } = await createActiveWallet();
    const { electrum } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    const txid = await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD);

    const history = await StorageService.getTransactionHistory(address);
    expect(history).toHaveLength(1);
    expect(history[0]).toMatchObject({
      txid,
      type: 'send',
      address: RECIPIENT,
      fromAddress: address,
      walletAddress: address,
      amount: 0.001,
      confirmations: 0,
    });
  });

  it('records what the recipient actually received when subtract-fee is on', async () => {
    const { address } = await createActiveWallet();
    const { electrum } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD, {
      subtractFeeFromAmount: true,
      feeRate: RATE,
    });

    const history = await StorageService.getTransactionHistory(address);
    // Recipient got amount − fee, and that (not the gross amount) is what history records.
    expect(history[0].amount).toBeCloseTo((100_000 - feeFor(1, 2)) / 100_000_000, 10);
  });

  it('builds a spendable-looking transaction for a native SegWit wallet', async () => {
    const { address } = await createActiveWallet('p2wpkh');
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD);

    const tx = broadcastTx(broadcast);
    expect(tx.ins[0].witness.length).toBeGreaterThan(0);
    expect(outputsOf(tx)).toContainEqual({ address: RECIPIENT, value: 100_000 });
  });
});

describe('sendTransaction failures', () => {
  it('refuses when there is no active wallet', async () => {
    const { electrum } = createFakeElectrum(RECIPIENT, [500_000]);
    const wallet = new WalletService(electrum as never);

    await expect(wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD)).rejects.toThrow(
      /No active wallet/,
    );
  });

  it('refuses to spend from an encrypted wallet without a password', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await expect(wallet.sendTransaction(RECIPIENT, 100_000)).rejects.toThrow(/Password required/);
    expect(broadcast).not.toHaveBeenCalled();
  });

  it('refuses the wrong password and broadcasts nothing', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await expect(wallet.sendTransaction(RECIPIENT, 100_000, 'wrong-password')).rejects.toThrow(
      /Invalid password/,
    );
    expect(broadcast).not.toHaveBeenCalled();
  });

  it('refuses when the wallet has no UTXOs', async () => {
    const { address } = await createActiveWallet();
    const { electrum } = createFakeElectrum(address, []);
    const wallet = new WalletService(electrum as never);

    await expect(wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD)).rejects.toThrow(
      /No unspent transaction outputs/,
    );
  });

  it('refuses when the balance cannot cover the amount plus the fee', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [105_000]);
    const wallet = new WalletService(electrum as never);

    await expect(wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD)).rejects.toThrow(
      /Insufficient funds/,
    );
    expect(broadcast).not.toHaveBeenCalled();
  });

  it('refuses an address that is not valid on the Avian network', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await expect(
      wallet.sendTransaction('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 100_000, TEST_PASSWORD),
    ).rejects.toThrow();
    expect(broadcast).not.toHaveBeenCalled();
  });

  it('does not record history when the broadcast is rejected', async () => {
    const { address } = await createActiveWallet();
    const { electrum } = createFakeElectrum(address, [500_000]);
    electrum.broadcastTransaction.mockRejectedValueOnce(new Error('node rejected the transaction'));
    const wallet = new WalletService(electrum as never);

    await expect(wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD)).rejects.toThrow();
    expect(await StorageService.getTransactionHistory(address)).toEqual([]);
  });

  it('does not record history when the broadcast returns nothing usable', async () => {
    const { address } = await createActiveWallet();
    const { electrum } = createFakeElectrum(address, [500_000]);
    electrum.broadcastTransaction.mockResolvedValueOnce(undefined as never);
    const wallet = new WalletService(electrum as never);

    await expect(wallet.sendTransaction(RECIPIENT, 100_000, TEST_PASSWORD)).rejects.toThrow(
      /broadcast failed/,
    );
    expect(await StorageService.getTransactionHistory(address)).toEqual([]);
  });
});

describe('sendTransactionWithManualUTXOs', () => {
  it('spends exactly the UTXOs it was handed', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast, utxos } = createFakeElectrum(address, [
      200_000, 300_000, 400_000,
    ]);
    const wallet = new WalletService(electrum as never);

    const chosen = [utxos[0], utxos[2]].map((utxo) => ({ ...utxo, address }));

    await wallet.sendTransactionWithManualUTXOs(RECIPIENT, 100_000, chosen, TEST_PASSWORD);

    const tx = broadcastTx(broadcast);
    expect(tx.ins).toHaveLength(2);

    const spent = tx.ins.map((input) =>
      Buffer.from(input.hash).reverse().toString('hex'),
    );
    expect(spent.sort()).toEqual([utxos[0].txid, utxos[2].txid].sort());
  });

  it('refuses a manual selection that cannot cover the spend', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast, utxos } = createFakeElectrum(address, [50_000]);
    const wallet = new WalletService(electrum as never);

    await expect(
      wallet.sendTransactionWithManualUTXOs(
        RECIPIENT,
        100_000,
        [{ ...utxos[0], address }],
        TEST_PASSWORD,
      ),
    ).rejects.toThrow();
    expect(broadcast).not.toHaveBeenCalled();
  });

  it('signs a UTXO on a derived address of a descriptor-imported wallet', async () => {
    // A descriptor import has no mnemonic, so the HD signing path has to fall back to the
    // stored account xprv — otherwise funds on any address but the first are unspendable.
    const accountNode = bip32
      .fromSeed(bip39.mnemonicToSeedSync(TEST_MNEMONIC), avianNetwork)
      .derivePath("m/44'/921'/0'");
    const derivedChild = accountNode.derive(0).derive(3);
    const derivedAddress = deriveAddress(Buffer.from(derivedChild.publicKey), 'p2pkh');

    const { electrum, broadcast, utxos } = createFakeElectrum(derivedAddress, [500_000]);
    const wallet = new WalletService(electrum as never);

    const body = buildDescriptorBody('p2pkh', 'deadbeef', 44, 921, accountNode.toBase58());
    const imported = await wallet.importWalletFromDescriptor({
      name: 'Descriptor',
      descriptor: `${body}#${descriptorChecksum(body)}`,
      password: TEST_PASSWORD,
      makeActive: true,
    });
    expect(derivedAddress).not.toBe(imported.address);

    await wallet.sendTransactionWithManualUTXOs(
      RECIPIENT,
      100_000,
      [{ ...utxos[0], address: derivedAddress }],
      TEST_PASSWORD,
    );

    const tx = broadcastTx(broadcast);
    expect(tx.ins).toHaveLength(1);
    // Signed with the derived key rather than the wallet's primary key.
    const [signature, pubkey] = bitcoin.script.decompile(tx.ins[0].script) as Buffer[];
    expect(signature[signature.length - 1]).toBe(SIGHASH_ALL_FORKID);
    expect(Buffer.from(pubkey).toString('hex')).toBe(
      Buffer.from(derivedChild.publicKey).toString('hex'),
    );
  });
});

describe('buildUnsignedPsbt', () => {
  const RATE = 1;
  const feeFor = (inputs: number, outputs: number) => estimateTxFee(inputs, outputs, RATE);

  it('exports an unsigned PSBT with the same selection and fee as a send — no key needed', async () => {
    const { address } = await createActiveWallet();
    const { electrum } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    // No password passed — building the unsigned PSBT must not need the private key.
    const result = await wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE });

    expect(result.inputs).toBe(1);
    expect(result.fee).toBe(feeFor(1, 2));
    expect(result.sendAmount).toBe(100_000);
    expect(result.changeAmount).toBe(500_000 - 100_000 - feeFor(1, 2));

    const psbt = bitcoin.Psbt.fromBase64(result.psbt, { network: avianNetwork });
    expect(psbt.inputCount).toBe(1);
    // Unsigned: no input carries a signature yet.
    expect(psbt.data.inputs.every((i) => !i.partialSig && !i.finalScriptSig)).toBe(true);
    // Outputs: recipient + change back to us.
    const outs = psbt.txOutputs.map((o) => ({ address: o.address, value: o.value }));
    expect(outs).toContainEqual({ address: RECIPIENT, value: 100_000 });
    expect(outs).toContainEqual({ address, value: 500_000 - 100_000 - feeFor(1, 2) });
  });

  it('round-trips: the exported PSBT signs and finalises to a valid FORKID transaction', async () => {
    const { address, keyPair } = await createActiveWallet();
    const { electrum } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    const { psbt } = await wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE });
    const signed = await wallet.signPsbt(psbt, TEST_PASSWORD);
    expect(signed.signedInputs).toBe(1);
    expect(signed.complete).toBe(true);

    const { hex } = wallet.finalizePsbt(signed.psbt);
    const tx = bitcoin.Transaction.fromHex(hex);
    const [signature, pubkey] = bitcoin.script.decompile(tx.ins[0].script) as Buffer[];
    expect(signature[signature.length - 1]).toBe(SIGHASH_ALL_FORKID);
    expect(Buffer.from(pubkey).toString('hex')).toBe(Buffer.from(keyPair.publicKey).toString('hex'));
    expect(outputsOf(tx)).toContainEqual({ address: RECIPIENT, value: 100_000 });
  });

  it('signs for the named account, not whichever wallet happens to be active', async () => {
    // Avian Connect signs for the account a site connected with. If the user switches wallets
    // mid-session the active wallet differs, and signing with it would produce a transaction the
    // approval screen never described — while leaving the connected account's input unsigned.
    const connected = await createActiveWallet();
    const { electrum } = createFakeElectrum(connected.address, [500_000]);
    const wallet = new WalletService(electrum as never);
    const { psbt } = await wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE });

    // A second wallet becomes active, as if the user switched after connecting.
    const otherKey = ECPair.makeRandom({ network: avianNetwork });
    const otherAddress = deriveAddress(Buffer.from(otherKey.publicKey), 'p2pkh');
    await StorageService.createWallet({
      name: 'Switched to',
      address: otherAddress,
      privateKey: await secureEncrypt(otherKey.toWIF(), TEST_PASSWORD),
      isEncrypted: true,
      makeActive: true,
    });
    expect((await StorageService.getActiveWallet())?.address).toBe(otherAddress);

    const signed = await wallet.signPsbt(psbt, TEST_PASSWORD, connected.address);
    expect(signed.signedInputs).toBe(1);

    const { hex } = wallet.finalizePsbt(signed.psbt);
    const tx = bitcoin.Transaction.fromHex(hex);
    const [, pubkey] = bitcoin.script.decompile(tx.ins[0].script) as Buffer[];
    expect(Buffer.from(pubkey).toString('hex')).toBe(
      Buffer.from(connected.keyPair.publicKey).toString('hex'),
    );
  });

  it('signs nothing when the active wallet does not own the inputs', async () => {
    // The old behaviour, now reachable only by omitting the account: the active wallet's key does
    // not match the input, so no input is signed. Fail-safe, but the caller gets an empty result.
    const connected = await createActiveWallet();
    const { electrum } = createFakeElectrum(connected.address, [500_000]);
    const wallet = new WalletService(electrum as never);
    const { psbt } = await wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE });

    const otherKey = ECPair.makeRandom({ network: avianNetwork });
    await StorageService.createWallet({
      name: 'Switched to',
      address: deriveAddress(Buffer.from(otherKey.publicKey), 'p2pkh'),
      privateKey: await secureEncrypt(otherKey.toWIF(), TEST_PASSWORD),
      isEncrypted: true,
      makeActive: true,
    });

    const signed = await wallet.signPsbt(psbt, TEST_PASSWORD);
    expect(signed.signedInputs).toBe(0);
    expect(signed.complete).toBe(false);
  });

  it('broadcasts when asked and reports the txid', async () => {
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);
    const { psbt } = await wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE });

    const result = await wallet.signAndBroadcastPsbt(psbt, TEST_PASSWORD, address);

    expect(result.broadcast).toBe(true);
    expect(result.txid).toBe(broadcastTx(broadcast).getId());
    // The user sees the spend in their own history rather than an unchanged wallet.
    const history = await StorageService.getTransactionHistory(address);
    expect(history.map((entry) => entry.txid)).toContain(result.txid);
  });

  it('keeps the signature when the broadcast fails, so it can be retried', async () => {
    // A marketplace race lands here: another buyer took the listing, so the inputs are gone.
    const { address } = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(address, [500_000]);
    broadcast.mockRejectedValueOnce(new Error('missing-inputs'));
    const wallet = new WalletService(electrum as never);
    const { psbt } = await wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE });

    const result = await wallet.signAndBroadcastPsbt(psbt, TEST_PASSWORD, address);

    expect(result.broadcast).toBe(false);
    expect(result.broadcastError).toMatch(/missing-inputs/);
    expect(result.txid).toBeUndefined();
    // The signature is not lost — the caller can broadcast it themselves.
    expect(result.complete).toBe(true);
    expect(wallet.finalizePsbt(result.psbt).hex.length).toBeGreaterThan(0);
    expect(await StorageService.getTransactionHistory(address)).toEqual([]);
  });

  it('does not broadcast a transaction somebody else still has to sign', async () => {
    const connected = await createActiveWallet();
    const { electrum, broadcast } = createFakeElectrum(connected.address, [500_000]);
    const wallet = new WalletService(electrum as never);
    const { psbt } = await wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE });

    // Sign as a wallet that owns none of the inputs: nothing gets signed, so nothing completes.
    const otherKey = ECPair.makeRandom({ network: avianNetwork });
    const otherAddress = deriveAddress(Buffer.from(otherKey.publicKey), 'p2pkh');
    await StorageService.createWallet({
      name: 'Not the owner',
      address: otherAddress,
      privateKey: await secureEncrypt(otherKey.toWIF(), TEST_PASSWORD),
      isEncrypted: true,
    });

    const result = await wallet.signAndBroadcastPsbt(psbt, TEST_PASSWORD, otherAddress);

    expect(result.broadcast).toBe(false);
    expect(result.broadcastError).toMatch(/needs other signatures/);
    expect(broadcast).not.toHaveBeenCalled();
  });

  it('refuses to export for a wrapped-SegWit wallet (needs the pubkey for a redeemScript)', async () => {
    // Register a p2sh-p2wpkh active wallet directly so the export guard trips.
    const keyPair = ECPair.makeRandom({ network: avianNetwork });
    const address = deriveAddress(Buffer.from(keyPair.publicKey), 'p2pkh');
    await StorageService.createWallet({
      name: 'Wrapped',
      address,
      privateKey: await secureEncrypt(keyPair.toWIF(), TEST_PASSWORD),
      isEncrypted: true,
      addressType: 'p2sh-p2wpkh',
    });
    const { electrum } = createFakeElectrum(address, [500_000]);
    const wallet = new WalletService(electrum as never);

    await expect(wallet.buildUnsignedPsbt(RECIPIENT, 100_000, { feeRate: RATE })).rejects.toThrow(
      /wrapped-SegWit/,
    );
  });
});
