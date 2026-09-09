/**
 * WalletService.ts
 *
 * Avian cryptocurrency wallet service using bitcoinjs-lib with Avian network parameters.
 *
 */

import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bip39 from 'bip39';
import { BIP32Factory } from 'bip32';
import { ElectrumService, type DetailedBalance } from '../core/ElectrumService';
import { StorageService, type TransactionData } from '../core/StorageService';
import { walletLogger } from '@/lib/Logger';
import { getExplorerUrl, openTransactionInExplorer } from '@/lib/explorer';
import {
    UTXOSelectionService,
    EnhancedUTXO,
    CoinSelectionStrategy,
    UTXOSelectionOptions,
} from './UTXOSelectionService';
import * as bitcoinMessage from 'bitcoinjs-message';
import { randomBytes, createHash, createCipheriv, createDecipheriv, createHmac } from 'crypto';
import { secureEncrypt, secureDecrypt, decryptData, legacyDecrypt } from './encryption';
import { runWithConcurrency } from './concurrency';
import { estimateTxFee, DEFAULT_FEE_RATE_SAT_PER_VBYTE, DUST_THRESHOLD_SATS } from './fees';
import {
    SIGHASH_ALL_FORKID,
    isAssetScript,
    type PsbtSummary,
    type PsbtInputSummary,
    type PsbtOutputSummary,
} from './psbt';
import {
    buildAssetTransferScript,
    buildIssuanceScript,
    buildOwnerScript,
    buildReissueScript,
    isValidRootAssetName,
    ISSUE_BURN,
} from './assetScript';
import { isAssetIssuanceEnabled, ASSET_ISSUANCE_DISABLED_MESSAGE } from '@/lib/featureFlags';

// How many transaction.get requests to keep in flight while syncing history. Electrum matches
// responses by id, so a small pool cuts the latency of a large sync ~N-fold. Kept deliberately low:
// public ElectrumX nodes rate-limit per connection and will drop the socket under a burst, so a
// gentle pool (plus retry-on-drop below) syncs reliably rather than fast-but-flaky.
const HISTORY_SYNC_CONCURRENCY = 4;

// Per-transaction fetch retries when a request fails mid-sync (a rate-limiting server dropping the
// connection is the common cause). Between attempts we wait for the socket to reconnect and back
// off a little, so a dropped request is recovered instead of losing that transaction.
const TX_FETCH_ATTEMPTS = 3;

// Re-exported so existing importers of these helpers from WalletService keep working. New code
// that only needs encryption should import from './encryption' directly, to avoid pulling the
// elliptic-curve dependencies this module binds at load.
export { secureEncrypt, decryptData, legacyDecrypt, inspectEncryptionFormat } from './encryption';

// Initialize ECPair and BIP32 with secp256k1
const ECPair = ECPairFactory(ecc);
const bip32 = BIP32Factory(ecc);

const ECIES_PREFIX = Buffer.from('BIE1');

/** Address type determines the BIP derivation path and script type used. */
export type AddressType = 'p2pkh' | 'p2wpkh' | 'p2sh-p2wpkh';

/** Maps an AddressType to its BIP44/49/84 purpose level and a human-readable label. */
export const ADDRESS_TYPE_INFO: Record<AddressType, { purpose: number; label: string; bipLabel: string }> = {
    p2pkh:       { purpose: 44, label: 'Legacy (P2PKH)',        bipLabel: 'BIP44' },
    'p2sh-p2wpkh': { purpose: 49, label: 'SegWit Wrapped (P2SH-P2WPKH)', bipLabel: 'BIP49' },
    p2wpkh:      { purpose: 84, label: 'Native SegWit (P2WPKH)', bipLabel: 'BIP84' },
};

/**
 * Outcome of building an asset issuance or reissue. Both the txid and the raw hex are always
 * present; `broadcast` says whether it was sent. A `buildOnly` dry run returns `broadcast: false`
 * — the transaction is signed and valid but nothing has been spent, so the txid is what it *would*
 * have, not something on chain yet.
 */
export interface AssetTxResult {
    txid: string;
    /** Raw signed transaction, ready for `testmempoolaccept` or a manual broadcast. */
    hex: string;
    broadcast: boolean;
}

export interface WalletData {
    id?: number;
    name: string;
    address: string;
    privateKey: string;
    mnemonic?: string; // BIP39 mnemonic phrase for backup/recovery
    bip39Passphrase?: string; // Optional encrypted BIP39 passphrase (25th word)
    xprv?: string; // Encrypted account-level xprv (used for descriptor-imported wallets, replaces mnemonic for HD derivation)
    coinType?: 921 | 175; // BIP44 coin type for derivation (default: 921 for Avian, 175 for Ravencoin legacy)
    addressType?: AddressType; // Script type / BIP derivation standard (default: p2pkh)
    descriptor?: string; // Output script descriptor (BIP380) derived at import/creation time
    isEncrypted: boolean;
    isActive: boolean;
    createdAt: Date;
    lastAccessed: Date;
}

// Legacy interface for backward compatibility
export interface LegacyWalletData {
    address: string;
    privateKey: string;
    mnemonic?: string;
}

// Avian network configuration
// bech32 HRP confirmed from Avian Core v5.0.0 chainparams.cpp: bech32_hrp = "avn"
// Testnet uses "tavn", regtest uses "avnrt"
export const avianNetwork: bitcoin.Network = {
    messagePrefix: '\x16Raven Signed Message:\n',
    bech32: 'avn', // Avian native SegWit address HRP (P2WPKH addresses start with 'avn1')
    bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4,
    },
    pubKeyHash: 0x3c, // Avian P2PKH addresses start with 'R' (decimal 60)
    scriptHash: 0x7a, // Avian P2SH addresses start with 'r' (decimal 122)
    wif: 0x80, // WIF version byte (decimal 128)
};

/**
 * Derives an address from a public key for the given address type on the Avian network.
 * Asset operations MUST use P2PKH (enforced by Avian Core v5.0.0).
 */
export function deriveAddress(
    pubkey: Buffer,
    addressType: AddressType = 'p2pkh',
): string {
    switch (addressType) {
        case 'p2wpkh': {
            const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network: avianNetwork });
            if (!p2wpkh.address) throw new Error('Failed to derive P2WPKH address');
            return p2wpkh.address;
        }
        case 'p2sh-p2wpkh': {
            const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network: avianNetwork });
            const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: avianNetwork });
            if (!p2sh.address) throw new Error('Failed to derive P2SH-P2WPKH address');
            return p2sh.address;
        }
        case 'p2pkh':
        default: {
            const p2pkh = bitcoin.payments.p2pkh({ pubkey, network: avianNetwork });
            if (!p2pkh.address) throw new Error('Failed to derive P2PKH address');
            return p2pkh.address;
        }
    }
}

/**
 * Returns the BIP derivation path purpose level for the given address type.
 * p2pkh → 44, p2sh-p2wpkh → 49, p2wpkh → 84
 */
export function purposeForAddressType(addressType: AddressType): number {
    return ADDRESS_TYPE_INFO[addressType].purpose;
}

/**
 * True when the string is a WIF private key valid on the Avian network.
 *
 * This is the only reliable way to tell a correct decryption from a wrong password on the legacy
 * (CryptoJS AES-CBC) format, which carries no authentication tag — see decryptData. Anything that
 * decrypts a legacy blob and then *writes* the result must check it with this first.
 */
export function isValidWIF(key: string): boolean {
    try {
        // WIF keys are base58 and, on Avian, start with '5', 'K' or 'L'.
        if (!/^[5KL][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(key)) {
            return false;
        }

        const ECPair = ECPairFactory(ecc);
        ECPair.fromWIF(key, avianNetwork);
        return true;
    } catch {
        return false;
    }
}

/**
 * Splits a spend into its recipient amount and change, given the inputs already selected.
 *
 * The fee paid to miners is always `feeRate`; `subtractFeeFromAmount` only decides who absorbs it:
 * - off: the recipient receives `amount`, and the sender's total outlay is `amount + feeRate`.
 * - on:  the recipient receives `amount - feeRate`, and the sender's total outlay is `amount`.
 *
 * Either way the miner fee is `totalInput - sendAmount - change = feeRate`. `totalInput` is
 * expected to already cover the sender's outlay — UTXO selection guarantees that upstream — so
 * change is non-negative in practice; callers still apply their own dust threshold before
 * emitting a change output.
 *
 * Shared by every send path so the three cannot drift apart again, which is exactly how the fee
 * became inconsistent in the first place.
 */
export function resolveSendAmounts(
    amount: number,
    feeRate: number,
    totalInput: number,
    subtractFeeFromAmount: boolean,
): { sendAmount: number; change: number } {
    const sendAmount = subtractFeeFromAmount ? Math.max(0, amount - feeRate) : amount;
    const change = totalInput - sendAmount - feeRate;
    return { sendAmount, change };
}

// Fee model lives in ./fees (dependency-free, shared with the UI so the two cannot drift apart).
export {
    estimateTxVBytes,
    estimateTxFee,
    DEFAULT_FEE_RATE_SAT_PER_VBYTE,
    DUST_THRESHOLD_SATS,
} from './fees';





/**
 * Recover a secp256k1 public key from a Bitcoin-message signature.
 *
 * @param message        The original UTF-8 string that was signed.
 * @param signatureB64   The Base64-encoded “compact” signature (with recovery flag byte).
 * @returns              The recovered public key (33- or 65-byte Buffer/Uint8Array).
 * @throws               If recovery fails or the signature flag is invalid.
 */
export function recoverPubKey(message: string, signatureB64: string): Uint8Array {
    // 1) Base64 → Buffer
    const sigBuf = Buffer.from(signatureB64, 'base64');

    // 2) Peel off first byte to get recovery & compression bits
    const flag = sigBuf[0] - 27;
    if (flag < 0 || flag > 15) {
        throw new Error('Invalid signature flag');
    }
    const recoveryId = flag & 0x03;
    const compressed = Boolean(flag & 0x04);

    // 3) Extract the 64-byte (r||s) signature
    const sig64 = sigBuf.subarray(1);

    // 4) Hash the message with Bitcoin’s “magic” prefix
    // Ensure we use Avian's prefix for proper message signing
    const msgHash = bitcoinMessage.magicHash(message, avianNetwork.messagePrefix);

    // 5) Recover the pubkey
    const pubkey = ecc.recover(msgHash, sig64, recoveryId as ecc.RecoveryIdType, compressed);
    if (!pubkey) {
        throw new Error('Public key recovery failed');
    }

    return pubkey;
}

export class WalletService {
    protected electrum: ElectrumService;

    constructor(electrumService?: ElectrumService) {
        this.electrum = electrumService || new ElectrumService();
    }

    async generateWallet(
        password: string,
        useMnemonic: boolean = true,
        passphrase?: string,
    ): Promise<LegacyWalletData> {
        // Validate required password
        if (!password || password.length < 8) {
            throw new Error('Password is required and must be at least 8 characters long');
        }

        try {
            let keyPair: any;
            let mnemonic: string | undefined;

            if (useMnemonic) {
                // Generate BIP39 mnemonic
                mnemonic = bip39.generateMnemonic(128); // 12 words

                // Derive seed from mnemonic with optional passphrase (BIP39 25th word)
                const seed = await bip39.mnemonicToSeed(mnemonic, passphrase || '');

                // Create HD wallet root
                const root = bip32.fromSeed(seed, avianNetwork);

                // Derive key at standard path m/44'/921'/0'/0/0 (921 is Avian's coin type)
                // generateWallet always creates P2PKH legacy wallets for asset compatibility
                const path = "m/44'/921'/0'/0/0";
                const child = root.derivePath(path);

                if (!child.privateKey) {
                    throw new Error('Failed to derive private key from mnemonic');
                }

                // Create ECPair from derived private key
                keyPair = ECPair.fromPrivateKey(child.privateKey, { network: avianNetwork });
            } else {
                // Generate a random key pair directly (legacy method)
                keyPair = ECPair.makeRandom({ network: avianNetwork });
            }

            const privateKeyWIF = keyPair.toWIF();

            // P2PKH address (legacy generateWallet always uses P2PKH for asset compatibility)
            const address = deriveAddress(Buffer.from(keyPair.publicKey), 'p2pkh');

            if (!address) {
                throw new Error('Failed to generate address');
            }

            // Encrypt private key with password (now mandatory)
            const finalPrivateKey = await secureEncrypt(privateKeyWIF, password);

            // Encrypt mnemonic with password (now mandatory if mnemonic exists)
            const finalMnemonic = mnemonic ? await secureEncrypt(mnemonic, password) : mnemonic;

            // Store mnemonic if generated
            if (mnemonic) {
                await StorageService.setMnemonic(finalMnemonic!);
            }

            return {
                address,
                privateKey: finalPrivateKey,
                mnemonic: finalMnemonic,
            };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to generate wallet: ${errorMessage}`);
        }
    }

    async restoreWallet(privateKey: string, password?: string): Promise<LegacyWalletData> {
        try {
            // Decrypt private key if password provided
            const { decrypted: decryptedKey } = password
                ? await decryptData(privateKey, password)
                : { decrypted: privateKey };

            if (!decryptedKey) {
                throw new Error('Invalid password or corrupted private key');
            }

            // Create key pair from WIF using ECPair
            const keyPair = ECPair.fromWIF(decryptedKey, avianNetwork);

            // Get the address
            const { address } = bitcoin.payments.p2pkh({
                pubkey: Buffer.from(keyPair.publicKey),
                network: avianNetwork,
            });

            if (!address) {
                throw new Error('Failed to restore address');
            }

            return {
                address,
                privateKey,
            };
        } catch (error) {
            throw new Error('Failed to restore wallet');
        }
    }

    async getBalance(address: string, forceRefresh: boolean = false): Promise<number> {
        return (await this.getBalanceDetailed(address, forceRefresh)).balance;
    }

    /**
     * Balance plus its provenance. A bare number cannot distinguish "the server says 0" from
     * "the server is unreachable and nothing is cached" — callers that display the balance
     * should use this and treat 'unknown' as unavailable rather than as zero.
     */
    async getBalanceDetailed(
        address: string,
        forceRefresh: boolean = false,
    ): Promise<DetailedBalance> {
        try {
            return await this.electrum.getBalanceDetailed(address, forceRefresh);
        } catch (error) {
            return { balance: 0, source: 'unknown' };
        }
    }

    /**
     * Subscribes to wallet updates via ElectrumX
     * @param address - The wallet address to monitor
     * @param onUpdate - Optional callback when updates occur
     */
    async subscribeToWalletUpdates(address: string, onUpdate?: (data: any) => void): Promise<void> {
        try {
            // Subscribe to address changes via ElectrumX
            await this.electrum.subscribeToAddress(address, async (status: string) => {
                // Process transaction history to detect new received transactions
                try {
                    await this.processTransactionHistory(address);
                } catch (error) {
                    walletLogger.error(
                        'Error processing transaction history during subscription update:',
                        error,
                    );
                }

                // Trigger balance update when status changes
                this.getBalance(address, true)
                    .then((newBalance) => {
                        // Store updated balance in wallet record
                        StorageService.setWalletBalance(address, newBalance);

                        // Call the callback if provided
                        if (onUpdate) {
                            onUpdate({ address, balance: newBalance, status: status });
                        }
                    })
                    .catch((error) => {
                        walletLogger.error('Error updating balance after subscription notification:', error);
                    });
            });
        } catch (error) {
            walletLogger.error('Error subscribing to wallet updates:', error);
            throw error;
        }
    }

    async unsubscribeFromWalletUpdates(address: string): Promise<void> {
        try {
            // Unsubscribe from address updates via ElectrumX
            await this.electrum.unsubscribeFromAddress(address);

            // We no longer disable wallet notifications during unsubscribe
            // This ensures notification settings are preserved when switching wallets
            walletLogger.info(
                `Unsubscribed from wallet updates for ${address} (notifications preserved)`,
            );

            // Note: Previously this would disable notifications for the wallet,
            // but that caused issues when switching wallets as it would disable
            // notifications for all wallets that were previously active
        } catch (error) {
            walletLogger.error('Error unsubscribing from wallet updates:', error);
            throw error;
        }
    }

    /**
     * Initialize wallet by connecting to Electrum, getting balance, and processing transaction history
     * @param address - The wallet address to initialize
     * @param onUpdate - Optional callback for updates from subscription
     * @param onProgress - Optional callback for transaction processing progress (passed to other methods)
     */
    async initializeWallet(
        address: string,
        onUpdate?: (data: any) => void,
        onProgress?: (processed: number, total: number, currentTx?: string) => void,
    ): Promise<void> {
        try {
            // Connect to Electrum server only if not already connected
            if (!this.electrum.isConnectedToServer()) {
                await this.electrum.connect();
            }

            // Get initial balance
            const balance = await this.getBalance(address);

            // Store balance in wallet record and global preference for compatibility
            await StorageService.setWalletBalance(address, balance);

            // Migrate transaction addresses for better multi-wallet support
            try {
                const migratedCount = await StorageService.migrateTransactionAddresses();
                if (migratedCount > 0) {
                }
            } catch (migrationError) {
                walletLogger.warn('Error during transaction address migration:', migrationError);
            }

            // Migrate balance data to wallet table (only once)
            try {
                // Check if the migration has been completed before
                const migrationCompleted = localStorage.getItem('balanceMigrationCompleted');
                if (!migrationCompleted) {
                    await StorageService.migrateBalanceData();

                    // Mark migration as completed
                    localStorage.setItem('balanceMigrationCompleted', 'true');
                }
            } catch (balanceMigrationError) {
                walletLogger.warn('Error during balance data migration:', balanceMigrationError);
            }

            // Check if there are any transactions without wallet address for this wallet
            try {
                const txHistory = await StorageService.getTransactionHistory(address);
                const missingWalletAddress = txHistory.filter((tx) => !tx.walletAddress);

                if (missingWalletAddress.length > 0) {
                    for (const tx of missingWalletAddress) {
                        tx.walletAddress = address;
                        await StorageService.saveTransaction(tx);
                    }
                }
            } catch (fixError) {
                walletLogger.warn('Error fixing transactions without wallet address:', fixError);
            }

            // Pull transaction history on load. This is incremental: after the first sync it only
            // fetches transactions we haven't stored yet, so opening the wallet is fast even with a
            // large history. Previously this did a FULL reprocess (re-fetching every transaction)
            // on first login and every 24h thereafter, which is very slow for big wallets — a full
            // reclassification is rarely needed and remains available on demand (balance card
            // long-press -> reprocessTransactionHistory).
            try {
                const lastProcessedKey = `${address}_last_processed_time`;
                await this.refreshTransactionHistory(address, onProgress);
                localStorage.setItem(lastProcessedKey, Date.now().toString());
            } catch (error) {
                walletLogger.error('Error processing initial transaction history:', error);
            }

            // Subscribe to updates
            await this.subscribeToWalletUpdates(address, onUpdate);
        } catch (error) {
            walletLogger.error('Error initializing wallet:', error);
            throw error;
        }
    }

    /**
     * The fee rate (sat/vByte) to use for a spend: a caller override if given, otherwise the node's
     * reported rate but never below Avian Core's default (fee estimation is unavailable on this
     * low-volume chain, so Core's default is the reliable floor).
     */
    private async resolveFeeRate(optionRate?: number): Promise<number> {
        if (optionRate && optionRate > 0) {
            return optionRate;
        }
        let networkRate = 0;
        try {
            networkRate = await this.electrum.getFeeRateSatPerVByte();
        } catch {
            networkRate = 0;
        }
        return Math.max(DEFAULT_FEE_RATE_SAT_PER_VBYTE, networkRate);
    }

    // --- PSBT (BIP174) -------------------------------------------------------------------------
    // Avian PSBTs are stock BIP174; the only Avian detail is the 0x41 (ALL|FORKID) sighash, which
    // bitcoinjs already produces for legacy and SegWit-v0 inputs when that type is set. So signing
    // reuses the same path regular sends use. Asset inputs are never signed (that would burn them).

    /**
     * Decrypt a wallet's key into an ECPair (throws on a missing/bad password).
     *
     * `address` picks a specific wallet; without it the active wallet is used. Avian Connect
     * signs for the account a site connected with, which is not necessarily the active one — the
     * user may have switched wallets mid-session.
     */
    private async getWalletKeyPair(password?: string, address?: string) {
        const activeWallet = address
            ? await StorageService.getWalletByAddress(address)
            : await StorageService.getActiveWallet();
        if (!activeWallet) {
            throw new Error(address ? `No wallet found for ${address}` : 'No active wallet found');
        }
        let wif = activeWallet.privateKey;
        if (activeWallet.isEncrypted) {
            if (!password) throw new Error('Password required for encrypted wallet');
            try {
                const { decrypted } = await decryptData(wif, password);
                if (!decrypted) throw new Error('Invalid password');
                wif = decrypted;
            } catch {
                throw new Error('Invalid password');
            }
        }
        return ECPair.fromWIF(wif, avianNetwork);
    }

    /** Prevout {script,value} for a PSBT input, from its witnessUtxo or nonWitnessUtxo. */
    private psbtPrevOut(psbt: bitcoin.Psbt, index: number): { script: Buffer; value: number } | null {
        const data = psbt.data.inputs[index];
        if (data.witnessUtxo) {
            return { script: data.witnessUtxo.script, value: data.witnessUtxo.value };
        }
        if (data.nonWitnessUtxo) {
            const prevTx = bitcoin.Transaction.fromBuffer(data.nonWitnessUtxo);
            const out = prevTx.outs[psbt.txInputs[index].index];
            return out ? { script: out.script, value: out.value } : null;
        }
        return null;
    }

    private scriptToAddress(script: Buffer): string | null {
        try {
            return bitcoin.address.fromOutputScript(script, avianNetwork);
        } catch {
            return null;
        }
    }

    private inputHasAnySig(data: any): boolean {
        return !!(
            data.finalScriptSig ||
            data.finalScriptWitness ||
            (data.partialSig && data.partialSig.length)
        );
    }

    /**
     * Decode a base64 PSBT and describe it — each input's prevout, ownership and asset status, each
     * output, totals and fee, how many inputs this wallet can sign, and whether it is ready to
     * finalize. No key access, so it is safe to show before authentication.
     */
    async summarizePsbt(psbtBase64: string, ownAddress?: string): Promise<PsbtSummary> {
        const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: avianNetwork });
        const mine = ownAddress ?? (await StorageService.getActiveWallet())?.address ?? null;
        const myScript = mine ? bitcoin.address.toOutputScript(mine, avianNetwork) : null;

        const inputs: PsbtInputSummary[] = psbt.txInputs.map((txIn, i) => {
            const prev = this.psbtPrevOut(psbt, i);
            const script = prev?.script ?? null;
            return {
                txid: Buffer.from(txIn.hash).reverse().toString('hex'),
                vout: txIn.index,
                value: prev?.value ?? null,
                address: script ? this.scriptToAddress(script) : null,
                isMine: !!(script && myScript && script.equals(myScript)),
                isAsset: !!(script && isAssetScript(script)),
                signed: this.inputHasAnySig(psbt.data.inputs[i]),
            };
        });

        const outputs: PsbtOutputSummary[] = psbt.txOutputs.map((out) => ({
            address: this.scriptToAddress(out.script),
            value: out.value,
            isMine: !!(myScript && out.script.equals(myScript)),
            isAsset: isAssetScript(out.script),
        }));

        const knownIn = inputs.every((i) => i.value !== null);
        const totalIn = knownIn ? inputs.reduce((s, i) => s + (i.value ?? 0), 0) : null;
        const totalOut = outputs.reduce((s, o) => s + o.value, 0);

        return {
            inputs,
            outputs,
            totalIn,
            totalOut,
            fee: totalIn !== null ? totalIn - totalOut : null,
            signableByUs: inputs.filter((i) => i.isMine && !i.isAsset && !i.signed).length,
            complete: inputs.every((i) => i.signed),
            hasAsset: inputs.some((i) => i.isAsset) || outputs.some((o) => o.isAsset),
        };
    }

    /** The unsigned global transaction of a PSBT (empty input scripts), for computing sighashes. */
    private unsignedTxFromPsbt(psbt: bitcoin.Psbt): bitcoin.Transaction {
        const tx = new bitcoin.Transaction();
        tx.version = psbt.version;
        tx.locktime = psbt.locktime;
        for (const input of psbt.txInputs) tx.addInput(Buffer.from(input.hash), input.index, input.sequence);
        for (const output of psbt.txOutputs) tx.addOutput(output.script, output.value);
        return tx;
    }

    /** Whether a prevout script is a native P2WPKH (`OP_0 <20-byte hash>`). */
    private isP2wpkhScript(script: Buffer): boolean {
        return script.length === 22 && script[0] === 0x00 && script[1] === 0x14;
    }

    /** Serialize a witness stack (count + length-prefixed items) for a PSBT finalScriptWitness. */
    private serializeWitnessStack(items: Buffer[]): Buffer {
        const chunks: Buffer[] = [this.encodeVarint(items.length)];
        for (const item of items) chunks.push(this.encodeVarint(item.length), item);
        return Buffer.concat(chunks);
    }

    private encodeVarint(n: number): Buffer {
        if (n < 0xfd) return Buffer.from([n]);
        if (n <= 0xffff) {
            const b = Buffer.allocUnsafe(3);
            b[0] = 0xfd;
            b.writeUInt16LE(n, 1);
            return b;
        }
        const b = Buffer.allocUnsafe(5);
        b[0] = 0xfe;
        b.writeUInt32LE(n, 1);
        return b;
    }

    /** Set an input's final scriptSig (legacy) or scriptWitness (SegWit) from a [sig, pubkey] pair. */
    private setFinalScript(psbt: bitcoin.Psbt, index: number, sig: Buffer, pub: Buffer, isSegwit: boolean) {
        if (isSegwit) {
            psbt.updateInput(index, { finalScriptWitness: this.serializeWitnessStack([sig, pub]) });
        } else {
            psbt.updateInput(index, { finalScriptSig: bitcoin.script.compile([sig, pub]) });
        }
    }

    /**
     * Sign every input owned by `account` (defaulting to the active wallet) — skipping asset inputs
     * and any already signed — with the Avian FORKID sighash, returning the updated base64 PSBT
     * with those inputs finalized.
     *
     * Callers that signed on behalf of somebody else — Avian Connect signs for the account a site
     * connected with — must pass `account`. Defaulting to the active wallet there would sign with
     * whichever wallet the user last switched to, which is not the one the approval screen
     * described.
     *
     * Two Avian-specific reasons this doesn't use bitcoinjs-lib's PSBT signer/finaliser:
     *  1. Its signer rejects the 0x41 (ALL|FORKID) sighash ("Invalid hashType 65"), so we compute
     *     the digest ourselves — legacy `hashForSignature` for P2PKH, BIP143 `hashForWitnessV0` for
     *     native SegWit — exactly as the regular send path already broadcasts on mainnet.
     *  2. **Avian Core cannot decode a FORKID `partial_sig`**: its PSBT parser runs every partial
     *     signature through `CheckSignatureEncoding` without `SCRIPT_ENABLE_SIGHASH_FORKID`
     *     (interpreter.cpp), so the 0x40 bit is rejected as an illegal encoding. Core sidesteps this
     *     by finalising immediately (the signature then rides in `final_scriptsig`, which decode does
     *     not validate). Our inputs are single-key, so one signature completes them — so we finalise
     *     each input as we sign it. The result carries `final_scriptsig`/`final_scriptwitness`, which
     *     Core and other wallets read and broadcast; a lingering FORKID `partial_sig` would not
     *     round-trip to Core.
     */
    async signPsbt(
        psbtBase64: string,
        password?: string,
        account?: string,
    ): Promise<{ psbt: string; complete: boolean; signedInputs: number }> {
        const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: avianNetwork });
        const keyPair = await this.getWalletKeyPair(password, account);
        const pubkey = Buffer.from(keyPair.publicKey);
        const p2pkhScript = bitcoin.payments.p2pkh({ pubkey, network: avianNetwork }).output!;
        const p2wpkhScript = bitcoin.payments.p2wpkh({ pubkey, network: avianNetwork }).output!;
        const unsigned = this.unsignedTxFromPsbt(psbt);

        let signedInputs = 0;
        for (let i = 0; i < psbt.inputCount; i++) {
            const data = psbt.data.inputs[i];
            if (data.finalScriptSig || data.finalScriptWitness) continue; // already finalized
            const prev = this.psbtPrevOut(psbt, i);
            if (!prev) continue;
            if (isAssetScript(prev.script)) continue; // never sign an asset input — it would burn it
            const isP2pkh = prev.script.equals(p2pkhScript);
            const isP2wpkh = prev.script.equals(p2wpkhScript);
            if (!isP2pkh && !isP2wpkh) continue; // not our key
            try {
                let digest: Buffer;
                if (isP2wpkh) {
                    // BIP143 sighash: the scriptCode is the equivalent P2PKH, amount is committed.
                    const scriptCode = bitcoin.script.compile([
                        bitcoin.opcodes.OP_DUP,
                        bitcoin.opcodes.OP_HASH160,
                        bitcoin.crypto.hash160(pubkey),
                        bitcoin.opcodes.OP_EQUALVERIFY,
                        bitcoin.opcodes.OP_CHECKSIG,
                    ]);
                    digest = unsigned.hashForWitnessV0(i, scriptCode, prev.value, SIGHASH_ALL_FORKID);
                } else {
                    // Legacy sighash: amount is not committed; the prevout script is the scriptCode.
                    digest = unsigned.hashForSignature(i, prev.script, SIGHASH_ALL_FORKID);
                }
                const sig = this.encodeDERWithCustomHashType(
                    Buffer.from(keyPair.sign(digest)),
                    SIGHASH_ALL_FORKID,
                );
                // Finalize immediately (single-key input) rather than leaving a FORKID partial_sig,
                // which Avian Core refuses to decode. See the method comment above.
                this.setFinalScript(psbt, i, sig, pubkey, isP2wpkh);
                signedInputs++;
            } catch (error) {
                walletLogger.warn(`Could not sign PSBT input ${i}:`, error);
            }
        }

        return {
            psbt: psbt.toBase64(),
            complete: psbt.data.inputs.every((d) => this.inputHasAnySig(d)),
            signedInputs,
        };
    }

    /**
     * Finalize a fully-signed PSBT and extract the raw transaction (hex + txid). `signPsbt` already
     * finalizes the inputs it signs, so this is normally just an extract; for a PSBT that still
     * carries a `partial_sig` (from another signer) it builds the final script from that first.
     */
    finalizePsbt(psbtBase64: string): { hex: string; txid: string } {
        const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: avianNetwork });
        for (let i = 0; i < psbt.inputCount; i++) {
            const data = psbt.data.inputs[i];
            if (data.finalScriptSig || data.finalScriptWitness) continue; // already finalized
            const partialSig = data.partialSig?.[0];
            if (!partialSig) throw new Error(`PSBT input ${i} is not signed`);
            const prev = this.psbtPrevOut(psbt, i);
            this.setFinalScript(
                psbt,
                i,
                Buffer.from(partialSig.signature),
                Buffer.from(partialSig.pubkey),
                !!(prev && this.isP2wpkhScript(prev.script)),
            );
        }
        const tx = psbt.extractTransaction();
        return { hex: tx.toHex(), txid: tx.getId() };
    }

    /** Broadcast a raw transaction hex (e.g. from finalizePsbt) and return its txid. */
    async broadcastRawTransaction(hex: string): Promise<string> {
        const result = await this.electrum.broadcastTransaction(hex);
        if (!result || typeof result !== 'string') {
            throw new Error('Transaction broadcast failed. Please try again later.');
        }
        return result;
    }

    /** Sign the active wallet's inputs, finalize, and broadcast. Returns the txid. */
    async signAndBroadcastPsbt(psbtBase64: string, password?: string): Promise<string> {
        const signed = await this.signPsbt(psbtBase64, password);
        const { hex, txid } = this.finalizePsbt(signed.psbt);
        await this.broadcastRawTransaction(hex);
        return txid;
    }

    /**
     * Plan a spend from a single address and build the *unsigned* PSBT: fetch and select UTXOs with
     * an iterative size-based fee, split into recipient + change (folding sub-dust change into the
     * fee), and add the inputs (nonWitnessUtxo for legacy, witnessUtxo for SegWit) and outputs.
     *
     * Shared by `sendTransaction` (which then signs) and `buildUnsignedPsbt` (which exports it), so
     * selection and fee logic have a single source of truth. Needs no private key; pass `pubkey`
     * only for P2SH-P2WPKH, whose redeemScript requires it.
     */
    private async planSpend(params: {
        fromAddress: string;
        walletAddrType: AddressType;
        toAddress: string;
        amount: number;
        options?: {
            strategy?: CoinSelectionStrategy;
            feeRate?: number;
            maxInputs?: number;
            minConfirmations?: number;
            changeAddress?: string;
            subtractFeeFromAmount?: boolean;
        };
        pubkey?: Buffer;
    }): Promise<{
        psbt: bitcoin.Psbt;
        selectedUTXOs: any[];
        fee: number;
        finalSendAmount: number;
        finalChange: number;
        changeAddress: string;
    }> {
        const { fromAddress, walletAddrType, toAddress, amount, options, pubkey } = params;

        // Get UTXOs for the address
        const rawUTXOs = await this.electrum.getUTXOs(fromAddress);
        if (rawUTXOs.length === 0) {
            throw new Error('No unspent transaction outputs found');
        }

        // Enhance UTXOs with additional metadata
        const currentBlockHeight = await this.electrum.getCurrentBlockHeight();
        const enhancedUTXOs: EnhancedUTXO[] = rawUTXOs.map((utxo) => ({
            ...utxo,
            confirmations: utxo.height ? Math.max(0, currentBlockHeight - utxo.height + 1) : 0,
            isConfirmed: utxo.height ? currentBlockHeight - utxo.height + 1 >= 1 : false,
            ageInBlocks: utxo.height ? currentBlockHeight - utxo.height + 1 : 0,
            address: fromAddress,
        }));

        // Calculate total available amount
        const totalAvailable = enhancedUTXOs.reduce((sum, utxo) => sum + utxo.value, 0);

        // Size-based fee: sat/vByte rate (caller override, else the node's rate, floored).
        const subtractFee = options?.subtractFeeFromAmount ?? false;
        const satPerVByte = await this.resolveFeeRate(options?.feeRate);

        // Select optimal UTXOs using the selection service
        const strategyRecommendation = UTXOSelectionService.getRecommendedStrategy(
            amount,
            enhancedUTXOs,
            {
                consolidateDust: options?.strategy === CoinSelectionStrategy.CONSOLIDATE_DUST,
            },
        );

        // Get wallet's own address for dust consolidation
        let selfAddress;
        if (
            strategyRecommendation.recommendSelfAddress ||
            options?.strategy === CoinSelectionStrategy.CONSOLIDATE_DUST
        ) {
            const wallet = await StorageService.getActiveWallet();
            if (wallet) {
                selfAddress = wallet.address;
            }
        }

        // The fee depends on how many inputs get selected, and selection depends on the fee, so
        // iterate: estimate a fee, select, re-estimate from the actual input count, and reselect
        // if it grew. Converges in a pass or two because the fee is tiny next to the amounts.
        let selectedUTXOs: any[] = [];
        let totalSelected = 0;
        let fee = estimateTxFee(1, 2, satPerVByte);
        for (let iteration = 0; iteration < 4; iteration++) {
            // For subtract-fee the recipient absorbs the fee, so the inputs only need to cover
            // `amount`; otherwise they must cover `amount + fee`. This is what makes send-max
            // with subtract-fee possible.
            const selectionTarget = subtractFee ? Math.max(0, amount - fee) : amount;
            const totalRequired = selectionTarget + fee;
            if (totalAvailable < totalRequired) {
                throw new Error(
                    `Insufficient funds. Required: ${totalRequired} satoshis, Available: ${totalAvailable} satoshis`,
                );
            }

            const selectionOptions: UTXOSelectionOptions = {
                strategy: options?.strategy || strategyRecommendation.strategy,
                targetAmount: selectionTarget,
                feeRate: fee,
                maxInputs: options?.maxInputs || 20,
                minConfirmations: options?.minConfirmations || 0,
                allowUnconfirmed: true,
                includeDust: options?.strategy === CoinSelectionStrategy.CONSOLIDATE_DUST,
                isAutoConsolidation: options?.strategy === CoinSelectionStrategy.CONSOLIDATE_DUST,
                selfAddress: selfAddress,
            };

            const selectionResult = UTXOSelectionService.selectUTXOs(enhancedUTXOs, selectionOptions);
            if (!selectionResult) {
                throw new Error('Unable to select suitable UTXOs for transaction');
            }
            selectedUTXOs = selectionResult.selectedUTXOs;
            totalSelected = selectedUTXOs.reduce((sum, utxo) => sum + utxo.value, 0);

            const recomputed = estimateTxFee(selectedUTXOs.length, 2, satPerVByte);
            if (recomputed <= fee) {
                fee = recomputed;
                break;
            }
            fee = recomputed; // grew with the input count — reselect to cover the larger fee
        }

        // Split into recipient and change, folding sub-dust change into the fee rather than
        // emitting an output the network would reject as dust.
        const split = resolveSendAmounts(amount, fee, totalSelected, subtractFee);
        const finalSendAmount = split.sendAmount;
        if (finalSendAmount <= 0) {
            throw new Error('Send amount is zero or negative after subtracting the fee');
        }
        if (split.change < 0) {
            throw new Error('Insufficient funds to cover the network fee');
        }
        const finalChange = split.change >= DUST_THRESHOLD_SATS ? split.change : 0;

        // Determine change address - use custom address if provided, otherwise sender's address
        const changeAddress =
            options?.changeAddress && options.changeAddress.trim() !== ''
                ? options.changeAddress
                : fromAddress;

        // Build transaction using PSBT
        const psbt = new bitcoin.Psbt({ network: avianNetwork });

        // SegWit inputs (P2WPKH, P2SH-P2WPKH) use witnessUtxo; legacy P2PKH uses nonWitnessUtxo.
        const isSegWit = walletAddrType === 'p2wpkh' || walletAddrType === 'p2sh-p2wpkh';

        // Add inputs from selected UTXOs
        for (const utxo of selectedUTXOs) {
            const txHex = await this.electrum.getTransaction(utxo.txid, false);
            const prevTx = bitcoin.Transaction.fromHex(txHex);
            const prevOut = prevTx.outs[utxo.vout];

            if (isSegWit) {
                // SegWit inputs: provide witnessUtxo (the output being spent) so PSBT can compute
                // the BIP143 sighash without the full previous transaction. Stamp sighashType so a
                // signer knows Avian's 0x41 is expected.
                const inputObj: any = {
                    hash: utxo.txid,
                    index: utxo.vout,
                    sighashType: SIGHASH_ALL_FORKID,
                    witnessUtxo: {
                        script: prevOut.script,
                        value: prevOut.value,
                    },
                };
                // P2SH-P2WPKH also needs the redeemScript so the finaliser can build the input
                // scriptSig (the push of the redeem script). Only available when we hold the pubkey.
                if (walletAddrType === 'p2sh-p2wpkh' && pubkey) {
                    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network: avianNetwork });
                    inputObj.redeemScript = p2wpkh.output!;
                }
                psbt.addInput(inputObj);
            } else {
                // Legacy P2PKH inputs: provide the full previous transaction hex.
                psbt.addInput({
                    hash: utxo.txid,
                    index: utxo.vout,
                    nonWitnessUtxo: Buffer.from(txHex, 'hex'),
                });
            }
        }

        // Add output for recipient
        psbt.addOutput({ address: toAddress, value: finalSendAmount });

        // Add change output if needed
        if (finalChange > 0) {
            psbt.addOutput({ address: changeAddress, value: finalChange });
        }

        return { psbt, selectedUTXOs, fee, finalSendAmount, finalChange, changeAddress };
    }

    /**
     * Build an unsigned PSBT for a spend and return it as base64 — the same selection and fee logic
     * as `sendTransaction`, but stopping before signing. Requires no password for P2PKH/P2WPKH
     * wallets (no key needed to describe the inputs). Use it to sign the transaction elsewhere
     * (Avian Core, a co-signer) and broadcast it there or via the PSBT import tool.
     */
    async buildUnsignedPsbt(
        toAddress: string,
        amount: number,
        options?: {
            strategy?: CoinSelectionStrategy;
            feeRate?: number;
            maxInputs?: number;
            minConfirmations?: number;
            changeAddress?: string;
            subtractFeeFromAmount?: boolean;
        },
    ): Promise<{ psbt: string; fee: number; inputs: number; sendAmount: number; changeAmount: number }> {
        const activeWallet = await StorageService.getActiveWallet();
        if (!activeWallet) throw new Error('No active wallet found');
        const walletAddrType: AddressType = activeWallet.addressType || 'p2pkh';
        if (walletAddrType === 'p2sh-p2wpkh') {
            // The redeemScript needs the public key, which we can't derive without decrypting; a
            // wrapped-SegWit wallet should sign directly instead of exporting an unsigned PSBT.
            throw new Error('Exporting an unsigned PSBT is not supported for wrapped-SegWit wallets');
        }
        const plan = await this.planSpend({
            fromAddress: activeWallet.address,
            walletAddrType,
            toAddress,
            amount,
            options,
        });
        return {
            psbt: plan.psbt.toBase64(),
            fee: plan.fee,
            inputs: plan.selectedUTXOs.length,
            sendAmount: plan.finalSendAmount,
            changeAmount: plan.finalChange,
        };
    }

    /**
     * Send `amount` (on-chain integer units, scaled by 10^8) of an Avian asset to a legacy address.
     *
     * Asset accounting is a separate ledger from AVN: asset transfer outputs carry 0 AVN value, so
     * the network fee is paid entirely by AVN inputs. We spend asset UTXOs for the asset (with asset
     * change back to ourselves) and AVN UTXOs for the fee (with AVN change). ElectrumX segregates the
     * two — getAssetUTXOs returns only the named asset's outputs and getUTXOs only AVN — so the two
     * input sets are disjoint and a plain-AVN send can never touch an asset.
     *
     * Spending an asset UTXO is an ordinary P2PKH spend: OP_DROP discards the asset rider at
     * execution, so the sighash is taken over the full asset script and the scriptSig is [sig,
     * pubkey], signed with the Avian FORKID (0x41) exactly like every other input.
     *
     * NOTE: build/parse is byte-validated against Core (see assetScript.ts), but this end-to-end
     * builder must be regtest-validated against Avian Core before it is wired into any UI.
     */
    async sendAssetTransfer(
        assetName: string,
        amount: bigint,
        toAddress: string,
        password?: string,
        options?: { feeRate?: number; changeAddress?: string },
    ): Promise<string> {
        try {
            if (amount <= 0n) throw new Error('Asset amount must be positive');

            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) throw new Error('No active wallet found');
            if ((activeWallet.addressType || 'p2pkh') !== 'p2pkh') {
                throw new Error('Assets can only be sent from a legacy (R…) address');
            }

            let privateKeyWIF = activeWallet.privateKey;
            if (activeWallet.isEncrypted) {
                if (!password) throw new Error('Password required for encrypted wallet');
                try {
                    const { decrypted } = await decryptData(privateKeyWIF, password);
                    if (!decrypted) throw new Error('Invalid password');
                    privateKeyWIF = decrypted;
                } catch {
                    throw new Error('Invalid password');
                }
            }

            const keyPair = ECPair.fromWIF(privateKeyWIF, avianNetwork);
            const pubkey = Buffer.from(keyPair.publicKey);
            const fromAddress = activeWallet.address;
            const changeAddress = options?.changeAddress?.trim() || fromAddress;

            // --- Asset side: select asset UTXOs to cover the amount, with asset change to self. ---
            const assetUTXOs = await this.electrum.getAssetUTXOs(fromAddress, assetName);
            const sortedAssets = [...assetUTXOs].sort((a, b) => b.value - a.value);
            const selectedAssets: typeof assetUTXOs = [];
            let assetIn = 0n;
            for (const utxo of sortedAssets) {
                if (assetIn >= amount) break;
                selectedAssets.push(utxo);
                assetIn += BigInt(Math.trunc(utxo.value));
            }
            if (assetIn < amount) {
                throw new Error(`Insufficient ${assetName}: have ${assetIn}, need ${amount}`);
            }
            const assetChange = assetIn - amount;

            const transferScript = buildAssetTransferScript(toAddress, assetName, amount);
            const assetChangeScript =
                assetChange > 0n ? buildAssetTransferScript(fromAddress, assetName, assetChange) : null;

            // --- AVN side: size the fee and select AVN UTXOs to cover it (iterating on input count). ---
            const satPerVByte = await this.resolveFeeRate(options?.feeRate);
            const avnUTXOs = await this.electrum.getUTXOs(fromAddress);
            const sortedAvn = [...avnUTXOs].sort((a, b) => b.value - a.value);
            const totalAvn = sortedAvn.reduce((sum, utxo) => sum + utxo.value, 0);

            // Asset output scripts are larger than a plain 34-byte output; size them exactly (script
            // length is always < 253, so its length prefix is one byte). Always budget an AVN change
            // output (+34); if change turns out to be dust it is folded into the fee, costing nothing.
            const assetOutputsVBytes =
                (8 + 1 + transferScript.length) +
                (assetChangeScript ? 8 + 1 + assetChangeScript.length : 0);
            const sizeFor = (avnInputCount: number) =>
                10 + (selectedAssets.length + avnInputCount) * 148 + assetOutputsVBytes + 34;

            let selectedAvn: typeof avnUTXOs = [];
            let avnIn = 0;
            let fee = 0;
            for (let iteration = 0; iteration < 6; iteration++) {
                fee = Math.ceil(sizeFor(Math.max(selectedAvn.length, 1)) * satPerVByte);
                if (totalAvn < fee) {
                    throw new Error(`Insufficient AVN for the network fee (need ${fee} sat)`);
                }
                selectedAvn = [];
                avnIn = 0;
                for (const utxo of sortedAvn) {
                    if (avnIn >= fee) break;
                    selectedAvn.push(utxo);
                    avnIn += utxo.value;
                }
                const recomputed = Math.ceil(sizeFor(selectedAvn.length) * satPerVByte);
                if (avnIn >= recomputed && recomputed <= fee) {
                    fee = recomputed;
                    break;
                }
                fee = recomputed;
            }
            if (avnIn < fee) throw new Error('Insufficient AVN for the network fee');
            const avnChange = avnIn - fee;
            const finalAvnChange = avnChange >= DUST_THRESHOLD_SATS ? avnChange : 0;

            // --- Build the transaction: asset inputs + AVN inputs; asset outputs (0 value) + AVN change. ---
            const tx = new bitcoin.Transaction();
            tx.version = 2;
            tx.locktime = 0;
            const allInputs = [...selectedAssets, ...selectedAvn];
            for (const utxo of allInputs) {
                tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
            }
            tx.addOutput(transferScript, 0);
            if (assetChangeScript) tx.addOutput(assetChangeScript, 0);
            if (finalAvnChange > 0) {
                tx.addOutput(bitcoin.address.toOutputScript(changeAddress, avianNetwork), finalAvnChange);
            }

            // --- Sign every input as a legacy P2PKH spend with the FORKID sighash. ---
            for (let i = 0; i < allInputs.length; i++) {
                const utxo = allInputs[i];
                const prevTxHex = await this.electrum.getTransaction(utxo.txid, false);
                const prevOut = bitcoin.Transaction.fromHex(prevTxHex).outs[utxo.vout];
                const digest = tx.hashForSignature(i, prevOut.script, SIGHASH_ALL_FORKID);
                const derSignature = this.encodeDERWithCustomHashType(
                    Buffer.from(keyPair.sign(digest)),
                    SIGHASH_ALL_FORKID,
                );
                tx.ins[i].script = bitcoin.script.compile([derSignature, pubkey]);
            }

            const txHex = tx.toHex();
            const txId = tx.getId();
            await this.broadcastRawTransaction(txHex);
            return txId;
        } catch (error) {
            walletLogger.error('Asset transfer failed:', error);
            const message = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Asset transfer failed: ${message}`);
        }
    }

    /**
     * Create (issue) a new root asset. This **burns 500 AVN** to an unspendable address and is
     * irreversible. Builds `[burn, AVN change, owner token, new asset]` — the new-asset output must
     * be last and the owner token second-to-last (Avian Core requires that ordering) — funds the
     * burn + fee from AVN inputs, signs P2PKH inputs with the FORKID sighash, and broadcasts.
     * Also mints the `NAME!` owner token (controls reissue) to the sender.
     *
     * The scripts are byte-validated against a real Core issuance (see assetScript.ts). Sub/unique
     * issuance (which spends the parent owner token) is a separate method.
     *
     * `options.buildOnly` signs the transaction but does not broadcast it: the result carries
     * `broadcast: false` and the raw `hex`, which Core's `testmempoolaccept` will check against
     * consensus before anything is irreversible. Nothing is spent and no history entry is written.
     */
    async issueAsset(
        name: string,
        params: { amount: bigint; units: number; reissuable: boolean; ipfs?: string },
        password?: string,
        options?: { feeRate?: number; changeAddress?: string; buildOnly?: boolean },
    ): Promise<AssetTxResult> {
        try {
            if (!isAssetIssuanceEnabled()) throw new Error(ASSET_ISSUANCE_DISABLED_MESSAGE);
            if (!isValidRootAssetName(name)) {
                throw new Error(
                    'Invalid asset name. Use 3–30 characters of A–Z, 0–9, _ and . (no leading, trailing or doubled punctuation).',
                );
            }
            if (params.amount <= 0n) throw new Error('Issuance amount must be positive');
            if (params.units < 0 || params.units > 8) throw new Error('Units must be between 0 and 8');

            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) throw new Error('No active wallet found');
            if ((activeWallet.addressType || 'p2pkh') !== 'p2pkh') {
                throw new Error('Assets can only be issued from a legacy (R…) address');
            }

            let privateKeyWIF = activeWallet.privateKey;
            if (activeWallet.isEncrypted) {
                if (!password) throw new Error('Password required for encrypted wallet');
                try {
                    const { decrypted } = await decryptData(privateKeyWIF, password);
                    if (!decrypted) throw new Error('Invalid password');
                    privateKeyWIF = decrypted;
                } catch {
                    throw new Error('Invalid password');
                }
            }

            const keyPair = ECPair.fromWIF(privateKeyWIF, avianNetwork);
            const pubkey = Buffer.from(keyPair.publicKey);
            const fromAddress = activeWallet.address;
            const changeAddress = options?.changeAddress?.trim() || fromAddress;

            const burnAmount = Number(ISSUE_BURN.root.amount); // 500 AVN in sats
            const burnScript = bitcoin.address.toOutputScript(ISSUE_BURN.root.address, avianNetwork);
            const ownerScript = buildOwnerScript(fromAddress, name);
            const assetScript = buildIssuanceScript(fromAddress, {
                name,
                amount: params.amount,
                units: params.units,
                reissuable: params.reissuable,
                ipfs: params.ipfs,
            });

            // Fund the burn + fee from AVN UTXOs (iterating on the selected input count).
            const satPerVByte = await this.resolveFeeRate(options?.feeRate);
            const avnUTXOs = await this.electrum.getUTXOs(fromAddress);
            const sortedAvn = [...avnUTXOs].sort((a, b) => b.value - a.value);
            const totalAvn = sortedAvn.reduce((sum, utxo) => sum + utxo.value, 0);

            // Outputs: burn (34) + AVN change (34) + owner + new asset.
            const fixedOutputsVBytes =
                34 + 34 + (8 + 1 + ownerScript.length) + (8 + 1 + assetScript.length);
            const sizeFor = (inputCount: number) => 10 + inputCount * 148 + fixedOutputsVBytes;

            let selectedAvn: typeof avnUTXOs = [];
            let avnIn = 0;
            let fee = 0;
            for (let iteration = 0; iteration < 6; iteration++) {
                fee = Math.ceil(sizeFor(Math.max(selectedAvn.length, 1)) * satPerVByte);
                const target = burnAmount + fee;
                if (totalAvn < target) {
                    throw new Error(
                        `Insufficient AVN: issuing "${name}" burns 500 AVN plus a network fee.`,
                    );
                }
                selectedAvn = [];
                avnIn = 0;
                for (const utxo of sortedAvn) {
                    if (avnIn >= target) break;
                    selectedAvn.push(utxo);
                    avnIn += utxo.value;
                }
                const recomputed = Math.ceil(sizeFor(selectedAvn.length) * satPerVByte);
                if (avnIn >= burnAmount + recomputed && recomputed <= fee) {
                    fee = recomputed;
                    break;
                }
                fee = recomputed;
            }
            if (avnIn < burnAmount + fee) throw new Error('Insufficient AVN for the burn and fee');
            const change = avnIn - burnAmount - fee;
            const finalChange = change >= DUST_THRESHOLD_SATS ? change : 0;

            // Build: burn, [AVN change], owner (second-to-last), new asset (last).
            const tx = new bitcoin.Transaction();
            tx.version = 2;
            tx.locktime = 0;
            for (const utxo of selectedAvn) {
                tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
            }
            tx.addOutput(burnScript, burnAmount);
            if (finalChange > 0) {
                tx.addOutput(bitcoin.address.toOutputScript(changeAddress, avianNetwork), finalChange);
            }
            tx.addOutput(ownerScript, 0);
            tx.addOutput(assetScript, 0);

            for (let i = 0; i < selectedAvn.length; i++) {
                const utxo = selectedAvn[i];
                const prevTxHex = await this.electrum.getTransaction(utxo.txid, false);
                const prevOut = bitcoin.Transaction.fromHex(prevTxHex).outs[utxo.vout];
                const digest = tx.hashForSignature(i, prevOut.script, SIGHASH_ALL_FORKID);
                const derSignature = this.encodeDERWithCustomHashType(
                    Buffer.from(keyPair.sign(digest)),
                    SIGHASH_ALL_FORKID,
                );
                tx.ins[i].script = bitcoin.script.compile([derSignature, pubkey]);
            }

            const txHex = tx.toHex();
            const txId = tx.getId();
            // Dry run: signed and valid, but nothing spent — for `testmempoolaccept`.
            if (options?.buildOnly) return { txid: txId, hex: txHex, broadcast: false };
            await this.broadcastRawTransaction(txHex);
            return { txid: txId, hex: txHex, broadcast: true };
        } catch (error) {
            walletLogger.error('Asset issuance failed:', error);
            const message = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Asset issuance failed: ${message}`);
        }
    }

    /**
     * Issue a sub-asset (`PARENT/SUB`, burns 100 AVN). Requires owning the `PARENT!` owner token.
     * `options.buildOnly` signs without broadcasting (see issueAsset).
     */
    async issueSubAsset(
        subName: string,
        params: { amount: bigint; units: number; reissuable: boolean; ipfs?: string },
        password?: string,
        options?: { feeRate?: number; changeAddress?: string; buildOnly?: boolean },
    ): Promise<AssetTxResult> {
        const slash = subName.lastIndexOf('/');
        if (slash <= 0) throw new Error('A sub-asset name must be PARENT/CHILD');
        return this.issueChildAsset({
            childName: subName,
            parentName: subName.slice(0, slash),
            amount: params.amount,
            units: params.units,
            reissuable: params.reissuable,
            createOwnerToken: true, // sub-assets have their own CHILD! owner token
            ipfs: params.ipfs,
            burnAmount: ISSUE_BURN.sub.amount,
            burnAddress: ISSUE_BURN.sub.address,
            password,
            options,
        });
    }

    /**
     * Issue a unique asset (`PARENT#tag`, burns 5 AVN). Always quantity 1, 0 divisions,
     * non-reissuable. Requires owning the `PARENT!` owner token. An optional IPFS/txid may be set.
     */
    async issueUniqueAsset(
        uniqueName: string,
        ipfs?: string,
        password?: string,
        options?: { feeRate?: number; changeAddress?: string; buildOnly?: boolean },
    ): Promise<AssetTxResult> {
        const hash = uniqueName.indexOf('#');
        if (hash <= 0) throw new Error('A unique asset name must be PARENT#tag');
        return this.issueChildAsset({
            childName: uniqueName,
            parentName: uniqueName.slice(0, hash),
            amount: 100_000_000n, // exactly 1 unit
            units: 0,
            reissuable: false,
            createOwnerToken: false, // uniques have NO owner token — consensus rejects one
            ipfs,
            burnAmount: ISSUE_BURN.unique.amount,
            burnAddress: ISSUE_BURN.unique.address,
            password,
            options,
        });
    }

    /**
     * Shared engine for sub/unique issuance. Spends the `PARENT!` owner token (returning it to
     * ourselves) and burns the type's fee. Sub-assets also create their own `CHILD!` owner token;
     * unique assets must NOT — a unique has no owner token of its own, it inherits authority from
     * the parent root owner. Emitting a `NAME#unique!` owner-creation output is rejected by Avian
     * consensus (Core 4.2.0, and 5.0.3 onward) and previously split the chain, so `createOwnerToken`
     * is false for uniques. Output order matches Core: burn, AVN change, parent-owner transfer,
     * [new owner (2nd-last) for sub only], new asset (last). Validated against real Core issuances.
     */
    private async issueChildAsset(opts: {
        childName: string;
        parentName: string;
        amount: bigint;
        units: number;
        reissuable: boolean;
        /** Sub-assets get a `CHILD!` owner token; unique assets must not (consensus rejects it). */
        createOwnerToken: boolean;
        ipfs?: string;
        burnAmount: bigint;
        burnAddress: string;
        password?: string;
        options?: { feeRate?: number; changeAddress?: string; buildOnly?: boolean };
    }): Promise<AssetTxResult> {
        try {
            if (!isAssetIssuanceEnabled()) throw new Error(ASSET_ISSUANCE_DISABLED_MESSAGE);
            const { childName, parentName, amount, units, reissuable, burnAmount, burnAddress } = opts;
            if (amount <= 0n) throw new Error('Issuance amount must be positive');
            if (units < 0 || units > 8) throw new Error('Units must be between 0 and 8');

            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) throw new Error('No active wallet found');
            if ((activeWallet.addressType || 'p2pkh') !== 'p2pkh') {
                throw new Error('Assets can only be issued from a legacy (R…) address');
            }

            let privateKeyWIF = activeWallet.privateKey;
            if (activeWallet.isEncrypted) {
                if (!opts.password) throw new Error('Password required for encrypted wallet');
                try {
                    const { decrypted } = await decryptData(privateKeyWIF, opts.password);
                    if (!decrypted) throw new Error('Invalid password');
                    privateKeyWIF = decrypted;
                } catch {
                    throw new Error('Invalid password');
                }
            }

            const keyPair = ECPair.fromWIF(privateKeyWIF, avianNetwork);
            const pubkey = Buffer.from(keyPair.publicKey);
            const fromAddress = activeWallet.address;
            const changeAddress = opts.options?.changeAddress?.trim() || fromAddress;

            // The PARENT! owner token must be held; it is spent and returned.
            const ownerName = `${parentName}!`;
            const ownerUTXOs = await this.electrum.getAssetUTXOs(fromAddress, ownerName);
            if (ownerUTXOs.length === 0) {
                throw new Error(`You must own the ${ownerName} owner token to create ${childName}`);
            }
            const ownerUTXO = ownerUTXOs[0];
            const ownerAmount = BigInt(Math.trunc(ownerUTXO.value)); // 1 unit

            const burnScript = bitcoin.address.toOutputScript(burnAddress, avianNetwork);
            const parentReturnScript = buildAssetTransferScript(changeAddress, ownerName, ownerAmount);
            // Sub-assets carry their own owner token; unique assets must not — a NAME#unique! owner
            // output is rejected by consensus and caused the 5.0.x/4.2.0 chain split.
            const newOwnerScript = opts.createOwnerToken ? buildOwnerScript(fromAddress, childName) : null;
            const newAssetScript = buildIssuanceScript(fromAddress, {
                name: childName,
                amount,
                units,
                reissuable,
                ipfs: opts.ipfs,
            });

            const burn = Number(burnAmount);
            const satPerVByte = await this.resolveFeeRate(opts.options?.feeRate);
            const avnUTXOs = await this.electrum.getUTXOs(fromAddress);
            const sortedAvn = [...avnUTXOs].sort((a, b) => b.value - a.value);
            const totalAvn = sortedAvn.reduce((sum, utxo) => sum + utxo.value, 0);

            // Outputs: burn(34) + change(34) + parentReturn + newOwner + newAsset. One owner input is
            // always present, plus the AVN fee inputs.
            const fixedOutputsVBytes =
                34 + 34 +
                (8 + 1 + parentReturnScript.length) +
                (newOwnerScript ? 8 + 1 + newOwnerScript.length : 0) +
                (8 + 1 + newAssetScript.length);
            const sizeFor = (avnInputCount: number) =>
                10 + (1 + avnInputCount) * 148 + fixedOutputsVBytes;

            let selectedAvn: typeof avnUTXOs = [];
            let avnIn = 0;
            let fee = 0;
            for (let iteration = 0; iteration < 6; iteration++) {
                fee = Math.ceil(sizeFor(Math.max(selectedAvn.length, 1)) * satPerVByte);
                const target = burn + fee;
                if (totalAvn < target) {
                    throw new Error(
                        `Insufficient AVN: creating ${childName} burns ${Number(burnAmount) / 1e8} AVN plus a network fee.`,
                    );
                }
                selectedAvn = [];
                avnIn = 0;
                for (const utxo of sortedAvn) {
                    if (avnIn >= target) break;
                    selectedAvn.push(utxo);
                    avnIn += utxo.value;
                }
                const recomputed = Math.ceil(sizeFor(selectedAvn.length) * satPerVByte);
                if (avnIn >= burn + recomputed && recomputed <= fee) {
                    fee = recomputed;
                    break;
                }
                fee = recomputed;
            }
            if (avnIn < burn + fee) throw new Error('Insufficient AVN for the burn and fee');
            const change = avnIn - burn - fee;
            const finalChange = change >= DUST_THRESHOLD_SATS ? change : 0;

            const tx = new bitcoin.Transaction();
            tx.version = 2;
            tx.locktime = 0;
            // Inputs: the parent owner token first, then AVN fee inputs.
            const allInputs = [ownerUTXO, ...selectedAvn];
            for (const utxo of allInputs) {
                tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
            }
            tx.addOutput(burnScript, burn);
            if (finalChange > 0) {
                tx.addOutput(bitcoin.address.toOutputScript(changeAddress, avianNetwork), finalChange);
            }
            tx.addOutput(parentReturnScript, 0);
            if (newOwnerScript) tx.addOutput(newOwnerScript, 0);
            tx.addOutput(newAssetScript, 0);

            for (let i = 0; i < allInputs.length; i++) {
                const utxo = allInputs[i];
                const prevTxHex = await this.electrum.getTransaction(utxo.txid, false);
                const prevOut = bitcoin.Transaction.fromHex(prevTxHex).outs[utxo.vout];
                const digest = tx.hashForSignature(i, prevOut.script, SIGHASH_ALL_FORKID);
                const derSignature = this.encodeDERWithCustomHashType(
                    Buffer.from(keyPair.sign(digest)),
                    SIGHASH_ALL_FORKID,
                );
                tx.ins[i].script = bitcoin.script.compile([derSignature, pubkey]);
            }

            const txHex = tx.toHex();
            const txId = tx.getId();
            // Dry run: signed and valid, but nothing spent — for `testmempoolaccept`.
            if (opts.options?.buildOnly) return { txid: txId, hex: txHex, broadcast: false };
            await this.broadcastRawTransaction(txHex);
            return { txid: txId, hex: txHex, broadcast: true };
        } catch (error) {
            walletLogger.error('Child asset issuance failed:', error);
            const message = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Asset issuance failed: ${message}`);
        }
    }

    /**
     * Reissue an existing reissuable asset you own: mint more supply (`amount`, 0 for metadata-only)
     * and/or change its units/reissuable/IPFS. **Burns 100 AVN.** Requires the `NAME!` owner token,
     * which is spent and returned. Outputs: burn, AVN change, owner transfer (2nd-last), reissue
     * output (last) — Core's order. Validated byte-for-byte against a real Core reissue.
     *
     * `units` is the new divisions (0–8, can only increase) or -1 to leave unchanged; a supplied
     * `ipfs` replaces the asset's hash, omitting it keeps the current one.
     */
    async reissueAsset(
        name: string,
        params: { amount: bigint; units: number; reissuable: boolean; ipfs?: string },
        password?: string,
        options?: { feeRate?: number; changeAddress?: string; buildOnly?: boolean },
    ): Promise<AssetTxResult> {
        try {
            if (!isAssetIssuanceEnabled()) throw new Error(ASSET_ISSUANCE_DISABLED_MESSAGE);
            if (params.amount < 0n) throw new Error('Reissue amount cannot be negative');

            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) throw new Error('No active wallet found');
            if ((activeWallet.addressType || 'p2pkh') !== 'p2pkh') {
                throw new Error('Assets can only be reissued from a legacy (R…) address');
            }

            let privateKeyWIF = activeWallet.privateKey;
            if (activeWallet.isEncrypted) {
                if (!password) throw new Error('Password required for encrypted wallet');
                try {
                    const { decrypted } = await decryptData(privateKeyWIF, password);
                    if (!decrypted) throw new Error('Invalid password');
                    privateKeyWIF = decrypted;
                } catch {
                    throw new Error('Invalid password');
                }
            }

            const keyPair = ECPair.fromWIF(privateKeyWIF, avianNetwork);
            const pubkey = Buffer.from(keyPair.publicKey);
            const fromAddress = activeWallet.address;
            const changeAddress = options?.changeAddress?.trim() || fromAddress;

            // The NAME! owner token proves authority; it is spent and returned.
            const ownerName = `${name}!`;
            const ownerUTXOs = await this.electrum.getAssetUTXOs(fromAddress, ownerName);
            if (ownerUTXOs.length === 0) {
                throw new Error(`You must own the ${ownerName} owner token to reissue ${name}`);
            }
            const ownerUTXO = ownerUTXOs[0];
            const ownerAmount = BigInt(Math.trunc(ownerUTXO.value));

            const burnScript = bitcoin.address.toOutputScript(ISSUE_BURN.reissue.address, avianNetwork);
            const parentReturnScript = buildAssetTransferScript(changeAddress, ownerName, ownerAmount);
            const reissueScript = buildReissueScript(fromAddress, {
                name,
                amount: params.amount,
                units: params.units,
                reissuable: params.reissuable,
                ipfs: params.ipfs,
            });

            const burn = Number(ISSUE_BURN.reissue.amount);
            const satPerVByte = await this.resolveFeeRate(options?.feeRate);
            const avnUTXOs = await this.electrum.getUTXOs(fromAddress);
            const sortedAvn = [...avnUTXOs].sort((a, b) => b.value - a.value);
            const totalAvn = sortedAvn.reduce((sum, utxo) => sum + utxo.value, 0);

            // Outputs: burn(34) + change(34) + owner transfer + reissue. One owner input + AVN inputs.
            const fixedOutputsVBytes =
                34 + 34 + (8 + 1 + parentReturnScript.length) + (8 + 1 + reissueScript.length);
            const sizeFor = (avnInputCount: number) =>
                10 + (1 + avnInputCount) * 148 + fixedOutputsVBytes;

            let selectedAvn: typeof avnUTXOs = [];
            let avnIn = 0;
            let fee = 0;
            for (let iteration = 0; iteration < 6; iteration++) {
                fee = Math.ceil(sizeFor(Math.max(selectedAvn.length, 1)) * satPerVByte);
                const target = burn + fee;
                if (totalAvn < target) {
                    throw new Error(`Insufficient AVN: reissuing ${name} burns 100 AVN plus a network fee.`);
                }
                selectedAvn = [];
                avnIn = 0;
                for (const utxo of sortedAvn) {
                    if (avnIn >= target) break;
                    selectedAvn.push(utxo);
                    avnIn += utxo.value;
                }
                const recomputed = Math.ceil(sizeFor(selectedAvn.length) * satPerVByte);
                if (avnIn >= burn + recomputed && recomputed <= fee) {
                    fee = recomputed;
                    break;
                }
                fee = recomputed;
            }
            if (avnIn < burn + fee) throw new Error('Insufficient AVN for the burn and fee');
            const change = avnIn - burn - fee;
            const finalChange = change >= DUST_THRESHOLD_SATS ? change : 0;

            const tx = new bitcoin.Transaction();
            tx.version = 2;
            tx.locktime = 0;
            const allInputs = [ownerUTXO, ...selectedAvn];
            for (const utxo of allInputs) {
                tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
            }
            tx.addOutput(burnScript, burn);
            if (finalChange > 0) {
                tx.addOutput(bitcoin.address.toOutputScript(changeAddress, avianNetwork), finalChange);
            }
            tx.addOutput(parentReturnScript, 0);
            tx.addOutput(reissueScript, 0);

            for (let i = 0; i < allInputs.length; i++) {
                const utxo = allInputs[i];
                const prevTxHex = await this.electrum.getTransaction(utxo.txid, false);
                const prevOut = bitcoin.Transaction.fromHex(prevTxHex).outs[utxo.vout];
                const digest = tx.hashForSignature(i, prevOut.script, SIGHASH_ALL_FORKID);
                const derSignature = this.encodeDERWithCustomHashType(
                    Buffer.from(keyPair.sign(digest)),
                    SIGHASH_ALL_FORKID,
                );
                tx.ins[i].script = bitcoin.script.compile([derSignature, pubkey]);
            }

            const txHex = tx.toHex();
            const txId = tx.getId();
            // Dry run: signed and valid, but nothing spent — for `testmempoolaccept`.
            if (options?.buildOnly) return { txid: txId, hex: txHex, broadcast: false };
            await this.broadcastRawTransaction(txHex);
            return { txid: txId, hex: txHex, broadcast: true };
        } catch (error) {
            walletLogger.error('Asset reissue failed:', error);
            const message = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Asset reissue failed: ${message}`);
        }
    }

    async sendTransaction(
        toAddress: string,
        amount: number,
        password?: string,
        options?: {
            strategy?: CoinSelectionStrategy;
            feeRate?: number;
            maxInputs?: number;
            minConfirmations?: number;
            changeAddress?: string; // Custom change address for HD wallets
            subtractFeeFromAmount?: boolean; // Whether to subtract fee from the send amount
        },
    ): Promise<string> {
        try {
            // Get current wallet data
            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) {
                throw new Error('No active wallet found');
            }

            let privateKeyWIF = activeWallet.privateKey;

            // Decrypt private key if encrypted
            if (activeWallet.isEncrypted) {
                if (!password) {
                    throw new Error('Password required for encrypted wallet');
                }
                try {
                    const { decrypted } = await decryptData(privateKeyWIF, password);
                    if (!decrypted) {
                        throw new Error('Invalid password');
                    }
                    privateKeyWIF = decrypted;
                } catch (error) {
                    throw new Error('Invalid password');
                }
            }

            // Create key pair from private key
            const keyPair = ECPair.fromWIF(privateKeyWIF, avianNetwork);
            const fromAddress = activeWallet.address;

            // Avian requires SIGHASH_ALL | SIGHASH_FORKID (0x41) for all inputs.
            const hashType = SIGHASH_ALL_FORKID; // 0x41
            const walletAddrType: AddressType = activeWallet.addressType || 'p2pkh';

            // Select UTXOs, size the fee, and build the unsigned PSBT. Shared with buildUnsignedPsbt
            // so selection and fee logic live in one place.
            const { psbt, selectedUTXOs, finalSendAmount, finalChange, changeAddress } =
                await this.planSpend({
                    fromAddress,
                    walletAddrType,
                    toAddress,
                    amount,
                    options,
                    pubkey: Buffer.from(keyPair.publicKey),
                });

            // Create a compatible signer object with Avian fork ID support
            const signer = {
                publicKey: Buffer.from(keyPair.publicKey),
                sign: (hash: Buffer) => Buffer.from(keyPair.sign(hash)),
            };

            try {
                // First, try the standard approach with sighash type array
                for (let i = 0; i < selectedUTXOs.length; i++) {
                    // Pass the hashType in the sighashTypes array to whitelist it
                    psbt.signInput(i, signer, [hashType]);
                }
            } catch (psbtError) {
                // Create transaction for signing
                const tx = new bitcoin.Transaction();
                tx.version = 2;
                tx.locktime = 0;

                // Add all inputs
                for (const u of selectedUTXOs) {
                    tx.addInput(Buffer.from(u.txid, 'hex').reverse(), u.vout);
                }

                // Add all outputs
                tx.addOutput(bitcoin.address.toOutputScript(toAddress, avianNetwork), finalSendAmount);
                if (finalChange > 0) {
                    tx.addOutput(bitcoin.address.toOutputScript(changeAddress, avianNetwork), finalChange);
                }

                // Sign each input manually with fork ID
                for (let i = 0; i < selectedUTXOs.length; i++) {
                    const utxo = selectedUTXOs[i];
                    const prevTxHex = await this.electrum.getTransaction(utxo.txid, false);
                    const prevTx = bitcoin.Transaction.fromHex(prevTxHex);
                    const prevOut = prevTx.outs[utxo.vout];

                    if (walletAddrType === 'p2wpkh') {
                        // BIP143 sighash for native SegWit (P2WPKH) with Avian FORKID
                        const pubkeyHash = bitcoin.crypto.hash160(Buffer.from(keyPair.publicKey));
                        const scriptCode = bitcoin.script.compile([
                            bitcoin.opcodes.OP_DUP,
                            bitcoin.opcodes.OP_HASH160,
                            pubkeyHash,
                            bitcoin.opcodes.OP_EQUALVERIFY,
                            bitcoin.opcodes.OP_CHECKSIG,
                        ]);
                        const signatureHash = tx.hashForWitnessV0(i, scriptCode, prevOut.value, hashType);
                        const signature = keyPair.sign(signatureHash);
                        const derSignature = this.encodeDERWithCustomHashType(Buffer.from(signature), hashType);
                        // P2WPKH: witness holds [sig, pubkey]; scriptSig stays empty
                        tx.ins[i].witness = [derSignature, Buffer.from(keyPair.publicKey)];
                    } else {
                        // Legacy P2PKH / P2SH-P2WPKH
                        const prevOutScript = prevOut.script;
                        const signatureHash = tx.hashForSignature(i, prevOutScript, hashType);
                        const signature = keyPair.sign(signatureHash);
                        const derSignature = this.encodeDERWithCustomHashType(Buffer.from(signature), hashType);
                        const scriptSig = bitcoin.script.compile([derSignature, Buffer.from(keyPair.publicKey)]);
                        tx.ins[i].script = scriptSig;
                    }
                }

                // Return the manually built transaction
                const txHex = tx.toHex();
                const txId = tx.getId();

                // Validate the transaction structure
                try {
                    const validateTx = bitcoin.Transaction.fromHex(txHex);

                    // Check each input has a valid script or witness
                    for (let i = 0; i < validateTx.ins.length; i++) {
                        const inp = validateTx.ins[i];
                        if (inp.script.length === 0 && (!inp.witness || inp.witness.length === 0)) {
                            throw new Error(`Input ${i} has empty script and witness`);
                        }
                    }
                } catch (validationError) {
                    walletLogger.error('Transaction validation failed:', validationError);
                    throw new Error(`Invalid transaction created: ${validationError}`);
                }

                // Broadcast the transaction
                const broadcastResult = await this.electrum.broadcastTransaction(txHex);

                // Validate broadcast was successful before saving transaction
                if (!broadcastResult || typeof broadcastResult !== 'string') {
                    throw new Error('Transaction broadcast failed. Please try again later.');
                }

                // Save transaction to local history
                await StorageService.saveTransaction({
                    txid: txId,
                    amount: finalSendAmount / 100000000, // what the recipient received (net of fee if subtracted)
                    address: toAddress,
                    fromAddress: fromAddress,
                    walletAddress: fromAddress,
                    type: 'send',
                    timestamp: new Date(),
                    confirmations: 0,
                });

                return txId;
            }

            // If PSBT signing succeeded, finalize and extract the transaction
            psbt.finalizeAllInputs();

            // Extract the raw transaction hex
            const tx = psbt.extractTransaction();
            const txHex = tx.toHex();
            const txId = tx.getId();

            // Broadcast the transaction
            const broadcastResult = await this.electrum.broadcastTransaction(txHex);

            // Validate broadcast was successful before saving transaction
            if (!broadcastResult || typeof broadcastResult !== 'string') {
                throw new Error('Transaction broadcast failed. Please try again later.');
            }

            // Save transaction to local history
            await StorageService.saveTransaction({
                txid: txId,
                amount: finalSendAmount / 100000000, // what the recipient received (net of fee if subtracted)
                address: toAddress,
                fromAddress: fromAddress,
                walletAddress: fromAddress, // Add wallet address for proper multi-wallet support
                type: 'send',
                timestamp: new Date(),
                confirmations: 0,
            });

            return txId;
        } catch (error) {
            walletLogger.error('Error sending transaction:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Transaction failed: ${errorMessage}`);
        }
    }

    /**
     * Send transaction using manually selected UTXOs from multiple addresses
     */
    async sendTransactionWithManualUTXOs(
        toAddress: string,
        amount: number,
        manualUTXOs: EnhancedUTXO[],
        password?: string,
        options?: {
            feeRate?: number;
            changeAddress?: string;
            subtractFeeFromAmount?: boolean;
        },
    ): Promise<string> {
        try {
            // Get current wallet data
            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) {
                throw new Error('No active wallet found');
            }

            if (!manualUTXOs || manualUTXOs.length === 0) {
                throw new Error('No UTXOs provided for manual selection');
            }

            // Validate that we have sufficient funds
            const totalAvailable = manualUTXOs.reduce((sum, utxo) => sum + utxo.value, 0);
            const subtractFee = options?.subtractFeeFromAmount ?? false;
            const satPerVByte = await this.resolveFeeRate(options?.feeRate);
            // Inputs are fixed here, so the fee is known directly (recipient + change ≈ 2 outputs).
            const fee = estimateTxFee(manualUTXOs.length, 2, satPerVByte);
            const totalRequired = subtractFee ? amount : amount + fee;

            if (totalAvailable < totalRequired) {
                throw new Error(
                    `Insufficient funds. Available: ${totalAvailable}, Required: ${totalRequired}`,
                );
            }

            let privateKeyWIF = activeWallet.privateKey;

            // Decrypt private key if encrypted
            if (activeWallet.isEncrypted) {
                if (!password) {
                    throw new Error('Password required for encrypted wallet');
                }
                try {
                    privateKeyWIF = await secureDecrypt(activeWallet.privateKey, password);
                } catch (error) {
                    throw new Error('Invalid password');
                }
            }

            // Check if we need HD wallet capabilities
            const hasHdUtxos = manualUTXOs.some(
                (utxo) => utxo.address && utxo.address !== activeWallet.address,
            );
            let hdRoot = null;
            let mnemonic = null;
            // Account-level node for descriptor-imported wallets (xprv, no mnemonic)
            let hdAccountNode: ReturnType<typeof bip32.fromBase58> | null = null;

            if (hasHdUtxos) {
                // Get mnemonic for HD wallet operations
                mnemonic = await StorageService.getMnemonic();

                if (mnemonic) {
                    // Decrypt mnemonic if needed
                    let decryptedMnemonic = mnemonic;
                    if (activeWallet.isEncrypted && password) {
                        try {
                            decryptedMnemonic = await secureDecrypt(mnemonic, password);
                        } catch (error) {
                            // If mnemonic decryption fails, try using it as-is (might not be encrypted)
                            decryptedMnemonic = mnemonic;
                        }
                    }

                    // Create HD root from mnemonic
                    const seed = await bip39.mnemonicToSeed(decryptedMnemonic);
                    hdRoot = bip32.fromSeed(seed, avianNetwork);
                } else if (activeWallet.xprv) {
                    // Descriptor-imported wallet — the stored xprv is already at account level
                    let decryptedXprv = activeWallet.xprv;
                    if (activeWallet.isEncrypted) {
                        if (!password) {
                            throw new Error('Password required to sign from derived addresses');
                        }
                        try {
                            decryptedXprv = await secureDecrypt(activeWallet.xprv, password);
                        } catch (error) {
                            throw new Error('Invalid password or corrupted xprv');
                        }
                    }
                    hdAccountNode = bip32.fromBase58(decryptedXprv, avianNetwork);
                } else {
                    throw new Error(
                        'HD wallet UTXOs detected but no mnemonic or account key found. Cannot sign from derived addresses.',
                    );
                }
            }

            // Helper function to get the correct key pair for an address
            const getKeyPairForAddress = async (address: string): Promise<any> => {
                if (address === activeWallet.address) {
                    // Main wallet address - use main private key
                    return ECPair.fromWIF(privateKeyWIF, avianNetwork);
                }

                // HD address - find which derivation path this address corresponds to.
                // Use the wallet's stored coin type and address type for derivation.
                const coinType = activeWallet.coinType || 921;
                const walletType: AddressType = activeWallet.addressType || 'p2pkh';
                const walletPurpose = purposeForAddressType(walletType);

                if (hdRoot) {
                    // Check both receiving (0) and change (1) paths
                    for (const changePath of [0, 1]) {
                        for (let addressIndex = 0; addressIndex < 50; addressIndex++) {
                            // Check up to 50 addresses
                            const path = `m/${walletPurpose}'/${coinType}'/0'/${changePath}/${addressIndex}`;
                            const child = hdRoot.derivePath(path);
                            const derivedAddress = deriveAddress(
                                Buffer.from(child.publicKey),
                                walletType,
                            );

                            if (derivedAddress === address) {
                                // Found the matching derivation path
                                return ECPair.fromPrivateKey(Buffer.from(child.privateKey!), {
                                    network: avianNetwork,
                                });
                            }
                        }
                    }
                    throw new Error(`Could not find derivation path for HD address: ${address}`);
                } else if (hdAccountNode) {
                    // xprv is at account level, so only change/index remain to be derived
                    for (const changePath of [0, 1]) {
                        const changeNode = hdAccountNode.derive(changePath);
                        for (let addressIndex = 0; addressIndex < 50; addressIndex++) {
                            const child = changeNode.derive(addressIndex);
                            const derivedAddress = deriveAddress(
                                Buffer.from(child.publicKey),
                                walletType,
                            );

                            if (derivedAddress === address) {
                                return ECPair.fromPrivateKey(Buffer.from(child.privateKey!), {
                                    network: avianNetwork,
                                });
                            }
                        }
                    }
                    throw new Error(`Could not find derivation path for HD address: ${address}`);
                }

                throw new Error(`Cannot sign UTXO from address ${address} - HD wallet not available`);
            };

            // Manual transaction building (skip PSBT since it has sighash issues)
            const tx = new bitcoin.Transaction();
            tx.version = 2;

            // Add inputs
            for (const utxo of manualUTXOs) {
                tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
            }

            // Split into recipient and change via the shared rule.
            const totalInput = manualUTXOs.reduce((sum, utxo) => sum + utxo.value, 0);
            const { sendAmount: actualAmount, change } = resolveSendAmounts(
                amount,
                fee,
                totalInput,
                subtractFee,
            );
            if (actualAmount <= 0) {
                throw new Error('Send amount is zero or negative after subtracting the fee');
            }
            if (change < 0) {
                throw new Error('Insufficient funds to cover the network fee');
            }

            // Add outputs
            tx.addOutput(bitcoin.address.toOutputScript(toAddress, avianNetwork), actualAmount);

            // Fold sub-dust change into the fee rather than emit a rejected dust output.
            if (change >= DUST_THRESHOLD_SATS) {
                const changeAddress = options?.changeAddress || activeWallet.address;
                tx.addOutput(bitcoin.address.toOutputScript(changeAddress, avianNetwork), change);
            }

            // Sign inputs with the correct private keys
            const SIGHASH_ALL = 0x01;
            const SIGHASH_FORKID = 0x40;
            const hashType = SIGHASH_ALL | SIGHASH_FORKID;

            for (let i = 0; i < manualUTXOs.length; i++) {
                const utxo = manualUTXOs[i];

                // Get the correct key pair for this UTXO's address
                if (!utxo.address) {
                    throw new Error('UTXO is missing address property');
                }
                const keyPair = await getKeyPairForAddress(utxo.address);

                // Create P2PKH script for this input
                const prevOutScript = bitcoin.address.toOutputScript(utxo.address, avianNetwork);

                // Calculate signature hash
                const signatureHash = tx.hashForSignature(i, prevOutScript, hashType);

                // Sign the hash
                const signature = keyPair.sign(signatureHash);
                const derSignature = this.encodeDERWithCustomHashType(Buffer.from(signature), hashType);

                // Build script sig (P2PKH: <signature> <publicKey>)
                const scriptSig = bitcoin.script.compile([derSignature, Buffer.from(keyPair.publicKey)]);

                tx.ins[i].script = scriptSig;
            }

            // Extract transaction
            const txHex = tx.toHex();
            const txId = tx.getId();

            // Broadcast the transaction
            const broadcastResult = await this.electrum.broadcastTransaction(txHex);

            if (!broadcastResult || typeof broadcastResult !== 'string') {
                throw new Error('Transaction broadcast failed. Please try again later.');
            }

            // Save transaction to local history
            await StorageService.saveTransaction({
                txid: txId,
                amount: actualAmount / 100000000, // Convert satoshis to AVN
                address: toAddress,
                fromAddress: activeWallet.address,
                walletAddress: activeWallet.address,
                type: 'send',
                timestamp: new Date(),
                confirmations: 0,
            });

            return txId;
        } catch (error) {
            walletLogger.error('Error sending transaction with manual UTXOs:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Transaction failed: ${errorMessage}`);
        }
    }
    async encryptWallet(password: string): Promise<void> {
        try {
            const privateKey = await StorageService.getPrivateKey();
            if (!privateKey) {
                throw new Error('No private key to encrypt');
            }

            // If already encrypted, throw error
            const isEncrypted = await StorageService.getIsEncrypted();
            if (isEncrypted) {
                throw new Error('Wallet is already encrypted');
            }

            // Encrypt private key
            const encryptedKey = await secureEncrypt(privateKey, password);
            await StorageService.setPrivateKey(encryptedKey);

            // Encrypt mnemonic if it exists
            const mnemonic = await StorageService.getMnemonic();
            if (mnemonic) {
                const encryptedMnemonic = await secureEncrypt(mnemonic, password);
                await StorageService.setMnemonic(encryptedMnemonic);
            }

            await StorageService.setIsEncrypted(true);
        } catch (error) {
            walletLogger.error('Error encrypting wallet:', error);
            throw error;
        }
    }

    async decryptWallet(password: string): Promise<void> {
        try {
            const encryptedKey = await StorageService.getPrivateKey();
            if (!encryptedKey) {
                throw new Error('No private key found');
            }

            const isEncrypted = await StorageService.getIsEncrypted();
            if (!isEncrypted) {
                throw new Error('Wallet is not encrypted');
            }

            // Decrypt private key
            const { decrypted: decryptedKey } = await decryptData(encryptedKey, password);
            if (!decryptedKey) {
                throw new Error('Invalid password');
            }

            await StorageService.setPrivateKey(decryptedKey);

            // Decrypt mnemonic if it exists
            const encryptedMnemonic = await StorageService.getMnemonic();
            if (encryptedMnemonic) {
                try {
                    const { decrypted: decryptedMnemonic } = await decryptData(encryptedMnemonic, password);
                    if (decryptedMnemonic) {
                        await StorageService.setMnemonic(decryptedMnemonic);
                    }
                } catch (mnemonicError) {
                    walletLogger.warn(
                        'Failed to decrypt mnemonic, but private key was decrypted successfully',
                    );
                }
            }

            await StorageService.setIsEncrypted(false);
        } catch (error) {
            walletLogger.error('Error decrypting wallet:', error);
            throw error;
        }
    }

    async exportPrivateKey(password?: string): Promise<string> {
        try {
            const storedPrivateKey = await StorageService.getPrivateKey();
            if (!storedPrivateKey) {
                throw new Error(
                    'No private key found. Private keys cannot be recreated - you must restore from a backup or generate a new wallet.',
                );
            }

            const isEncrypted = await StorageService.getIsEncrypted();

            if (isEncrypted && !password) {
                throw new Error('Password required for encrypted wallet');
            }

            let exportedKey: string;

            if (isEncrypted) {
                // Decrypt private key
                const { decrypted } = await decryptData(storedPrivateKey, password!);
                exportedKey = decrypted;
            } else {
                exportedKey = storedPrivateKey;
            }

            // Validate the decrypted key
            if (!exportedKey) {
                throw new Error('Failed to decrypt private key. Please check your password.');
            }

            // Validate WIF format
            try {
                ECPair.fromWIF(exportedKey, avianNetwork);
            } catch (wifError) {
                // If it's not WIF, try to convert it
                if (exportedKey.length === 64 && /^[0-9a-fA-F]+$/.test(exportedKey)) {
                    // It's a hex private key, convert to WIF
                    const privateKeyBuffer = Buffer.from(exportedKey, 'hex');
                    const keyPair = ECPair.fromPrivateKey(privateKeyBuffer, { network: avianNetwork });
                    exportedKey = keyPair.toWIF();
                } else {
                    throw new Error(
                        'Corrupted private key detected. The stored key is not in a valid format.',
                    );
                }
            }

            return exportedKey;
        } catch (error) {
            walletLogger.error('Error exporting private key:', error);
            throw error;
        }
    }

    async checkWalletRecoveryOptions(): Promise<{
        hasWallet: boolean;
        isEncrypted: boolean;
        hasMnemonic: boolean;
        recoveryOptions: string[];
    }> {
        try {
            const storedPrivateKey = await StorageService.getPrivateKey();
            const storedAddress = await StorageService.getAddress();
            const storedMnemonic = await StorageService.getMnemonic();
            const isEncrypted = await StorageService.getIsEncrypted();

            const hasWallet = !!(storedPrivateKey && storedAddress);
            const hasMnemonic = !!storedMnemonic;
            const recoveryOptions: string[] = [];

            if (!hasWallet) {
                recoveryOptions.push(
                    'Generate a new wallet (creates new private key, address, and mnemonic)',
                );
                recoveryOptions.push('Import existing private key (WIF format)');
                recoveryOptions.push('Restore from BIP39 mnemonic phrase (12 words)');
            }

            return {
                hasWallet,
                isEncrypted,
                hasMnemonic,
                recoveryOptions,
            };
        } catch (error) {
            walletLogger.error('Error checking wallet recovery options:', error);
            return {
                hasWallet: false,
                isEncrypted: false,
                hasMnemonic: false,
                recoveryOptions: [
                    'Generate a new wallet',
                    'Import existing private key',
                    'Restore from BIP39 mnemonic',
                    'Check browser storage permissions',
                ],
            };
        }
    }

    async validatePrivateKey(privateKey: string): Promise<boolean> {
        try {
            // Try to create an ECPair from the private key
            ECPair.fromWIF(privateKey, avianNetwork);
            return true;
        } catch (error) {
            walletLogger.error('Private key validation failed:', error);
            return false;
        }
    }

    /**
     * Validates if a password can successfully decrypt the wallet
     * @param password The password to validate
     * @returns True if the password is valid, false otherwise
     */
    async validateWalletPassword(password: string): Promise<boolean> {
        try {
            // With no wallet there is nothing to validate the password against, so there is no
            // basis on which to call it valid. This used to fall through to the unencrypted
            // branch below and answer true for any password at all.
            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) {
                return false;
            }

            if (!activeWallet.isEncrypted) {
                // Nothing is encrypted, so there is no password to get wrong.
                return true;
            }

            // Try to decrypt either the mnemonic (if available) or private key
            const storedMnemonic = await StorageService.getMnemonic();
            if (storedMnemonic) {
                try {
                    const { decrypted: decryptedMnemonic } = await decryptData(storedMnemonic, password);
                    // Validate the decrypted mnemonic
                    return !!decryptedMnemonic && bip39.validateMnemonic(decryptedMnemonic);
                } catch (error) {
                    return false;
                }
            }

            // Try private key if no mnemonic
            const privateKeyWIF = await StorageService.getPrivateKey();
            if (privateKeyWIF) {
                try {
                    const { decrypted: decryptedKey } = await decryptData(privateKeyWIF, password);
                    // A valid private key should be 51-52 characters and starts with specific characters
                    return !!decryptedKey && decryptedKey.length >= 51 && decryptedKey.length <= 52;
                } catch (error) {
                    return false;
                }
            }

            // If we couldn't find anything to validate against
            return false;
        } catch (error) {
            walletLogger.error('Error validating wallet password:', error);
            return false;
        }
    }

    // Connection management methods
    async connectToElectrum(): Promise<void> {
        try {
            if (!this.electrum.isConnectedToServer()) {
                await this.electrum.connect();
            }
        } catch (error) {
            walletLogger.error('Failed to connect to ElectrumX server:', error);
            throw error;
        }
    }

    async disconnectFromElectrum(): Promise<void> {
        try {
            await this.electrum.disconnect();
        } catch (error) {
            walletLogger.error('Error disconnecting from ElectrumX server:', error);
            throw error;
        }
    }

    isConnectedToElectrum(): boolean {
        return this.electrum.isConnectedToServer();
    }

    getElectrumServerInfo(): { url: string; servers: any[] } {
        return {
            url: this.electrum.getServerUrl(),
            servers: this.electrum.getAvailableServers(),
        };
    }

    async selectElectrumServer(index: number): Promise<void> {
        try {
            // Capture the connection state up front: selectServer() tears the socket down, so
            // checking afterwards always reads "disconnected" and the reconnect never fired — that
            // was the bug where switching servers left the wallet dead until a reload.
            const wasConnected = this.isConnectedToElectrum();
            if (wasConnected) {
                // Await a full disconnect so the old socket is closed before we open the new one.
                await this.disconnectFromElectrum();
            }

            this.electrum.selectServer(index);

            // Persist the choice so it survives a reload.
            const host = this.electrum.getCurrentServer()?.host;
            if (host) {
                await StorageService.setSelectedElectrumServer(host);
            }

            if (wasConnected) {
                await this.connectToElectrum();
            }
        } catch (error) {
            walletLogger.error('Error selecting ElectrumX server:', error);
            throw error;
        }
    }

    /**
     * Re-apply the user's last saved ElectrumX server before connecting. The ElectrumService always
     * constructs with the first server as its default, so without this a reload silently reverts to
     * it. Call this after constructing the service and before connecting. A saved host that no longer
     * exists (the server list changed) just falls back to the default.
     */
    async restoreSelectedServer(): Promise<void> {
        try {
            const host = await StorageService.getSelectedElectrumServer();
            if (host) {
                this.electrum.selectServerByHost(host);
            }
        } catch (error) {
            walletLogger.warn('Could not restore the saved ElectrumX server; using default', error);
        }
    }

    async testElectrumConnection(): Promise<boolean> {
        try {
            // First check if we're connected
            if (!this.electrum.isConnectedToServer()) {
                return false;
            }

            // If connected, try to ping
            await this.electrum.ping();
            return true;
        } catch (error) {
            walletLogger.error('ElectrumX connection test failed:', error);
            return false;
        }
    }

    async getElectrumServerVersion(): Promise<{ server: string; protocol: string }> {
        try {
            return await this.electrum.getServerVersion();
        } catch (error) {
            walletLogger.error('Failed to get server version:', error);
            throw error;
        }
    }

    async generateWalletFromMnemonic(
        mnemonic: string,
        password: string,
        passphrase?: string,
    ): Promise<LegacyWalletData> {
        // Validate required password
        if (!password || password.length < 8) {
            throw new Error('Password is required and must be at least 8 characters long');
        }

        try {
            // Validate mnemonic
            if (!bip39.validateMnemonic(mnemonic)) {
                throw new Error('Invalid BIP39 mnemonic phrase');
            }

            // Derive seed from mnemonic with optional passphrase (BIP39 25th word)
            const seed = await bip39.mnemonicToSeed(mnemonic, passphrase || '');

            // Create HD wallet root
            const root = bip32.fromSeed(seed, avianNetwork);

            // Derive key at standard path m/44'/921'/0'/0/0 (921 is Avian's coin type)
            const path = "m/44'/921'/0'/0/0";
            const child = root.derivePath(path);

            if (!child.privateKey) {
                throw new Error('Failed to derive private key from mnemonic');
            }

            // Create ECPair from derived private key
            const keyPair = ECPair.fromPrivateKey(child.privateKey, { network: avianNetwork });

            const privateKeyWIF = keyPair.toWIF();

            // Get the address
            const { address } = bitcoin.payments.p2pkh({
                pubkey: Buffer.from(keyPair.publicKey),
                network: avianNetwork,
            });

            if (!address) {
                throw new Error('Failed to generate address from mnemonic');
            }

            // Encrypt private key with password (now mandatory)
            const finalPrivateKey = await secureEncrypt(privateKeyWIF, password);

            // Encrypt mnemonic with password (now mandatory)
            const finalMnemonic = await secureEncrypt(mnemonic, password);

            // Store mnemonic
            await StorageService.setMnemonic(finalMnemonic);

            return {
                address,
                privateKey: finalPrivateKey,
                mnemonic: finalMnemonic,
            };
        } catch (error) {
            walletLogger.error('Error generating wallet from mnemonic:', error);
            throw new Error('Failed to generate wallet from mnemonic');
        }
    }

    async validateMnemonic(mnemonic: string): Promise<boolean> {
        try {
            return bip39.validateMnemonic(mnemonic);
        } catch (error) {
            walletLogger.error('Mnemonic validation failed:', error);
            return false;
        }
    }

    async exportMnemonic(password?: string): Promise<string | null> {
        try {
            const storedMnemonic = await StorageService.getMnemonic();
            if (!storedMnemonic) {
                return null; // No mnemonic stored (wallet created without BIP39)
            }

            const isEncrypted = await StorageService.getIsEncrypted();

            if (isEncrypted && password) {
                try {
                    const { decrypted: decryptedMnemonic } = await decryptData(storedMnemonic, password);
                    if (!decryptedMnemonic) {
                        throw new Error('Failed to decrypt mnemonic');
                    }
                    return decryptedMnemonic;
                } catch (error) {
                    throw new Error('Invalid password or corrupted mnemonic');
                }
            } else if (!isEncrypted) {
                return storedMnemonic;
            } else {
                throw new Error('Password required for encrypted wallet');
            }
        } catch (error) {
            walletLogger.error('Error exporting mnemonic:', error);
            throw error;
        }
    }

    // Utility method to open transaction in block explorer
    // These delegate to the crypto-free helpers in lib/explorer so a read-only view can link to
    // the explorer without importing this module. Kept here for existing callers.
    static openTransactionInExplorer(txid: string): void {
        openTransactionInExplorer(txid);
    }

    static getExplorerUrl(txid: string): string {
        return getExplorerUrl(txid);
    }

    // Utility method for testing WIF compatibility
    static testWIFCompatibility(testWIF?: string): {
        success: boolean;
        address: string;
        error?: string;
    } {
        try {
            // If no test WIF provided, generate one
            const keyPair = testWIF
                ? ECPair.fromWIF(testWIF, avianNetwork)
                : ECPair.makeRandom({ network: avianNetwork });

            // Get the WIF
            const wif = keyPair.toWIF();

            // Decode it back
            const decodedKeyPair = ECPair.fromWIF(wif, avianNetwork);

            // Generate address
            const { address } = bitcoin.payments.p2pkh({
                pubkey: Buffer.from(decodedKeyPair.publicKey),
                network: avianNetwork,
            });

            if (!address) {
                throw new Error('Failed to generate address from WIF');
            }

            return {
                success: true,
                address: address,
            };
        } catch (error) {
            walletLogger.error('WIF compatibility test failed:', error);
            return {
                success: false,
                address: '',
                error: error instanceof Error ? error.message : 'Unknown error',
            };
        }
    }

    // Utility method for testing both coin types to help users import legacy wallets
    static async detectCoinTypeFromMnemonic(
        mnemonic: string,
        passphrase?: string,
    ): Promise<{
        coinType921: { address: string; path: string };
        coinType175: { address: string; path: string };
        recommendation: string;
    }> {
        try {
            // Validate mnemonic
            if (!bip39.validateMnemonic(mnemonic)) {
                throw new Error('Invalid BIP39 mnemonic');
            }

            // Derive seed from mnemonic
            const seed = await bip39.mnemonicToSeed(mnemonic, passphrase || '');
            const root = bip32.fromSeed(seed, avianNetwork);

            // Test both coin types
            const results = {
                coinType921: { address: '', path: "m/44'/921'/0'/0/0" },
                coinType175: { address: '', path: "m/44'/175'/0'/0/0" },
                recommendation: '',
            };

            // Test coin type 921 (Avian)
            try {
                const child921 = root.derivePath(results.coinType921.path);
                if (child921.privateKey) {
                    const keyPair921 = ECPair.fromPrivateKey(child921.privateKey, { network: avianNetwork });
                    const { address: addr921 } = bitcoin.payments.p2pkh({
                        pubkey: Buffer.from(keyPair921.publicKey),
                        network: avianNetwork,
                    });
                    if (addr921) {
                        results.coinType921.address = addr921;
                    }
                }
            } catch (error) {
                walletLogger.warn('Failed to derive address for coin type 921:', error);
            }

            // Test coin type 175 (Ravencoin legacy)
            try {
                const child175 = root.derivePath(results.coinType175.path);
                if (child175.privateKey) {
                    const keyPair175 = ECPair.fromPrivateKey(child175.privateKey, { network: avianNetwork });
                    const { address: addr175 } = bitcoin.payments.p2pkh({
                        pubkey: Buffer.from(keyPair175.publicKey),
                        network: avianNetwork,
                    });
                    if (addr175) {
                        results.coinType175.address = addr175;
                    }
                }
            } catch (error) {
                walletLogger.warn('Failed to derive address for coin type 175:', error);
            }

            // Provide recommendation
            if (results.coinType921.address && results.coinType175.address) {
                results.recommendation =
                    'Both coin types generated valid addresses. Use 921 (Avian) for new wallets, or 175 if this wallet was created with Ravencoin compatibility.';
            } else if (results.coinType921.address) {
                results.recommendation = 'Use coin type 921 (Avian standard)';
            } else if (results.coinType175.address) {
                results.recommendation = 'Use coin type 175 (Ravencoin legacy compatibility)';
            } else {
                results.recommendation = 'Unable to derive addresses from this mnemonic';
            }

            return results;
        } catch (error) {
            walletLogger.error('Error detecting coin type from mnemonic:', error);
            throw new Error('Failed to analyze mnemonic for coin type detection');
        }
    }

    // Utility method for testing BIP39 mnemonic compatibility
    static async testMnemonicCompatibility(
        testMnemonic?: string,
    ): Promise<{ success: boolean; address: string; mnemonic: string; error?: string }> {
        try {
            // If no test mnemonic provided, generate one
            const mnemonic = testMnemonic || bip39.generateMnemonic(128);

            // Validate mnemonic
            if (!bip39.validateMnemonic(mnemonic)) {
                throw new Error('Invalid BIP39 mnemonic');
            }

            // Derive seed from mnemonic
            const seed = await bip39.mnemonicToSeed(mnemonic);

            // Create HD wallet root
            const root = bip32.fromSeed(seed, avianNetwork);

            // Derive key at standard path m/44'/921'/0'/0/0
            const path = "m/44'/921'/0'/0/0";
            const child = root.derivePath(path);

            if (!child.privateKey) {
                throw new Error('Failed to derive private key from mnemonic');
            }

            // Create ECPair from derived private key
            const keyPair = ECPair.fromPrivateKey(child.privateKey, { network: avianNetwork });

            // Generate address
            const { address } = bitcoin.payments.p2pkh({
                pubkey: Buffer.from(keyPair.publicKey),
                network: avianNetwork,
            });

            if (!address) {
                throw new Error('Failed to generate address from mnemonic');
            }

            return {
                success: true,
                address: address,
                mnemonic: mnemonic,
            };
        } catch (error) {
            walletLogger.error('Mnemonic compatibility test failed:', error);
            return {
                success: false,
                address: '',
                mnemonic: '',
                error: error instanceof Error ? error.message : 'Unknown error',
            };
        }
    }

    // Multi-wallet support methods
    async createNewWallet(params: {
        name: string;
        password: string; // Now required for security
        useMnemonic?: boolean;
        mnemonic?: string; // Optional: use specific mnemonic instead of generating new one
        passphrase?: string; // Optional BIP39 passphrase
        mnemonicLength?: 128 | 256; // 12 or 24 words (default: 128)
        makeActive?: boolean;
    }): Promise<WalletData> {
        try {
            // Validate required password
            if (!params.password || params.password.length < 8) {
                throw new Error('Password is required and must be at least 8 characters long');
            }
            let keyPair: any;
            let mnemonic: string | undefined;

            if (params.useMnemonic !== false) {
                // Use provided mnemonic or generate a new one
                if (params.mnemonic) {
                    // Validate provided mnemonic
                    if (!bip39.validateMnemonic(params.mnemonic)) {
                        throw new Error('Invalid mnemonic provided');
                    }
                    mnemonic = params.mnemonic;
                } else {
                    // Generate BIP39 mnemonic with specified length (default: 128 bits = 12 words)
                    const entropyBits = params.mnemonicLength || 128;
                    mnemonic = bip39.generateMnemonic(entropyBits); // 12 or 24 words
                }

                // Derive seed from mnemonic with optional passphrase
                const seed = await bip39.mnemonicToSeed(mnemonic, params.passphrase || '');

                // Create HD wallet root
                const root = bip32.fromSeed(seed, avianNetwork);

                // Derive key at standard path m/44'/921'/0'/0/0
                const path = "m/44'/921'/0'/0/0";
                const child = root.derivePath(path);

                if (!child.privateKey) {
                    throw new Error('Failed to derive private key from mnemonic');
                }

                // Create ECPair from derived private key
                keyPair = ECPair.fromPrivateKey(child.privateKey, { network: avianNetwork });
            } else {
                // Generate a random key pair directly
                keyPair = ECPair.makeRandom({ network: avianNetwork });
            }

            const privateKeyWIF = keyPair.toWIF();

            // Get the address
            const { address } = bitcoin.payments.p2pkh({
                pubkey: Buffer.from(keyPair.publicKey),
                network: avianNetwork,
            });

            if (!address) {
                throw new Error('Failed to generate address');
            }

            // Encrypt private key with password (now mandatory)
            const finalPrivateKey = await secureEncrypt(privateKeyWIF, params.password);

            // Encrypt mnemonic with password (now mandatory if mnemonic exists)
            let finalMnemonic: string | undefined;
            if (mnemonic) {
                finalMnemonic = await secureEncrypt(mnemonic, params.password);
            }

            // Encrypt BIP39 passphrase if provided
            let encryptedPassphrase: string | undefined;
            if (params.passphrase) {
                encryptedPassphrase = await secureEncrypt(params.passphrase, params.password);
            }

            // Create wallet in storage
            const walletData = await StorageService.createWallet({
                name: params.name,
                address,
                privateKey: finalPrivateKey,
                mnemonic: finalMnemonic,
                bip39Passphrase: encryptedPassphrase,
                coinType: 921, // Always use standard Avian coin type for new wallets
                isEncrypted: true, // Always encrypted now
                makeActive: params.makeActive,
            });

            return walletData;
        } catch (error) {
            walletLogger.error('Error creating wallet:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to create wallet: ${errorMessage}`);
        }
    }

    async importWalletFromMnemonic(params: {
        name: string;
        mnemonic: string;
        password: string; // Now required for security
        passphrase?: string; // Optional BIP39 passphrase (25th word)
        coinType?: 921 | 175; // BIP44 coin type for legacy compatibility (default: 921)
        addressType?: AddressType; // Script type / BIP standard (default: p2pkh)
        makeActive?: boolean;
    }): Promise<WalletData> {
        try {
            // Validate required password
            if (!params.password || params.password.length < 8) {
                throw new Error('Password is required and must be at least 8 characters long');
            }

            // Validate mnemonic
            if (!bip39.validateMnemonic(params.mnemonic)) {
                throw new Error('Invalid mnemonic phrase');
            }

            // Derive seed from mnemonic with optional passphrase
            const seed = await bip39.mnemonicToSeed(params.mnemonic, params.passphrase || '');

            // Create HD wallet root
            const root = bip32.fromSeed(seed, avianNetwork);

            // Choose derivation path based on address type:
            // P2PKH (default) → BIP44 purpose 44
            // P2SH-P2WPKH     → BIP49 purpose 49
            // P2WPKH          → BIP84 purpose 84
            const coinType = params.coinType || 921;
            const addrType: AddressType = params.addressType || 'p2pkh';
            const purpose = purposeForAddressType(addrType);
            const path = `m/${purpose}'/${coinType}'/0'/0/0`;
            walletLogger.info(
                `Importing wallet using derivation path: ${path} (${ADDRESS_TYPE_INFO[addrType].bipLabel}, coin type ${coinType === 921 ? 'Avian' : 'Ravencoin Legacy'})`,
            );
            const child = root.derivePath(path);

            if (!child.privateKey) {
                throw new Error('Failed to derive private key from mnemonic');
            }

            // Create ECPair from derived private key
            const keyPair = ECPair.fromPrivateKey(child.privateKey, { network: avianNetwork });
            const privateKeyWIF = keyPair.toWIF();

            // Derive address for the chosen script type
            const address = deriveAddress(Buffer.from(keyPair.publicKey), addrType);

            if (!address) {
                throw new Error('Failed to generate address from mnemonic');
            }

            // Check if wallet already exists
            if (await StorageService.walletExists(address)) {
                throw new Error('Wallet with this address already exists');
            }

            // Encrypt private key with password (now mandatory)
            const finalPrivateKey = await secureEncrypt(privateKeyWIF, params.password);

            // Encrypt mnemonic with password (now mandatory)
            const finalMnemonic = await secureEncrypt(params.mnemonic, params.password);

            // Encrypt passphrase if provided
            let encryptedPassphrase: string | undefined = undefined;
            if (params.passphrase) {
                encryptedPassphrase = await secureEncrypt(params.passphrase, params.password);
                walletLogger.debug('BIP39 passphrase encrypted and stored securely');
            }

            // Build output script descriptor (BIP380) for this wallet
            // Derives the xpub at account level (m/purpose'/coinType'/0') and formats descriptor
            const accountChild = root.derivePath(`m/${purpose}'/${coinType}'/0'`);
            const xpub = accountChild.neutered().toBase58();
            const fingerprint = Array.from(root.fingerprint).map(b => b.toString(16).padStart(2, '0')).join('');
            const descriptorBody = buildDescriptorBody(addrType, fingerprint, purpose, coinType, xpub);
            const descriptor = `${descriptorBody}#${descriptorChecksum(descriptorBody)}`;

            // Create wallet in storage
            const walletData = await StorageService.createWallet({
                name: params.name,
                address,
                privateKey: finalPrivateKey,
                mnemonic: finalMnemonic,
                bip39Passphrase: encryptedPassphrase,
                coinType: coinType, // Store the coin type used for derivation
                addressType: addrType,
                descriptor,
                isEncrypted: true,
                makeActive: params.makeActive,
            });

            return walletData;
        } catch (error) {
            walletLogger.error('Error importing wallet from mnemonic:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to import wallet: ${errorMessage}`);
        }
    }

    /**
     * Parses a BIP380 output script descriptor (with or without checksum) and extracts
     * the address type, key material, and derivation metadata.
     *
     * Handles descriptors produced by `listdescriptors true` from Avian Core v5, e.g.:
     *   wpkh([a1b2c3d4/84h/921h/0h]xprvABC.../0/*)#checksum
     *   sh(wpkh([a1b2c3d4/49h/921h/0h]xprvABC.../0/*))#checksum
     *   pkh([a1b2c3d4/44h/921h/0h]xprvABC.../0/*)#checksum
     *
     * Both `h` and `'` hardened-path notations are accepted.
     */
    static parseDescriptor(descriptor: string): {
        addrType: AddressType;
        xkey: string;
        isPrivate: boolean;
        fingerprint: string;
        purpose: number;
        coinType: number;
        accountIndex: number;
        /** Set when xkey is a root key with an inline derivation path (e.g. xprv.../44h/921h/0h/0/*) */
        accountDerivationPath?: string;
    } {
        const clean = descriptor.trim().replace(/#[a-zA-Z0-9]+$/, '');

        let addrType: AddressType;
        let inner: string;

        if (clean.startsWith('sh(wpkh(') && clean.endsWith('))')) {
            addrType = 'p2sh-p2wpkh';
            inner = clean.slice(8, -2);
        } else if (clean.startsWith('wpkh(') && clean.endsWith(')')) {
            addrType = 'p2wpkh';
            inner = clean.slice(5, -1);
        } else if (clean.startsWith('pkh(') && clean.endsWith(')')) {
            addrType = 'p2pkh';
            inner = clean.slice(4, -1);
        } else {
            throw new Error(
                'Unsupported descriptor type. Expected pkh(...), wpkh(...), or sh(wpkh(...)).',
            );
        }

        // Try full origin expression: [fingerprint/purpose'/coinType'/account']xkey
        const mFull = inner.match(
            /^\[([0-9a-fA-F]{8})\/(\d+)[h']\/(\d+)[h']\/(\d+)[h']\]([a-zA-Z0-9]+)/,
        );

        let fingerprint: string;
        let purpose: number;
        let coinType: number;
        let accountIndex: number;
        let xkey: string;

        if (mFull) {
            [, fingerprint, , , , xkey] = mFull;
            fingerprint = fingerprint.toLowerCase();
            purpose = parseInt(mFull[2], 10);
            coinType = parseInt(mFull[3], 10);
            accountIndex = parseInt(mFull[4], 10);
        } else {
            // No origin — accept bare xkey with optional inline path
            // e.g. pkh(xprv.../44h/921h/0h/0/*) or wpkh(xpubXXX/0/*)
            const mBare = inner.match(/^([a-zA-Z0-9]+)((?:\/(?:\d+[h']?|\*))*)/);
            if (!mBare || (!mBare[1].startsWith('xprv') && !mBare[1].startsWith('xpub') &&
                          !mBare[1].startsWith('tprv') && !mBare[1].startsWith('tpub'))) {
                throw new Error(
                    'Descriptor must contain an xprv/xpub key, optionally with an origin ' +
                    'expression: [fingerprint/84h/921h/0h]xprv...',
                );
            }
            xkey = mBare[1];
            fingerprint = '00000000';

            // Parse hardened path components from the inline suffix (e.g. /44h/921h/0h/0/*)
            const pathSuffix = mBare[2] || '';
            const hComponents: number[] = [];
            const hRe = /\/(\d+)[h']/g;
            let hm: RegExpExecArray | null;
            while ((hm = hRe.exec(pathSuffix)) !== null) {
                hComponents.push(parseInt(hm[1], 10));
            }

            let accountDerivationPath: string | undefined;
            if (hComponents.length >= 3) {
                // Full BIP44 path: purpose/coinType/account all present
                purpose = hComponents[0];
                coinType = hComponents[1];
                accountIndex = hComponents[2];
                accountDerivationPath = `m/${purpose}'/${coinType}'/${accountIndex}'`;
            } else if (hComponents.length === 2) {
                purpose = hComponents[0];
                coinType = hComponents[1];
                accountIndex = 0;
                accountDerivationPath = `m/${purpose}'/${coinType}'/${accountIndex}'`;
            } else {
                // No inline hardened path — xkey is already at account level; infer from script type
                accountIndex = 0;
                if (addrType === 'p2wpkh')           { purpose = 84; coinType = 921; }
                else if (addrType === 'p2sh-p2wpkh') { purpose = 49; coinType = 921; }
                else                                  { purpose = 44; coinType = 921; }
            }

            const isPriv = xkey.startsWith('xprv') || xkey.startsWith('tprv');
            return {
                addrType, xkey, isPrivate: isPriv, fingerprint,
                purpose, coinType, accountIndex, accountDerivationPath,
            };
        }

        const isPrivate = xkey.startsWith('xprv') || xkey.startsWith('tprv');

        return {
            addrType,
            xkey,
            isPrivate,
            fingerprint,
            purpose,
            coinType,
            accountIndex,
        };
    }

    /** Upper bound on the receive index a descriptor import may be anchored to. */
    static readonly MAX_IMPORT_ADDRESS_INDEX = 1000;

    /**
     * Receive addresses a descriptor would produce, without importing anything or touching
     * storage. Lets the import screen show the account's addresses so the user can pick the
     * one holding their coins or assets instead of having to know its index up front.
     *
     * Works for xpub-only descriptors too: addresses need no private key.
     */
    static previewDescriptorAddresses(
        descriptor: string,
        count = 10,
        startIndex = 0,
    ): Array<{ index: number; path: string; address: string }> {
        const parsed = WalletService.parseDescriptor(descriptor);

        let accountNode: ReturnType<typeof bip32.fromBase58>;
        try {
            const rawNode = bip32.fromBase58(parsed.xkey, avianNetwork);
            accountNode = parsed.accountDerivationPath
                ? rawNode.derivePath(parsed.accountDerivationPath)
                : rawNode;
        } catch {
            throw new Error(
                'Invalid extended key in descriptor — check the descriptor is from an Avian mainnet wallet',
            );
        }

        const changeNode = accountNode.derive(0);
        const addresses: Array<{ index: number; path: string; address: string }> = [];

        for (let i = startIndex; i < startIndex + count; i++) {
            const child = changeNode.derive(i);
            addresses.push({
                index: i,
                path: `m/${parsed.purpose}'/${parsed.coinType}'/${parsed.accountIndex}'/0/${i}`,
                address: deriveAddress(Buffer.from(child.publicKey), parsed.addrType),
            });
        }

        return addresses;
    }

    /**
     * Import a wallet from a BIP380 output script descriptor containing an xprv.
     * Use `listdescriptors true` in Avian Core v5 to obtain the descriptor.
     * The encrypted xprv is stored, enabling full HD address derivation without a mnemonic.
     *
     * `addressIndex` anchors the wallet's primary address to account/0/N rather than the
     * usual account/0/0. Features that read `wallet.address` — the asset list, asset
     * transfers, Avian Connect — then operate on that address. The whole account tree stays
     * derivable either way, since the stored xprv is at account level.
     */
    async importWalletFromDescriptor(params: {
        name: string;
        descriptor: string;
        password: string;
        addressIndex?: number;
        makeActive?: boolean;
    }): Promise<WalletData> {
        try {
            if (!params.password || params.password.length < 8) {
                throw new Error('Password is required and must be at least 8 characters long');
            }

            const addressIndex = params.addressIndex ?? 0;
            if (
                !Number.isInteger(addressIndex) ||
                addressIndex < 0 ||
                addressIndex > WalletService.MAX_IMPORT_ADDRESS_INDEX
            ) {
                throw new Error(
                    `Address index must be a whole number between 0 and ${WalletService.MAX_IMPORT_ADDRESS_INDEX}`,
                );
            }

            const parsed = WalletService.parseDescriptor(params.descriptor);

            if (!parsed.isPrivate) {
                throw new Error(
                    'This descriptor contains only a public key (xpub). ' +
                    'Run `listdescriptors true` in Avian Core to export the xprv descriptor.',
                );
            }

            let accountNode: ReturnType<typeof bip32.fromBase58>;
            let resolvedFingerprint = parsed.fingerprint;
            try {
                const rawNode = bip32.fromBase58(parsed.xkey, avianNetwork);
                if (parsed.accountDerivationPath) {
                    // xkey is the root key — compute the master fingerprint then derive to account
                    resolvedFingerprint = Array.from(rawNode.fingerprint)
                        .map(b => b.toString(16).padStart(2, '0')).join('');
                    accountNode = rawNode.derivePath(parsed.accountDerivationPath);
                } else {
                    accountNode = rawNode;
                }
            } catch {
                throw new Error('Invalid xprv in descriptor — check the descriptor is from an Avian mainnet wallet');
            }

            if (!accountNode.privateKey) {
                throw new Error('Failed to extract private key from xprv');
            }

            // Derive the anchor receiving address: account/0/addressIndex
            const receiveNode = accountNode.derive(0).derive(addressIndex);
            if (!receiveNode.privateKey) {
                throw new Error('Failed to derive child key from xprv');
            }

            const keyPair = ECPair.fromPrivateKey(Buffer.from(receiveNode.privateKey), {
                network: avianNetwork,
            });
            const address = deriveAddress(Buffer.from(keyPair.publicKey), parsed.addrType);
            const privateKeyWIF = keyPair.toWIF();

            if (await StorageService.walletExists(address)) {
                throw new Error('Wallet with this address already exists');
            }

            const encryptedPrivateKey = await secureEncrypt(privateKeyWIF, params.password);
            // Store account-level xprv (not root), so deriveCurrentWalletAddresses works correctly
            const encryptedXprv = await secureEncrypt(accountNode.toBase58(), params.password);

            // Build canonical descriptor with xpub (no private key in stored descriptor)
            const descriptorBody = buildDescriptorBody(
                parsed.addrType,
                resolvedFingerprint,
                parsed.purpose,
                parsed.coinType,
                accountNode.neutered().toBase58(),
            );
            const descriptor = `${descriptorBody}#${descriptorChecksum(descriptorBody)}`;

            const walletData = await StorageService.createWallet({
                name: params.name,
                address,
                privateKey: encryptedPrivateKey,
                xprv: encryptedXprv,
                coinType: (parsed.coinType === 175 ? 175 : 921) as 921 | 175,
                addressType: parsed.addrType,
                descriptor,
                isEncrypted: true,
                makeActive: params.makeActive,
            });

            return walletData;
        } catch (error) {
            walletLogger.error('Error importing wallet from descriptor:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to import descriptor wallet: ${errorMessage}`);
        }
    }

    async importWalletFromPrivateKey(params: {
        name: string;
        privateKey: string;
        password: string; // Now required for security
        makeActive?: boolean;
    }): Promise<WalletData> {
        try {
            // Validate required password
            if (!params.password || params.password.length < 8) {
                throw new Error('Password is required and must be at least 8 characters long');
            }

            let keyPair: any;
            let decryptedKey = params.privateKey;

            // Helper function to check if a string is a valid WIF private key

            // Check if the private key is encrypted by trying to parse it as WIF first
            if (!isValidWIF(params.privateKey)) {
                // This doesn't look like a valid WIF key, it's likely encrypted
                try {
                    const { decrypted } = await decryptData(params.privateKey, params.password);
                    decryptedKey = decrypted;

                    // Validate the decrypted key is a valid WIF
                    if (!isValidWIF(decryptedKey)) {
                        throw new Error('Decrypted data is not a valid WIF private key');
                    }
                } catch (e) {
                    // If decryption fails or produces invalid WIF, it's an error
                    throw new Error('Invalid private key format or incorrect password');
                }
            }

            if (!decryptedKey) {
                throw new Error('Invalid private key or password');
            }

            // Import the private key
            try {
                keyPair = ECPair.fromWIF(decryptedKey, avianNetwork);
            } catch (error) {
                throw new Error('Invalid private key format');
            }

            // Get the address
            const { address } = bitcoin.payments.p2pkh({
                pubkey: Buffer.from(keyPair.publicKey),
                network: avianNetwork,
            });

            if (!address) {
                throw new Error('Failed to generate address from private key');
            }

            // Check if wallet already exists
            if (await StorageService.walletExists(address)) {
                throw new Error('Wallet with this address already exists');
            }

            // Encrypt private key with password (now mandatory)
            const finalPrivateKey = await secureEncrypt(decryptedKey, params.password);

            // Create wallet in storage
            const walletData = await StorageService.createWallet({
                name: params.name,
                address,
                privateKey: finalPrivateKey,
                isEncrypted: true, // Always encrypted now
                makeActive: params.makeActive,
            });

            return walletData;
        } catch (error) {
            walletLogger.error('Error importing wallet from private key:', error);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`Failed to import wallet: ${errorMessage}`);
        }
    }

    async getAllWallets(): Promise<WalletData[]> {
        return await StorageService.getAllWallets();
    }

    async getActiveWallet(): Promise<WalletData | null> {
        return await StorageService.getActiveWallet();
    }

    async switchWallet(walletId: number): Promise<boolean> {
        return await StorageService.switchToWallet(walletId);
    }

    async updateWalletName(walletId: number, newName: string): Promise<boolean> {
        return await StorageService.updateWalletName(walletId, newName);
    }

    async deleteWallet(walletId: number): Promise<boolean> {
        return await StorageService.deleteWallet(walletId);
    }

    async getWalletCount(): Promise<number> {
        return await StorageService.getWalletCount();
    }

    // Export mnemonic for active wallet
    async exportActiveWalletMnemonic(password?: string): Promise<string> {
        const wallet = await this.getActiveWallet();
        if (!wallet || !wallet.mnemonic) {
            throw new Error('No mnemonic available for current wallet');
        }

        if (wallet.isEncrypted && !password) {
            throw new Error('Password required to decrypt mnemonic');
        }

        if (wallet.isEncrypted && password) {
            try {
                const { decrypted } = await decryptData(wallet.mnemonic, password);
                if (!decrypted) {
                    throw new Error('Invalid password');
                }
                return decrypted;
            } catch (error) {
                throw new Error('Invalid password');
            }
        }

        return wallet.mnemonic;
    }

    // Export private key for active wallet
    async exportActiveWalletPrivateKey(password?: string): Promise<string> {
        const wallet = await this.getActiveWallet();
        if (!wallet) {
            throw new Error('No active wallet');
        }

        if (wallet.isEncrypted && !password) {
            throw new Error('Password required to decrypt private key');
        }

        if (wallet.isEncrypted && password) {
            try {
                const { decrypted, wasLegacy } = await decryptData(wallet.privateKey, password);

                // The legacy format is unauthenticated, so a wrong password can decrypt to
                // plausible-looking rubbish instead of failing. Never treat that as the key, and
                // above all never write it back — doing so would overwrite the real key and
                // destroy the wallet.
                if (!isValidWIF(decrypted)) {
                    throw new Error('Invalid password');
                }

                if (wasLegacy) {
                    walletLogger.info(`Upgrading encryption for wallet: ${wallet.name}`);
                    const newEncryptedKey = await secureEncrypt(decrypted, password);
                    await StorageService.updateWalletPrivateKey(wallet.id!, newEncryptedKey);
                }
                return decrypted;
            } catch (error) {
                throw new Error('Invalid password');
            }
        }

        return wallet.privateKey;
    }

    async getTransactionHistory(address?: string): Promise<any[]> {
        try {
            // If no address provided, use the active wallet's address
            if (!address) {
                const activeWallet = await this.getActiveWallet();
                if (activeWallet) {
                    address = activeWallet.address;
                }
            }

            return await StorageService.getTransactionHistory(address);
        } catch (error) {
            walletLogger.error('Error getting transaction history:', error);
            return [];
        }
    }

    private async calculateConfirmations(blockHeight?: number): Promise<number> {
        if (!blockHeight) {
            return 0; // Unconfirmed transaction
        }

        try {
            const currentHeight = await this.electrum.getCurrentBlockHeight();
            return this.confirmationsAtHeight(blockHeight, currentHeight);
        } catch (error) {
            walletLogger.error('Error calculating confirmations:', error);
            // Fallback: return 1 for confirmed transactions, 0 for unconfirmed
            return blockHeight ? 1 : 0;
        }
    }

    // Synchronous confirmation count against an already-known chain tip. Lets a bulk sync fetch the
    // tip once instead of calling getCurrentBlockHeight for every transaction.
    private confirmationsAtHeight(blockHeight?: number, currentHeight?: number): number {
        if (!blockHeight) return 0; // Unconfirmed
        if (!currentHeight) return 1; // Tip unknown but the tx is in a block — at least 1
        return Math.max(0, currentHeight - blockHeight + 1);
    }

    // Fetch a verbose transaction, reusing a per-sync cache so the same parent transaction is never
    // pulled from the server twice. Input-address resolution repeatedly needs a transaction's
    // parents, and across a whole history the same parents recur constantly (a wallet's sends spend
    // its own earlier receives), so this collapses a large share of the round-trips.
    //
    // The cache stores the in-flight promise, not the resolved value, so many concurrent workers
    // asking for the same parent at once share a single request instead of each firing their own (a
    // thundering herd the pool would otherwise create). A failed fetch is evicted so a later item
    // can retry rather than inheriting a cached rejection.
    private getTransactionCached(txid: string, cache?: Map<string, Promise<any>>): Promise<any> {
        if (!cache) {
            return this.fetchTransactionWithRetry(txid);
        }
        const inFlight = cache.get(txid);
        if (inFlight) {
            return inFlight;
        }
        const request = this.fetchTransactionWithRetry(txid).catch((error) => {
            cache.delete(txid);
            throw error;
        });
        cache.set(txid, request);
        return request;
    }

    // Fetch a verbose transaction, retrying when the request fails mid-flight. The usual cause is a
    // rate-limiting server dropping the connection, which now rejects in-flight requests immediately
    // (see ElectrumService.failPendingRequests); between attempts we wait for the socket to
    // reconnect and back off, so a dropped request is recovered instead of losing that transaction.
    private async fetchTransactionWithRetry(txid: string): Promise<any> {
        for (let attempt = 1; attempt <= TX_FETCH_ATTEMPTS; attempt++) {
            try {
                return await this.electrum.getTransaction(txid, true);
            } catch (error) {
                if (attempt === TX_FETCH_ATTEMPTS) {
                    throw error;
                }
                // Wait for the connection to come back (the close handler reconnects with backoff),
                // then pause briefly before retrying so we don't immediately re-trip the rate limit.
                try {
                    await this.electrum.waitForConnection();
                } catch {
                    // If it never reconnects, fall through and let the next attempt (or the final
                    // throw) surface the failure.
                }
                await new Promise((resolve) => setTimeout(resolve, 300 * attempt));
            }
        }
    }

    // Order a raw get_history list newest-first, in place: mempool entries (height <= 0) first, then
    // confirmed transactions by descending block height. get_history only carries tx_hash + height,
    // so this is approximate within a single block — good enough to surface recent activity first.
    private sortHistoryNewestFirst(history: Array<{ tx_hash: string; height: number }>): void {
        history.sort((a, b) => {
            const aUnconfirmed = (a.height ?? 0) <= 0;
            const bUnconfirmed = (b.height ?? 0) <= 0;
            if (aUnconfirmed !== bUnconfirmed) {
                return aUnconfirmed ? -1 : 1;
            }
            return (b.height ?? 0) - (a.height ?? 0);
        });
    }

    // Map one pre-classified get_history_rich row to a stored TransactionData. The server already
    // resolved direction/amount/counterparty, so this is a pure shape conversion (satoshis -> AVN,
    // unix seconds -> Date). `address` is the wallet's own address. Following TransactionData's
    // convention, `address` holds the counterparty for both directions and `fromAddress` is the
    // sender (the counterparty for a receive, us for a send).
    private richRowToTransaction(
        row: import('../core/ElectrumService').RichHistoryTx,
        walletAddress: string,
    ): Omit<TransactionData, 'id'> {
        // counterparty is null whenever there is no single address to show — a coinbase payout, but
        // also an output to a non-standard script (OP_RETURN, bare multisig, an asset-tagging
        // output). Only the server's explicit `coinbase` flag means "mined", which we label
        // "Coinbase" to match the standard reconstruction path; every other null is just "no
        // address", stored as "" so the UI shows a neutral placeholder. Never store null —
        // TransactionData.address is a string the UI relies on.
        const counterparty = row.coinbase === true ? 'Coinbase' : (row.counterparty ?? '');
        return {
            txid: row.txid,
            amount: row.amount / 100000000,
            address: counterparty,
            fromAddress: row.type === 'receive' ? counterparty : walletAddress,
            walletAddress,
            type: row.type,
            timestamp: row.time ? new Date(row.time * 1000) : new Date(),
            confirmations: row.confirmations ?? 0,
            blockHeight: row.height > 0 ? row.height : undefined,
        };
    }

    /**
     * Sync history via the server's get_history_rich extension: page through the pre-classified
     * rows (newest-first) and persist them. Far cheaper than the standard path — one request per
     * page of up to 100 instead of one per transaction plus one per input. For an incremental
     * refresh (onlyNewTransactions) it stops as soon as a whole page is already stored, since
     * newest-first means every older page is stored too.
     */
    private async processTransactionHistoryRich(
        address: string,
        onProgress?: (processed: number, total: number, currentTx?: string) => void,
        onlyNewTransactions: boolean = false,
    ): Promise<void> {
        const PAGE_SIZE = 100;

        const existingTxs = (await StorageService.getTransactionHistory(address)).filter(
            (tx) => tx.walletAddress === address,
        );
        const existingByKey = new Map(existingTxs.map((tx) => [`${tx.txid}-${tx.type}`, tx]));
        const existingIds = new Set(existingTxs.map((tx) => tx.txid));

        const first = await this.fetchRichPageWithRetry(address, 0, PAGE_SIZE);
        const total = first.total ?? 0;
        if (total === 0) {
            onProgress?.(0, 0);
            return;
        }
        const pageCount = Math.ceil(total / PAGE_SIZE);
        let processed = 0;
        onProgress?.(0, total);

        // Persist a page; returns how many of its rows were new (for the incremental early-stop).
        const handlePage = async (page: { txs: import('../core/ElectrumService').RichHistoryTx[] }) => {
            let fresh = 0;
            for (const row of page.txs) {
                if (onlyNewTransactions && existingIds.has(row.txid)) {
                    processed++;
                    onProgress?.(processed, total, row.txid);
                    continue;
                }
                fresh++;
                const tx = this.richRowToTransaction(row, address);
                const existing = existingByKey.get(`${row.txid}-${tx.type}`);
                try {
                    if (existing) {
                        const needsUpdate =
                            existing.amount !== tx.amount ||
                            existing.address !== tx.address ||
                            existing.fromAddress !== tx.fromAddress ||
                            existing.confirmations !== tx.confirmations ||
                            !existing.walletAddress;
                        if (needsUpdate) {
                            await StorageService.saveTransaction({ ...tx, id: existing.id } as any);
                        }
                    } else {
                        await StorageService.saveTransaction(tx);
                    }
                } catch (error) {
                    walletLogger.warn(`Failed to save rich transaction ${row.txid}:`, error);
                }
                processed++;
                onProgress?.(processed, total, row.txid);
            }
            return fresh;
        };

        await handlePage(first);

        for (let page = 1; page < pageCount; page++) {
            const data = await this.fetchRichPageWithRetry(address, page, PAGE_SIZE);
            const fresh = await handlePage(data);
            // Incremental refresh: once a full page holds nothing new, every older page is already
            // stored (newest-first), so stop.
            if (onlyNewTransactions && fresh === 0) {
                break;
            }
        }

        onProgress?.(processed, total);
    }

    // Fetch a rich history page, retrying on a dropped connection the same way single-tx fetches do.
    private async fetchRichPageWithRetry(
        address: string,
        page: number,
        pageSize: number,
    ): Promise<import('../core/ElectrumService').RichHistoryPage> {
        for (let attempt = 1; attempt <= TX_FETCH_ATTEMPTS; attempt++) {
            try {
                return await this.electrum.getRichHistoryPage(address, page, pageSize);
            } catch (error) {
                if (attempt === TX_FETCH_ATTEMPTS) {
                    throw error;
                }
                try {
                    await this.electrum.waitForConnection();
                } catch {
                    // fall through to retry / final throw
                }
                await new Promise((resolve) => setTimeout(resolve, 300 * attempt));
            }
        }
        // Unreachable: the loop either returns or throws on the last attempt.
        throw new Error('rich history fetch failed');
    }

    /**
     * Process transaction history for a wallet address
     * @param address - The wallet address
     * @param onProgress - Optional callback for progress updates (currently unused in implementation)
     * @param onlyNewTransactions - Whether to process only new transactions
     */
    async processTransactionHistory(
        address: string,
        onProgress?: (processed: number, total: number, currentTx?: string) => void,
        onlyNewTransactions: boolean = false,
    ): Promise<void> {
        try {
            // Fast path: if the server offers our get_history_rich extension it returns rows already
            // classified (direction, amount, counterparty), so we skip the per-transaction and
            // per-input reconstruction entirely. Any failure falls through to the standard path.
            if (await this.electrum.supportsRichHistory()) {
                try {
                    await this.processTransactionHistoryRich(address, onProgress, onlyNewTransactions);
                    return;
                } catch (richError) {
                    walletLogger.warn(
                        'Rich history path failed; falling back to standard reconstruction',
                        richError,
                    );
                }
            }

            // Get transaction history from ElectrumX
            const txHistory = await this.electrum.getTransactionHistory(address);

            if (!txHistory || txHistory.length === 0) {
                return;
            }

            // Process newest-first so the transactions a user actually looks at land in storage (and
            // on screen) first, while older history backfills behind them. get_history's own order is
            // not guaranteed, so sort explicitly for deterministic behaviour: mempool entries
            // (height <= 0) first, then confirmed transactions by descending block height.
            this.sortHistoryNewestFirst(txHistory);

            // Get existing transactions from local storage.
            // getTransactionHistory falls back to matching the counterparty address when a wallet
            // has no rows of its own yet, so it can return another wallet's transactions. Scope
            // the lookups to this wallet or an internal transfer would suppress its own receive.
            const existingTxs = (await StorageService.getTransactionHistory(address)).filter(
                (tx) => tx.walletAddress === address,
            );

            // Create maps for faster lookups
            const existingTxMap = new Map(existingTxs.map((tx) => [`${tx.txid}-${tx.type}`, tx]));
            const existingTxIdSet = new Set(existingTxs.map((tx) => tx.txid));

            // Get the total to process (might include some existing ones that need updating)
            const total = txHistory.length;
            let processedCount = 0;
            let updatedCount = 0;

            // Report initial progress
            onProgress?.(0, total);

            // Fetch the chain tip once so each transaction's confirmation count is computed locally
            // rather than asking the server per transaction.
            let currentHeight = 0;
            try {
                currentHeight = await this.electrum.getCurrentBlockHeight();
            } catch (heightError) {
                walletLogger.warn('Could not fetch chain tip for confirmations; using fallback', heightError);
            }

            // Shared per-sync cache so input-address resolution never refetches the same parent tx.
            const txCache = new Map<string, Promise<any>>();

            // Fetch and classify with a bounded pool of concurrent requests instead of one-at-a-time.
            // Each worker is self-contained and swallows its own errors, so a single bad transaction
            // never aborts the sync; progress is reported as each finishes (order is not guaranteed,
            // but the count is monotonic).
            await runWithConcurrency(txHistory, HISTORY_SYNC_CONCURRENCY, async (historyTx) => {
                try {
                    // Skip already processed transactions if onlyNewTransactions is true
                    if (onlyNewTransactions && existingTxIdSet.has(historyTx.tx_hash)) {
                        // Still count as processed for progress reporting
                        processedCount++;
                        onProgress?.(processedCount, total, historyTx.tx_hash);
                        return;
                    }
                    // Get detailed transaction information (cached, so parents resolve cheaply)
                    const txDetails = await this.getTransactionCached(historyTx.tx_hash, txCache);
                    if (!txDetails) {
                        processedCount++;
                        onProgress?.(processedCount, total, historyTx.tx_hash);
                        return;
                    }

                    // Classify transaction as sent or received, sharing the per-sync cache
                    const classification = await this.classifyTransaction(txDetails, address, txCache);
                    if (!classification) {
                        processedCount++;
                        onProgress?.(processedCount, total, historyTx.tx_hash);
                        return;
                    }

                    // Confirmations against the tip we fetched once above
                    const confirmations = this.confirmationsAtHeight(historyTx.height, currentHeight);

                    // Check if we have an existing transaction of this type
                    const existingTx = existingTxMap.get(`${historyTx.tx_hash}-${classification.type}`);

                    // Create the transaction object with all required fields
                    const updatedTx = {
                        txid: historyTx.tx_hash,
                        amount: classification.amount / 100000000, // Convert satoshis to AVN
                        address: classification.toAddress,
                        fromAddress: classification.fromAddress,
                        walletAddress: address, // Ensure wallet address is set for proper multi-wallet support
                        type: classification.type,
                        timestamp: new Date(txDetails.time ? txDetails.time * 1000 : Date.now()),
                        confirmations: confirmations,
                        blockHeight: historyTx.height || undefined,
                    };

                    // Check if we need to update an existing transaction
                    if (existingTx) {
                        // Only update if data has changed
                        const needsUpdate =
                            existingTx.amount !== updatedTx.amount ||
                            existingTx.address !== updatedTx.address ||
                            existingTx.fromAddress !== updatedTx.fromAddress ||
                            existingTx.confirmations !== updatedTx.confirmations ||
                            !existingTx.walletAddress; // Always update if walletAddress is missing

                        if (needsUpdate) {
                            try {
                                // Update with existing ID - using the raw object modification
                                // to avoid TypeScript issues with the ID property
                                const txWithId = { ...updatedTx } as any;
                                txWithId.id = existingTx.id;
                                await StorageService.saveTransaction(txWithId);
                                updatedCount++;
                            } catch (error) {
                                const errorMsg = error instanceof Error ? error.message : String(error);
                                walletLogger.warn(
                                    `Failed to update existing transaction ${historyTx.tx_hash}: ${errorMsg}`,
                                );
                                // Continue processing other transactions even if this one fails
                            }
                        }
                    } else {
                        // No row of this type for this wallet yet, so record it. Keyed by type so
                        // a send and a receive of the same txid can coexist across wallets.
                        try {
                            // This is a new transaction, save it
                            await StorageService.saveTransaction(updatedTx);
                            updatedCount++;
                        } catch (error) {
                            const errorMsg = error instanceof Error ? error.message : String(error);
                            walletLogger.warn(`Failed to save new transaction ${historyTx.tx_hash}: ${errorMsg}`);
                            // Continue processing other transactions even if this one fails
                        }
                    }

                    processedCount++;
                    onProgress?.(processedCount, total, historyTx.tx_hash);
                } catch (error) {
                    walletLogger.error(`Error processing transaction ${historyTx.tx_hash}:`, error);
                    processedCount++;
                    onProgress?.(processedCount, total, historyTx.tx_hash);
                }
            });

            // Report final progress
            if (total > 0) {
                onProgress?.(processedCount, total);
            }
        } catch (error) {
            walletLogger.error('Error processing transaction history:', error);
        }
    }

    /**
     * Refresh transaction history, focusing only on new transactions
     * @param address - Optional wallet address, will use active wallet if not provided
     * @param onProgress - Optional progress callback (currently unused in implementation)
     */
    async refreshTransactionHistory(
        address?: string,
        onProgress?: (processed: number, total: number, currentTx?: string) => void,
    ): Promise<void> {
        try {
            // If no address provided, use the active wallet's address
            if (!address) {
                const activeWallet = await this.getActiveWallet();
                if (activeWallet) {
                    address = activeWallet.address;
                }
            }

            if (address) {
                // Only process new transactions during regular refresh
                await this.processTransactionHistory(address, onProgress, true);
            } else {
                walletLogger.warn('No address available to refresh transaction history');
            }
        } catch (error) {
            walletLogger.error('Error refreshing transaction history:', error);
            throw error;
        }
    }

    private async isTransactionReceived(txDetails: any, address: string): Promise<boolean> {
        // First check if this transaction is already stored as a sent transaction
        const existingTxs = await StorageService.getTransactionHistory(address);
        const existingSentTx = existingTxs.find(
            (tx) => tx.txid === txDetails.txid && tx.type === 'send',
        );

        if (existingSentTx) {
            return false;
        }

        // Check if any output is directed to our address
        let hasOutputToUs = false;
        if (txDetails.vout) {
            for (const output of txDetails.vout) {
                if (output.scriptPubKey) {
                    if (this.scriptPubKeyToAddresses(output.scriptPubKey).includes(address)) {
                        hasOutputToUs = true;
                        break;
                    }
                }
            }
        }

        if (!hasOutputToUs) {
            return false;
        }

        // Check if any inputs belong specifically to this address
        // (we want to allow transactions between our wallets to show as received)
        if (txDetails.vin) {
            for (const input of txDetails.vin) {
                // Check for direct address field
                if (input.address && input.address === address) {
                    return false;
                }

                // Check scriptSig.addresses
                if (input.scriptSig && input.scriptSig.addresses) {
                    for (const inputAddress of input.scriptSig.addresses) {
                        if (inputAddress === address) {
                            return false;
                        }
                    }
                }

                // If no direct address info, check previous transaction
                if (input.txid && input.vout !== undefined) {
                    try {
                        const prevTxDetails = await this.electrum.getTransaction(input.txid, true);
                        if (prevTxDetails && prevTxDetails.vout && prevTxDetails.vout[input.vout]) {
                            const prevOutput = prevTxDetails.vout[input.vout];
                            if (prevOutput.scriptPubKey) {
                                for (const inputAddress of this.scriptPubKeyToAddresses(prevOutput.scriptPubKey)) {
                                    if (inputAddress === address) {
                                        return false;
                                    }
                                }
                            }
                        }
                    } catch (error) {
                        walletLogger.warn(
                            `Failed to get previous transaction ${input.txid} for input analysis:`,
                            error,
                        );
                    }
                }
            }
        }

        // If we reach here, there's an output to us but no inputs from this specific address
        return true;
    }

    private calculateReceivedAmount(txDetails: any, address: string): number {
        let totalReceived = 0;

        if (txDetails.vout) {
            for (const output of txDetails.vout) {
                if (output.scriptPubKey) {
                    if (this.scriptPubKeyToAddresses(output.scriptPubKey).includes(address)) {
                        // Handle both number and string values for output.value
                        const valueStr = output.value.toString();
                        const value = parseFloat(valueStr);

                        // If the value is already in satoshis (large numbers like 2000000000)
                        if (value > 100000000 && !valueStr.includes('.')) {
                            totalReceived += value;
                        } else {
                            // Otherwise convert to satoshis
                            totalReceived += Math.round(value * 100000000);
                        }
                    }
                }
            }
        }

        return totalReceived;
    }

    /**
     * Resolve address(es) from any scriptPubKey format, including native SegWit
     * outputs that only carry an `asm` / `hex` field without an `addresses` array.
     */
    private scriptPubKeyToAddresses(scriptPubKey: any): string[] {
        // Standard path — legacy & P2SH outputs
        if (scriptPubKey.addresses && scriptPubKey.addresses.length > 0) {
            return scriptPubKey.addresses;
        }
        // Single address field (some server variants)
        if (scriptPubKey.address) {
            return [scriptPubKey.address];
        }
        // Native SegWit (P2WPKH / P2WSH) — reconstruct from scriptPubKey hex
        if (scriptPubKey.hex) {
            try {
                const script = Buffer.from(scriptPubKey.hex, 'hex');
                const addr = bitcoin.address.fromOutputScript(script, avianNetwork);
                return [addr];
            } catch {
                // not a recognised script for this network
            }
        }
        return [];
    }

    private getSenderAddress(txDetails: any): string {
        // Try to get the first input address as sender
        if (txDetails.vin && txDetails.vin.length > 0) {
            const firstInput = txDetails.vin[0];

            // Skip coinbase transactions
            if (firstInput.coinbase) {
                return 'Coinbase';
            }

            // Check for direct address field first (more common in modern ElectrumX)
            if (firstInput.address) {
                return firstInput.address;
            }

            // Fallback to scriptSig.addresses for legacy format
            if (
                firstInput.scriptSig &&
                firstInput.scriptSig.addresses &&
                firstInput.scriptSig.addresses.length > 0
            ) {
                return firstInput.scriptSig.addresses[0];
            }

            // If no direct address available, we'd need to look up the previous transaction
            // This is handled in the classifyTransaction method
            if (firstInput.txid && firstInput.vout !== undefined) {
                return 'Unknown (requires lookup)';
            }
        }
        return 'External'; // Use a more descriptive placeholder
    }

    /**
     * Classify a transaction as sent, received, or neither (not related to our address)
     */
    private async classifyTransaction(
        txDetails: any,
        address: string,
        cache?: Map<string, Promise<any>>,
    ): Promise<{
        type: 'send' | 'receive';
        amount: number;
        fromAddress: string;
        toAddress: string;
    } | null> {
        try {
            // Enhanced transaction classification for better multi-wallet support

            // Check if we have inputs (spending from our address)
            let inputFromCurrentAddress = false;
            const inputAddresses: string[] = [];
            let totalInputValue = 0; // Track input value for fee calculation

            if (txDetails.vin) {
                for (const input of txDetails.vin) {
                    // Skip coinbase transactions (no previous output)
                    if (input.coinbase) {
                        continue;
                    }

                    // Track input value when available
                    if (input.value) {
                        totalInputValue += Math.round(parseFloat(input.value.toString()) * 100000000);
                    }

                    // Check if input has an address field directly (some ElectrumX servers provide this)
                    if (input.address) {
                        inputAddresses.push(input.address);
                        if (input.address === address) {
                            inputFromCurrentAddress = true;
                        }
                    }
                    // Also check scriptSig.addresses for legacy format
                    else if (input.scriptSig && input.scriptSig.addresses) {
                        for (const inputAddress of input.scriptSig.addresses) {
                            inputAddresses.push(inputAddress);
                            if (inputAddress === address) {
                                inputFromCurrentAddress = true;
                            }
                        }
                    }
                    // If no direct address, we need to look up the previous transaction output
                    else if (input.txid && input.vout !== undefined) {
                        try {
                            const prevTxDetails = await this.getTransactionCached(input.txid, cache);
                            if (prevTxDetails && prevTxDetails.vout && prevTxDetails.vout[input.vout]) {
                                const prevOutput = prevTxDetails.vout[input.vout];

                                // Track input value from previous transaction
                                if (prevOutput.value) {
                                    totalInputValue += Math.round(
                                        parseFloat(prevOutput.value.toString()) * 100000000,
                                    );
                                }

                                if (prevOutput.scriptPubKey) {
                                    for (const inputAddress of this.scriptPubKeyToAddresses(prevOutput.scriptPubKey)) {
                                        inputAddresses.push(inputAddress);
                                        if (inputAddress === address) {
                                            inputFromCurrentAddress = true;
                                        }
                                    }
                                }
                            }
                        } catch (prevTxError) {
                            walletLogger.warn(
                                `Failed to get previous transaction ${input.txid} for input analysis:`,
                                prevTxError,
                            );
                        }
                    }
                }
            }

            // Check if we have outputs (receiving to our address)
            let hasOutputToCurrentAddress = false;
            let totalOutputToCurrentAddress = 0;
            let totalOutputToOthers = 0;
            let totalOutputValue = 0; // Track total output for fee calculation
            const outputsToOthers: Array<{ address: string; value: number }> = [];
            // Outputs paying another wallet this user owns. These still leave the address being
            // analysed, so from its point of view they are money sent, not change.
            let totalOutputToOwnedElsewhere = 0;
            const outputsToOwnedElsewhere: Array<{ address: string; value: number }> = [];

            if (txDetails.vout) {
                for (let i = 0; i < txDetails.vout.length; i++) {
                    const output = txDetails.vout[i];
                    if (output.scriptPubKey) {
                        const outputAddresses = this.scriptPubKeyToAddresses(output.scriptPubKey);
                        if (outputAddresses.length === 0) continue;

                        // Handle both number and string values for output.value
                        const outputValue = Math.round(parseFloat(output.value.toString()) * 100000000); // Convert to satoshis
                        totalOutputValue += outputValue;

                        // Check if this output goes to our address or any of our addresses
                        let isOurOutput = false;
                        let isTargetAddress = false;
                        for (const outputAddr of outputAddresses) {
                            if (outputAddr === address) {
                                isTargetAddress = true;
                                isOurOutput = true;
                                break;
                            } else {
                                const isOurAddr = await this.isOurAddress(outputAddr);
                                if (isOurAddr) {
                                    isOurOutput = true;
                                    break;
                                }
                            }
                        }

                        if (isTargetAddress) {
                            // This output comes back to the address we're analyzing — change, or
                            // a consolidation. It never counts as money sent.
                            hasOutputToCurrentAddress = true;
                            totalOutputToCurrentAddress += outputValue;
                        } else if (isOurOutput) {
                            // This output pays another wallet the user owns. The funds still left
                            // this address, so it is a send from here and a receive over there.
                            totalOutputToOwnedElsewhere += outputValue;
                            outputsToOwnedElsewhere.push({
                                address: outputAddresses[0],
                                value: outputValue,
                            });
                        } else {
                            // This output goes to an external address
                            totalOutputToOthers += outputValue;

                            // Store all outputs to external addresses
                            outputsToOthers.push({
                                address: outputAddresses[0],
                                value: outputValue,
                            });
                        }
                    }
                }
            }

            // Calculate the transaction fee if we have all input values
            const fee = totalInputValue > 0 ? totalInputValue - totalOutputValue : 0;

            // Everything that left this address, whether it went to a stranger or to another
            // wallet the same user owns. Change coming back here is deliberately excluded.
            const outputsLeavingAddress = [...outputsToOthers, ...outputsToOwnedElsewhere];
            const totalOutputLeavingAddress = totalOutputToOthers + totalOutputToOwnedElsewhere;

            // Handle special case where we're checking a specific address
            if (!inputFromCurrentAddress && hasOutputToCurrentAddress) {
                // If we're analyzing a specific address that received funds but didn't spend any,
                // this is a receive transaction for this address

                // Prefer naming another of the user's own wallets as the sender when one funded
                // this transaction, so an internal transfer reads as coming from that wallet.
                let senderAddress = '';

                if (inputAddresses.length > 0) {
                    for (const inputAddr of inputAddresses) {
                        if (await this.isOurAddress(inputAddr)) {
                            senderAddress = inputAddr;
                            break;
                        }
                    }

                    // If no specific sender found, use the first input
                    if (!senderAddress) {
                        senderAddress = inputAddresses[0];
                    }
                } else {
                    senderAddress = this.getSenderAddress(txDetails);
                }

                return {
                    type: 'receive',
                    amount: totalOutputToCurrentAddress,
                    fromAddress: senderAddress,
                    toAddress: address,
                };
            }

            // Classify the transaction
            if (inputFromCurrentAddress) {
                // This address is spending funds
                if (totalOutputLeavingAddress > 0) {
                    // Where several recipients were paid, report the largest as the primary one.
                    // A single recipient is just the degenerate case of the same rule.
                    let largestOutput = outputsLeavingAddress[0];
                    for (const output of outputsLeavingAddress) {
                        if (output.value > largestOutput.value) {
                            largestOutput = output;
                        }
                    }

                    return {
                        type: 'send',
                        amount: totalOutputLeavingAddress, // Total sent to all recipients
                        fromAddress: address,
                        toAddress: largestOutput?.address || 'Unknown',
                    };
                } else if (hasOutputToCurrentAddress) {
                    // This is a self-transfer (consolidation to the same wallet)
                    return {
                        type: 'receive', // We display self-transfers as receives
                        amount: totalOutputToCurrentAddress,
                        fromAddress: address, // It's from ourselves
                        toAddress: address, // To ourselves
                    };
                } else if (fee > 0 && totalOutputValue === 0) {
                    // This might be a burn transaction or fee-only transaction
                    return {
                        type: 'send',
                        amount: fee, // Use the fee as the amount
                        fromAddress: address,
                        toAddress: 'Fee/Burn',
                    };
                }
            } else if (hasOutputToCurrentAddress) {
                // This is a receive transaction to this address
                const senderAddress =
                    inputAddresses.length > 0 ? inputAddresses[0] : this.getSenderAddress(txDetails);
                return {
                    type: 'receive',
                    amount: totalOutputToCurrentAddress,
                    fromAddress: senderAddress,
                    toAddress: address,
                };
            }

            // Transaction doesn't involve our address meaningfully
            return null;
        } catch (error) {
            walletLogger.error('Error classifying transaction:', error);
            return null;
        }
    }

    // Custom DER encoding method that supports Avian's fork ID
    private encodeDERWithCustomHashType(signature: Buffer, hashType: number): Buffer {
        // If signature is 64 bytes (r + s), convert to DER format
        if (signature.length === 64) {
            const r = signature.subarray(0, 32);
            const s = signature.subarray(32, 64);

            // Create DER encoded signature
            const derSig = this.toDERFormat(r, s);

            // Append hash type (this bypasses bitcoinjs-lib validation)
            // Ensure hashType is 0x41 (SIGHASH_ALL | SIGHASH_FORKID) for Avian network
            const result = Buffer.concat([derSig, Buffer.from([hashType & 0xff])]);
            return result;
        } else {
            // If it's already DER encoded, just append hash type
            const result = Buffer.concat([signature, Buffer.from([hashType & 0xff])]);
            return result;
        }
    }

    private toDERFormat(r: Buffer, s: Buffer): Buffer {
        const rClean = this.removeLeadingZeros(r);
        const sClean = this.removeLeadingZeros(s);

        // If first byte is >= 0x80, prepend 0x00 to indicate positive number
        const rWithPadding = rClean[0] >= 0x80 ? Buffer.concat([Buffer.from([0x00]), rClean]) : rClean;
        const sWithPadding = sClean[0] >= 0x80 ? Buffer.concat([Buffer.from([0x00]), sClean]) : sClean;

        // Build DER structure: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
        const rPart = Buffer.concat([Buffer.from([0x02, rWithPadding.length]), rWithPadding]);
        const sPart = Buffer.concat([Buffer.from([0x02, sWithPadding.length]), sWithPadding]);

        const content = Buffer.concat([rPart, sPart]);
        return Buffer.concat([Buffer.from([0x30, content.length]), content]);
    }

    private removeLeadingZeros(buffer: Buffer): Buffer {
        let start = 0;
        while (start < buffer.length - 1 && buffer[start] === 0) {
            start++;
        }
        return buffer.subarray(start);
    }

    private async isOurAddress(address: string): Promise<boolean> {
        try {
            const wallets = await StorageService.getAllWallets();
            return wallets.some((wallet: WalletData) => wallet.address === address);
        } catch (error) {
            walletLogger.error('Error checking if address belongs to our wallets:', error);
            return false;
        }
    }

    /**
     * Clean up misclassified transactions in the database.
     * This removes "receive" transactions that are actually change outputs from our own sent transactions.
     */
    async cleanupMisclassifiedTransactions(address?: string): Promise<number> {
        try {
            let targetAddress = address;
            if (!targetAddress) {
                const activeWallet = await this.getActiveWallet();
                if (!activeWallet) {
                    walletLogger.warn('No active wallet found for cleanup');
                    return 0;
                }
                targetAddress = activeWallet.address;
            }

            const existingTxs = await StorageService.getTransactionHistory(targetAddress);
            const sentTxIds = new Set(
                existingTxs.filter((tx) => tx.type === 'send').map((tx) => tx.txid),
            );

            // Find received transactions that are actually change from sent transactions
            const misclassifiedTxs = existingTxs.filter(
                (tx) => tx.type === 'receive' && sentTxIds.has(tx.txid),
            );

            // Remove misclassified transactions
            for (const tx of misclassifiedTxs) {
                await StorageService.removeTransaction(tx.txid, targetAddress);
            }

            return misclassifiedTxs.length;
        } catch (error) {
            walletLogger.error('Error cleaning up misclassified transactions:', error);
            return 0;
        }
    }

    /**
     * Reprocess transaction history for an address
     * @param address - Optional wallet address, will use active wallet if not provided
     * @param onProgress - Optional progress callback (currently unused in implementation)
     * @param onBalanceUpdate - Optional balance update callback (currently unused in implementation)
     * @returns The number of transactions updated
     */
    async reprocessTransactionHistory(
        address?: string,
        onProgress?: (processed: number, total: number, currentTx?: string) => void,
        onBalanceUpdate?: (newBalance: number) => void,
    ): Promise<number> {
        try {
            // If no address provided, use the active wallet's address
            if (!address) {
                const activeWallet = await this.getActiveWallet();
                if (activeWallet) {
                    address = activeWallet.address;
                }
            }

            if (!address) {
                walletLogger.warn('No address available to reprocess transaction history');
                return 0;
            }

            // Get transaction history from ElectrumX
            const txHistory = await this.electrum.getTransactionHistory(address);

            if (!txHistory || txHistory.length === 0) {
                return 0;
            }

            // Get existing transactions from local storage
            const existingTxs = await StorageService.getTransactionHistory(address);
            const existingTxMap = new Map(existingTxs.map((tx) => [tx.txid, tx]));

            let updatedCount = 0;
            let processedCount = 0;
            const total = txHistory.length;

            // Report initial progress
            onProgress?.(processedCount, total);

            // Process each transaction from history
            for (const historyTx of txHistory) {
                try {
                    // Get detailed transaction data
                    const txDetails = await this.electrum.getTransaction(historyTx.tx_hash, true);

                    if (!txDetails) {
                        continue;
                    }

                    // Reclassify the transaction
                    const classification = await this.classifyTransaction(txDetails, address);
                    if (!classification) {
                        continue;
                    }

                    // Calculate proper confirmations
                    const confirmations = await this.calculateConfirmations(historyTx.height);

                    // Create the updated transaction object
                    const updatedTx = {
                        txid: historyTx.tx_hash,
                        amount: classification.amount / 100000000, // Convert satoshis to AVN
                        address: classification.toAddress,
                        fromAddress: classification.fromAddress,
                        walletAddress: address, // Add wallet address for proper multi-wallet support
                        type: classification.type,
                        timestamp: new Date(txDetails.time ? txDetails.time * 1000 : Date.now()),
                        confirmations: confirmations,
                        blockHeight: historyTx.height || undefined,
                    };

                    // Check if this transaction exists and needs updating
                    const existingTx = existingTxMap.get(historyTx.tx_hash);

                    if (existingTx) {
                        // Check if any fields need updating
                        const needsUpdate =
                            existingTx.type !== updatedTx.type ||
                            existingTx.amount !== updatedTx.amount ||
                            existingTx.address !== updatedTx.address ||
                            existingTx.fromAddress !== updatedTx.fromAddress;

                        if (needsUpdate) {
                            // Update the transaction
                            await StorageService.saveTransaction(updatedTx);
                            updatedCount++;
                        }
                    } else {
                        // This is a new transaction, save it
                        await StorageService.saveTransaction(updatedTx);
                        updatedCount++;
                    }

                    // Update balance periodically
                    if ((processedCount % 5 === 0 || processedCount === total - 1) && onBalanceUpdate) {
                        const currentBalance = await this.getBalance(address);
                        onBalanceUpdate(currentBalance);
                    }

                    processedCount++;
                    onProgress?.(processedCount, total, historyTx.tx_hash);
                } catch (error) {
                    walletLogger.error(`Error reprocessing transaction ${historyTx.tx_hash}:`, error);
                    processedCount++;
                    onProgress?.(processedCount, total, historyTx.tx_hash);
                }
            } // Report final progress
            onProgress?.(processedCount, total);

            // Final balance update
            if (onBalanceUpdate) {
                const finalBalance = await this.getBalance(address);
                onBalanceUpdate(finalBalance);
            }

            return updatedCount;
        } catch (error) {
            walletLogger.error('Error reprocessing transaction history:', error);
            return 0;
        }
    }

    /**
     * Progressively reprocesses transaction history for an address one transaction at a time,
     * allowing for more interactive UI updates.
     *
     * @param address The wallet address to reprocess transactions for
     * @param onProgress Callback to report progress and new transaction data
     * @param onBalanceUpdate Optional callback to report balance updates
     * @returns The number of transactions that were processed
     */
    async reprocessTransactionHistoryProgressive(
        address?: string,
        onProgress?: (
            processed: number,
            total: number,
            currentTx?: string,
            newTransaction?: any,
        ) => void,
        onBalanceUpdate?: (newBalance: number) => void,
    ): Promise<number> {
        try {
            // If no address provided, use the active wallet's address
            if (!address) {
                const activeWallet = await this.getActiveWallet();
                if (activeWallet) {
                    address = activeWallet.address;
                }
            }

            if (!address) {
                walletLogger.warn('No address available to reprocess transaction history');
                return 0;
            }

            // Get transaction history from ElectrumX
            const txHistory = await this.electrum.getTransactionHistory(address);

            if (!txHistory || txHistory.length === 0) {
                return 0;
            }

            // Get existing transactions from local storage
            const existingTxs = await StorageService.getTransactionHistory(address);
            const existingTxMap = new Map(existingTxs.map((tx) => [`${tx.txid}-${tx.type}`, tx]));

            let processedCount = 0;
            const total = txHistory.length;

            // Report initial progress
            onProgress?.(processedCount, total);

            // Process each transaction one at a time
            for (const historyTx of txHistory) {
                try {
                    // Get detailed transaction data
                    const txDetails = await this.electrum.getTransaction(historyTx.tx_hash, true);
                    if (!txDetails) {
                        processedCount++;
                        onProgress?.(processedCount, total, historyTx.tx_hash);
                        continue;
                    }

                    // Reclassify the transaction
                    const classification = await this.classifyTransaction(txDetails, address);
                    if (!classification) {
                        processedCount++;
                        onProgress?.(processedCount, total, historyTx.tx_hash);
                        continue;
                    }

                    // Calculate proper confirmations
                    const confirmations = await this.calculateConfirmations(historyTx.height);

                    // Create the updated transaction object
                    const updatedTx = {
                        txid: historyTx.tx_hash,
                        amount: classification.amount / 100000000, // Convert satoshis to AVN
                        address: classification.toAddress,
                        fromAddress: classification.fromAddress,
                        walletAddress: address, // Add wallet address for proper multi-wallet support
                        type: classification.type,
                        timestamp: new Date(txDetails.time ? txDetails.time * 1000 : Date.now()),
                        confirmations: confirmations,
                        blockHeight: historyTx.height || undefined,
                    };

                    // Check if this transaction exists and needs updating
                    const existingTx = existingTxMap.get(`${historyTx.tx_hash}-${classification.type}`);
                    let isUpdated = false;

                    if (existingTx) {
                        // Check if any fields need updating
                        const needsUpdate =
                            existingTx.type !== updatedTx.type ||
                            existingTx.amount !== updatedTx.amount ||
                            existingTx.address !== updatedTx.address ||
                            existingTx.fromAddress !== updatedTx.fromAddress ||
                            existingTx.confirmations !== updatedTx.confirmations ||
                            !existingTx.walletAddress; // Always update if walletAddress is missing

                        if (needsUpdate) {
                            // Update the transaction with existing ID
                            const txWithId = { ...updatedTx } as any;
                            txWithId.id = existingTx.id;
                            await StorageService.saveTransaction(txWithId);
                            isUpdated = true;
                        }
                    } else {
                        // This is a new transaction, save it
                        await StorageService.saveTransaction(updatedTx);
                        isUpdated = true;
                    }

                    // For self-transfers, also check and update the opposite transaction type
                    const oppositeType = classification.type === 'send' ? 'receive' : 'send';
                    const existingOppositeTx = existingTxMap.get(`${historyTx.tx_hash}-${oppositeType}`);

                    if (existingOppositeTx) {
                        // Check if this is a self-transfer by comparing addresses
                        const isSelfTransfer =
                            (classification.type === 'send' &&
                                existingOppositeTx.type === 'receive' &&
                                existingOppositeTx.fromAddress === classification.toAddress) ||
                            (classification.type === 'receive' &&
                                existingOppositeTx.type === 'send' &&
                                existingOppositeTx.address === classification.fromAddress);

                        if (isSelfTransfer) {
                            // Update the opposite transaction's confirmations to match
                            const needsOppositeUpdate = existingOppositeTx.confirmations !== confirmations;

                            if (needsOppositeUpdate) {
                                const oppositeUpdatedTx = {
                                    ...existingOppositeTx,
                                    confirmations: confirmations,
                                    blockHeight: historyTx.height || existingOppositeTx.blockHeight,
                                };

                                await StorageService.saveTransaction(oppositeUpdatedTx);
                                isUpdated = true;
                            }
                        }
                    }

                    // Update balance periodically
                    if ((processedCount % 5 === 0 || processedCount === total - 1) && onBalanceUpdate) {
                        const currentBalance = await this.getBalance(address);
                        onBalanceUpdate(currentBalance);
                    }

                    processedCount++;

                    // Call progress callback with transaction data if it was updated
                    if (isUpdated) {
                        onProgress?.(processedCount, total, historyTx.tx_hash, updatedTx);
                    } else {
                        onProgress?.(processedCount, total, historyTx.tx_hash);
                    }
                } catch (error) {
                    walletLogger.error(`Error reprocessing transaction ${historyTx.tx_hash}:`, error);
                    processedCount++;
                    onProgress?.(processedCount, total, historyTx.tx_hash);
                }

                // Small delay to allow UI to update
                await new Promise((resolve) => setTimeout(resolve, 10));
            }

            // Final balance update
            if (onBalanceUpdate) {
                const finalBalance = await this.getBalance(address);
                onBalanceUpdate(finalBalance);
            }

            // Report final progress
            onProgress?.(processedCount, total);

            return processedCount;
        } catch (error) {
            walletLogger.error('Error progressively reprocessing transaction history:', error);
            return 0;
        }
    }

    /**
     * Derives multiple addresses from a given mnemonic phrase and checks their balances
     * Static method that can be used without an initialized wallet
     */
    static async deriveAddressesWithBalances(
        mnemonic: string,
        passphrase?: string,
        accountIndex: number = 0,
        addressCount: number = 10,
        addressType: AddressType | string = 'p2pkh',
        changePath: number = 0, // 0 for receiving addresses, 1 for change addresses
        coinType: number = 921, // 921 for Avian, 175 for Ravencoin compatibility
    ): Promise<Array<{ path: string; address: string; balance: number; hasTransactions: boolean }>> {
        // Validate mnemonic
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid BIP39 mnemonic phrase');
        }

        // Normalise addressType to a known AddressType (default p2pkh for unrecognised values)
        const resolvedType: AddressType =
            addressType === 'p2wpkh' || addressType === 'p2sh-p2wpkh'
                ? (addressType as AddressType)
                : 'p2pkh';
        const purpose = purposeForAddressType(resolvedType);

        try {
            // Create ElectrumService instance for balance checking
            const electrum = new ElectrumService();

            // Connect to Electrum server if not already connected
            if (!electrum.isConnectedToServer()) {
                await electrum.connect();
            }

            // Derive seed from mnemonic with optional passphrase (BIP39 25th word)
            const seed = await bip39.mnemonicToSeed(mnemonic, passphrase || '');

            // Create HD wallet root
            const root = bip32.fromSeed(seed, avianNetwork);

            // Array to store derived addresses with balances
            const derivedAddresses: Array<{
                path: string;
                address: string;
                balance: number;
                hasTransactions: boolean;
            }> = [];

            // Generate addresses for the selected address type.
            // BIP44: m/44'/coinType'/account'/change/index (P2PKH)
            // BIP49: m/49'/coinType'/account'/change/index (P2SH-P2WPKH)
            // BIP84: m/84'/coinType'/account'/change/index (P2WPKH / native SegWit)
            for (let i = 0; i < addressCount; i++) {
                const path = `m/${purpose}'/${coinType}'/${accountIndex}'/${changePath}/${i}`;
                const child = root.derivePath(path);

                if (!child.privateKey) {
                    throw new Error(`Failed to derive private key for path ${path}`);
                }

                const keyPair = ECPair.fromPrivateKey(child.privateKey, { network: avianNetwork });
                const address = deriveAddress(Buffer.from(keyPair.publicKey), resolvedType);

                if (!address) {
                    throw new Error(`Failed to generate address for path ${path}`);
                }

                // Check balance and history for the address
                const balance = await electrum.getBalance(address);
                const history = await electrum.getTransactionHistory(address);
                const hasTransactions = history.length > 0;

                derivedAddresses.push({
                    path,
                    address,
                    balance,
                    hasTransactions,
                });
            }

            return derivedAddresses;
        } catch (error) {
            walletLogger.error('Error deriving addresses with balances:', error);
            throw new Error('Failed to derive addresses with balances');
        }
    }

    /**
     * Derives multiple addresses from the current wallet's mnemonic phrase and checks their balances
     * Requires wallet password to decrypt the mnemonic
     */
    async deriveCurrentWalletAddresses(
        password: string,
        accountIndex: number = 0,
        addressCount: number = 10,
        addressType?: string,
        changePath: number = 0, // 0 for receiving addresses, 1 for change addresses
    ): Promise<Array<{ path: string; address: string; balance: number; hasTransactions: boolean }>> {
        try {
            // Get the current wallet to retrieve its coin type
            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) {
                throw new Error('No active wallet found');
            }

            // Callers that don't specify a type get the wallet's own script type —
            // deriving p2pkh for a wpkh wallet would scan addresses it doesn't own
            const resolvedAddressType = addressType || activeWallet.addressType || 'p2pkh';

            // Use the wallet's stored coin type, defaulting to 921 for legacy wallets
            const coinType = activeWallet.coinType || 921;

            // ── xprv-based wallet (imported from descriptor) ──────────────────
            if (activeWallet.xprv && !activeWallet.mnemonic) {
                const isEncryptedXprv = await StorageService.getIsEncrypted();
                let decryptedXprv: string;

                if (isEncryptedXprv) {
                    try {
                        const { decrypted } = await decryptData(activeWallet.xprv, password);
                        decryptedXprv = decrypted;
                    } catch {
                        throw new Error('Invalid password or corrupted xprv');
                    }
                } else {
                    decryptedXprv = activeWallet.xprv;
                }

                const accountNode = bip32.fromBase58(decryptedXprv, avianNetwork);
                const resolvedType = resolvedAddressType as AddressType;
                const purpose = purposeForAddressType(resolvedType);

                const result: Array<{ path: string; address: string; balance: number; hasTransactions: boolean }> = [];
                const electrum = this.electrum;
                const changeNode = accountNode.derive(changePath);

                for (let i = 0; i < addressCount; i++) {
                    const childNode = changeNode.derive(i);
                    if (!childNode.privateKey) throw new Error(`Failed to derive key at ${changePath}/${i}`);
                    const kp = ECPair.fromPrivateKey(Buffer.from(childNode.privateKey), { network: avianNetwork });
                    const addr = deriveAddress(Buffer.from(kp.publicKey), resolvedType as AddressType);

                    const descriptivePath = `m/${purpose}'/${coinType}'/${accountIndex}'/${changePath}/${i}`;
                    const balance = await electrum.getBalance(addr);
                    const history = await electrum.getTransactionHistory(addr);

                    result.push({ path: descriptivePath, address: addr, balance, hasTransactions: history.length > 0 });
                }
                return result;
            }

            // ── mnemonic-based wallet ─────────────────────────────────────────
            const storedMnemonic = await StorageService.getMnemonic();
            if (!storedMnemonic) {
                throw new Error('No mnemonic stored for this wallet. Address derivation is not available.');
            }

            const isEncrypted = await StorageService.getIsEncrypted();
            let decryptedMnemonic: string;

            if (isEncrypted) {
                try {
                    const { decrypted } = await decryptData(storedMnemonic, password);
                    decryptedMnemonic = decrypted;
                    if (!decryptedMnemonic) {
                        throw new Error('Failed to decrypt mnemonic');
                    }

                    // Validate the decrypted mnemonic
                    if (!bip39.validateMnemonic(decryptedMnemonic)) {
                        throw new Error('Decrypted mnemonic is invalid');
                    }
                } catch (error) {
                    throw new Error('Invalid password or corrupted mnemonic');
                }
            } else {
                decryptedMnemonic = storedMnemonic;
            }

            // Decrypt the stored passphrase if it exists
            let decryptedPassphrase: string | undefined;
            if (activeWallet.bip39Passphrase && isEncrypted) {
                try {
                    const { decrypted } = await decryptData(activeWallet.bip39Passphrase, password);
                    decryptedPassphrase = decrypted;
                } catch (error) {
                    throw new Error('Invalid password or corrupted passphrase');
                }
            } else if (activeWallet.bip39Passphrase && !isEncrypted) {
                // If wallet is not encrypted but has a passphrase, use it directly
                decryptedPassphrase = activeWallet.bip39Passphrase;
            }

            // Use the static method to derive addresses
            return WalletService.deriveAddressesWithBalances(
                decryptedMnemonic,
                decryptedPassphrase, // Use the decrypted passphrase from wallet
                accountIndex,
                addressCount,
                resolvedAddressType,
                changePath,
                coinType,
            );
        } catch (error) {
            walletLogger.error('Error deriving addresses from current wallet:', error);
            throw error;
        }
    }
    /**
     * Sign a message with the private key of the given wallet address
     * @param privateKeyWIF - The WIF private key to sign the message with (may be encrypted)
     * @param message - The message to sign
     * @param password - Optional password for decrypting an encrypted private key
     * @returns The signature as a base64 string
     */
    async signMessage(privateKeyWIF: string, message: string, password?: string): Promise<string> {
        try {
            let decryptedKey = privateKeyWIF;

            // Helper function to check if a string is a valid WIF private key

            // Check if the private key is encrypted by trying to parse it as WIF first
            if (!isValidWIF(privateKeyWIF)) {
                // This doesn't look like a valid WIF key, it's likely encrypted
                if (!password) {
                    throw new Error('This private key is encrypted. Password is required for signing.');
                }

                try {
                    // Attempt to decrypt with the provided password
                    const { decrypted } = await decryptData(privateKeyWIF, password);
                    decryptedKey = decrypted;
                    if (!decryptedKey) {
                        throw new Error('Failed to decrypt private key');
                    }

                    // Validate the decrypted key is a valid WIF
                    if (!isValidWIF(decryptedKey)) {
                        throw new Error('Decrypted data is not a valid WIF private key');
                    }
                } catch (decryptError) {
                    walletLogger.error('Error decrypting private key:', decryptError);
                    throw new Error('Invalid password or corrupted private key');
                }
            }

            // Now use the (potentially decrypted) key to create the ECPair
            const ECPair = ECPairFactory(ecc);
            const keyPair = ECPair.fromWIF(decryptedKey, avianNetwork);

            if (!keyPair.privateKey) {
                throw new Error('Private key is undefined');
            }

            // Sign the message
            const signature = bitcoinMessage.sign(
                message,
                Buffer.from(keyPair.privateKey),
                keyPair.compressed,
                avianNetwork.messagePrefix,
            );

            // Base64-encode for transport/storage
            const signatureB64 = signature.toString('base64');

            return signatureB64;
        } catch (error) {
            walletLogger.error('Failed to sign message:', error);
            throw new Error(
                `Failed to sign message: ${error instanceof Error ? error.message : 'Unknown error'}`,
            );
        }
    }

    /**
     * Verify a signed message
     * @param address - The Avian address that supposedly signed the message
     * @param message - The original message
     * @param signature - The signature as a base64 string
     * @returns True if the signature is valid, false otherwise
     */
    async verifyMessage(
        address: string,
        message: string,
        signature: string,
        returnPublicKey: boolean = false,
    ): Promise<boolean | { isValid: boolean; publicKey?: string }> {
        try {
            const isValid = bitcoinMessage.verify(
                message,
                address,
                signature,
                avianNetwork.messagePrefix, // Use the network's message prefix
                false,
            );

            if (returnPublicKey && isValid) {
                try {
                    // Recover the public key from the message and signature
                    const recoveredPubKeyRaw = recoverPubKey(message, signature);

                    if (recoveredPubKeyRaw === null) {
                        return { isValid: true }; // Public key couldn't be retrieved
                    }

                    // Convert to hex format
                    const publicKey = Buffer.from(recoveredPubKeyRaw).toString('hex');

                    // You can optionally validate here if this matches your expected public key
                    // by comparing it with a known key from your wallet

                    return {
                        isValid: true,
                        publicKey,
                    };
                } catch (pubKeyError) {
                    walletLogger.error('Failed to get public key for address:', pubKeyError);
                    return { isValid: true };
                }
            }

            return returnPublicKey ? { isValid } : isValid;
        } catch (error) {
            walletLogger.error('Failed to verify message:', error);
            return returnPublicKey ? { isValid: false } : false;
        }
    }

    /**
     * Encrypt a message for a specific public key
     * @param recipientPublicKey - The recipient's public key in hex format
     * @param message - The message to encrypt
     * @returns The encrypted message as a base64 string
     */
    async encryptMessage(recipientPublicKey: string, message: string): Promise<string> {
        try {
            // Use the public key directly
            const P = Buffer.from(recipientPublicKey, 'hex');
            const r = randomBytes(32); // ephemeral priv
            const R = ecc.pointFromScalar(r, true)!; // 33-byte ephemeral pub
            // Ensure r is treated as a regular Uint8Array for pointMultiply
            const S = ecc.pointMultiply(P, Buffer.from(r))!; // ECDH shared
            const sharedPoint = Buffer.from(S); // Convert to Buffer for consistent handling

            // KDF: SHA-512(S)
            const K = createHash('sha512').update(sharedPoint).digest();
            const iv = K.subarray(0, 16); // 16-byte IV
            const keyE = K.subarray(16, 32); // 16-byte AES key (AES-128)
            const keyM = K.subarray(32); // remaining 32 bytes for HMAC

            // AES-128-CBC
            const cipher = createCipheriv('aes-128-cbc', keyE, iv);
            const C = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);

            // Create the entire message without MAC
            const messageWithoutMac = Buffer.concat([ECIES_PREFIX, R, C]);

            // HMAC-SHA256 over the entire message without MAC
            const mac = createHmac('sha256', keyM).update(messageWithoutMac).digest();

            // Final envelope: magic ∥ R ∥ C ∥ mac, base64-encoded
            return Buffer.concat([messageWithoutMac, mac]).toString('base64');
        } catch (error) {
            walletLogger.error('Failed to encrypt message:', error);
            throw error;
        }
    }

    /**
     * Decrypt a message that was encrypted for you
     * @param recipientPrivateKeyWIF - The recipient's private key in WIF format (may be encrypted)
     * @param encryptedMessage - The encrypted message to decrypt
     * @param password - Optional password for decrypting an encrypted private key
     * @returns The decrypted message
     */
    async decryptMessage(
        recipientPrivateKeyWIF: string,
        encryptedMessage: string,
        password?: string,
    ): Promise<string> {
        try {
            // First, decrypt the recipient's private key if necessary
            let decryptedKey = recipientPrivateKeyWIF;

            // Helper function to check if a string is a valid WIF private key

            // Check if the private key is encrypted by trying to parse it as WIF first
            if (!isValidWIF(recipientPrivateKeyWIF)) {
                // This doesn't look like a valid WIF key, it's likely encrypted
                if (!password) {
                    throw new Error('This private key is encrypted. Password is required for decryption.');
                }

                try {
                    // Attempt to decrypt with the provided password
                    const { decrypted } = await decryptData(recipientPrivateKeyWIF, password);
                    decryptedKey = decrypted;
                    if (!decryptedKey) {
                        throw new Error('Failed to decrypt private key');
                    }

                    // Validate the decrypted key is a valid WIF
                    if (!isValidWIF(decryptedKey)) {
                        throw new Error('Decrypted data is not a valid WIF private key');
                    }
                } catch (decryptError) {
                    walletLogger.error('Error decrypting private key:', decryptError);
                    throw new Error('Invalid password or corrupted private key');
                }
            }

            // Debug: show base64 input
            const buf = Buffer.from(encryptedMessage, 'base64');

            // Verify the message has the correct prefix
            if (!buf.subarray(0, 4).equals(ECIES_PREFIX)) throw new Error('Bad prefix');

            // Verify minimal required length
            const minLength = 4 + 33 + 16 + 32; // prefix + R + minimum ciphertext + MAC
            if (buf.length < minLength) {
                throw new Error(
                    `Message too short (${buf.length} bytes), minimum required length is ${minLength} bytes`,
                );
            }

            // Extract the ephemeral public key R from the encrypted message
            // First 4 bytes are the magic bytes (format identifier) - skipping as not needed
            const R = buf.subarray(4, 4 + 33); // next 33 bytes
            const cipherTextWithMac = buf.subarray(4 + 33); // C ∥ mac
            const mac = cipherTextWithMac.subarray(cipherTextWithMac.length - 32); // last 32 bytes
            const C = cipherTextWithMac.subarray(0, cipherTextWithMac.length - 32); // the ciphertext

            // ECDH using the ephemeral public key R and recipient's private key
            const ECPair = ECPairFactory(ecc);
            const recipientKeyPair = ECPair.fromWIF(decryptedKey, avianNetwork);
            if (!recipientKeyPair.privateKey) {
                throw new Error('Private key is undefined');
            }

            const d = recipientKeyPair.privateKey;
            // Ensure private key is treated as a regular Uint8Array for pointMultiply
            const privateKeyBytes = Buffer.from(d);
            const S = ecc.pointMultiply(R, privateKeyBytes)!;
            const sharedPoint = Buffer.from(S);

            // KDF: SHA-512(S)
            const K = createHash('sha512').update(sharedPoint).digest();
            const iv = Buffer.alloc(16);
            K.copy(iv, 0, 0, 16);
            const keyE = K.subarray(16, 32); // 16-byte AES key (AES-128)
            const keyM = K.subarray(32); // remaining 32 bytes for HMAC

            // verify HMAC - reconstruct the same data that was used in encryption
            // HMAC is calculated over the entire message except the MAC itself
            const preMac = buf.subarray(0, buf.length - 32); // All data up to but not including the MAC
            const mac2 = createHmac('sha256', keyM).update(preMac).digest();

            // Compare MACs
            if (!mac.equals(mac2)) {
                throw new Error('MAC mismatch');
            }

            // decrypt AES-128-CBC
            const decipher = createDecipheriv('aes-128-cbc', keyE, iv);
            const pt = Buffer.concat([decipher.update(C), decipher.final()]);
            return pt.toString('utf8');
        } catch (error) {
            walletLogger.error('Failed to decrypt message:', error);
            throw error;
        }
    }

    /**
     * Send a transaction from a specific derived address
     * @param toAddress - The recipient's address
     * @param amount - Amount to send in satoshis
     * @param password - The wallet's encryption password
     * @param derivationPath - The BIP32 derivation path (e.g., "m/44'/921'/0'/0/1")
     * @param options - Optional settings for transaction creation
     * @returns Transaction ID
     */
    async sendFromDerivedAddress(
        toAddress: string,
        amount: number,
        password: string,
        derivationPath: string,
        options?: {
            strategy?: CoinSelectionStrategy;
            feeRate?: number;
            maxInputs?: number;
            minConfirmations?: number;
            changeAddress?: string; // Custom change address for HD wallets
            subtractFeeFromAmount?: boolean; // Whether to subtract fee from the send amount
        },
    ): Promise<string> {
        try {
            // Get current wallet data
            const activeWallet = await StorageService.getActiveWallet();
            if (!activeWallet) {
                throw new Error('No active wallet found');
            }

            // Check if wallet has a mnemonic (required for derivation)
            const storedMnemonic = await StorageService.getMnemonic();
            if (!storedMnemonic) {
                throw new Error('No mnemonic stored for this wallet. HD functionality is not available.');
            }

            // Decrypt mnemonic if encrypted
            let decryptedMnemonic: string;
            if (activeWallet.isEncrypted) {
                try {
                    const { decrypted } = await decryptData(storedMnemonic, password);
                    decryptedMnemonic = decrypted;
                    if (!decryptedMnemonic) {
                        throw new Error('Invalid password');
                    }

                    // Validate the decrypted mnemonic
                    if (!bip39.validateMnemonic(decryptedMnemonic)) {
                        throw new Error('Invalid mnemonic');
                    }
                } catch (error) {
                    throw new Error('Invalid password or corrupted mnemonic');
                }
            } else {
                decryptedMnemonic = storedMnemonic;
            }

            // Derive the private key for the specified path
            const seed = await bip39.mnemonicToSeed(decryptedMnemonic);
            const root = bip32.fromSeed(seed, avianNetwork);

            // Remove 'm/' prefix if present in the path
            const cleanPath = derivationPath.startsWith('m/')
                ? derivationPath.substring(2)
                : derivationPath;

            const child = root.derivePath(cleanPath);

            if (!child.privateKey) {
                throw new Error(`Failed to derive private key for path ${derivationPath}`);
            }

            // Create ECPair from derived private key
            const keyPair = ECPair.fromPrivateKey(child.privateKey, { network: avianNetwork });

            // Generate the address from the derived key
            const p2pkh = bitcoin.payments.p2pkh({
                pubkey: Buffer.from(keyPair.publicKey),
                network: avianNetwork,
            });

            const fromAddress = p2pkh.address;
            if (!fromAddress) {
                throw new Error('Failed to generate address from derived key');
            }

            // Get UTXOs for the derived address
            const rawUTXOs = await this.electrum.getUTXOs(fromAddress);
            if (rawUTXOs.length === 0) {
                throw new Error('No unspent transaction outputs found for this derived address');
            }

            // Enhance UTXOs with additional metadata
            const currentBlockHeight = await this.electrum.getCurrentBlockHeight();
            const enhancedUTXOs: EnhancedUTXO[] = rawUTXOs.map((utxo) => ({
                ...utxo,
                confirmations: utxo.height ? Math.max(0, currentBlockHeight - utxo.height + 1) : 0,
                isConfirmed: utxo.height ? currentBlockHeight - utxo.height + 1 >= 1 : false,
                ageInBlocks: utxo.height ? currentBlockHeight - utxo.height + 1 : 0,
                address: fromAddress,
            }));

            // Calculate total available amount
            const totalAvailable = enhancedUTXOs.reduce((sum, utxo) => sum + utxo.value, 0);

            // Size-based fee: sat/vByte rate (caller override, else the node's rate, floored).
            const subtractFee = options?.subtractFeeFromAmount ?? false;
            const satPerVByte = await this.resolveFeeRate(options?.feeRate);
            const maxInputs = options?.maxInputs || 650; // Default: stay under ~100KB for standard txs
            const minConfirmations =
                options?.minConfirmations !== undefined ? options?.minConfirmations : 6;
            const strategy = options?.strategy || CoinSelectionStrategy.BEST_FIT;

            // Iterate so the fee tracks the selected input count (see sendTransaction for rationale).
            let selectedUTXOs: any[] = [];
            let totalSelected = 0;
            let fee = estimateTxFee(1, 2, satPerVByte);
            for (let iteration = 0; iteration < 4; iteration++) {
                const selectionTarget = subtractFee ? Math.max(0, amount - fee) : amount;
                if (totalAvailable < selectionTarget + fee) {
                    throw new Error(
                        `Insufficient funds. Required: ${selectionTarget + fee} satoshis, Available: ${totalAvailable} satoshis`,
                    );
                }
                const selectionOptions: UTXOSelectionOptions = {
                    strategy: strategy,
                    targetAmount: selectionTarget,
                    feeRate: fee,
                    maxInputs: maxInputs,
                    minConfirmations: minConfirmations,
                    allowUnconfirmed: true,
                    includeDust: false,
                };
                const selectionResult = UTXOSelectionService.selectUTXOs(enhancedUTXOs, selectionOptions);
                if (!selectionResult) {
                    throw new Error('Unable to select suitable UTXOs for transaction');
                }
                selectedUTXOs = selectionResult.selectedUTXOs;
                totalSelected = selectedUTXOs.reduce((sum, utxo) => sum + utxo.value, 0);
                const recomputed = estimateTxFee(selectedUTXOs.length, 2, satPerVByte);
                if (recomputed <= fee) {
                    fee = recomputed;
                    break;
                }
                fee = recomputed;
            }

            // Split into recipient and change, folding sub-dust change into the fee.
            const split = resolveSendAmounts(amount, fee, totalSelected, subtractFee);
            const finalSendAmount = split.sendAmount;
            if (finalSendAmount <= 0) {
                throw new Error('Send amount is zero or negative after subtracting the fee');
            }
            if (split.change < 0) {
                throw new Error('Insufficient funds to cover the network fee');
            }
            const finalChangeAmount = split.change >= DUST_THRESHOLD_SATS ? split.change : 0;

            // Determine change address - use custom address if provided, otherwise sender's address
            const changeAddress =
                options?.changeAddress && options.changeAddress.trim() !== ''
                    ? options.changeAddress
                    : fromAddress;

            // Create transaction
            const tx = new bitcoin.Transaction();

            // Add inputs from selected UTXOs
            for (const utxo of selectedUTXOs) {
                tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
            }

            // Add output for recipient
            tx.addOutput(bitcoin.address.toOutputScript(toAddress, avianNetwork), finalSendAmount);

            // Add change output if needed (sub-dust change was already folded into the fee above).
            if (finalChangeAmount > 0) {
                tx.addOutput(
                    bitcoin.address.toOutputScript(changeAddress, avianNetwork),
                    finalChangeAmount,
                );
            }

            // Sign the transaction inputs
            for (let i = 0; i < tx.ins.length; i++) {
                try {
                    // Get the previous transaction to use the correct scriptPubKey
                    const utxo = selectedUTXOs[i];
                    const prevTxHex = await this.electrum.getTransaction(utxo.txid, false);
                    const prevTx = bitcoin.Transaction.fromHex(prevTxHex);
                    const prevOutScript = prevTx.outs[utxo.vout].script;

                    // Define hashType consistent with the sendTransaction method
                    const SIGHASH_ALL = 0x01;
                    const SIGHASH_FORKID = 0x40;
                    const hashType = SIGHASH_ALL | SIGHASH_FORKID; // 0x41 for Avian

                    // Create the signature hash using hashForSignature instead of hashForWitnessV0
                    // This is the correct method for P2PKH addresses
                    const signatureHash = tx.hashForSignature(i, prevOutScript, hashType);

                    // Sign the hash
                    const signature = keyPair.sign(signatureHash);

                    // Encode signature in DER format with custom hashtype
                    const signatureWithHashType = this.encodeDERWithCustomHashType(
                        Buffer.from(signature),
                        hashType,
                    );

                    // Build scriptSig manually (matches what's used in sendTransaction)
                    const scriptSig = bitcoin.script.compile([
                        signatureWithHashType,
                        Buffer.from(keyPair.publicKey),
                    ]);

                    // Set the input script
                    tx.ins[i].script = scriptSig;
                } catch (error: any) {
                    walletLogger.error(`Error signing input ${i}:`, error);
                    throw new Error(`Failed to sign input ${i}: ${error.message || 'Unknown error'}`);
                }
            }

            // Validate the transaction before broadcasting
            for (let i = 0; i < tx.ins.length; i++) {
                if (!tx.ins[i].script || tx.ins[i].script.length === 0) {
                    throw new Error(`Input ${i} has empty script after signing!`);
                }
            }

            // Broadcast the transaction
            const serializedTx = tx.toHex();
            const txId = await this.electrum.broadcastTransaction(serializedTx);

            if (!txId) {
                throw new Error('Failed to broadcast transaction');
            }

            // Track this as a sent transaction in our history
            const txData = {
                txid: txId,
                amount: finalSendAmount / 100000000, // what the recipient received (net of fee if subtracted)
                address: toAddress,
                fromAddress: fromAddress,
                walletAddress: fromAddress, // Use the derived address
                type: 'send' as 'send', // Explicitly typed as 'send'
                timestamp: new Date(),
                confirmations: 0,
            };

            // Save transaction to history
            await StorageService.saveTransaction(txData);

            return txId;
        } catch (error) {
            walletLogger.error('Error sending transaction from derived address:', error);
            throw error;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PSBT utilities (Avian Core v5.0.0 / Bitcoin 30.2 base)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Serialises a PSBT to base64 for export / QR display.
     */
    static exportPSBT(psbt: bitcoin.Psbt): string {
        return psbt.toBase64();
    }

    /**
     * Imports a base64-encoded PSBT, finalises it and broadcasts the extracted
     * transaction to the Avian network via ElectrumX.
     */
    async importAndBroadcastPSBT(base64: string): Promise<string> {
        const psbt = bitcoin.Psbt.fromBase64(base64, { network: avianNetwork });
        psbt.finalizeAllInputs();
        const tx = psbt.extractTransaction();
        return await this.electrum.broadcastTransaction(tx.toHex());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Descriptor utilities (BIP380, Avian Core v5 descriptor wallets)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Derives and returns the BIP380 output-script descriptor for the given
     * wallet, decrypting the mnemonic with the supplied password.
     *
     * The descriptor format depends on the wallet's address type:
     *   P2PKH        → pkh([fingerprint/44h/921h/0h]xpub/0/*)
     *   P2SH-P2WPKH  → sh(wpkh([fingerprint/49h/921h/0h]xpub/0/*))
     *   P2WPKH       → wpkh([fingerprint/84h/921h/0h]xpub/0/*)
     *
     * A BIP380 checksum is appended (e.g. `#abcdef12`).
     */
    async getWalletDescriptor(wallet: WalletData, password: string): Promise<string> {
        // Descriptor-imported wallets store the canonical descriptor directly
        if (!wallet.mnemonic && wallet.descriptor) {
            return wallet.descriptor;
        }

        // xprv-only descriptor wallet: derive xpub from the stored encrypted xprv
        if (!wallet.mnemonic && wallet.xprv) {
            const xprvDecrypted = await secureDecrypt(wallet.xprv, password);
            const accountNode = bip32.fromBase58(xprvDecrypted, avianNetwork);
            const xpub = accountNode.neutered().toBase58();
            const addrType: AddressType = wallet.addressType || 'p2pkh';
            const coinType = wallet.coinType || 921;
            const purpose = purposeForAddressType(addrType);
            const fingerprint = '00000000'; // not stored when imported without origin
            const body = buildDescriptorBody(addrType, fingerprint, purpose, coinType, xpub);
            return `${body}#${descriptorChecksum(body)}`;
        }

        if (!wallet.mnemonic) {
            throw new Error('Descriptor generation requires an HD wallet with a mnemonic');
        }

        const encryptedMnemonic = await StorageService.getMnemonic();
        if (!encryptedMnemonic) {
            throw new Error('No mnemonic found in storage');
        }

        const mnemonic = await secureDecrypt(encryptedMnemonic, password);
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Decrypted mnemonic is invalid — wrong password?');
        }

        const passphrase = wallet.bip39Passphrase
            ? await secureDecrypt(wallet.bip39Passphrase, password)
            : '';
        const seed = await bip39.mnemonicToSeed(mnemonic, passphrase);
        const root = bip32.fromSeed(seed, avianNetwork);

        const coinType = wallet.coinType || 921;
        const addrType: AddressType = wallet.addressType || 'p2pkh';
        const purpose = purposeForAddressType(addrType);

        const accountChild = root.derivePath(`m/${purpose}'/${coinType}'/0'`);
        const xpub = accountChild.neutered().toBase58();
        const fingerprint = Array.from(root.fingerprint).map(b => b.toString(16).padStart(2, '0')).join('');

        const body = buildDescriptorBody(addrType, fingerprint, purpose, coinType, xpub);
        return `${body}#${descriptorChecksum(body)}`;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BIP380 descriptor helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Builds the descriptor string body (without checksum) for a given address type
 * and account-level xpub.
 */
export function buildDescriptorBody(
    addrType: AddressType,
    fingerprint: string,
    purpose: number,
    coinType: number,
    xpub: string,
): string {
    const origin = `[${fingerprint}/${purpose}h/${coinType}h/0h]${xpub}`;
    switch (addrType) {
        case 'p2wpkh':
            return `wpkh(${origin}/0/*)`;
        case 'p2sh-p2wpkh':
            return `sh(wpkh(${origin}/0/*))`;
        default:
            return `pkh(${origin}/0/*)`;
    }
}

/**
 * Computes a BIP380-compliant 8-character checksum for a descriptor body string.
 *
 * Reference implementation:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp
 */
export function descriptorChecksum(desc: string): string {
    const INPUT_CHARSET =
        '0123456789()[]\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\  ';
    const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    let c = BigInt(1);
    let cls = 0;
    let clscount = 0;

    for (const ch of desc) {
        const pos = INPUT_CHARSET.indexOf(ch);
        if (pos === -1) return '????????';
        c = descriptorPolymod(c ^ BigInt(pos & 31));
        cls = cls * 3 + (pos >> 5);
        clscount += 1;
        if (clscount === 3) {
            c = descriptorPolymod(c ^ BigInt(cls));
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0) {
        c = descriptorPolymod(c ^ BigInt(cls));
    }
    for (let j = 0; j < 8; j++) {
        c = descriptorPolymod(c ^ BigInt(0));
    }
    c ^= BigInt(1);

    let result = '';
    for (let j = 0; j < 8; j++) {
        result = CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - j))) & BigInt(31))] + result;
    }
    return result.split('').reverse().join('');
}

function descriptorPolymod(c: bigint): bigint {
    const GEN = [
        BigInt(0xf5dee51989),
        BigInt(0xa9fdca3312),
        BigInt(0x1bab10e32d),
        BigInt(0x3706b1677a),
        BigInt(0x644d626ffd),
    ];
    const b = c >> BigInt(35);
    c = ((c & BigInt(0x7ffffffff)) << BigInt(5)) ^ BigInt(0);
    for (let i = 0; i < 5; i++) {
        if ((b >> BigInt(i)) & BigInt(1)) {
            c ^= GEN[i];
        }
    }
    return c;
}

// ─────────────────────────────────────────────────────────────────────────────
// RIP-25 (ML-DSA-44 / Post-Quantum) — STUB
// Active on testnet/regtest only. Not enabled on Avian mainnet.
// Full implementation requires liboqs WASM bindings (out of scope).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Stub for RIP-25 ML-DSA-44 post-quantum address generation.
 *
 * RIP-25 introduces Dilithium (ML-DSA-44) lattice-based signing.
 * As of Avian Core v5.0.0, the deployment is ONLY active on testnet/regtest.
 * Mainnet deployment is not yet scheduled.
 *
 * To implement this fully, the liboqs WASM module would be required for
 * ML-DSA-44 key generation and signing in browser environments.
 *
 * @throws Always throws — not available on mainnet.
 */
export function generateMLDSA44Address(): never {
    throw new Error(
        'RIP-25 ML-DSA-44 post-quantum addresses are currently only available on ' +
        'Avian testnet/regtest (not mainnet). ' +
        'Full implementation requires liboqs WASM bindings.',
    );
}
