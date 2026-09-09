// PSBT (BIP174) helpers. Avian Core uses stock BIP174 — the only Avian-specific detail is that
// signatures carry SIGHASH_ALL | SIGHASH_FORKID (0x41), which bitcoinjs-lib already produces for
// both legacy (hashForSignature) and SegWit v0 (hashForWitnessV0) inputs when that sighash type is
// set. So PSBT signing reuses the same path regular sends use; this module holds the shared
// constants, the asset-script guard, and the decoded-summary shapes.

/** SIGHASH_ALL (0x01) | SIGHASH_FORKID (0x40). Every Avian signature must carry this. */
export const SIGHASH_ALL_FORKID = 0x41;

/**
 * SIGHASH_SINGLE (0x03) | SIGHASH_FORKID (0x40) | SIGHASH_ANYONECANPAY (0x80) — the marketplace
 * listing sighash.
 *
 * SINGLE commits to the output at the signed input's index; ANYONECANPAY commits to that input
 * alone. A seller signing input[0] against output[0] therefore commits to exactly "I spend this
 * asset UTXO and I am paid this amount", leaving a buyer free to add payment inputs, an asset
 * destination and change without invalidating the signature. That bound is what makes signing an
 * asset input safe here, where it is refused everywhere else.
 */
export const SIGHASH_SINGLE_FORKID_ANYONECANPAY = 0xc3;

/** OP_AVN_ASSET — marks an Avian asset script. See Avian Core script/script.h. */
export const OP_AVN_ASSET = 0xc0;

/**
 * Whether an output script carries an Avian asset. Asset scripts are a standard 25-byte P2PKH
 * followed by `OP_AVN_ASSET <data> OP_DROP`, so the tell is a byte 0xc0 immediately after the P2PKH.
 * A plain-AVN wallet must never sign an asset input or select it as a fee input — spending it as a
 * bare transfer would burn the asset — so this errs toward caution.
 */
export function isAssetScript(script: Uint8Array): boolean {
  // A bare P2PKH is exactly 25 bytes (76 a9 14 <20> 88 ac); anything longer with OP_AVN_ASSET right
  // after it is an asset carrier. (A 0xc0 byte inside the 20-byte hash of a bare P2PKH is harmless
  // because those scripts are exactly 25 bytes.)
  return script.length > 25 && script[25] === OP_AVN_ASSET;
}

export interface PsbtInputSummary {
  txid: string;
  vout: number;
  /** Prevout value in satoshis, or null if the PSBT didn't include it. */
  value: number | null;
  /** Prevout address, or null if the script isn't a standard address. */
  address: string | null;
  /** The prevout script belongs to this wallet (we can sign it). */
  isMine: boolean;
  /** The prevout carries an Avian asset — we refuse to sign it. */
  isAsset: boolean;
  /** This input already has a signature (ours or another party's). */
  signed: boolean;
}

export interface PsbtOutputSummary {
  address: string | null;
  value: number;
  isMine: boolean;
  isAsset: boolean;
}

export interface PsbtSummary {
  inputs: PsbtInputSummary[];
  outputs: PsbtOutputSummary[];
  /** Sum of input values, or null if any prevout value is unknown. */
  totalIn: number | null;
  totalOut: number;
  /** totalIn − totalOut, or null if totalIn is unknown. */
  fee: number | null;
  /** How many inputs this wallet can sign (ours, non-asset, not already signed by us). */
  signableByUs: number;
  /** Every input is finalizable (fully signed) — ready to extract/broadcast. */
  complete: boolean;
  /** Any input or output touches an asset — surfaced as a warning. */
  hasAsset: boolean;
}
