/**
 * Avian Connect — phase 1 wire types.
 *
 * The canonical specification lives in docs/AVIAN_CONNECT.md. Everything a dApp can send or
 * receive is described here; nothing beyond an address, an optional public key and a base64
 * signature ever crosses this boundary.
 */

/** Wire version tag carried by every envelope. */
export const AVIAN_CONNECT_VERSION = 1;

export const CONNECT_ERROR_CODES = [
  'USER_REJECTED',
  /**
   * The user switched the wallet this origin is connected with instead of answering. The grant has
   * moved and `accountsChanged` has been emitted, so the request should be rebuilt against the new
   * account and sent again — not reported as a refusal.
   */
  'ACCOUNT_CHANGED',
  'ORIGIN_NOT_APPROVED',
  'WALLET_LOCKED',
  'UNSUPPORTED_METHOD',
  'INVALID_REQUEST',
] as const;

export type ConnectErrorCode = (typeof CONNECT_ERROR_CODES)[number];

/** Methods implemented in phase 1. Anything else resolves to UNSUPPORTED_METHOD. */
export const SUPPORTED_METHODS = [
  'connect',
  'getAccounts',
  'signMessage',
  'signPsbt',
  'createAssetListing',
  'completeAssetListing',
  'getNetwork',
  'disconnect',
] as const;

export type ConnectMethod = (typeof SUPPORTED_METHODS)[number];

export const CONNECT_EVENTS = ['accountsChanged', 'networkChanged', 'disconnect'] as const;

export type ConnectEventName = (typeof CONNECT_EVENTS)[number];

/** Upper bounds enforced by the parser so a hostile page cannot hand us unbounded strings. */
export const LIMITS = {
  id: 128,
  method: 64,
  message: 8192,
  /** Base64 PSBT length. ~100 KB of base64 is ~75 KB of PSBT — far beyond any normal transaction. */
  psbt: 100_000,
  /** Avian asset names top out well under this; anything longer is not a name. */
  assetName: 64,
} as const;

export interface ConnectRequest {
  avianConnect: typeof AVIAN_CONNECT_VERSION;
  id: string;
  method: string;
  params?: Record<string, unknown>;
  /** Only meaningful on the redirect transport, where it is matched against redirect_uri. */
  origin?: string;
}

export interface ConnectError {
  code: ConnectErrorCode;
  message: string;
}

export interface ConnectResponse {
  avianConnect: typeof AVIAN_CONNECT_VERSION;
  id: string;
  result?: unknown;
  error?: ConnectError;
}

export interface ConnectEvent {
  avianConnect: typeof AVIAN_CONNECT_VERSION;
  event: ConnectEventName;
  data: unknown;
}

/** Result shapes, exported so the wallet UI and the demo dApp agree on them. */
export interface ConnectResult {
  address: string;
  publicKey?: string;
}

export interface SignMessageResult {
  signature: string;
}

/**
 * completeAssetListing buys an asset: the wallet decodes the seller's listing, funds it from this
 * account, appends the asset destination and change, signs its own inputs and broadcasts.
 *
 * The price comes from the seller-signed bytes, never from the dApp, so a site cannot show a buyer
 * one price and have them pay another.
 */
export interface CompleteAssetListingResult {
  /** The completed PSBT, whether or not it was broadcast. */
  psbt: string;
  broadcast: boolean;
  txid?: string;
  broadcastError?: string;
  assetName: string;
  /** 10^8-scaled quantity, as a decimal string (JSON has no bigint). */
  assetAmount: string;
  /** What the buyer paid the seller, in satoshis. */
  pricePaidSats: number;
  /** Network fee the buyer paid, in satoshis. */
  feeSats: number;
}

/**
 * createAssetListing sells an asset: the wallet signs the seller's asset input with
 * SIGHASH_SINGLE|FORKID|ANYONECANPAY, committing to that input and the payment output alone. A
 * buyer can then add payment inputs, an asset destination and change without invalidating it.
 *
 * It is deliberately separate from signPsbt, which still refuses every asset input. Widening
 * signPsbt instead would let any connected site slip an asset input into an ordinary signing
 * request, where a SIGHASH_ALL signature carries none of the guarantees this shape does.
 */
export interface CreateAssetListingResult {
  /** The base64 PSBT with the seller's input signed and finalised. */
  psbt: string;
  /** The asset output the listing spends, so a dApp can detect a cancelled or spent listing. */
  assetUtxo: { txid: string; vout: number };
  /** Asset the listing sells, e.g. `RLM#BRBAEY6A94VXQ`. */
  assetName: string;
  /** Asset quantity, 10^8-scaled, as a decimal string (JSON has no bigint). */
  assetAmount: string;
  /** What the seller is paid, in satoshis. */
  priceSats: number;
  /** Address the payment output pays — always the connected account. */
  payTo: string;
}

/**
 * signPsbt is sign-only: the wallet signs the inputs it owns with Avian's FORKID sighash and hands
 * the updated PSBT back. It never broadcasts on a site's behalf, so the dApp finalises/broadcasts.
 */
export interface SignPsbtResult {
  /** The base64 PSBT with this wallet's signatures added. */
  psbt: string;
  /** Every input is now signed. */
  complete: boolean;
  /** How many inputs this wallet signed. */
  signedInputs: number;
  /** Whether the wallet finalised and broadcast it. False unless `broadcast: true` was requested. */
  broadcast: boolean;
  /** Set when the wallet broadcast it. */
  txid?: string;
  /**
   * Why a requested broadcast did not happen. The signature is still returned above, so the dApp
   * can retry or broadcast itself — a marketplace race (someone took the listing first) lands here.
   */
  broadcastError?: string;
}

export interface NetworkResult {
  network: 'mainnet';
  genesisHash: string | null;
}

export interface DisconnectResult {
  disconnected: true;
}

/** A site the user chose to remember, as persisted in the preferences store. */
export interface OriginPermission {
  origin: string;
  accounts: string[];
  grantedAt: number;
  lastUsedAt: number;
}
