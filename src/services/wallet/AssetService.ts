// Avian asset reads: compose held-asset balances with their metadata into a display-ready list.
// Assets are Ravencoin-style: an integer amount scaled by the asset's `divisions` (0–8). All the
// formatting lives here so the UI never does raw scaling. Sending assets is a separate, higher-risk
// concern (see docs/proposals/avian-assets.md) and is not in this module.

import type { ElectrumService, AssetMeta } from '@/services/core/ElectrumService';

/** Avian's IPFS gateway, for rendering an asset's image from its IPFS hash. */
export const IPFS_GATEWAY = 'https://ipfs.avn.network/ipfs/';

/** URL for an asset's IPFS content, or null if it has none. */
export function ipfsImageUrl(hash: string | null | undefined): string | null {
  // Only IPFS v0 CIDs (Qm…) are real content here; a txid reference isn't an image.
  return hash && hash.startsWith('Qm') ? `${IPFS_GATEWAY}${hash}` : null;
}

/** What an asset's IPFS hash resolves to, once we know whether it is an image or metadata. */
export interface AssetMedia {
  /** Image to render, or null when the hash holds neither an image nor usable metadata. */
  imageUrl: string | null;
  /** Display name from metadata, e.g. "Runed Grips". */
  name?: string;
  description?: string;
}

/**
 * Turn a metadata `image` value into something safe to put in an `<img src>`.
 *
 * The metadata is attacker-controlled — anyone can mint an asset whose JSON points anywhere — so
 * only `https:` and `ipfs:` are accepted. That rules out `javascript:`, `data:` (a vector for
 * oversized or mislabelled payloads) and plaintext `http:`.
 */
export function resolveMediaUrl(value: unknown): string | null {
  if (typeof value !== 'string' || !value) return null;
  if (value.startsWith('ipfs://')) return `${IPFS_GATEWAY}${value.slice('ipfs://'.length)}`;
  try {
    return new URL(value).protocol === 'https:' ? value : null;
  } catch {
    return null;
  }
}

/** Largest metadata document we will read; real ones are a few hundred bytes. */
const MAX_METADATA_BYTES = 64 * 1024;

const mediaCache = new Map<string, Promise<AssetMedia>>();

/**
 * Resolve an asset's IPFS hash to something renderable.
 *
 * An asset's IPFS content is either the image itself (the original Ravencoin convention) or a JSON
 * metadata document pointing at one — which is what REALM mints:
 *
 *   { "name": "Runed Grips", "image": "https://…/grips.webp", … }
 *
 * Both are common on-chain, and the hash alone does not say which, so this looks at the response's
 * content type: images are handed back as the gateway URL (the browser fetches them once, for the
 * `<img>`), and anything else is parsed as metadata.
 *
 * Failures are not errors — an unreachable gateway or an unreadable document simply means no image.
 * Results are cached per hash for the session, since asset content is immutable.
 */
export async function resolveAssetMedia(hash: string | null | undefined): Promise<AssetMedia> {
  const url = ipfsImageUrl(hash);
  if (!url || !hash) return { imageUrl: null };

  const cached = mediaCache.get(hash);
  if (cached) return cached;

  const pending = (async (): Promise<AssetMedia> => {
    try {
      const controller = new AbortController();
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) return { imageUrl: null };

      const contentType = response.headers.get('content-type') ?? '';
      if (contentType.startsWith('image/')) {
        // Stop the download: the <img> below will fetch it properly (and stream it).
        controller.abort();
        return { imageUrl: url };
      }

      const body = await response.text();
      if (body.length > MAX_METADATA_BYTES) return { imageUrl: null };

      const meta: unknown = JSON.parse(body);
      if (!meta || typeof meta !== 'object') return { imageUrl: null };

      const record = meta as Record<string, unknown>;
      return {
        imageUrl: resolveMediaUrl(record.image),
        name: typeof record.name === 'string' ? record.name : undefined,
        description: typeof record.description === 'string' ? record.description : undefined,
      };
    } catch {
      // Offline, CORS-blocked, not JSON — all the same to the caller: nothing to show.
      return { imageUrl: null };
    }
  })();

  mediaCache.set(hash, pending);
  return pending;
}

export interface HeldAsset {
  name: string;
  /** Confirmed + unconfirmed, formatted with the asset's divisions. */
  amount: string;
  confirmedSats: number;
  unconfirmedSats: number;
  divisions: number;
  meta: AssetMeta | null;
}

/**
 * Format an on-chain asset amount as a decimal string. Avian assets (Ravencoin model) store every
 * quantity scaled by 10^8 (COIN), exactly like AVN — a quantity of "1" is on-chain `100000000`.
 * `divisions` (0–8) only says how many of those decimal places are meaningful, so we always divide
 * by 10^8 and then show `divisions` decimals (0 → a whole number). BigInt keeps large supplies exact.
 */
export function formatAssetAmount(sats: number, divisions: number): string {
  const units = Math.min(Math.max(divisions | 0, 0), 8);
  const value = BigInt(Math.trunc(sats));
  const COIN = 100_000_000n; // asset amounts are scaled by 10^8, like AVN — not by 10^divisions
  const whole = value / COIN;
  if (units === 0) return whole.toString();
  const frac8 = (value % COIN).toString().padStart(8, '0');
  return `${whole.toString()}.${frac8.slice(0, units)}`;
}

/**
 * Parse a user-entered asset amount into the on-chain integer (scaled by 10^8). Rejects a malformed
 * number, or more decimal places than the asset's `divisions` allow (a 0-division asset must be a
 * whole number). The inverse of formatAssetAmount.
 */
export function parseAssetAmount(input: string, divisions: number): bigint {
  const units = Math.min(Math.max(divisions | 0, 0), 8);
  const trimmed = input.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) throw new Error('Enter a valid amount');
  const [whole, frac = ''] = trimmed.split('.');
  if (frac.length > units) {
    throw new Error(
      units === 0
        ? 'This asset is not divisible — enter a whole number'
        : `This asset allows at most ${units} decimal place${units === 1 ? '' : 's'}`,
    );
  }
  const amount = BigInt(whole) * 100_000_000n + BigInt(frac.padEnd(8, '0'));
  if (amount <= 0n) throw new Error('Amount must be greater than zero');
  return amount;
}

/**
 * Every asset held at `address`, sorted by name, each with its metadata (divisions, reissuable,
 * IPFS) and a formatted quantity. The base coin (AVN) is excluded — it is the ordinary balance.
 */
export async function getHeldAssets(electrum: ElectrumService, address: string): Promise<HeldAsset[]> {
  const balances = await electrum.getAssetBalances(address);
  const names = Object.keys(balances).sort((a, b) => a.localeCompare(b));

  const metas = await Promise.all(names.map((name) => electrum.getAssetMeta(name)));

  return names.map((name, i) => {
    const meta = metas[i];
    const divisions = meta?.divisions ?? 0;
    const { confirmed, unconfirmed } = balances[name];
    return {
      name,
      confirmedSats: confirmed,
      unconfirmedSats: unconfirmed,
      divisions,
      meta,
      amount: formatAssetAmount(confirmed + unconfirmed, divisions),
    };
  });
}
