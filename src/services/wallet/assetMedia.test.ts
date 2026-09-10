import { afterEach, describe, expect, it, vi } from 'vitest';

import { IPFS_GATEWAY, resolveAssetMedia, resolveMediaUrl } from './AssetService';

/**
 * An asset's IPFS hash is either the image itself (the original Ravencoin convention) or a JSON
 * document pointing at one, and the hash does not say which. Getting this wrong shows a coin glyph
 * where an item should be — or, worse, follows a URL out of attacker-controlled metadata, since
 * anyone can mint an asset whose JSON points anywhere.
 */

/** The real REALM document at QmY6dx… — a unique game item minted on Avian. */
/** The 1x1 PNG REALM uses in its inline sample. */
const INLINE_PNG =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

const REALM_METADATA = {
  symbol: 'RLM#RK1KJRAPGFOMI',
  name: 'Runed Grips',
  description: 'A rare grips forged in REALM, minted by craigd.avn.',
  image: 'https://therealm.avn.zone/assets/artifacts/grips.webp',
  creator: { name: 'craigd.avn' },
  realm: {
    category: 'gloves',
    kind: 'grips',
    rarity: 'rare',
    stats: { attack: 4 },
    creator: 'craigd.avn',
  },
};

/** A fetch stub returning one body with one content type. Each test uses a fresh hash for the cache. */
const respondWith = (contentType: string, body: string, ok = true) =>
  vi.fn(async () => ({
    ok,
    headers: { get: (name: string) => (name === 'content-type' ? contentType : null) },
    text: async () => body,
  })) as unknown as typeof fetch;

// Never reset: resolveAssetMedia caches by hash for the session, so every test needs its own.
let hashCounter = 0;
const freshHash = () => `Qm${'x'.repeat(20)}${(hashCounter += 1)}`;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('resolveMediaUrl', () => {
  it('accepts https and maps ipfs:// onto the gateway', () => {
    expect(resolveMediaUrl('https://therealm.avn.zone/assets/artifacts/grips.webp')).toBe(
      'https://therealm.avn.zone/assets/artifacts/grips.webp',
    );
    expect(resolveMediaUrl('ipfs://QmAbc')).toBe(`${IPFS_GATEWAY}QmAbc`);
  });

  it('accepts an inline raster image, which newer REALM mints embed directly', () => {
    expect(resolveMediaUrl(INLINE_PNG)).toBe(INLINE_PNG);
    expect(resolveMediaUrl('data:image/webp;base64,UklGRg==')).toBe('data:image/webp;base64,UklGRg==');
  });

  it('refuses schemes that are not fetchable raster images', () => {
    // Metadata is attacker-controlled, so everything outside the narrow accepted set is dropped.
    expect(resolveMediaUrl('javascript:alert(1)')).toBeNull();
    expect(resolveMediaUrl('http://therealm.avn.zone/grips.webp')).toBeNull();
    expect(resolveMediaUrl('')).toBeNull();
    expect(resolveMediaUrl(undefined)).toBeNull();
    expect(resolveMediaUrl(42)).toBeNull();
  });

  it('refuses SVG and other data URIs that are not raster images', () => {
    // An <img> will not run scripts in an SVG, but SVG is the one image type that is also a
    // document, and nothing here needs it.
    expect(resolveMediaUrl('data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=')).toBeNull();
    expect(resolveMediaUrl('data:image/svg+xml,<svg onload="alert(1)"/>')).toBeNull();
    expect(resolveMediaUrl('data:text/html;base64,PGgxPmhpPC9oMT4=')).toBeNull();
    expect(resolveMediaUrl('data:application/json;base64,e30=')).toBeNull();
    // Not base64 at all, so not something we hand to an <img>.
    expect(resolveMediaUrl('data:image/png,notbase64')).toBeNull();
  });
});

describe('resolveAssetMedia', () => {
  it('reads the image out of a REALM metadata document', async () => {
    vi.stubGlobal('fetch', respondWith('application/json', JSON.stringify(REALM_METADATA)));

    const media = await resolveAssetMedia(freshHash());

    expect(media.imageUrl).toBe('https://therealm.avn.zone/assets/artifacts/grips.webp');
    expect(media.name).toBe('Runed Grips');
    expect(media.description).toBe('A rare grips forged in REALM, minted by craigd.avn.');
  });

  it('uses the gateway URL directly when the hash is the image', async () => {
    vi.stubGlobal('fetch', respondWith('image/webp', ''));
    const hash = freshHash();

    const media = await resolveAssetMedia(hash);

    expect(media.imageUrl).toBe(`${IPFS_GATEWAY}${hash}`);
    expect(media.name).toBeUndefined();
  });

  it('drops an image URL the metadata should not be able to set', async () => {
    vi.stubGlobal(
      'fetch',
      respondWith('application/json', JSON.stringify({ name: 'Bad', image: 'javascript:alert(1)' })),
    );

    const media = await resolveAssetMedia(freshHash());

    expect(media.imageUrl).toBeNull();
    // The rest of the document is still readable; only the URL is refused.
    expect(media.name).toBe('Bad');
  });

  it('reports no image rather than throwing when the gateway is unreachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      }) as unknown as typeof fetch,
    );

    await expect(resolveAssetMedia(freshHash())).resolves.toEqual({ imageUrl: null });
  });

  it('survives content that is neither an image nor JSON', async () => {
    vi.stubGlobal('fetch', respondWith('text/plain', 'just some text'));

    await expect(resolveAssetMedia(freshHash())).resolves.toEqual({ imageUrl: null });
  });

  it('ignores a hash that is not IPFS content, without fetching', async () => {
    const fetchStub = respondWith('application/json', '{}');
    vi.stubGlobal('fetch', fetchStub);

    // Assets can carry a txid reference instead of a CID; there is nothing to load.
    await expect(resolveAssetMedia('9f3a…not-a-cid')).resolves.toEqual({ imageUrl: null });
    await expect(resolveAssetMedia(null)).resolves.toEqual({ imageUrl: null });
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('fetches a given hash once, since asset content is immutable', async () => {
    const fetchStub = respondWith('application/json', JSON.stringify(REALM_METADATA));
    vi.stubGlobal('fetch', fetchStub);
    const hash = freshHash();

    const [first, second] = await Promise.all([
      resolveAssetMedia(hash),
      resolveAssetMedia(hash),
    ]);
    await resolveAssetMedia(hash);

    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(first).toEqual(second);
  });

  it('refuses a document too large to be metadata, inlined art included', async () => {
    // The ceiling is generous enough for embedded art but still bounds what one asset can make
    // the wallet hold in memory.
    const huge = JSON.stringify({ image: 'https://x.test/a.webp', pad: 'x'.repeat(600 * 1024) });
    vi.stubGlobal('fetch', respondWith('application/json', huge));

    await expect(resolveAssetMedia(freshHash())).resolves.toEqual({ imageUrl: null });
  });
});

describe('the two shapes of REALM metadata', () => {
  /** Newer mints inline the art; the ones already on chain link to it. Both must work. */
  const INLINE_METADATA = {
    symbol: 'RLM#RYI7RS9Y5E7B5',
    name: 'Runed Grips',
    description: 'A rare grips forged in REALM, minted by craigd.avn.',
    image: INLINE_PNG,
    creator: { name: 'craigd.avn' },
    realm: { category: 'gloves', kind: 'grips', rarity: 'rare', stats: { attack: 4, defence: 0 } },
  };

  it('reads an inline image straight out of the document', async () => {
    vi.stubGlobal('fetch', respondWith('application/json', JSON.stringify(INLINE_METADATA)));

    const media = await resolveAssetMedia(freshHash());

    expect(media.imageUrl).toBe(INLINE_PNG);
    expect(media.name).toBe('Runed Grips');
  });

  it('still reads a linked image, since those are already on chain', async () => {
    vi.stubGlobal('fetch', respondWith('application/json', JSON.stringify(REALM_METADATA)));

    const media = await resolveAssetMedia(freshHash());

    expect(media.imageUrl).toBe('https://therealm.avn.zone/assets/artifacts/grips.webp');
  });

  it('reads a document big enough to carry real art inline', async () => {
    // A 90 KB webp is ~120 KB once base64-encoded — comfortably past the old 64 KB ceiling, which
    // would have shown no image at all for every newer mint.
    const art = 'A'.repeat(160 * 1024);
    const heavy = JSON.stringify({ name: 'Heavy', image: `data:image/webp;base64,${art}` });
    expect(heavy.length).toBeGreaterThan(64 * 1024);
    vi.stubGlobal('fetch', respondWith('application/json', heavy));

    const media = await resolveAssetMedia(freshHash());

    expect(media.imageUrl).toBe(`data:image/webp;base64,${art}`);
  });
});
