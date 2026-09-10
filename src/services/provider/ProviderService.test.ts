import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CompleteAssetListingResult,
  CreateAssetListingResult,
  OriginPermission,
  SignPsbtResult,
} from '@/types/avianConnect';
import { grantPermission, revokePermission, touchPermission } from './permissions';
// vi.mock below is hoisted above this import, so ProviderService picks up the stub.
import { ProviderService } from './ProviderService';

/**
 * The engine's only dependency on storage is PermissionService, so it is replaced with an
 * in-memory equivalent built from the same pure helpers. Everything else the engine touches
 * comes from the ProviderHost, which the transport supplies.
 */
const store: { permissions: OriginPermission[] } = { permissions: [] };

vi.mock('./PermissionService', () => ({
  PermissionService: {
    list: async () => store.permissions,
    get: async (origin: string) =>
      store.permissions.find((entry) => entry.origin === origin.toLowerCase()) || null,
    grant: async (origin: string, accounts: string[]) => {
      store.permissions = grantPermission(store.permissions, origin, accounts, 1000);
    },
    revoke: async (origin: string) => {
      store.permissions = revokePermission(store.permissions, origin);
    },
    touch: async (origin: string) => {
      store.permissions = touchPermission(store.permissions, origin, 2000);
    },
  },
}));

const ORIGIN = 'https://realm.example';
const ADDRESS = 'RAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const PUBLIC_KEY = '02'.padEnd(66, 'a');
const SIGNATURE = 'H9base64signature==';
// Base64-charset placeholder; the host is mocked so the bytes never get decoded.
const PSBT = 'cHNidP8BAAoAAAAAAAAAAAAA';
const SIGNED_PSBT: SignPsbtResult = {
  psbt: PSBT,
  complete: true,
  signedInputs: 1,
  broadcast: false,
};
const SIGNED_LISTING: CreateAssetListingResult = {
  psbt: PSBT,
  assetName: 'RLM#BRBAEY6A94VXQ',
  assetAmount: '100000000',
  priceSats: 500 * 100_000_000,
  payTo: ADDRESS,
  assetUtxo: { txid: 'a'.repeat(64), vout: 0 },
};
const BOUGHT: CompleteAssetListingResult = {
  psbt: PSBT,
  broadcast: true,
  txid: 'b'.repeat(64),
  assetName: 'RLM#BRBAEY6A94VXQ',
  assetAmount: '100000000',
  pricePaidSats: 500 * 100_000_000,
  feeSats: 512_500,
};

const createHost = (overrides: Partial<ReturnType<typeof baseHost>> = {}) => ({
  ...baseHost(),
  ...overrides,
});

function baseHost() {
  return {
    isLocked: vi.fn(() => false),
    requestConnectApproval: vi.fn(async () => ({
      approved: true,
      accounts: [ADDRESS],
      remember: true,
    })),
    requestSignApproval: vi.fn(async () => true),
    signMessage: vi.fn(async () => SIGNATURE as string | null),
    requestSignPsbtApproval: vi.fn(async () => true),
    signPsbt: vi.fn(async () => SIGNED_PSBT as SignPsbtResult | null),
    requestSignAssetListingApproval: vi.fn(async () => true),
    createAssetListing: vi.fn(async () => SIGNED_LISTING as CreateAssetListingResult | null),
    requestBuyAssetApproval: vi.fn(async () => true),
    completeAssetListing: vi.fn(async () => BOUGHT as CompleteAssetListingResult | null),
    getPublicKey: vi.fn(async () => undefined as string | undefined),
    getNetwork: vi.fn(async () => ({ network: 'mainnet' as const, genesisHash: null })),
    emit: vi.fn(),
  };
}

const request = (method: string, params?: Record<string, unknown>, id = 'id-1') => ({
  avianConnect: 1,
  id,
  method,
  params,
});

beforeEach(() => {
  store.permissions = [];
});

describe('envelope handling', () => {
  it('echoes the request id', async () => {
    const provider = new ProviderService(ORIGIN, createHost());
    const response = await provider.handle(request('connect', undefined, 'abc-123'));
    expect(response.id).toBe('abc-123');
    expect(response.avianConnect).toBe(1);
  });

  it('rejects a malformed envelope without reaching the wallet', async () => {
    const host = createHost();
    const provider = new ProviderService(ORIGIN, host);

    const response = await provider.handle({ avianConnect: 2, id: 'x', method: 'connect' });

    expect(response.error?.code).toBe('INVALID_REQUEST');
    expect(host.requestConnectApproval).not.toHaveBeenCalled();
  });
});

describe('unsupported methods', () => {
  it.each(['sendTransaction', 'issueAsset', 'eth_requestAccounts'])(
    'refuses %s',
    async (method) => {
      const host = createHost();
      await new ProviderService(ORIGIN, host).handle(request('connect'));
      const response = await new ProviderService(ORIGIN, host).handle(request(method));

      expect(response.error?.code).toBe('UNSUPPORTED_METHOD');
      expect(host.signMessage).not.toHaveBeenCalled();
    },
  );
});

describe('connect', () => {
  it('reports WALLET_LOCKED without prompting when the wallet is locked', async () => {
    const host = createHost({ isLocked: vi.fn(() => true) });
    const response = await new ProviderService(ORIGIN, host).handle(request('connect'));

    expect(response.error?.code).toBe('WALLET_LOCKED');
    expect(host.requestConnectApproval).not.toHaveBeenCalled();
  });

  it('returns the approved address and nothing else', async () => {
    const host = createHost();
    const response = await new ProviderService(ORIGIN, host).handle(request('connect'));

    expect(response.result).toEqual({ address: ADDRESS });
    expect(host.requestConnectApproval).toHaveBeenCalledWith(ORIGIN);
  });

  it('includes the public key only when the wallet already knows it', async () => {
    const host = createHost({ getPublicKey: vi.fn(async () => PUBLIC_KEY) });
    const response = await new ProviderService(ORIGIN, host).handle(request('connect'));

    expect(response.result).toEqual({ address: ADDRESS, publicKey: PUBLIC_KEY });
  });

  it('maps a rejected approval to USER_REJECTED and stores nothing', async () => {
    const host = createHost({
      requestConnectApproval: vi.fn(async () => ({
        approved: false,
        accounts: [],
        remember: false,
      })),
    });

    const response = await new ProviderService(ORIGIN, host).handle(request('connect'));

    expect(response.error?.code).toBe('USER_REJECTED');
    expect(store.permissions).toEqual([]);
  });

  it('resolves silently for a remembered origin', async () => {
    const host = createHost();
    await new ProviderService(ORIGIN, host).handle(request('connect'));
    expect(store.permissions).toHaveLength(1);

    // A fresh instance stands in for a later visit from the same site.
    const later = createHost();
    const response = await new ProviderService(ORIGIN, later).handle(request('connect'));

    expect(response.result).toEqual({ address: ADDRESS });
    expect(later.requestConnectApproval).not.toHaveBeenCalled();
  });

  it('asks again on a later visit when the user did not choose to remember', async () => {
    const decision = {
      approved: true,
      accounts: [ADDRESS],
      remember: false,
    };
    const host = createHost({ requestConnectApproval: vi.fn(async () => decision) });

    await new ProviderService(ORIGIN, host).handle(request('connect'));
    expect(store.permissions).toEqual([]);

    const later = createHost({ requestConnectApproval: vi.fn(async () => decision) });
    await new ProviderService(ORIGIN, later).handle(request('connect'));
    expect(later.requestConnectApproval).toHaveBeenCalledTimes(1);
  });

  it('does not leak another origin’s grant', async () => {
    await new ProviderService(ORIGIN, createHost()).handle(request('connect'));

    const evilHost = createHost();
    await new ProviderService('https://evil.example', evilHost).handle(request('connect'));

    expect(evilHost.requestConnectApproval).toHaveBeenCalledWith('https://evil.example');
  });
});

describe('getAccounts', () => {
  it('requires a permission', async () => {
    const response = await new ProviderService(ORIGIN, createHost()).handle(request('getAccounts'));
    expect(response.error?.code).toBe('ORIGIN_NOT_APPROVED');
  });

  it('returns only the accounts exposed to this origin', async () => {
    await new ProviderService(ORIGIN, createHost()).handle(request('connect'));
    store.permissions = grantPermission(
      store.permissions,
      'https://other.example',
      ['ROtherAccount'],
      1,
    );

    const response = await new ProviderService(ORIGIN, createHost()).handle(request('getAccounts'));

    expect(response.result).toEqual([ADDRESS]);
  });

  it('works within a session that was approved without remembering', async () => {
    const host = createHost({
      requestConnectApproval: vi.fn(async () => ({
        approved: true,
        accounts: [ADDRESS],
        remember: false,
      })),
    });
    const provider = new ProviderService(ORIGIN, host);

    await provider.handle(request('connect'));
    const response = await provider.handle(request('getAccounts'));

    expect(response.result).toEqual([ADDRESS]);
  });
});

describe('signMessage', () => {
  const connectFirst = async (host: ReturnType<typeof baseHost>) => {
    const provider = new ProviderService(ORIGIN, host);
    await provider.handle(request('connect'));
    return provider;
  };

  it('requires a permission', async () => {
    const host = createHost();
    const response = await new ProviderService(ORIGIN, host).handle(
      request('signMessage', { message: 'hi' }),
    );

    expect(response.error?.code).toBe('ORIGIN_NOT_APPROVED');
    expect(host.requestSignApproval).not.toHaveBeenCalled();
    expect(host.signMessage).not.toHaveBeenCalled();
  });

  it('reports WALLET_LOCKED before anything else', async () => {
    const host = createHost();
    const provider = await connectFirst(host);
    host.isLocked.mockReturnValue(true);

    const response = await provider.handle(request('signMessage', { message: 'hi' }));

    expect(response.error?.code).toBe('WALLET_LOCKED');
    expect(host.signMessage).not.toHaveBeenCalled();
  });

  it('always shows the approval screen, even for a remembered origin', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signMessage', { message: 'log me in' }));

    expect(host.requestSignApproval).toHaveBeenCalledWith(ORIGIN, 'log me in', ADDRESS);
    expect(response.result).toEqual({ signature: SIGNATURE });
  });

  it('never signs when the user rejects the approval screen', async () => {
    const host = createHost({ requestSignApproval: vi.fn(async () => false) });
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signMessage', { message: 'hi' }));

    expect(response.error?.code).toBe('USER_REJECTED');
    expect(host.signMessage).not.toHaveBeenCalled();
  });

  it('treats cancelled authentication as a rejection', async () => {
    const host = createHost({ signMessage: vi.fn(async () => null) });
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signMessage', { message: 'hi' }));

    expect(response.error?.code).toBe('USER_REJECTED');
    expect(response.result).toBeUndefined();
  });

  it.each([
    ['no params', undefined],
    ['an empty message', { message: '' }],
    ['a non-string message', { message: 42 }],
  ])('rejects %s as INVALID_REQUEST', async (_label, params) => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signMessage', params));

    expect(response.error?.code).toBe('INVALID_REQUEST');
    expect(host.requestSignApproval).not.toHaveBeenCalled();
  });

  it('returns the signature and nothing else', async () => {
    const provider = await connectFirst(createHost());
    const response = await provider.handle(request('signMessage', { message: 'hi' }));

    expect(Object.keys(response.result as object)).toEqual(['signature']);
  });

  it('stops working as soon as the permission is revoked elsewhere', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    // Simulates Settings → Connected Sites → Revoke while the session is still open.
    store.permissions = revokePermission(store.permissions, ORIGIN);

    const response = await provider.handle(request('signMessage', { message: 'hi' }));
    expect(response.error?.code).toBe('ORIGIN_NOT_APPROVED');
  });
});

describe('createAssetListing', () => {
  const LIST = { assetName: 'RLM#BRBAEY6A94VXQ', priceSats: 500 * 100_000_000 };

  const connectFirst = async (host: ReturnType<typeof baseHost>) => {
    const provider = new ProviderService(ORIGIN, host);
    await provider.handle(request('connect'));
    return provider;
  };

  it('requires a permission', async () => {
    const host = createHost();
    const response = await new ProviderService(ORIGIN, host).handle(
      request('createAssetListing', LIST),
    );

    expect(response.error?.code).toBe('ORIGIN_NOT_APPROVED');
    expect(host.createAssetListing).not.toHaveBeenCalled();
  });

  it('reports WALLET_LOCKED before anything else', async () => {
    const host = createHost();
    const provider = await connectFirst(host);
    host.isLocked.mockReturnValue(true);

    const response = await provider.handle(request('createAssetListing', LIST));

    expect(response.error?.code).toBe('WALLET_LOCKED');
    expect(host.createAssetListing).not.toHaveBeenCalled();
  });

  it('takes an asset and a price — never a PSBT the site composed', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('createAssetListing', LIST));

    expect(host.requestSignAssetListingApproval).toHaveBeenCalledWith(
      ORIGIN,
      LIST.assetName,
      LIST.priceSats,
      ADDRESS,
    );
    expect(host.createAssetListing).toHaveBeenCalledWith(ADDRESS, {
      assetName: LIST.assetName,
      priceSats: LIST.priceSats,
      amount: undefined,
    });
    expect(response.result).toEqual(SIGNED_LISTING);
  });

  it('never lists when the user rejects', async () => {
    const host = createHost({ requestSignAssetListingApproval: vi.fn(async () => false) });
    const provider = await connectFirst(host);

    const response = await provider.handle(request('createAssetListing', LIST));

    expect(response.error?.code).toBe('USER_REJECTED');
    expect(host.createAssetListing).not.toHaveBeenCalled();
  });

  it('rejects a malformed asset name, price or amount without prompting', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    for (const params of [
      undefined,
      { priceSats: 1 },
      { assetName: '', priceSats: 1 },
      { assetName: 'X'.repeat(65), priceSats: 1 },
      { ...LIST, priceSats: 0 },
      { ...LIST, priceSats: -1 },
      { ...LIST, priceSats: 1.5 },
      { ...LIST, priceSats: '500' },
      { ...LIST, amount: 1 },
      { ...LIST, amount: 'not a number' },
    ]) {
      const response = await provider.handle(request('createAssetListing', params));
      expect(response.error?.code).toBe('INVALID_REQUEST');
    }
    expect(host.requestSignAssetListingApproval).not.toHaveBeenCalled();
  });
});

describe('completeAssetListing', () => {
  const connectFirst = async (host: ReturnType<typeof baseHost>) => {
    const provider = new ProviderService(ORIGIN, host);
    await provider.handle(request('connect'));
    return provider;
  };

  it('requires a permission', async () => {
    const host = createHost();
    const response = await new ProviderService(ORIGIN, host).handle(
      request('completeAssetListing', { psbt: PSBT }),
    );

    expect(response.error?.code).toBe('ORIGIN_NOT_APPROVED');
    expect(host.completeAssetListing).not.toHaveBeenCalled();
  });

  it('shows the buyer what the seller signed, then buys', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('completeAssetListing', { psbt: PSBT }));

    expect(host.requestBuyAssetApproval).toHaveBeenCalledWith(ORIGIN, PSBT, ADDRESS);
    expect(host.completeAssetListing).toHaveBeenCalledWith(ADDRESS, PSBT, true);
    expect(response.result).toEqual(BOUGHT);
  });

  it('passes broadcast: false through, so a caller can inspect the swap first', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    await provider.handle(request('completeAssetListing', { psbt: PSBT, broadcast: false }));

    // Silently ignoring this would send an irreversible transaction the caller asked to hold back.
    expect(host.completeAssetListing).toHaveBeenCalledWith(ADDRESS, PSBT, false);
  });

  it('never buys when the user rejects', async () => {
    const host = createHost({ requestBuyAssetApproval: vi.fn(async () => false) });
    const provider = await connectFirst(host);

    const response = await provider.handle(request('completeAssetListing', { psbt: PSBT }));

    expect(response.error?.code).toBe('USER_REJECTED');
    expect(host.completeAssetListing).not.toHaveBeenCalled();
  });
});

describe('signPsbt', () => {
  const connectFirst = async (host: ReturnType<typeof baseHost>) => {
    const provider = new ProviderService(ORIGIN, host);
    await provider.handle(request('connect'));
    return provider;
  };

  it('requires a permission', async () => {
    const host = createHost();
    const response = await new ProviderService(ORIGIN, host).handle(
      request('signPsbt', { psbt: PSBT }),
    );

    expect(response.error?.code).toBe('ORIGIN_NOT_APPROVED');
    expect(host.requestSignPsbtApproval).not.toHaveBeenCalled();
    expect(host.signPsbt).not.toHaveBeenCalled();
  });

  it('reports WALLET_LOCKED before anything else', async () => {
    const host = createHost();
    const provider = await connectFirst(host);
    host.isLocked.mockReturnValue(true);

    const response = await provider.handle(request('signPsbt', { psbt: PSBT }));

    expect(response.error?.code).toBe('WALLET_LOCKED');
    expect(host.signPsbt).not.toHaveBeenCalled();
  });

  it('always shows the approval screen, even for a remembered origin', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signPsbt', { psbt: PSBT }));

    expect(host.requestSignPsbtApproval).toHaveBeenCalledWith(ORIGIN, PSBT, ADDRESS, false);
    expect(response.result).toEqual(SIGNED_PSBT);
  });

  it('never signs when the user rejects the approval screen', async () => {
    const host = createHost({ requestSignPsbtApproval: vi.fn(async () => false) });
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signPsbt', { psbt: PSBT }));

    expect(response.error?.code).toBe('USER_REJECTED');
    expect(host.signPsbt).not.toHaveBeenCalled();
  });

  it('treats cancelled authentication as a rejection', async () => {
    const host = createHost({ signPsbt: vi.fn(async () => null) });
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signPsbt', { psbt: PSBT }));

    expect(response.error?.code).toBe('USER_REJECTED');
    expect(response.result).toBeUndefined();
  });

  it.each([
    ['no params', undefined],
    ['an empty psbt', { psbt: '' }],
    ['a non-string psbt', { psbt: 42 }],
    ['a non-base64 psbt', { psbt: 'not valid base64!!' }],
  ])('rejects %s as INVALID_REQUEST', async (_label, params) => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signPsbt', params));

    expect(response.error?.code).toBe('INVALID_REQUEST');
    expect(host.requestSignPsbtApproval).not.toHaveBeenCalled();
  });

  it('returns the signed PSBT and what happened to it — nothing else', async () => {
    const provider = await connectFirst(createHost());
    const response = await provider.handle(request('signPsbt', { psbt: PSBT }));

    expect(Object.keys(response.result as object).sort()).toEqual([
      'broadcast',
      'complete',
      'psbt',
      'signedInputs',
    ]);
  });

  it('does not broadcast unless the site asks', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signPsbt', { psbt: PSBT }));

    expect(host.signPsbt).toHaveBeenCalledWith(ADDRESS, PSBT, false);
    expect((response.result as SignPsbtResult).broadcast).toBe(false);
  });

  it('broadcasts when the site asks, and says so on the approval screen', async () => {
    const broadcastResult: SignPsbtResult = { ...SIGNED_PSBT, broadcast: true, txid: 'abc123' };
    const host = createHost({ signPsbt: vi.fn(async () => broadcastResult as SignPsbtResult | null) });
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signPsbt', { psbt: PSBT, broadcast: true }));

    // The user is told this will be sent, not merely signed.
    expect(host.requestSignPsbtApproval).toHaveBeenCalledWith(ORIGIN, PSBT, ADDRESS, true);
    expect(host.signPsbt).toHaveBeenCalledWith(ADDRESS, PSBT, true);
    expect(response.result).toEqual(broadcastResult);
  });

  it('rejects a non-boolean broadcast flag without prompting', async () => {
    const host = createHost();
    const provider = await connectFirst(host);

    const response = await provider.handle(request('signPsbt', { psbt: PSBT, broadcast: 'yes' }));

    expect(response.error?.code).toBe('INVALID_REQUEST');
    expect(host.requestSignPsbtApproval).not.toHaveBeenCalled();
  });
});

describe('getNetwork', () => {
  it('answers without requiring a permission', async () => {
    const response = await new ProviderService(ORIGIN, createHost()).handle(request('getNetwork'));
    expect(response.result).toEqual({ network: 'mainnet', genesisHash: null });
  });
});

describe('disconnect', () => {
  it('revokes the grant and announces it', async () => {
    const host = createHost();
    const provider = new ProviderService(ORIGIN, host);
    await provider.handle(request('connect'));

    const response = await provider.handle(request('disconnect'));

    expect(response.result).toEqual({ disconnected: true });
    expect(store.permissions).toEqual([]);
    expect(host.emit).toHaveBeenCalledWith('accountsChanged', { accounts: [] });
    expect(host.emit).toHaveBeenCalledWith('disconnect', expect.anything());
  });

  it('succeeds for an origin that was never connected', async () => {
    const response = await new ProviderService(ORIGIN, createHost()).handle(request('disconnect'));
    expect(response.result).toEqual({ disconnected: true });
  });

  it('forces the next connect to prompt again', async () => {
    const host = createHost();
    const provider = new ProviderService(ORIGIN, host);
    await provider.handle(request('connect'));
    await provider.handle(request('disconnect'));

    host.requestConnectApproval.mockClear();
    await provider.handle(request('connect'));

    expect(host.requestConnectApproval).toHaveBeenCalledTimes(1);
  });
});

describe('host failures', () => {
  it('does not leak internal errors to the page', async () => {
    const host = createHost({
      signMessage: vi.fn(async () => {
        throw new Error('decryption failed for wallet xprv...');
      }),
    });
    const provider = new ProviderService(ORIGIN, host);
    await provider.handle(request('connect'));

    const response = await provider.handle(request('signMessage', { message: 'hi' }));

    expect(response.error?.code).toBe('INVALID_REQUEST');
    expect(JSON.stringify(response)).not.toContain('xprv');
  });
});
