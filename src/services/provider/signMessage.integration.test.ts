import { describe, expect, it, vi } from 'vitest';

import { OriginPermission } from '@/types/avianConnect';
import { grantPermission, touchPermission } from './permissions';
import { ProviderService, ProviderHost } from './ProviderService';
import { WalletService } from '@/services/wallet/WalletService';

/**
 * End-to-end cover for the claim the manual walkthrough makes: a signature obtained through
 * Avian Connect verifies with the very call Message Utilities → Verify uses. Real key
 * generation and real signing; only the permission store is in memory.
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
    revoke: async () => {
      store.permissions = [];
    },
    touch: async (origin: string) => {
      store.permissions = touchPermission(store.permissions, origin, 2000);
    },
  },
}));

const ORIGIN = 'https://realm.example';
const PASSWORD = 'testpassword123';
const MESSAGE = 'realm.example wants you to sign in with your Avian address.\nNonce: 0123abcd';

describe('signMessage over Avian Connect', () => {
  it('returns a signature that verifyMessage accepts for the connected address', async () => {
    const wallet = new WalletService();
    const generated = await wallet.generateWallet(PASSWORD, false);

    const host: ProviderHost = {
      isLocked: () => false,
      requestConnectApproval: async () => ({
        approved: true,
        accounts: [generated.address],
        remember: true,
      }),
      requestSignApproval: async () => true,
      signMessage: (_account, message) =>
        wallet.signMessage(generated.privateKey, message, PASSWORD),
      requestSignPsbtApproval: async () => true,
      signPsbt: async () => null,
      getPublicKey: async () => undefined,
      getNetwork: async () => ({ network: 'mainnet', genesisHash: null }),
      requestSignAssetListingApproval: async () => true,
    signAssetListing: async () => null,
    emit: () => undefined,
    };

    const provider = new ProviderService(ORIGIN, host);

    const connected = await provider.handle({ avianConnect: 1, id: '1', method: 'connect' });
    expect(connected.result).toEqual({ address: generated.address });

    const signed = await provider.handle({
      avianConnect: 1,
      id: '2',
      method: 'signMessage',
      params: { message: MESSAGE },
    });

    const { signature } = signed.result as { signature: string };
    expect(signature).toMatch(/^[A-Za-z0-9+/]+=*$/);

    const verified = await wallet.verifyMessage(generated.address, MESSAGE, signature, true);
    expect(typeof verified === 'object' && verified.isValid).toBe(true);

    // A tampered message must not verify against the same signature.
    expect(await wallet.verifyMessage(generated.address, `${MESSAGE} extra`, signature)).toBe(false);
  });
});
