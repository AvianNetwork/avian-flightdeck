import { beforeEach, describe, expect, it } from 'vitest';

import { StorageService } from './StorageService';
import { inspectEncryptionFormat } from '@/services/wallet/encryption';
import { resetStorage } from '@/test/helpers';

const ADDRESS_A = 'RAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ADDRESS_B = 'RBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const createWallet = (overrides: Record<string, unknown> = {}) =>
  StorageService.createWallet({
    name: 'Main',
    address: ADDRESS_A,
    privateKey: 'encrypted-key-blob',
    isEncrypted: true,
    ...overrides,
  });

beforeEach(() => {
  resetStorage();
});

describe('biometric password migration', () => {
  // A real scrypt v2 blob: decrypts with secureKey 'golden-scrypt2-pw' to 'golden scrypt v2 secret'.
  // Stands in for a biometric credential enrolled before the move to Argon2id.
  const SCRYPT_BIO_BLOB =
    'v2.eyJrZGYiOiJzY3J5cHQiLCJOIjoxNjM4NCwiciI6OCwicCI6MSwiZGtMZW4iOjMyfQ==.RdYnkfB8LnYg74SIohSK3Dc/PZM8JcDwD9taYVX9ALekeIkdW+2iJidL8VgsbWL3cqrMI+yrpy1yqAfhRqAEPLzZQAAqLPDWlcHMqDFKenRMoQLDZNH016KuRlNKJomXNxlq17DMR7GrBtvJL4jc4KymqkdF0qo=';
  const SECURE_KEY = 'golden-scrypt2-pw';
  const EXPECTED_PW = 'golden scrypt v2 secret';

  it('recovers the password and re-seals an older scrypt blob as Argon2id on read', async () => {
    const wallet = await createWallet();
    // Seed a biometric password sealed in the pre-Argon2id scrypt format.
    await StorageService.saveWalletWithBiometricData(
      { ...wallet, encryptedBiometricPassword: SCRYPT_BIO_BLOB },
      [1, 2, 3],
    );
    expect(inspectEncryptionFormat(SCRYPT_BIO_BLOB)).toBe('scrypt');

    const recovered = await StorageService.getEncryptedWalletPassword(SECURE_KEY, ADDRESS_A);
    expect(recovered).toBe(EXPECTED_PW);

    // The stored blob is upgraded to Argon2id, so future biometric logins skip the slow scrypt path…
    const after = await StorageService.getWalletByAddress(ADDRESS_A);
    expect(after?.encryptedBiometricPassword).toBeTruthy();
    expect(inspectEncryptionFormat(after!.encryptedBiometricPassword!)).toBe('argon2id');
    // …and it still unlocks to the same password.
    expect(await StorageService.getEncryptedWalletPassword(SECURE_KEY, ADDRESS_A)).toBe(EXPECTED_PW);
  });

  it('leaves an already-Argon2id biometric blob untouched', async () => {
    await createWallet();
    await StorageService.setEncryptedWalletPassword(SECURE_KEY, 'my-wallet-pw', ADDRESS_A);
    const before = (await StorageService.getWalletByAddress(ADDRESS_A))?.encryptedBiometricPassword;
    expect(inspectEncryptionFormat(before!)).toBe('argon2id');

    expect(await StorageService.getEncryptedWalletPassword(SECURE_KEY, ADDRESS_A)).toBe(
      'my-wallet-pw',
    );

    // No needless rewrite: secureEncrypt uses a fresh salt/IV each call, so an untouched blob is
    // byte-for-byte identical.
    const after = (await StorageService.getWalletByAddress(ADDRESS_A))?.encryptedBiometricPassword;
    expect(after).toBe(before);
  });
});

describe('per-wallet biometrics', () => {
  it('does not hand one wallet another wallet credential', async () => {
    // Enrolling wallet A also writes a global credential preference for older installs. Asking
    // about B must not return A's: the caller reads a credential as "this wallet has biometrics",
    // and B's password lookup is correctly scoped, so the unlock prompts and then finds nothing.
    const enrolled = await createWallet({ name: 'Enrolled' });
    await StorageService.setBiometricCredential([1, 2, 3], ADDRESS_A);
    await createWallet({ name: 'Not enrolled', address: ADDRESS_B, makeActive: false });

    expect(await StorageService.getBiometricCredential(ADDRESS_A)).toEqual([1, 2, 3]);
    expect(await StorageService.getBiometricCredential(ADDRESS_B)).toBeNull();
    expect(enrolled.address).toBe(ADDRESS_A);
  });

  it('keeps the enablement flags apart too', async () => {
    await createWallet({ name: 'Enrolled' });
    await StorageService.setBiometricCredential([1, 2, 3], ADDRESS_A);
    await createWallet({ name: 'Not enrolled', address: ADDRESS_B, makeActive: false });

    expect(await StorageService.isBiometricEnabledForWallet(ADDRESS_A)).toBe(true);
    expect(await StorageService.isBiometricEnabledForWallet(ADDRESS_B)).toBe(false);
  });

  it('still answers for the active wallet when no wallet is named', async () => {
    // The unnamed form is what older call sites use; it may fall back, a named one may not.
    await createWallet({ name: 'Enrolled' });
    await StorageService.setBiometricCredential([4, 5, 6], ADDRESS_A);

    expect(await StorageService.getBiometricCredential()).toEqual([4, 5, 6]);
  });
});

describe('creating wallets', () => {
  it('round-trips a wallet through IndexedDB', async () => {
    const created = await createWallet();

    expect(created.id).toBeTypeOf('number');
    const all = await StorageService.getAllWallets();
    expect(all).toHaveLength(1);
    expect(all[0].address).toBe(ADDRESS_A);
    expect(all[0].isEncrypted).toBe(true);
  });

  it('rejects a duplicate name', async () => {
    await createWallet();
    await expect(createWallet({ address: ADDRESS_B })).rejects.toThrow(/already exists/);
    expect(await StorageService.getWalletCount()).toBe(1);
  });

  it('rejects a duplicate address', async () => {
    await createWallet();
    await expect(createWallet({ name: 'Other' })).rejects.toThrow(/already exists/);
    expect(await StorageService.getWalletCount()).toBe(1);
  });

  it('stores the optional HD fields only when supplied', async () => {
    await createWallet({ coinType: 175, addressType: 'p2wpkh', descriptor: 'wpkh(xpub…)' });

    const stored = await StorageService.getWalletByAddress(ADDRESS_A);
    expect(stored?.coinType).toBe(175);
    expect(stored?.addressType).toBe('p2wpkh');

    resetStorage();
    await createWallet();
    const plain = await StorageService.getWalletByAddress(ADDRESS_A);
    expect(plain).not.toHaveProperty('coinType');
    expect(plain).not.toHaveProperty('descriptor');
  });

  it('makes the first wallet active by default', async () => {
    await createWallet();
    expect((await StorageService.getActiveWallet())?.name).toBe('Main');
  });

  it('honours makeActive: false', async () => {
    await createWallet();
    await createWallet({ name: 'Second', address: ADDRESS_B, makeActive: false });

    expect((await StorageService.getActiveWallet())?.name).toBe('Main');
  });
});

describe('lookups', () => {
  it('finds a wallet by address, name and id', async () => {
    const created = await createWallet();

    expect((await StorageService.getWalletByAddress(ADDRESS_A))?.name).toBe('Main');
    expect((await StorageService.getWalletByName('Main'))?.address).toBe(ADDRESS_A);
    expect((await StorageService.getWalletById(created.id!))?.address).toBe(ADDRESS_A);
  });

  it('returns null rather than throwing for unknown records', async () => {
    expect(await StorageService.getWalletByAddress('RNope')).toBeNull();
    expect(await StorageService.getWalletByName('Nope')).toBeNull();
    expect(await StorageService.getWalletById(4242)).toBeNull();
    expect(await StorageService.getActiveWallet()).toBeNull();
  });

  it('treats both mnemonic and descriptor wallets as HD-capable', async () => {
    // The UI gates the derived-address panel and HD UTXO scan on this, so a descriptor
    // import — which stores an account xprv instead of a mnemonic — must qualify too.
    await createWallet({ mnemonic: 'encrypted-mnemonic-blob' });
    expect(await StorageService.hasHdCapability()).toBe(true);

    resetStorage();
    await createWallet({ xprv: 'encrypted-xprv-blob' });
    expect(await StorageService.hasHdCapability()).toBe(true);
    expect(await StorageService.hasMnemonic()).toBe(false);

    resetStorage();
    await createWallet();
    expect(await StorageService.hasHdCapability()).toBe(false);
  });

  it('reports emptiness consistently', async () => {
    expect(await StorageService.hasWallet()).toBe(false);
    expect(await StorageService.getWalletCount()).toBe(0);
    expect(await StorageService.getAllWallets()).toEqual([]);
    expect(await StorageService.walletExists(ADDRESS_A)).toBe(false);
  });
});

describe('switching wallets', () => {
  const twoWallets = async () => {
    const one = await createWallet({ name: 'One' });
    const two = await createWallet({ name: 'Two', address: ADDRESS_B, makeActive: false });
    return { one, two };
  };

  it('leaves exactly one wallet active', async () => {
    const { two } = await twoWallets();

    expect(await StorageService.switchToWallet(two.id!)).toBe(true);

    const all = await StorageService.getAllWallets();
    expect(all.filter((entry) => entry.isActive)).toHaveLength(1);
    expect((await StorageService.getActiveWallet())?.name).toBe('Two');
  });

  it('refuses to switch to a wallet that does not exist and leaves the active one alone', async () => {
    await twoWallets();

    expect(await StorageService.switchToWallet(9999)).toBe(false);
    expect((await StorageService.getActiveWallet())?.name).toBe('One');
  });

  it('is a no-op when the target is already active', async () => {
    const { one } = await twoWallets();

    expect(await StorageService.switchToWallet(one.id!)).toBe(true);
    expect((await StorageService.getActiveWallet())?.name).toBe('One');
  });
});

describe('mutating wallets', () => {
  it('renames a wallet', async () => {
    const created = await createWallet();

    expect(await StorageService.updateWalletName(created.id!, 'Renamed')).toBe(true);
    expect((await StorageService.getWalletById(created.id!))?.name).toBe('Renamed');
  });

  it('replaces the stored private key', async () => {
    const created = await createWallet();

    expect(await StorageService.updateWalletPrivateKey(created.id!, 'new-blob')).toBe(true);
    expect((await StorageService.getWalletById(created.id!))?.privateKey).toBe('new-blob');
  });

  it('deletes a wallet', async () => {
    const created = await createWallet();

    expect(await StorageService.deleteWallet(created.id!)).toBe(true);
    expect(await StorageService.getWalletCount()).toBe(0);
    expect(await StorageService.walletExists(ADDRESS_A)).toBe(false);
  });
});

describe('preferences', () => {
  it('returns documented defaults before anything is written', async () => {
    expect(await StorageService.getCurrency()).toBe('USD');
    expect(await StorageService.getAVNUnits()).toBe('AVN');
    expect(await StorageService.getLastBalance()).toBe(0);
    expect(await StorageService.getExchangeRate()).toBe(0);
    expect(await StorageService.getChangeAddressCount()).toBe(5);
    expect(await StorageService.getSettings()).toEqual({});
  });

  it('overwrites a preference rather than appending a second record', async () => {
    await StorageService.setCurrency('GBP');
    await StorageService.setCurrency('EUR');

    expect(await StorageService.getCurrency()).toBe('EUR');
  });

  it('keeps a single row per preference even under concurrent writes to the same key', async () => {
    // The old two-transaction find-then-put could insert duplicate rows for one key when racing.
    await Promise.all(['USD', 'GBP', 'EUR', 'JPY'].map((c) => StorageService.setCurrency(c)));

    // One value wins, and a subsequent write still overwrites cleanly (no accumulated duplicates
    // that a later read might pick up instead).
    const settled = await StorageService.getCurrency();
    expect(['USD', 'GBP', 'EUR', 'JPY']).toContain(settled);

    await StorageService.setCurrency('CAD');
    expect(await StorageService.getCurrency()).toBe('CAD');
  });

  it('clamps the change address count to a sane range', async () => {
    await StorageService.setChangeAddressCount(0);
    expect(await StorageService.getChangeAddressCount()).toBe(1);

    await StorageService.setChangeAddressCount(500);
    expect(await StorageService.getChangeAddressCount()).toBe(20);
  });

  it('accepts settings as either an object or a JSON string', async () => {
    await StorageService.setSettings({ theme: 'dark' });
    expect(await StorageService.getSettings()).toEqual({ theme: 'dark' });

    await StorageService.setSettings(JSON.stringify({ theme: 'light' }));
    expect(await StorageService.getSettings()).toEqual({ theme: 'light' });
  });
});

describe('atomic settings mutation', () => {
  it('merges into the existing settings and returns the result', async () => {
    await StorageService.setSettings({ theme: 'dark' });

    const result = await StorageService.mutateSettings((current) => ({
      ...current,
      currency: 'GBP',
    }));

    expect(result).toEqual({ theme: 'dark', currency: 'GBP' });
    expect(await StorageService.getSettings()).toEqual({ theme: 'dark', currency: 'GBP' });
  });

  it('starts from an empty object when nothing is stored', async () => {
    const result = await StorageService.mutateSettings((current) => ({ ...current, a: 1 }));
    expect(result).toEqual({ a: 1 });
  });

  it('loses no writes when many mutations run concurrently', async () => {
    // The whole point of the fix: each of these reads-modifies-writes the one settings blob. The
    // old getSettings→mutate→setSettings pair left a gap in which a concurrent writer read stale
    // data and clobbered it. With an atomic single-transaction merge, every key survives.
    const keys = Array.from({ length: 25 }, (_, i) => `key_${i}`);

    await Promise.all(
      keys.map((key) => StorageService.mutateSettings((current) => ({ ...current, [key]: key }))),
    );

    const settings = await StorageService.getSettings();
    for (const key of keys) {
      expect(settings[key]).toBe(key);
    }
    expect(Object.keys(settings)).toHaveLength(keys.length);
  });

  it('keeps both a security-settings write and a watch-list write when they race', async () => {
    // The reported failure: SecurityService writes settings.security_settings while
    // WatchAddressService writes settings.watched_addresses_<addr>, and one clobbers the other.
    await Promise.all([
      StorageService.mutateSettings((current) => ({
        ...current,
        security_settings: { autoLock: { enabled: true } },
      })),
      StorageService.mutateSettings((current) => ({
        ...current,
        watched_addresses_RAbc: JSON.stringify([{ watch_address: 'RXyz' }]),
      })),
    ]);

    const settings = await StorageService.getSettings();
    expect(settings.security_settings).toEqual({ autoLock: { enabled: true } });
    expect(settings.watched_addresses_RAbc).toBe(JSON.stringify([{ watch_address: 'RXyz' }]));
  });

  it('applies concurrent updates to the same key in some order without corrupting the store', async () => {
    await Promise.all(
      [1, 2, 3, 4, 5].map((n) =>
        StorageService.mutateSettings((current) => ({ ...current, counter: n })),
      ),
    );

    const settings = await StorageService.getSettings();
    // One of the writers wins; the store is a single coherent object, not a lost/duplicated mess.
    expect([1, 2, 3, 4, 5]).toContain(settings.counter);
  });
});

describe('Avian Connect storage', () => {
  it('starts empty', async () => {
    expect(await StorageService.getConnectPermissions()).toEqual([]);
    expect(await StorageService.getKnownPublicKey('RAny')).toBeNull();
    expect(await StorageService.getCachedGenesisHash()).toBeNull();
  });

  it('round-trips permission records', async () => {
    const permissions = [
      { origin: 'https://realm.example', accounts: [ADDRESS_A], grantedAt: 1, lastUsedAt: 2 },
    ];
    await StorageService.setConnectPermissions(permissions);

    expect(await StorageService.getConnectPermissions()).toEqual(permissions);
  });

  it('accumulates public keys per address without dropping earlier ones', async () => {
    await StorageService.setKnownPublicKey(ADDRESS_A, '02aa');
    await StorageService.setKnownPublicKey(ADDRESS_B, '02bb');

    expect(await StorageService.getKnownPublicKey(ADDRESS_A)).toBe('02aa');
    expect(await StorageService.getKnownPublicKey(ADDRESS_B)).toBe('02bb');
  });
});

describe('transaction history', () => {
  const tx = (overrides: Record<string, unknown> = {}) => ({
    txid: 'a'.repeat(64),
    amount: 1.5,
    address: 'RRecipient',
    walletAddress: ADDRESS_A,
    type: 'send' as const,
    timestamp: new Date('2026-01-02T00:00:00Z'),
    confirmations: 3,
    ...overrides,
  });

  it('stores a transaction and reads it back for the wallet', async () => {
    await StorageService.saveTransaction(tx());

    const history = await StorageService.getTransactionHistory(ADDRESS_A);
    expect(history).toHaveLength(1);
    expect(history[0].txid).toBe('a'.repeat(64));
  });

  it('updates rather than duplicates when the same txid and type is saved again', async () => {
    await StorageService.saveTransaction(tx({ confirmations: 1 }));
    await StorageService.saveTransaction(tx({ confirmations: 6 }));

    const history = await StorageService.getTransactionHistory(ADDRESS_A);
    expect(history).toHaveLength(1);
    expect(history[0].confirmations).toBe(6);
  });

  it('keeps the send and receive legs of one txid apart', async () => {
    await StorageService.saveTransaction(tx({ type: 'send' }));
    await StorageService.saveTransaction(tx({ type: 'receive' }));

    expect(await StorageService.getTransactionHistory(ADDRESS_A)).toHaveLength(2);
  });

  it('does not leak one wallet’s transactions into another’s history', async () => {
    await StorageService.saveTransaction(tx());
    await StorageService.saveTransaction(
      tx({ txid: 'b'.repeat(64), walletAddress: ADDRESS_B }),
    );

    const history = await StorageService.getTransactionHistory(ADDRESS_A);
    expect(history).toHaveLength(1);
    expect(history[0].txid).toBe('a'.repeat(64));
  });

  it('clears history for a single address only', async () => {
    await StorageService.saveTransaction(tx());
    await StorageService.saveTransaction(tx({ txid: 'b'.repeat(64), address: 'ROther' }));

    await StorageService.clearTransactionHistoryForAddress('RRecipient');

    const remaining = await StorageService.getTransactionHistory(ADDRESS_A);
    expect(remaining.map((entry) => entry.address)).toEqual(['ROther']);
  });
});

describe('address book', () => {
  const contact = (overrides: Record<string, unknown> = {}) => ({
    id: '',
    name: 'Alice',
    address: ADDRESS_B,
    dateAdded: new Date('2026-01-01T00:00:00Z'),
    useCount: 0,
    ...overrides,
  });

  it('assigns an id on save, writing it back onto the caller’s object', async () => {
    const alice = contact();
    expect(await StorageService.saveAddress(alice)).toBe(true);

    const stored = await StorageService.getSavedAddresses();
    expect(stored).toHaveLength(1);
    expect(stored[0].id).toBeTruthy();
    // Callers read the generated id straight off the object they passed in.
    expect(alice.id).toBe(stored[0].id);
  });

  it('updates in place and keeps the original id when the same address is saved again', async () => {
    const alice = contact();
    await StorageService.saveAddress(alice);
    const originalId = alice.id;

    await StorageService.saveAddress(contact({ name: 'Alice Renamed' }));

    const stored = await StorageService.getSavedAddresses();
    expect(stored).toHaveLength(1);
    expect(stored[0].name).toBe('Alice Renamed');
    expect(stored[0].id).toBe(originalId);
  });

  it('updates a contact by id and refuses an unknown one', async () => {
    const alice = contact();
    await StorageService.saveAddress(alice);

    expect(await StorageService.updateAddress({ ...alice, name: 'Alice B' })).toBe(true);
    expect((await StorageService.getSavedAddresses())[0].name).toBe('Alice B');

    expect(await StorageService.updateAddress(contact({ id: 'nope' }))).toBe(false);
  });

  it('deletes a contact by id', async () => {
    const alice = contact();
    await StorageService.saveAddress(alice);

    expect(await StorageService.deleteAddress(alice.id)).toBe(true);
    expect(await StorageService.getSavedAddresses()).toEqual([]);
  });

  it('reports success when deleting an id that is not there, leaving the book intact', async () => {
    // Documents current behaviour: deleteAddress filters and cannot tell "removed" from
    // "was never present", so the return value is not a existence check.
    const alice = contact();
    await StorageService.saveAddress(alice);

    expect(await StorageService.deleteAddress('never-existed')).toBe(true);
    expect(await StorageService.getSavedAddresses()).toHaveLength(1);
  });

  it('tracks usage counts', async () => {
    await StorageService.saveAddress(contact());

    await StorageService.updateAddressUsage(ADDRESS_B);
    await StorageService.updateAddressUsage(ADDRESS_B);

    const [stored] = await StorageService.getSavedAddresses();
    expect(stored.useCount).toBe(2);
    expect(stored.lastUsed).toBeInstanceOf(Date);
  });
});

describe('test isolation', () => {
  it('sees an empty database even though earlier tests wrote to one', async () => {
    expect(await StorageService.getAllWallets()).toEqual([]);
    expect(await StorageService.getConnectPermissions()).toEqual([]);
    expect(await StorageService.getSavedAddresses()).toEqual([]);
  });
});
