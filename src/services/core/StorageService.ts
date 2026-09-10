// Required imports
import { SavedAddress } from '../../types/addressBook';
import { OriginPermission } from '../../types/avianConnect';
import { toast } from 'sonner';
import { secureEncrypt, decryptData } from '../wallet/encryption';
// Type-only: erased at compile time, so it does not pull WalletService (and its secp256k1
// dependency) into the bundle.
import type { AddressType } from '../wallet/WalletService';
import { storageLogger } from '@/lib/Logger';

interface WalletData {
  id?: number;
  name: string;
  address: string;
  privateKey: string;
  mnemonic?: string;
  bip39Passphrase?: string; // Optional encrypted BIP39 passphrase (25th word)
  coinType?: 921 | 175; // BIP44 coin type for derivation (default: 921 for Avian, 175 for Ravencoin legacy)
  addressType?: AddressType; // Script type / BIP standard: 'p2pkh' | 'p2wpkh' | 'p2sh-p2wpkh'
  descriptor?: string;  // BIP380 output-script descriptor with checksum
  xprv?: string;        // Encrypted account-level xprv for descriptor-imported HD wallets
  isEncrypted: boolean;
  isActive: boolean;
  createdAt: Date;
  lastAccessed: Date;
  balance?: number;
  lastBalanceUpdate?: Date;
  // Biometric fields
  biometricsEnabled?: boolean;
  biometricCredentialId?: number[];
  encryptedBiometricPassword?: string;
}

/**
 * Interface to track wallet switch state data
 * Used to prevent false notifications during wallet switches
 */
interface WalletSwitchState {
  inProgress: boolean;
  timestamp: number;
  fromAddress?: string;
  toAddress?: string;
  fromId?: number;
  toId?: number;
}

export interface TransactionData {
  id?: number;
  txid: string;
  amount: number;
  address: string; // For 'send': recipient address, for 'receive': sender address
  fromAddress?: string; // The sender's address
  walletAddress: string; // The address of the wallet this transaction belongs to
  type: 'send' | 'receive';
  timestamp: Date;
  confirmations: number;
  blockHeight?: number;
}

interface PreferenceData {
  id?: number;
  key: string;
  value: any;
  updatedAt: Date;
}

export class StorageService {
  private static dbName = 'AvianFlightDeck';
  private static oldDbName = 'AvianWalletDB';
  private static dbVersion = 6; // Incrementing database version for watched address balances integration
  private static db: IDBDatabase | null = null;
  private static migrationCompleted = false;

  // Initialize IndexedDB
  private static async initDB(): Promise<IDBDatabase> {
    if (this.db) {
      return this.db;
    }

    // Check for migration before opening the new database
    if (!this.migrationCompleted) {
      await this.migrateFromOldDatabase();
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.dbVersion);

      request.onerror = () => {
        reject(new Error('Failed to open IndexedDB'));
      };

      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        const transaction = (event.target as IDBOpenDBRequest).transaction!;

        // Wallet store
        if (!db.objectStoreNames.contains('wallets')) {
          const walletStore = db.createObjectStore('wallets', {
            keyPath: 'id',
            autoIncrement: true,
          });
          walletStore.createIndex('address', 'address', { unique: true });
          walletStore.createIndex('name', 'name', { unique: true });
          walletStore.createIndex('isActive', 'isActive', { unique: false });
        }

        // Transactions store
        if (!db.objectStoreNames.contains('transactions')) {
          const txStore = db.createObjectStore('transactions', {
            keyPath: 'id',
            autoIncrement: true,
          });
          txStore.createIndex('txid', 'txid', { unique: false }); // Changed to non-unique to allow multiple records with same txid
          txStore.createIndex('address', 'address', { unique: false });
          txStore.createIndex('fromAddress', 'fromAddress', { unique: false });
          txStore.createIndex('walletAddress', 'walletAddress', { unique: false });
          txStore.createIndex('timestamp', 'timestamp', { unique: false });
        } else if (event.oldVersion < 3) {
          // Add walletAddress index for existing transactions store
          const txStore = transaction.objectStore('transactions');
          if (!txStore.indexNames.contains('walletAddress')) {
            txStore.createIndex('walletAddress', 'walletAddress', { unique: false });
          }
        } else if (event.oldVersion < 4) {
          // Fix txid uniqueness issue in version 4
          try {
            // We need to delete the txid index and recreate it as non-unique
            const txStore = transaction.objectStore('transactions');

            // Check if the index exists before trying to delete it
            if (txStore.indexNames.contains('txid')) {
              // This will rebuild the index correctly with uniqueness set to false
              txStore.deleteIndex('txid');
              txStore.createIndex('txid', 'txid', { unique: false });
            }

            // Create a compound index for txid + type + walletAddress to ensure uniqueness
            // for the combination of these values
            txStore.createIndex('txid_type_wallet', ['txid', 'type', 'walletAddress'], {
              unique: true,
            });
          } catch (err) {
            storageLogger.error('Error during database upgrade to version 4:', err);
            // Continue with the upgrade process even if there's an error
          }
        } else if (event.oldVersion < 5) {
          // Migration for version 5: Move biometric data into wallet records
          try {
            // Retrieve biometric preferences asynchronously
            const getAllRequest = transaction.objectStore('preferences').getAll();

            getAllRequest.onsuccess = async () => {
              try {
                const allPreferences = getAllRequest.result;

                // Find biometric-related preferences
                const biometricEnabledPref = allPreferences.find(
                  (pref) => pref.key === 'biometricEnabled',
                );
                const biometricWalletCredentialsPref = allPreferences.find(
                  (pref) => pref.key === 'biometricWalletCredentials',
                );
                const biometricWalletPasswordsPref = allPreferences.find(
                  (pref) => pref.key === 'biometricWalletPasswords',
                );

                if (
                  biometricEnabledPref?.value === true &&
                  (biometricWalletCredentialsPref?.value || biometricWalletPasswordsPref?.value)
                ) {
                  const walletCredentials = biometricWalletCredentialsPref?.value || {};
                  const walletPasswords = biometricWalletPasswordsPref?.value || {};

                  // Get all wallets to update
                  const walletStore = transaction.objectStore('wallets');
                  const walletsRequest = walletStore.getAll();

                  walletsRequest.onsuccess = () => {
                    const wallets = walletsRequest.result;

                    // Update each wallet with its biometric data
                    wallets.forEach((wallet) => {
                      if (
                        wallet.address &&
                        walletCredentials[wallet.address] &&
                        walletPasswords[wallet.address]
                      ) {
                        // Update wallet with biometric data
                        wallet.biometricsEnabled = true;
                        wallet.biometricCredentialId = walletCredentials[wallet.address];
                        wallet.encryptedBiometricPassword = walletPasswords[wallet.address];

                        // Save the updated wallet
                        walletStore.put(wallet);
                      }
                    });
                  };
                }
              } catch (migrationError) {
                storageLogger.error('Error during biometric data migration:', migrationError);
              }
            };
          } catch (err) {
            storageLogger.error('Error during database upgrade to version 5:', err);
            // Continue with the upgrade process even if there's an error
          }
        } else if (event.oldVersion < 6) {
          // Version 6: Add watched address balances store
          try {
            // Create object store for watched address balances if it doesn't exist
            if (!db.objectStoreNames.contains('watched_address_balances')) {
              const watchedAddressStore = db.createObjectStore('watched_address_balances', {
                keyPath: 'address',
              });
              watchedAddressStore.createIndex('lastChecked', 'lastChecked', { unique: false });
              storageLogger.info('Created watched address balances store in main database');

              // Migrate data from old database if possible
              try {
                const migrateRequest = indexedDB.open('avian-wallet', 1);

                migrateRequest.onsuccess = function (event) {
                  try {
                    const oldDb = migrateRequest.result;

                    if (oldDb.objectStoreNames.contains('watched_address_balances')) {
                      const oldTx = oldDb.transaction(['watched_address_balances'], 'readonly');
                      const oldStore = oldTx.objectStore('watched_address_balances');
                      const getAllRequest = oldStore.getAll();

                      getAllRequest.onsuccess = function () {
                        const balances = getAllRequest.result;

                        if (balances && balances.length > 0) {
                          // Add migrated balances to the new store
                          const newTx = db.transaction(['watched_address_balances'], 'readwrite');
                          const newStore = newTx.objectStore('watched_address_balances');

                          balances.forEach((balance) => {
                            newStore.add(balance);
                          });

                          storageLogger.info(
                            `Migrated ${balances.length} watched address balances`,
                          );
                        }
                      };
                    }
                  } catch (migrateErr) {
                    storageLogger.error(
                      'Error accessing old watched address database:',
                      migrateErr,
                    );
                  }
                };
              } catch (migrateErr) {
                storageLogger.error('Error during watched address balance migration:', migrateErr);
              }
            }
          } catch (err) {
            storageLogger.error('Error during database upgrade to version 6:', err);
            // Continue with the upgrade process even if there's an error
          }
        }

        // Preferences store
        if (!db.objectStoreNames.contains('preferences')) {
          const prefStore = db.createObjectStore('preferences', {
            keyPath: 'id',
            autoIncrement: true,
          });
          prefStore.createIndex('key', 'key', { unique: true });
        }
      };
    });
  }

  // Database migration from old AvianWalletDB to new AvianFlightDeck
  private static async migrateFromOldDatabase(): Promise<void> {
    try {
      // Check if migration has already been completed
      const migrationFlag = localStorage.getItem('avian_db_migration_completed');
      if (migrationFlag === 'true') {
        this.migrationCompleted = true;
        return;
      }

      // Check if old database exists
      const oldDbExists = await this.checkDatabaseExists(this.oldDbName);
      if (!oldDbExists) {
        // No old database to migrate from
        localStorage.setItem('avian_db_migration_completed', 'true');
        this.migrationCompleted = true;
        return;
      }

      storageLogger.info('Starting migration from AvianWalletDB to AvianFlightDeck...');

      // Open the old database
      const oldDb = await this.openDatabase(this.oldDbName, undefined);
      if (!oldDb) {
        storageLogger.warn('Could not open old database for migration');
        localStorage.setItem('avian_db_migration_completed', 'true');
        this.migrationCompleted = true;
        return;
      }

      // Open the new database (without triggering another migration)
      this.migrationCompleted = true; // Temporarily set to avoid recursion
      const newDb = await this.openDatabase(this.dbName, this.dbVersion);
      if (!newDb) {
        storageLogger.error('Could not open new database for migration');
        return;
      }

      let migratedCount = 0;

      // Migrate wallets
      if (oldDb.objectStoreNames.contains('wallets')) {
        const wallets = await this.getAllFromStore(oldDb, 'wallets');
        if (wallets.length > 0) {
          await this.copyDataToNewDb(newDb, 'wallets', wallets);
          migratedCount += wallets.length;
          storageLogger.info(`Migrated ${wallets.length} wallets`);
        }
      }

      // Migrate transactions
      if (oldDb.objectStoreNames.contains('transactions')) {
        const transactions = await this.getAllFromStore(oldDb, 'transactions');
        if (transactions.length > 0) {
          await this.copyDataToNewDb(newDb, 'transactions', transactions);
          migratedCount += transactions.length;
          storageLogger.info(`Migrated ${transactions.length} transactions`);
        }
      }

      // Migrate preferences
      if (oldDb.objectStoreNames.contains('preferences')) {
        const preferences = await this.getAllFromStore(oldDb, 'preferences');
        if (preferences.length > 0) {
          await this.copyDataToNewDb(newDb, 'preferences', preferences);
          migratedCount += preferences.length;
          storageLogger.info(`Migrated ${preferences.length} preferences`);
        }
      }

      // Migrate watched address balances if they exist
      if (oldDb.objectStoreNames.contains('watched_address_balances')) {
        const balances = await this.getAllFromStore(oldDb, 'watched_address_balances');
        if (balances.length > 0) {
          await this.copyDataToNewDb(newDb, 'watched_address_balances', balances);
          migratedCount += balances.length;
          storageLogger.info(`Migrated ${balances.length} watched address balances`);
        }
      }

      // Close databases
      oldDb.close();
      newDb.close();

      if (migratedCount > 0) {
        storageLogger.info(
          `Migration completed successfully! Migrated ${migratedCount} total records.`,
        );

        // Delete the old database after successful migration
        await this.deleteDatabase(this.oldDbName);
        storageLogger.info('Old database cleaned up successfully');
      }

      // Mark migration as completed
      localStorage.setItem('avian_db_migration_completed', 'true');
      this.migrationCompleted = true;
    } catch (error) {
      storageLogger.error('Database migration failed:', error);
      // Mark migration as completed to avoid infinite retry loops
      localStorage.setItem('avian_db_migration_completed', 'true');
      this.migrationCompleted = true;
    }
  }

  // Helper method to check if a database exists
  private static async checkDatabaseExists(dbName: string): Promise<boolean> {
    if ('databases' in indexedDB && typeof (indexedDB as any).databases === 'function') {
      const dbs = await (indexedDB as any).databases();
      return dbs.some((db: { name?: string }) => db.name === dbName);
    }

    // Fallback for older browsers:
    return new Promise((resolve) => {
      let existed = true;
      const request = indexedDB.open(dbName);

      request.onupgradeneeded = () => {
        // This means the DB didn't exist — cancel creation
        existed = false;
        request.transaction?.abort();
      };

      request.onsuccess = () => {
        request.result.close();
        resolve(existed);
      };

      request.onerror = () => resolve(false);
    });
  }

  // Helper method to open a database
  private static async openDatabase(dbName: string, version?: number): Promise<IDBDatabase | null> {
    return new Promise((resolve, reject) => {
      const request = version ? indexedDB.open(dbName, version) : indexedDB.open(dbName);

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);

      request.onupgradeneeded = (event) => {
        // Only handle upgrade for new database
        if (dbName === this.dbName) {
          const db = (event.target as IDBOpenDBRequest).result;
          // Create the same stores as in the main initDB method
          this.createDatabaseSchema(db, event);
        }
      };
    });
  }

  // Helper method to get all data from a store
  private static async getAllFromStore(db: IDBDatabase, storeName: string): Promise<any[]> {
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([storeName], 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.getAll();

      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => resolve([]);
    });
  }

  // Helper method to copy data to new database
  private static async copyDataToNewDb(
    db: IDBDatabase,
    storeName: string,
    data: any[],
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([storeName], 'readwrite');
      const store = transaction.objectStore(storeName);

      let completed = 0;
      const total = data.length;

      if (total === 0) {
        resolve();
        return;
      }

      data.forEach((item) => {
        const request = store.add(item);
        request.onsuccess = () => {
          completed++;
          if (completed === total) {
            resolve();
          }
        };
        request.onerror = () => {
          // If add fails (duplicate), try put instead
          const putRequest = store.put(item);
          putRequest.onsuccess = () => {
            completed++;
            if (completed === total) {
              resolve();
            }
          };
          putRequest.onerror = () => {
            completed++;
            if (completed === total) {
              resolve();
            }
          };
        };
      });
    });
  }

  // Helper method to delete a database
  private static async deleteDatabase(dbName: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const deleteRequest = indexedDB.deleteDatabase(dbName);
      deleteRequest.onsuccess = () => {
        storageLogger.info(`Database ${dbName} deleted successfully`);
        resolve();
      };
      deleteRequest.onerror = () => {
        storageLogger.warn(`Failed to delete database ${dbName}`);
        resolve(); // Don't reject, as this is not critical
      };
    });
  }

  // Extract database schema creation to reusable method
  private static createDatabaseSchema(db: IDBDatabase, event: IDBVersionChangeEvent): void {
    const transaction = (event.target as IDBOpenDBRequest).transaction!;

    // Wallet store
    if (!db.objectStoreNames.contains('wallets')) {
      const walletStore = db.createObjectStore('wallets', { keyPath: 'id', autoIncrement: true });
      walletStore.createIndex('address', 'address', { unique: true });
      walletStore.createIndex('name', 'name', { unique: true });
      walletStore.createIndex('isActive', 'isActive', { unique: false });
    }

    // Transactions store
    if (!db.objectStoreNames.contains('transactions')) {
      const txStore = db.createObjectStore('transactions', { keyPath: 'id', autoIncrement: true });
      txStore.createIndex('txid', 'txid', { unique: false });
      txStore.createIndex('address', 'address', { unique: false });
      txStore.createIndex('fromAddress', 'fromAddress', { unique: false });
      txStore.createIndex('walletAddress', 'walletAddress', { unique: false });
      txStore.createIndex('timestamp', 'timestamp', { unique: false });
      txStore.createIndex('txid_type_wallet', ['txid', 'type', 'walletAddress'], { unique: true });
    }

    // Watched address balances store
    if (!db.objectStoreNames.contains('watched_address_balances')) {
      const watchedAddressStore = db.createObjectStore('watched_address_balances', {
        keyPath: 'address',
      });
      watchedAddressStore.createIndex('lastChecked', 'lastChecked', { unique: false });
    }

    // Preferences store
    if (!db.objectStoreNames.contains('preferences')) {
      const prefStore = db.createObjectStore('preferences', { keyPath: 'id', autoIncrement: true });
      prefStore.createIndex('key', 'key', { unique: true });
    }
  }

  // Generic database operations
  private static async performTransaction<T>(
    storeName: string,
    mode: IDBTransactionMode,
    operation: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const db = await this.initDB();
    const transaction = db.transaction([storeName], mode);
    const store = transaction.objectStore(storeName);
    const request = operation(store);

    return new Promise((resolve, reject) => {
      let result: T;
      // request.onsuccess fires when the individual request completes, which for a write is
      // BEFORE the transaction is durably committed. Capture the value here but resolve on the
      // transaction's oncomplete, so a caller that navigates away or reads immediately after a
      // write cannot race an uncommitted (and potentially discarded) change.
      request.onsuccess = () => {
        result = request.result;
      };
      request.onerror = () =>
        reject(new Error(`Database operation failed: ${request.error?.message}`));
      transaction.oncomplete = () => resolve(result);
      transaction.onabort = () =>
        reject(transaction.error ?? new Error('Database transaction aborted'));
      transaction.onerror = () =>
        reject(transaction.error ?? new Error('Database transaction failed'));
    });
  }

  /**
   * Atomically read-modify-write a single preference within one IndexedDB transaction.
   *
   * IndexedDB serialises readwrite transactions that touch the same object store, so two
   * concurrent mutations run one after the other and the second sees the first's committed
   * result — which the plain getPreference/setPreference pair (two separate transactions with a
   * gap between them) does not guarantee. That gap is how concurrent settings updates lost each
   * other's changes.
   *
   * `mutator` must be synchronous: an IndexedDB transaction closes as soon as control returns to
   * the event loop, so it cannot span an await.
   */
  private static async mutatePreference<T>(
    key: string,
    mutator: (current: unknown) => T,
  ): Promise<T> {
    const db = await this.initDB();
    return new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(['preferences'], 'readwrite');
      const store = transaction.objectStore('preferences');
      const getRequest = store.index('key').get(key);
      let nextValue: T;

      getRequest.onsuccess = () => {
        const existing = getRequest.result as PreferenceData | undefined;
        nextValue = mutator(existing?.value ?? null);
        const prefData: PreferenceData = {
          key,
          value: nextValue,
          updatedAt: new Date(),
          ...(existing ? { id: existing.id } : {}),
        };
        store.put(prefData);
      };
      getRequest.onerror = () =>
        reject(new Error(`Database operation failed: ${getRequest.error?.message}`));
      transaction.oncomplete = () => resolve(nextValue);
      transaction.onabort = () =>
        reject(transaction.error ?? new Error('Database transaction aborted'));
      transaction.onerror = () =>
        reject(transaction.error ?? new Error('Database transaction failed'));
    });
  }

  /**
   * Atomically merge into the settings blob. The merge is applied inside a single transaction, so
   * concurrent updaters — SecurityService and WatchAddressService in particular — cannot clobber
   * each other. The stored settings value is a JSON string; this handles parse and stringify so
   * the mutator works with a plain object.
   */
  static async mutateSettings(
    mutator: (current: Record<string, any>) => Record<string, any>,
  ): Promise<Record<string, any>> {
    return this.mutatePreference('settings', (raw) => {
      let current: Record<string, any> = {};
      if (typeof raw === 'string') {
        try {
          current = JSON.parse(raw);
        } catch {
          current = {};
        }
      } else if (raw && typeof raw === 'object') {
        current = raw as Record<string, any>;
      }
      return JSON.stringify(mutator(current));
    }).then((stored) => (typeof stored === 'string' ? JSON.parse(stored) : {}));
  }

  // Wallet data operations
  private static async getWalletData(): Promise<WalletData | null> {
    try {
      const wallets = await this.performTransaction('wallets', 'readonly', (store) =>
        store.getAll(),
      );
      return wallets.length > 0 ? wallets[0] : null;
    } catch (error) {
      storageLogger.error('Failed to get wallet data:', error);
      return null;
    }
  }

  private static async saveWalletData(data: Partial<WalletData>): Promise<void> {
    try {
      const existing = await this.getWalletData();
      const walletData: WalletData = {
        ...existing,
        ...data,
        lastAccessed: new Date(),
        createdAt: existing?.createdAt || new Date(),
      } as WalletData;

      await this.performTransaction('wallets', 'readwrite', (store) => store.put(walletData));
    } catch (error) {
      throw new Error('Storage operation failed');
    }
  }

  private static async clearWalletData(): Promise<void> {
    try {
      await this.performTransaction('wallets', 'readwrite', (store) => store.clear());
    } catch (error) {
      toast.error('Failed to clear wallet data. Please try again.', {
        description: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  // Multi-wallet management methods
  static async createWallet(params: {
    name: string;
    address: string;
    privateKey: string;
    mnemonic?: string;
    bip39Passphrase?: string; // Optional encrypted BIP39 passphrase
    xprv?: string; // Encrypted account-level xprv (for descriptor-imported HD wallets)
    coinType?: 921 | 175; // BIP44 coin type for derivation
    addressType?: AddressType; // Script type: 'p2pkh' | 'p2wpkh' | 'p2sh-p2wpkh'
    descriptor?: string;  // BIP380 output-script descriptor
    isEncrypted?: boolean;
    makeActive?: boolean;
  }): Promise<WalletData> {
    try {
      // Check if wallet with same name already exists
      const existingWallets = await this.getAllWallets();
      const nameExists = existingWallets.some((w) => w.name === params.name);
      if (nameExists) {
        throw new Error(`A wallet with the name "${params.name}" already exists`);
      }

      // Check if wallet with same address already exists
      if (await this.walletExists(params.address)) {
        throw new Error(`A wallet with this address already exists`);
      }

      // Note: We'll set the initial active state and update others after creation

      const walletData: WalletData = {
        name: params.name,
        address: params.address,
        privateKey: params.privateKey,
        mnemonic: params.mnemonic,
        ...(params.bip39Passphrase !== undefined && { bip39Passphrase: params.bip39Passphrase }),
        ...(params.xprv !== undefined && { xprv: params.xprv }),
        ...(params.coinType !== undefined && { coinType: params.coinType }),
        ...(params.addressType !== undefined && { addressType: params.addressType }),
        ...(params.descriptor !== undefined && { descriptor: params.descriptor }),
        isEncrypted: params.isEncrypted || false,
        isActive: params.makeActive !== false,
        createdAt: new Date(),
        lastAccessed: new Date(),
      };

      const result = await this.performTransaction('wallets', 'readwrite', (store) =>
        store.add(walletData),
      );

      const newWalletId = result as number;

      // If making this wallet active, update all wallets' active states
      if (params.makeActive !== false) {
        await this.updateWalletsActiveState(newWalletId);
      }

      // Return the saved wallet with the ID
      return { ...walletData, id: newWalletId };
    } catch (error) {
      throw new Error(
        `Failed to create wallet: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  static async getAllWallets(): Promise<WalletData[]> {
    try {
      return await this.performTransaction('wallets', 'readonly', (store) => store.getAll());
    } catch (error) {
      return [];
    }
  }

  static async getWalletById(id: number): Promise<WalletData | null> {
    try {
      return (
        (await this.performTransaction('wallets', 'readonly', (store) => store.get(id))) || null
      );
    } catch (error) {
      return null;
    }
  }

  static async getWalletByName(name: string): Promise<WalletData | null> {
    try {
      return (
        (await this.performTransaction('wallets', 'readonly', (store) =>
          store.index('name').get(name),
        )) || null
      );
    } catch (error) {
      return null;
    }
  }

  static async getWalletByAddress(address: string): Promise<WalletData | null> {
    try {
      return (
        (await this.performTransaction('wallets', 'readonly', (store) =>
          store.index('address').get(address),
        )) || null
      );
    } catch (error) {
      return null;
    }
  }

  /**
   * Set notification preferences for a specific wallet
   * This is separate from the wallet's active state to ensure notifications
   * work correctly even when switching between wallets
   */
  static async setWalletNotificationEnabled(
    walletAddress: string,
    enabled: boolean,
  ): Promise<boolean> {
    try {
      // Get the wallet to confirm it exists
      const wallet = await this.getWalletByAddress(walletAddress);
      if (!wallet) {
        storageLogger.warn(
          `Wallet with address ${walletAddress} not found for notification update`,
        );
        return false;
      }

      // We store notification preferences in localStorage rather than IndexedDB
      // This ensures they're preserved separately from wallet active state
      try {
        const { NotificationClientService } = await import(
          '../notifications/client/NotificationClientService'
        );
        return await NotificationClientService.setWalletNotificationEnabled(walletAddress, enabled);
      } catch (error) {
        storageLogger.error(
          `Error updating notification preferences for wallet ${walletAddress}:`,
          error,
        );
        return false;
      }
    } catch (error) {
      storageLogger.error(
        `Failed to set notification enabled state for wallet ${walletAddress}:`,
        error,
      );
      return false;
    }
  }

  static async getActiveWallet(): Promise<WalletData | null> {
    try {
      const wallets = await this.getAllWallets();
      // Filter for active wallet since IndexedDB doesn't support boolean queries directly
      const activeWallet = wallets.find((w) => w.isActive === true);
      return activeWallet || null;
    } catch (error) {
      return null;
    }
  }

  static async switchToWallet(walletId: number): Promise<boolean> {
    try {
      // Get the wallet we're switching to first to validate it exists
      const targetWallet = await this.getWalletById(walletId);
      if (!targetWallet) {
        storageLogger.warn(`Cannot switch to wallet ID ${walletId} - wallet not found`);
        return false;
      }

      // Get current active wallet information BEFORE setting flags
      let currentActiveWalletId: number | null = null;
      let currentActiveWalletAddress: string | null = null;

      const allWallets = await this.getAllWallets();
      const currentActiveWallet = allWallets.find((w) => w.isActive);

      if (currentActiveWallet) {
        currentActiveWalletId = currentActiveWallet.id ?? null;
        currentActiveWalletAddress = currentActiveWallet.address;

        // If trying to switch to the already active wallet, do nothing
        if (currentActiveWalletId === walletId) {
          storageLogger.info(`Wallet ID ${walletId} is already active, skipping switch`);
          return true;
        }
      }

      // Set up wallet switch state to prevent balance notifications
      this.setWalletSwitchState({
        inProgress: true,
        timestamp: Date.now(),
        fromAddress: currentActiveWalletAddress || undefined,
        toAddress: targetWallet.address,
        fromId: currentActiveWalletId || undefined,
        toId: walletId,
      });

      // Log the switch
      storageLogger.info(
        `Switching wallet from ${currentActiveWalletAddress || 'none'} ` +
        `(ID: ${currentActiveWalletId}) to ${targetWallet.address} (ID: ${walletId})`,
      );

      // Update the previous wallet address for notification checks
      if (currentActiveWalletAddress) {
        localStorage.setItem('previous_wallet_address', currentActiveWalletAddress);
      }

      // Only update wallets that need to change state
      const updatePromises = allWallets.map((wallet) => {
        // If already in correct state, skip update
        if (
          (wallet.id === walletId && wallet.isActive) ||
          (wallet.id !== walletId && !wallet.isActive)
        ) {
          return Promise.resolve();
        }

        // Update only the isActive field and lastAccessed for the new active wallet
        const updatedWallet = {
          ...wallet,
          isActive: wallet.id === walletId,
          ...(wallet.id === walletId && { lastAccessed: new Date() }),
        };

        return this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));
      });

      // Wait for all wallet updates to complete
      await Promise.all(updatePromises);

      // Update the last active wallet to prevent false balance change notifications
      if (targetWallet.address) {
        localStorage.setItem('last_active_wallet', targetWallet.address);
      }

      // Log success
      storageLogger.info(`Successfully switched to wallet ID ${walletId}`);

      // Clear the wallet switching state after a delay
      // This ensures all balance updates that might be triggered during the switch
      // happen while the flag is still set - 5 seconds should be enough for any
      // concurrent operations to complete
      setTimeout(() => {
        this.clearWalletSwitchState();
      }, 5000); // 5 second delay

      return true;
    } catch (error) {
      // Make sure to clean up all wallet switch flags even if there's an error
      this.clearWalletSwitchState();
      storageLogger.error('Failed to switch wallet:', error);
      return false;
    }
  }

  static async updateWalletName(walletId: number, newName: string): Promise<boolean> {
    try {
      const wallet = await this.getWalletById(walletId);
      if (!wallet) {
        return false;
      }

      const updatedWallet = {
        ...wallet,
        name: newName,
        lastAccessed: new Date(),
      };

      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));

      return true;
    } catch (error) {
      storageLogger.error('Failed to update wallet name:', error);
      return false;
    }
  }

  static async updateWalletPrivateKey(walletId: number, newPrivateKey: string): Promise<boolean> {
    try {
      const wallet = await this.getWalletById(walletId);
      if (!wallet) {
        storageLogger.warn(`Wallet with ID ${walletId} not found for private key update.`);
        return false;
      }

      const updatedWallet = {
        ...wallet,
        privateKey: newPrivateKey,
        lastAccessed: new Date(),
      };

      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));

      return true;
    } catch (error) {
      storageLogger.error(`Failed to update private key for wallet ${walletId}:`, error);
      return false;
    }
  }

  static async updateWalletEncryption(
    walletId: number,
    newPrivateKey: string,
    newMnemonic?: string,
  ): Promise<boolean> {
    try {
      const wallet = await this.getWalletById(walletId);
      if (!wallet) {
        storageLogger.warn(`Wallet with ID ${walletId} not found for encryption update.`);
        return false;
      }

      const updatedWallet = {
        ...wallet,
        privateKey: newPrivateKey,
        // Only update mnemonic if a new one is provided
        ...(newMnemonic !== undefined && { mnemonic: newMnemonic }),
        lastAccessed: new Date(),
      };

      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));

      storageLogger.info(`Successfully upgraded encryption for wallet ID ${walletId}`);
      return true;
    } catch (error) {
      storageLogger.error(`Failed to update encryption for wallet ${walletId}:`, error);
      return false;
    }
  }

  static async deleteWallet(walletId: number): Promise<boolean> {
    try {
      const wallet = await this.getWalletById(walletId);
      if (!wallet) {
        return false;
      }

      // Delete the wallet
      await this.performTransaction('wallets', 'readwrite', (store) => store.delete(walletId));

      // If this was the active wallet, activate another one if available
      if (wallet.isActive) {
        const remainingWallets = await this.getAllWallets();
        if (remainingWallets.length > 0) {
          await this.switchToWallet(remainingWallets[0].id!);
        }
      }

      // Delete associated transaction history
      await this.clearTransactionHistoryForAddress(wallet.address);

      // Clean up legacy biometric data from preferences (for transition period)
      await this.removeBiometricCredential(wallet.address);
      await this.removeEncryptedWalletPassword(wallet.address);

      // If there are no more wallets with biometrics, disable the global biometric setting
      const remainingWalletsWithBiometrics = await this.getWalletsWithBiometricsEnabled();
      if (remainingWalletsWithBiometrics.length === 0) {
        await this.setBiometricEnabled(false);
      }

      return true;
    } catch (error) {
      storageLogger.error('Failed to delete wallet:', error);
      return false;
    }
  }

  static async walletExists(address: string): Promise<boolean> {
    const wallet = await this.getWalletByAddress(address);
    return !!wallet;
  }

  static async getWalletCount(): Promise<number> {
    try {
      const wallets = await this.getAllWallets();
      return wallets.length;
    } catch (error) {
      storageLogger.error('Failed to get wallet count:', error);
      return 0;
    }
  }

  /**
   * Deactivates all wallets (sets isActive to false)
   * Note: This should be used carefully as it doesn't preserve other wallet properties
   * For wallet switching, use switchToWallet instead
   */
  private static async deactivateAllWallets(): Promise<void> {
    try {
      const wallets = await this.getAllWallets();
      const updatePromises = wallets.map((wallet) => {
        // Only update if the wallet is currently active
        if (wallet.isActive) {
          const updatedWallet = { ...wallet, isActive: false };
          return this.performTransaction('wallets', 'readwrite', (store) =>
            store.put(updatedWallet),
          );
        }
        return Promise.resolve();
      });
      await Promise.all(updatePromises);
    } catch (error) {
      storageLogger.error('Failed to deactivate all wallets:', error);
    }
  }

  /**
   * Updates just the active state of wallets without affecting other properties
   * This preserves all other wallet settings including notification preferences
   */
  private static async updateWalletsActiveState(activeWalletId: number): Promise<void> {
    try {
      const wallets = await this.getAllWallets();
      const updatePromises = wallets.map((wallet) => {
        const shouldBeActive = wallet.id === activeWalletId;
        // Only update wallets where the active state is changing
        if (wallet.isActive !== shouldBeActive) {
          const updatedWallet = {
            ...wallet,
            isActive: shouldBeActive,
            ...(shouldBeActive && { lastAccessed: new Date() }),
          };
          return this.performTransaction('wallets', 'readwrite', (store) =>
            store.put(updatedWallet),
          );
        }
        return Promise.resolve();
      });
      await Promise.all(updatePromises);
    } catch (error) {
      storageLogger.error('Failed to update wallet active states:', error);
    }
  }

  static async clearTransactionHistoryForAddress(address: string): Promise<void> {
    try {
      const transactions = await this.performTransaction('transactions', 'readonly', (store) =>
        store.index('address').getAll(address),
      );

      const deletePromises = transactions.map((tx) =>
        this.performTransaction('transactions', 'readwrite', (store) => store.delete(tx.id!)),
      );

      await Promise.all(deletePromises);
    } catch (error) {
      storageLogger.error('Failed to clear transaction history for address:', error);
    }
  }

  // Preference methods
  private static async getPreference(key: string): Promise<any> {
    try {
      const result = await this.performTransaction('preferences', 'readonly', (store) =>
        store.index('key').get(key),
      );
      return result?.value || null;
    } catch (error) {
      storageLogger.error('Failed to get preference:', error);
      return null;
    }
  }

  private static async setPreference(key: string, value: any): Promise<void> {
    try {
      // Find-existing-then-put used to span two transactions; a concurrent setPreference for the
      // same key could read no existing row in the gap and insert a duplicate, which getPreference
      // would then read arbitrarily. mutatePreference does the find and put in one transaction, so
      // the id is always reused and there is never more than one row per key.
      await this.mutatePreference(key, () => value);
    } catch (error) {
      storageLogger.error('Failed to set preference:', error);
      throw new Error('Storage operation failed');
    }
  }

  // Which ElectrumX server the user last selected, by host. Persisted so the choice survives a
  // page reload — the ElectrumService otherwise defaults back to the first server on every load.
  static async getSelectedElectrumServer(): Promise<string | null> {
    const host = (await this.getPreference('selectedElectrumServerHost')) as string | null;
    return host || null;
  }

  static async setSelectedElectrumServer(host: string): Promise<void> {
    await this.setPreference('selectedElectrumServerHost', host);
  }

  // Script hash methods
  static async getScriptHash(): Promise<string> {
    return (await this.getPreference('scripthash')) || '';
  }

  static async setScriptHash(scriptHash: string): Promise<void> {
    await this.setPreference('scripthash', scriptHash);
  }

  // Balance methods
  static async getLastBalance(): Promise<number> {
    const balance = await this.getPreference('last_balance');
    return balance ? Number(balance) : 0;
  }

  static async setLastBalance(balance: number): Promise<void> {
    await this.setPreference('last_balance', balance);
  }

  // Exchange rate methods
  static async getExchangeRate(): Promise<number> {
    const rate = await this.getPreference('exchange_rate');
    return rate ? Number(rate) : 0;
  }

  static async setExchangeRate(rate: number): Promise<void> {
    await this.setPreference('exchange_rate', rate);
  }

  // Currency methods
  static async getCurrency(): Promise<string> {
    return (await this.getPreference('currency')) || 'USD';
  }

  static async setCurrency(currency: string): Promise<void> {
    await this.setPreference('currency', currency);
  }

  // AVN units methods
  static async getAVNUnits(): Promise<string> {
    return (await this.getPreference('avn_units')) || 'AVN';
  }

  static async setAVNUnits(units: string): Promise<void> {
    await this.setPreference('avn_units', units);
  }

  // Change address count preference methods
  static async getChangeAddressCount(): Promise<number> {
    return (await this.getPreference('change_address_count')) || 5;
  }

  static async setChangeAddressCount(count: number): Promise<void> {
    // Validate the count is within reasonable bounds
    const validCount = Math.max(1, Math.min(20, count));
    await this.setPreference('change_address_count', validCount);
  }

  // Avian Connect methods — see docs/AVIAN_CONNECT.md
  static async getConnectPermissions(): Promise<OriginPermission[]> {
    const stored = await this.getPreference('avian_connect_permissions');
    return Array.isArray(stored) ? stored : [];
  }

  static async setConnectPermissions(permissions: OriginPermission[]): Promise<void> {
    await this.setPreference('avian_connect_permissions', permissions);
  }

  /**
   * Public keys the wallet has recovered from signatures the user already authorised. Public
   * keys are not secret; caching them lets connect() answer with one without touching the
   * private key.
   */
  static async getKnownPublicKey(address: string): Promise<string | null> {
    const keys = await this.getPreference('avian_connect_public_keys');
    return keys && typeof keys === 'object' ? keys[address] || null : null;
  }

  static async setKnownPublicKey(address: string, publicKey: string): Promise<void> {
    const keys = (await this.getPreference('avian_connect_public_keys')) || {};
    await this.setPreference('avian_connect_public_keys', { ...keys, [address]: publicKey });
  }

  /** Mainnet genesis hash as learned from an ElectrumX server, cached once known. */
  static async getCachedGenesisHash(): Promise<string | null> {
    return (await this.getPreference('genesis_hash')) || null;
  }

  static async setCachedGenesisHash(genesisHash: string): Promise<void> {
    await this.setPreference('genesis_hash', genesisHash);
  }

  // Settings methods
  static async getSettings(): Promise<any> {
    const settings = await this.getPreference('settings');
    return settings ? (typeof settings === 'string' ? JSON.parse(settings) : settings) : {};
  }

  static async setSettings(settings: any): Promise<void> {
    await this.setPreference(
      'settings',
      typeof settings === 'string' ? settings : JSON.stringify(settings),
    );
  }

  // Transaction history methods
  static async saveTransaction(
    transaction: Omit<TransactionData, 'id'> | TransactionData,
  ): Promise<void> {
    try {
      // Ensure walletAddress is always present
      if (!transaction.walletAddress) {
        // If walletAddress is not provided, use fromAddress for 'send' transactions
        // or address for 'receive' transactions to maintain backward compatibility
        transaction.walletAddress =
          transaction.type === 'send' ? transaction.fromAddress || '' : transaction.address;
      }

      // Check if this transaction has an ID (update case)
      if ('id' in transaction && transaction.id !== undefined) {
        // Update the existing transaction by ID
        await this.performTransaction('transactions', 'readwrite', (store) =>
          store.put(transaction),
        );
        return;
      }

      try {
        // Get all transactions with this txid for this specific wallet and type
        const allTransactions = await this.performTransaction('transactions', 'readonly', (store) =>
          store.index('txid').getAll(transaction.txid),
        );

        // Find one with matching type AND walletAddress if it exists
        const existingTx = allTransactions.find(
          (tx) => tx.type === transaction.type && tx.walletAddress === transaction.walletAddress,
        );

        if (existingTx) {
          // Update the existing transaction of this type for this wallet
          const updatedTx = { ...existingTx, ...transaction };
          await this.performTransaction('transactions', 'readwrite', (store) =>
            store.put(updatedTx),
          );
          return;
        }

        // For new transactions, use add instead of put to generate a new ID
        const newTx = { ...transaction };
        if ('id' in newTx) {
          delete (newTx as any).id;
        }

        // Create new transaction with auto-generated ID
        await this.performTransaction('transactions', 'readwrite', (store) => store.add(newTx));
      } catch (innerError) {
        // If we encounter a uniqueness error, use a more robust approach
        if (innerError instanceof Error && innerError.message.includes('uniqueness requirements')) {
          storageLogger.warn(
            `Transaction uniqueness issue for txid: ${transaction.txid} - using robust handling`,
          );

          try {
            // Try a different approach - first get ALL transactions
            const allTxs = await this.performTransaction('transactions', 'readonly', (store) =>
              store.getAll(),
            );

            // Find any existing transaction with the same txid, type, and wallet address
            const existingTx = allTxs.find(
              (tx) =>
                tx.txid === transaction.txid &&
                tx.type === transaction.type &&
                tx.walletAddress === transaction.walletAddress,
            );

            if (existingTx) {
              // Update the existing transaction instead of creating a new one
              const updatedTx = { ...existingTx, ...transaction };

              await this.performTransaction('transactions', 'readwrite', (store) =>
                store.put(updatedTx),
              );
              return;
            } else {
              // Create a fresh transaction object with no ID
              const freshTx = { ...transaction };
              delete (freshTx as any).id;

              // Try adding with a new auto-generated ID and adjusted timestamp to avoid conflicts
              if (freshTx.timestamp instanceof Date) {
                // Add a few milliseconds to ensure uniqueness
                freshTx.timestamp = new Date(
                  freshTx.timestamp.getTime() + Math.floor(Math.random() * 1000),
                );
              }

              await this.performTransaction('transactions', 'readwrite', (store) =>
                store.add(freshTx),
              );
              return;
            }
          } catch (fallbackError) {
            storageLogger.error(
              'All fallback attempts failed for txid:',
              transaction.txid,
              fallbackError,
            );
            // We'll continue to the generic error handler
          }
        }
        throw innerError;
      }
    } catch (error) {
      // Final fallback for all errors
      storageLogger.error('Failed to save transaction:', error);

      if (error instanceof Error && error.message.includes('uniqueness requirements')) {
        // Don't throw the error if it's a uniqueness issue - we'll just log and continue
        storageLogger.warn(
          `Skipping problematic transaction with ID ${transaction.txid} due to database constraints`,
        );
        return;
      }

      throw error;
    }
  }

  static async getTransactionHistory(address?: string): Promise<TransactionData[]> {
    try {
      if (address) {
        // First try to get transactions by walletAddress (new method)
        try {
          const walletTxs = await this.performTransaction('transactions', 'readonly', (store) =>
            store.index('walletAddress').getAll(address),
          );

          if (walletTxs && walletTxs.length > 0) {
            // Sort transactions by timestamp (newest first)
            return walletTxs.sort((a, b) => {
              // Convert strings to dates if necessary
              const dateA = a.timestamp instanceof Date ? a.timestamp : new Date(a.timestamp);
              const dateB = b.timestamp instanceof Date ? b.timestamp : new Date(b.timestamp);
              return dateB.getTime() - dateA.getTime();
            });
          }
        } catch (indexError) {
          // If walletAddress index doesn't exist yet, fall back to old method
          storageLogger.warn('walletAddress index not available, using legacy method');
        }

        // Legacy fallback: Get transactions where the address is either the recipient or sender
        const [sentTx, receivedTx] = await Promise.all([
          this.performTransaction('transactions', 'readonly', (store) =>
            store.index('fromAddress').getAll(address),
          ),
          this.performTransaction('transactions', 'readonly', (store) =>
            store.index('address').getAll(address),
          ),
        ]);

        // Deduplicate transactions that might match both criteria
        const txMap = new Map();
        [...sentTx, ...receivedTx].forEach((tx) => {
          // For backward compatibility, add walletAddress if missing
          if (!tx.walletAddress) {
            tx.walletAddress = address;
          }
          // Use a compound key to avoid overwriting different transaction types
          txMap.set(`${tx.txid}-${tx.type}`, tx);
        });

        // Return sorted transactions
        return Array.from(txMap.values()).sort((a, b) => {
          // Convert strings to dates if necessary
          const dateA = a.timestamp instanceof Date ? a.timestamp : new Date(a.timestamp);
          const dateB = b.timestamp instanceof Date ? b.timestamp : new Date(b.timestamp);
          return dateB.getTime() - dateA.getTime();
        });
      } else {
        // Get all transactions and sort by timestamp (newest first)
        const allTxs = await this.performTransaction('transactions', 'readonly', (store) =>
          store.getAll(),
        );

        return allTxs.sort((a, b) => {
          // Convert strings to dates if necessary
          const dateA = a.timestamp instanceof Date ? a.timestamp : new Date(a.timestamp);
          const dateB = b.timestamp instanceof Date ? b.timestamp : new Date(b.timestamp);
          return dateB.getTime() - dateA.getTime();
        });
      }
    } catch (error) {
      storageLogger.error('Failed to get transaction history:', error);
      return [];
    }
  }

  static async getTransaction(
    txid: string,
    type?: 'send' | 'receive',
  ): Promise<TransactionData | null> {
    try {
      // If type is provided, get all transactions with this txid and filter by type
      if (type) {
        const allTransactions = await this.performTransaction('transactions', 'readonly', (store) =>
          store.index('txid').getAll(txid),
        );

        return allTransactions.find((tx) => tx.type === type) || null;
      }

      // Otherwise, return the first transaction with this txid
      return (
        (await this.performTransaction('transactions', 'readonly', (store) =>
          store.index('txid').get(txid),
        )) || null
      );
    } catch (error) {
      storageLogger.error('Failed to get transaction:', error);
      return null;
    }
  }

  static async updateTransactionConfirmations(
    txid: string,
    confirmations: number,
  ): Promise<boolean> {
    try {
      // First get the transaction
      const transaction = await this.getTransaction(txid);
      if (!transaction) {
        storageLogger.warn('Transaction not found for confirmation update:', txid);
        return false;
      }

      // Update the confirmations
      transaction.confirmations = confirmations;

      // Save the updated transaction
      await this.performTransaction('transactions', 'readwrite', (store) => store.put(transaction));

      return true;
    } catch (error) {
      storageLogger.error('Failed to update transaction confirmations:', error);
      return false;
    }
  }

  static async clearTransactionHistory(): Promise<void> {
    try {
      await this.performTransaction('transactions', 'readwrite', (store) => store.clear());
    } catch (error) {
      storageLogger.error('Failed to clear transaction history:', error);
    }
  }

  // Clear all wallet data
  static async clearWallet(): Promise<void> {
    await this.clearWalletData();
    // Also clear transaction history when wallet is cleared
    try {
      await this.performTransaction('transactions', 'readwrite', (store) => store.clear());
    } catch (error) {
      storageLogger.error('Failed to clear transaction history:', error);
    }
  }

  // Backup/restore methods
  static async exportWalletData(): Promise<string> {
    const activeWallet = await this.getActiveWallet();
    const data = {
      address: activeWallet?.address || '',
      privateKey: activeWallet?.privateKey || '',
      mnemonic: activeWallet?.mnemonic || '',
      scriptHash: await this.getScriptHash(),
      isEncrypted: activeWallet?.isEncrypted || false,
      currency: await this.getCurrency(),
      avnUnits: await this.getAVNUnits(),
      settings: await this.getSettings(),
      createdAt: activeWallet?.createdAt,
      lastAccessed: activeWallet?.lastAccessed,
    };

    return JSON.stringify(data);
  }

  static async importWalletData(jsonData: string): Promise<void> {
    try {
      const data = JSON.parse(jsonData);

      // Import wallet data
      const walletData: Partial<WalletData> = {};
      if (data.address) walletData.address = data.address;
      if (data.privateKey) walletData.privateKey = data.privateKey;
      if (data.mnemonic) walletData.mnemonic = data.mnemonic;
      if (typeof data.isEncrypted === 'boolean') walletData.isEncrypted = data.isEncrypted;

      if (Object.keys(walletData).length > 0) {
        // Create a new wallet from imported data
        const walletName = `Imported Wallet ${Date.now()}`;
        await this.createWallet({
          name: walletName,
          address: data.address,
          privateKey: data.privateKey,
          mnemonic: data.mnemonic,
          isEncrypted: data.isEncrypted || false,
          makeActive: true,
        });
      }

      // Import preferences
      if (data.scriptHash) await this.setScriptHash(data.scriptHash);
      if (data.currency) await this.setCurrency(data.currency);
      if (data.avnUnits) await this.setAVNUnits(data.avnUnits);
      if (data.settings) await this.setSettings(data.settings);
    } catch (error) {
      storageLogger.error('Failed to import wallet data:', error);
      throw new Error('Invalid wallet data format');
    }
  }

  // Check if wallet exists
  static async hasWallet(): Promise<boolean> {
    const activeWallet = await this.getActiveWallet();
    return !!(activeWallet?.address && activeWallet?.privateKey);
  }

  // Database maintenance
  static async getDatabaseInfo(): Promise<{
    wallets: number;
    transactions: number;
    preferences: number;
  }> {
    try {
      const walletCount = (
        await this.performTransaction('wallets', 'readonly', (store) => store.getAll())
      ).length;

      const transactionCount = (
        await this.performTransaction('transactions', 'readonly', (store) => store.getAll())
      ).length;

      const preferenceCount = (
        await this.performTransaction('preferences', 'readonly', (store) => store.getAll())
      ).length;

      return { wallets: walletCount, transactions: transactionCount, preferences: preferenceCount };
    } catch (error) {
      storageLogger.error('Failed to get database info:', error);
      return { wallets: 0, transactions: 0, preferences: 0 };
    }
  }

  // Legacy compatibility methods - work with active wallet
  static async getAddress(): Promise<string> {
    const activeWallet = await this.getActiveWallet();
    return activeWallet?.address || '';
  }

  static async setAddress(address: string): Promise<void> {
    const activeWallet = await this.getActiveWallet();
    if (activeWallet) {
      const updatedWallet = { ...activeWallet, address, lastAccessed: new Date() };
      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));
    }
  }

  static async getPrivateKey(): Promise<string> {
    const activeWallet = await this.getActiveWallet();
    return activeWallet?.privateKey || '';
  }

  static async setPrivateKey(privateKey: string): Promise<void> {
    const activeWallet = await this.getActiveWallet();
    if (activeWallet) {
      const updatedWallet = { ...activeWallet, privateKey, lastAccessed: new Date() };
      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));
    }
  }

  static async getMnemonic(): Promise<string> {
    const activeWallet = await this.getActiveWallet();
    return activeWallet?.mnemonic || '';
  }

  static async setMnemonic(mnemonic: string): Promise<void> {
    const activeWallet = await this.getActiveWallet();
    if (activeWallet) {
      const updatedWallet = { ...activeWallet, mnemonic, lastAccessed: new Date() };
      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));
    }
  }

  static async hasMnemonic(): Promise<boolean> {
    const activeWallet = await this.getActiveWallet();
    return !!activeWallet?.mnemonic;
  }

  /**
   * Whether the active wallet can derive further addresses in its account tree.
   * True for mnemonic wallets and for descriptor-imported wallets, which store an
   * account-level xprv instead of a mnemonic.
   */
  static async hasHdCapability(): Promise<boolean> {
    const activeWallet = await this.getActiveWallet();
    return !!(activeWallet?.mnemonic || activeWallet?.xprv);
  }

  static async getIsEncrypted(): Promise<boolean> {
    const activeWallet = await this.getActiveWallet();
    return activeWallet?.isEncrypted || false;
  }

  static async setIsEncrypted(isEncrypted: boolean): Promise<void> {
    const activeWallet = await this.getActiveWallet();
    if (activeWallet) {
      const updatedWallet = { ...activeWallet, isEncrypted, lastAccessed: new Date() };
      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));
    }
  }

  // Utility method to migrate existing transactions to include fromAddress
  static async migrateTransactionHistory(): Promise<void> {
    try {
      const db = await this.initDB();
      const transaction = db.transaction(['transactions'], 'readwrite');
      const store = transaction.objectStore('transactions');
      const request = store.getAll();

      request.onsuccess = () => {
        const transactions = request.result;
        let updateCount = 0;

        transactions.forEach(async (tx) => {
          if (tx.type === 'send' && !tx.fromAddress) {
            // For sent transactions without fromAddress, we need to find the active wallet
            // This is a best-effort migration - in a real scenario, we'd need to store the wallet ID
            const activeWallet = await this.getActiveWallet();
            if (activeWallet) {
              tx.fromAddress = activeWallet.address;
              await store.put(tx);
              updateCount++;
            }
          }
        });
      };
    } catch (error) {
      storageLogger.error('Failed to migrate transaction history:', error);
    }
  }

  static async removeTransaction(txid: string, address?: string): Promise<boolean> {
    try {
      // Find the transaction to delete
      const transactions = await this.performTransaction('transactions', 'readonly', (store) =>
        store.getAll(),
      );

      let targetTransaction = null;

      if (address) {
        // Find transaction by txid for specific address
        targetTransaction = transactions.find(
          (tx) => tx.txid === txid && (tx.address === address || tx.fromAddress === address),
        );
      } else {
        // Find transaction by txid only
        targetTransaction = transactions.find((tx) => tx.txid === txid);
      }

      if (targetTransaction && targetTransaction.id) {
        await this.performTransaction('transactions', 'readwrite', (store) =>
          store.delete(targetTransaction.id),
        );
        return true;
      }

      return false;
    } catch (error) {
      storageLogger.error('Failed to remove transaction:', error);
      return false;
    }
  }

  // Address Book Methods
  static async getSavedAddresses(): Promise<SavedAddress[]> {
    try {
      const data = await this.getPreference('addressBook');
      return data?.addresses || [];
    } catch (error) {
      storageLogger.error('Failed to get saved addresses:', error);
      return [];
    }
  }

  static async saveAddress(address: SavedAddress): Promise<boolean> {
    try {
      const currentAddresses = await this.getSavedAddresses();

      // Check if address already exists
      const existingIndex = currentAddresses.findIndex((addr) => addr.address === address.address);

      if (existingIndex >= 0) {
        // Update existing address
        currentAddresses[existingIndex] = { ...address, id: currentAddresses[existingIndex].id };
      } else {
        // Add new address with unique ID
        address.id = Date.now().toString() + Math.random().toString(36).slice(2, 9);
        currentAddresses.push(address);
      }

      await this.setPreference('addressBook', { addresses: currentAddresses });
      return true;
    } catch (error) {
      storageLogger.error('Failed to save address:', error);
      return false;
    }
  }

  static async deleteAddress(addressId: string): Promise<boolean> {
    try {
      const currentAddresses = await this.getSavedAddresses();
      const filteredAddresses = currentAddresses.filter((addr) => addr.id !== addressId);

      await this.setPreference('addressBook', { addresses: filteredAddresses });
      return true;
    } catch (error) {
      storageLogger.error('Failed to delete address:', error);
      return false;
    }
  }

  static async updateAddress(address: SavedAddress): Promise<boolean> {
    try {
      const currentAddresses = await this.getSavedAddresses();
      const addressIndex = currentAddresses.findIndex((addr) => addr.id === address.id);

      if (addressIndex >= 0) {
        currentAddresses[addressIndex] = {
          ...currentAddresses[addressIndex],
          ...address,
          // Ensure we preserve metadata fields if not explicitly changed
          lastUsed: address.lastUsed || currentAddresses[addressIndex].lastUsed,
          useCount: address.useCount ?? currentAddresses[addressIndex].useCount,
        };
        await this.setPreference('addressBook', { addresses: currentAddresses });
        return true;
      }
      return false;
    } catch (error) {
      storageLogger.error('Failed to update address:', error);
      return false;
    }
  }

  static async updateAddressUsage(address: string): Promise<void> {
    try {
      const currentAddresses = await this.getSavedAddresses();
      const addressIndex = currentAddresses.findIndex((addr) => addr.address === address);

      if (addressIndex >= 0) {
        currentAddresses[addressIndex].lastUsed = new Date();
        currentAddresses[addressIndex].useCount =
          (currentAddresses[addressIndex].useCount || 0) + 1;
        await this.setPreference('addressBook', { addresses: currentAddresses });
      }
    } catch (error) {
      storageLogger.error('Failed to update address usage:', error);
    }
  }

  static async searchAddresses(query: string): Promise<SavedAddress[]> {
    try {
      const addresses = await this.getSavedAddresses();
      const lowercaseQuery = query.toLowerCase();

      return addresses.filter(
        (addr) =>
          addr.name.toLowerCase().includes(lowercaseQuery) ||
          addr.address.toLowerCase().includes(lowercaseQuery) ||
          (addr.description && addr.description.toLowerCase().includes(lowercaseQuery)),
      );
    } catch (error) {
      storageLogger.error('Failed to search addresses:', error);
      return [];
    }
  }

  // Biometric Authentication Storage
  static async setBiometricCredential(
    credentialId: number[],
    walletAddress?: string,
  ): Promise<void> {
    try {
      if (!walletAddress) {
        throw new Error('Wallet address is required for setting biometric credential');
      }

      // Get the wallet
      const wallet = await this.getWalletByAddress(walletAddress);
      if (!wallet) {
        throw new Error(`Wallet not found: ${walletAddress}`);
      }

      // Update wallet with biometric credential
      const updatedWallet = {
        ...wallet,
        biometricCredentialId: credentialId,
        biometricsEnabled: true,
      };

      // Save the updated wallet
      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));

      // Legacy: Also store in preferences during transition period
      let walletCredentials =
        ((await this.getPreference('biometricWalletCredentials')) as Record<string, number[]>) ||
        {};
      walletCredentials[walletAddress] = credentialId;
      await this.setPreference('biometricWalletCredentials', walletCredentials);

      // Update global credential for active wallet
      if (wallet.isActive) {
        await this.setPreference('biometricCredentialId', credentialId);
      }
    } catch (error) {
      storageLogger.error('Failed to store biometric credential:', error);
      throw error;
    }
  }

  static async getBiometricCredential(walletAddress?: string): Promise<number[] | null> {
    try {
      if (walletAddress) {
        // Get credential from the wallet record
        const wallet = await this.getWalletByAddress(walletAddress);
        if (wallet?.biometricCredentialId) {
          return wallet.biometricCredentialId;
        }

        // Legacy: Try to get from preferences during transition period
        const walletCredentials =
          ((await this.getPreference('biometricWalletCredentials')) as Record<string, number[]>) ||
          {};
        if (walletCredentials[walletAddress]) {
          return walletCredentials[walletAddress];
        }

        // Asked about a specific wallet and it has no credential: say so. Falling through to the
        // global preference would hand back a *different* wallet's credential, which the caller
        // then reads as "this wallet has biometrics". It does not — and the password lookup is
        // correctly scoped, so the unlock proceeds to a prompt and then fails to find anything to
        // decrypt. One wallet appearing to work and another failing oddly is this leak.
        return null;
      }

      // No wallet named: the active one, then the global preference for pre-per-wallet installs.
      const activeWallet = await this.getActiveWallet();
      if (activeWallet?.biometricCredentialId) {
        return activeWallet.biometricCredentialId;
      }

      const result = await this.getPreference('biometricCredentialId');
      return result as number[] | null;
    } catch (error) {
      storageLogger.error('Failed to retrieve biometric credential:', error);
      return null;
    }
  }

  static async removeBiometricCredential(walletAddress?: string): Promise<void> {
    try {
      if (walletAddress) {
        // Remove credential for a specific wallet
        const wallet = await this.getWalletByAddress(walletAddress);
        if (wallet) {
          // Update the wallet to remove biometric data
          const updatedWallet = {
            ...wallet,
            biometricsEnabled: false,
            biometricCredentialId: undefined,
            encryptedBiometricPassword: undefined,
          };

          // Save the updated wallet
          await this.performTransaction('wallets', 'readwrite', (store) =>
            store.put(updatedWallet),
          );
        }

        // Legacy: Clean up from preferences during transition period
        const walletCredentials =
          ((await this.getPreference('biometricWalletCredentials')) as Record<string, number[]>) ||
          {};

        if (walletCredentials[walletAddress]) {
          delete walletCredentials[walletAddress];
          await this.setPreference('biometricWalletCredentials', walletCredentials);
        }

        // If this is the active wallet, also remove the default credential
        const activeWallet = await this.getActiveWallet();
        if (activeWallet && activeWallet.address === walletAddress) {
          await this.removePreference('biometricCredentialId');
        }
      } else {
        // Remove biometrics from all wallets
        const wallets = await this.getAllWallets();

        for (const wallet of wallets) {
          if (wallet.biometricsEnabled) {
            const updatedWallet = {
              ...wallet,
              biometricsEnabled: false,
              biometricCredentialId: undefined,
              encryptedBiometricPassword: undefined,
            };

            await this.performTransaction('wallets', 'readwrite', (store) =>
              store.put(updatedWallet),
            );
          }
        }

        // Legacy: Remove all credentials from preferences
        await this.removePreference('biometricCredentialId');
        await this.removePreference('biometricWalletCredentials');
      }
    } catch (error) {
      storageLogger.error('Failed to remove biometric credential:', error);
      throw error;
    }
  }

  static async setBiometricEnabled(enabled: boolean): Promise<void> {
    try {
      await this.setPreference('biometricEnabled', enabled);
    } catch (error) {
      storageLogger.error('Failed to set biometric enabled status:', error);
      throw error;
    }
  }

  static async isBiometricEnabled(): Promise<boolean> {
    try {
      const result = await this.getPreference('biometricEnabled');
      return result === true;
    } catch (error) {
      storageLogger.error('Failed to get biometric enabled status:', error);
      return false;
    }
  }

  static async isBiometricEnabledForWallet(walletAddress: string): Promise<boolean> {
    try {
      if (!walletAddress) {
        return false;
      }

      // Get the wallet object
      const wallet = await this.getWalletByAddress(walletAddress);
      if (!wallet) {
        return false;
      }

      // Check if biometrics are enabled and credentials exist
      const hasBiometrics =
        wallet.biometricsEnabled === true &&
        Array.isArray(wallet.biometricCredentialId) &&
        wallet.biometricCredentialId.length > 0;

      return hasBiometrics;
    } catch (error) {
      storageLogger.error('Error checking if biometrics enabled for wallet:', error);
      return false;
    }
  }

  private static async removePreference(key: string): Promise<void> {
    try {
      const existing = await this.performTransaction('preferences', 'readonly', (store) =>
        store.index('key').get(key),
      );

      if (existing) {
        await this.performTransaction('preferences', 'readwrite', (store) =>
          store.delete(existing.id),
        );
      }
    } catch (error) {
      storageLogger.error('Failed to remove preference:', error);
      throw error;
    }
  }

  static async setEncryptedWalletPassword(
    secureKey: string,
    password: string,
    walletAddress: string,
  ): Promise<void> {
    try {
      if (!walletAddress) {
        throw new Error('Wallet address is required for setting encrypted password');
      }

      // Use AES encryption to secure the password
      const encryptedPassword = await secureEncrypt(password, secureKey);

      // Get the wallet
      const wallet = await this.getWalletByAddress(walletAddress);
      if (!wallet) {
        throw new Error(`Wallet not found: ${walletAddress}`);
      }

      // Update wallet with encrypted password
      const updatedWallet = {
        ...wallet,
        encryptedBiometricPassword: encryptedPassword,
        biometricsEnabled: true,
        // Ensure biometricCredentialId is maintained
        biometricCredentialId: wallet.biometricCredentialId,
      };

      // Save the updated wallet
      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));

      // Double-check that the wallet was updated correctly
      const updatedWalletRecord = await this.getWalletByAddress(walletAddress);

      // Legacy: Also store in preferences during transition period
      let walletPasswords =
        ((await this.getPreference('biometricWalletPasswords')) as Record<string, string>) || {};
      walletPasswords[walletAddress] = encryptedPassword;
      await this.setPreference('biometricWalletPasswords', walletPasswords);

      // Store the current biometric wallet address
      if (wallet.isActive) {
        await this.setPreference('biometricWalletAddress', walletAddress);
      }
    } catch (error) {
      storageLogger.error('Failed to store encrypted wallet password:', error);
      throw error;
    }
  }

  static async getEncryptedWalletPassword(
    secureKey: string,
    walletAddress: string,
  ): Promise<string | null> {
    try {
      if (!walletAddress) {
        return null;
      }

      // Get the wallet
      const wallet = await this.getWalletByAddress(walletAddress);

      // Try to get password from wallet record
      if (wallet?.encryptedBiometricPassword) {
        // Decrypt the password using the secure key
        const { decrypted, format } = await decryptData(
          wallet.encryptedBiometricPassword,
          secureKey,
        );
        // Unlike the wallet key, this blob has no unlock path that re-seals it, so a credential
        // enrolled under an older KDF (scrypt/legacy) would re-run that slow derivation on every
        // biometric login — painfully slow in a mobile browser. Transparently upgrade it to the
        // current Argon2id format on first read; best-effort, and never blocks the unlock.
        if (format !== 'argon2id') {
          await this.migrateBiometricPassword(secureKey, decrypted, walletAddress);
        }
        return decrypted;
      }

      // Legacy: Try to get from preferences during transition period
      const walletPasswords =
        ((await this.getPreference('biometricWalletPasswords')) as Record<string, string>) || {};
      const encryptedPassword = walletPasswords[walletAddress];

      if (!encryptedPassword) {
        storageLogger.warn(`No biometric password found for wallet: ${walletAddress}`);
        return null;
      }

      // Decrypt the password using the secure key
      const { decrypted, format } = await decryptData(encryptedPassword, secureKey);
      if (format !== 'argon2id') {
        await this.migrateBiometricPassword(secureKey, decrypted, walletAddress);
      }
      return decrypted;
    } catch (error) {
      storageLogger.error('Failed to retrieve encrypted wallet password:', error);
      return null;
    }
  }

  // Re-seal a biometric password blob with the current Argon2id format after it was read from an
  // older KDF. Best-effort: a failure here must never turn a successful biometric unlock into a
  // failed one, so it only logs. Reuses setEncryptedWalletPassword, which writes both the wallet
  // record and the legacy preferences map.
  private static async migrateBiometricPassword(
    secureKey: string,
    password: string,
    walletAddress: string,
  ): Promise<void> {
    try {
      await this.setEncryptedWalletPassword(secureKey, password, walletAddress);
    } catch (migrationError) {
      storageLogger.warn('Could not upgrade biometric password to Argon2id', migrationError);
    }
  }

  static async removeEncryptedWalletPassword(walletAddress?: string): Promise<void> {
    try {
      if (walletAddress) {
        // Remove password for a specific wallet
        const walletPasswords =
          ((await this.getPreference('biometricWalletPasswords')) as Record<string, string>) || {};

        if (walletPasswords[walletAddress]) {
          delete walletPasswords[walletAddress];
          await this.setPreference('biometricWalletPasswords', walletPasswords);
        }

        // If this was the current biometric wallet, remove that reference
        const currentBiometricWallet = (await this.getPreference(
          'biometricWalletAddress',
        )) as string;
        if (currentBiometricWallet === walletAddress) {
          await this.removePreference('biometricWalletAddress');
        }
      } else {
        // Remove all wallet passwords
        await this.removePreference('biometricWalletPasswords');
        await this.removePreference('biometricWalletAddress');
      }
    } catch (error) {
      storageLogger.error('Failed to remove encrypted wallet password:', error);
      throw error;
    }
  }

  /**
   * Migrate transaction records to include walletAddress for better multi-wallet support
   */
  static async migrateTransactionAddresses(): Promise<number> {
    try {
      // Get all transactions
      const allTransactions = await this.performTransaction('transactions', 'readonly', (store) =>
        store.getAll(),
      );

      // Get all wallet addresses for validation
      const wallets = await this.getAllWallets();
      const walletAddresses = wallets.map((wallet) => wallet.address);

      let updatedCount = 0;

      // For each transaction that doesn't have a walletAddress, add it
      for (const tx of allTransactions) {
        let needsUpdate = false;

        // If walletAddress is missing, we need to determine it
        if (!tx.walletAddress) {
          needsUpdate = true;
          if (tx.type === 'send') {
            // For 'send' transactions, the fromAddress should be the wallet address
            tx.walletAddress = tx.fromAddress || '';
          } else {
            // For 'receive' transactions, the recipient address is the wallet address
            tx.walletAddress = tx.address || '';
          }
        }

        // Validate if the assigned walletAddress is actually one of our wallets
        if (tx.walletAddress && !walletAddresses.includes(tx.walletAddress)) {
          // Try to fix it by checking if any other field matches our known wallets
          if (tx.fromAddress && walletAddresses.includes(tx.fromAddress)) {
            tx.walletAddress = tx.fromAddress;
            needsUpdate = true;
          } else if (tx.address && walletAddresses.includes(tx.address)) {
            tx.walletAddress = tx.address;
            needsUpdate = true;
          }
        }

        // Update transaction if needed
        if (needsUpdate) {
          await this.performTransaction('transactions', 'readwrite', (store) => store.put(tx));
          updatedCount++;
        }
      }

      return updatedCount;
    } catch (error) {
      storageLogger.error('Failed to migrate transaction addresses:', error);
      return 0;
    }
  }

  static async cleanupDuplicateTransactions(): Promise<number> {
    try {
      // Get all transactions
      const allTransactions = await this.performTransaction('transactions', 'readonly', (store) =>
        store.getAll(),
      );

      // Group transactions by their txid + type + walletAddress
      const groupedTransactions = new Map<string, TransactionData[]>();

      for (const tx of allTransactions) {
        const key = `${tx.txid}-${tx.type}-${tx.walletAddress || 'unknown'}`;
        if (!groupedTransactions.has(key)) {
          groupedTransactions.set(key, []);
        }
        groupedTransactions.get(key)!.push(tx);
      }

      let removedCount = 0;
      const toRemoveIds: number[] = [];

      // For each group that has duplicates, keep only the newest one
      Array.from(groupedTransactions.entries()).forEach(([key, transactions]) => {
        if (transactions.length > 1) {
          // Sort by ID (descending) to keep the newest one
          transactions.sort((a: TransactionData, b: TransactionData) => {
            const idA = a.id ?? 0;
            const idB = b.id ?? 0;
            return idB - idA;
          });

          // Keep the first one (highest ID), remove the rest
          const toKeep = transactions[0];
          const toRemove = transactions.slice(1);

          // Collect IDs to remove
          for (const tx of toRemove) {
            if (tx.id) {
              toRemoveIds.push(tx.id);
            }
          }
        }
      });

      // Delete all duplicates in one transaction
      for (const id of toRemoveIds) {
        try {
          await this.performTransaction('transactions', 'readwrite', (store) => store.delete(id));
          removedCount++;
        } catch (deleteError) {
          storageLogger.error(`Failed to remove duplicate transaction ${id}:`, deleteError);
        }
      }

      return removedCount;
    } catch (error) {
      storageLogger.error('Failed to cleanup duplicate transactions:', error);
      return 0;
    }
  }

  // Get wallet balance from wallet table
  static async getWalletBalance(walletAddress: string): Promise<number> {
    try {
      const wallet = await this.getWalletByAddress(walletAddress);
      if (wallet && typeof wallet.balance === 'number') {
        return wallet.balance;
      }
      // If no balance stored in wallet, fallback to global balance
      return this.getLastBalance();
    } catch (error) {
      storageLogger.error('Failed to get wallet balance:', error);
      return 0;
    }
  }

  // Set wallet balance in wallet table
  static async setWalletBalance(walletAddress: string, balance: number): Promise<void> {
    try {
      const wallet = await this.getWalletByAddress(walletAddress);
      if (wallet) {
        const updatedWallet = {
          ...wallet,
          balance,
          lastBalanceUpdate: new Date(),
          lastAccessed: new Date(),
        };

        await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));

        // Also update the last global balance for backward compatibility
        await this.setLastBalance(balance);

        // Update localStorage tracking for notification system
        try {
          // Store in the notification system's format for compatibility
          const balances = JSON.parse(localStorage.getItem('lastKnownBalances') || '{}');
          balances[walletAddress] = {
            balance,
            timestamp: Date.now(),
          };
          localStorage.setItem('lastKnownBalances', JSON.stringify(balances));
        } catch (e) {
          storageLogger.error('Failed to update lastKnownBalances in localStorage:', e);
        }
      }
    } catch (error) {
      storageLogger.error('Failed to set wallet balance:', error);
    }
  }

  // Migrate balance data from various sources to the wallet table
  static async migrateBalanceData(): Promise<void> {
    try {
      // Get all wallets
      const wallets = await this.getAllWallets();

      for (const wallet of wallets) {
        // Check if the wallet already has a balance
        if (wallet.balance !== undefined) {
          continue;
        }

        let balance: number | undefined;

        // First try to get wallet-specific balance from localStorage
        try {
          const balancesStr = localStorage.getItem('lastKnownBalances');
          if (balancesStr) {
            const balances = JSON.parse(balancesStr);
            if (balances[wallet.address]) {
              balance = balances[wallet.address].balance;
            }
          }
        } catch (e) {
          storageLogger.error('Error reading lastKnownBalances:', e);
        }

        // If no wallet-specific balance, try legacy storage
        if (balance === undefined) {
          try {
            // Check the old global format
            const oldBalanceStr = localStorage.getItem('lastKnownBalance');
            if (oldBalanceStr) {
              const oldBalance = JSON.parse(oldBalanceStr);
              if (oldBalance && typeof oldBalance.balance === 'number') {
                balance = oldBalance.balance;
              }
            }
          } catch (e) {
            storageLogger.error('Error reading lastKnownBalance:', e);
          }
        }

        // If still no balance, try even older format
        if (balance === undefined) {
          try {
            const oldestBalanceStr = localStorage.getItem('avian_wallet_last_balance');
            if (oldestBalanceStr) {
              balance = parseInt(oldestBalanceStr, 10);
            }
          } catch (e) {
            storageLogger.error('Error reading avian_wallet_last_balance:', e);
          }
        }

        // If still no balance, try global preference
        if (balance === undefined) {
          balance = await this.getLastBalance();
        }

        // Set the balance in the wallet record
        if (balance !== undefined) {
          const updatedWallet = {
            ...wallet,
            balance,
            lastBalanceUpdate: new Date(),
          };

          await this.performTransaction('wallets', 'readwrite', (store) =>
            store.put(updatedWallet),
          );
        }
      }
    } catch (error) {
      storageLogger.error('Failed to migrate balance data:', error);
    }
  }

  /**
   * Returns all wallets that have biometrics enabled
   */
  static async getWalletsWithBiometricsEnabled(): Promise<WalletData[]> {
    try {
      const wallets = await this.getAllWallets();
      return wallets.filter((wallet) => wallet.biometricsEnabled === true);
    } catch (error) {
      storageLogger.error('Failed to get wallets with biometrics:', error);
      return [];
    }
  }

  static async saveWalletWithBiometricData(
    wallet: WalletData,
    credentialId: number[],
  ): Promise<boolean> {
    try {
      if (!wallet || !wallet.address) {
        storageLogger.error('Invalid wallet provided for biometric data update');
        return false;
      }

      // Create updated wallet object with biometric data
      const updatedWallet = {
        ...wallet,
        biometricsEnabled: true,
        biometricCredentialId: credentialId,
        lastAccessed: new Date(), // Update last accessed time
      };

      // Save to IndexedDB
      await this.performTransaction('wallets', 'readwrite', (store) => store.put(updatedWallet));

      return true;
    } catch (error) {
      storageLogger.error('Failed to save wallet with biometric data:', error);
      return false;
    }
  }

  // Watched address balance history methods

  /**
   * Get all stored watched address balances
   */
  static async getAllWatchedAddressBalances(): Promise<Record<string, number>> {
    try {
      const balances = await this.performTransaction(
        'watched_address_balances',
        'readonly',
        (store) => store.getAll(),
      );

      // Convert array of objects to record
      const balanceRecord: Record<string, number> = {};
      balances.forEach((item: { address: string; balance: number }) => {
        balanceRecord[item.address] = item.balance;
      });

      return balanceRecord;
    } catch (error) {
      storageLogger.error('Error getting all watched address balances:', error);
      return {};
    }
  }

  /**
   * Get balance for specific watched address
   */
  static async getWatchedAddressBalance(address: string): Promise<number | null> {
    try {
      const result = await this.performTransaction(
        'watched_address_balances',
        'readonly',
        (store) => store.get(address),
      );

      return result ? result.balance : null;
    } catch (error) {
      storageLogger.error(`Error getting balance for watched address ${address}:`, error);
      return null;
    }
  }

  /**
   * Update balance for a watched address
   */
  static async updateWatchedAddressBalance(address: string, balance: number): Promise<void> {
    try {
      const record = {
        address,
        balance,
        lastChecked: Date.now(),
      };

      await this.performTransaction('watched_address_balances', 'readwrite', (store) =>
        store.put(record),
      );
    } catch (error) {
      storageLogger.error(`Error updating balance for watched address ${address}:`, error);
    }
  }

  /**
   * Update multiple watched address balances at once
   */
  static async updateWatchedAddressBalances(balances: Record<string, number>): Promise<void> {
    try {
      const db = await this.initDB();
      const transaction = db.transaction(['watched_address_balances'], 'readwrite');
      const store = transaction.objectStore('watched_address_balances');
      const now = Date.now();

      // Process each balance update
      for (const [address, balance] of Object.entries(balances)) {
        const record = {
          address,
          balance,
          lastChecked: now,
        };

        store.put(record);
      }

      return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () =>
          reject(new Error('Transaction failed while updating watched address balances'));
      });
    } catch (error) {
      storageLogger.error('Error updating multiple watched address balances:', error);
    }
  }

  /**
   * Helper to properly set up wallet switch state
   * This prevents false notifications during wallet switches
   */
  private static setWalletSwitchState(switchState: WalletSwitchState): void {
    try {
      // Set the in progress flag
      localStorage.setItem('wallet_switch_in_progress', String(switchState.inProgress));
      localStorage.setItem('wallet_switch_timestamp', String(switchState.timestamp));

      // Track wallet addresses
      if (switchState.fromAddress) {
        localStorage.setItem('switching_from_address', switchState.fromAddress);
      }
      if (switchState.toAddress) {
        localStorage.setItem('switching_to_address', switchState.toAddress);
        localStorage.setItem('previous_wallet_address', switchState.fromAddress || '');
      }

      // Track wallet IDs
      if (switchState.fromId !== undefined) {
        localStorage.setItem('switching_from_id', String(switchState.fromId));
      }
      if (switchState.toId !== undefined) {
        localStorage.setItem('switching_to_id', String(switchState.toId));
      }

      storageLogger.debug('Set wallet switch state', switchState);
    } catch (error) {
      storageLogger.error('Error setting wallet switch state:', error);
    }
  }

  /**
   * Helper to clear wallet switch state
   */
  private static clearWalletSwitchState(): void {
    try {
      localStorage.removeItem('wallet_switch_in_progress');
      localStorage.removeItem('wallet_switch_timestamp');
      localStorage.removeItem('switching_from_address');
      localStorage.removeItem('switching_to_address');
      localStorage.removeItem('switching_from_id');
      localStorage.removeItem('switching_to_id');

      storageLogger.debug('Cleared wallet switch state');
    } catch (error) {
      storageLogger.error('Error clearing wallet switch state:', error);
    }
  }

  /**
   * Helper to get current wallet switch state
   */
  static getWalletSwitchState(): WalletSwitchState | null {
    try {
      const inProgress = localStorage.getItem('wallet_switch_in_progress') === 'true';

      // If not in progress, return null
      if (!inProgress) {
        return null;
      }

      // Get timestamp
      const timestamp = parseInt(localStorage.getItem('wallet_switch_timestamp') || '0', 10);

      // Get addresses
      const fromAddress = localStorage.getItem('switching_from_address') || undefined;
      const toAddress = localStorage.getItem('switching_to_address') || undefined;

      // Get IDs
      const fromIdStr = localStorage.getItem('switching_from_id');
      const toIdStr = localStorage.getItem('switching_to_id');

      const fromId = fromIdStr ? parseInt(fromIdStr, 10) : undefined;
      const toId = toIdStr ? parseInt(toIdStr, 10) : undefined;

      return {
        inProgress,
        timestamp,
        fromAddress,
        toAddress,
        fromId,
        toId,
      };
    } catch (error) {
      storageLogger.error('Error getting wallet switch state:', error);
      return null;
    }
  }

  /**
   * Determines if the specified wallet address was involved in a wallet switch
   * Returns true if the address is either the source or target of a recent switch
   *
   * @param walletAddress The wallet address to check
   * @param timeWindowMs How recent the switch needs to be (default: 10 seconds)
   */
  static isAddressInRecentWalletSwitch(
    walletAddress: string,
    timeWindowMs: number = 10000,
  ): boolean {
    try {
      // Check if there's an active switch for this address
      const switchState = this.getWalletSwitchState();
      if (
        switchState &&
        (switchState.fromAddress === walletAddress || switchState.toAddress === walletAddress)
      ) {
        return true;
      }

      // Check if there was a recent switch involving this address
      const previousAddress = localStorage.getItem('previous_wallet_address');
      const lastActiveAddress = localStorage.getItem('last_active_wallet');

      // If this address was the previous or is the current, and they're different
      if (
        previousAddress &&
        lastActiveAddress &&
        previousAddress !== lastActiveAddress &&
        (walletAddress === previousAddress || walletAddress === lastActiveAddress)
      ) {
        // Check how long ago the switch happened
        const switchTimestamp = parseInt(
          localStorage.getItem('wallet_switch_timestamp') || '0',
          10,
        );
        if (switchTimestamp && Date.now() - switchTimestamp < timeWindowMs) {
          return true;
        }
      }

      return false;
    } catch (error) {
      storageLogger.error('Error checking if address was in recent wallet switch:', error);
      return false;
    }
  }
}
