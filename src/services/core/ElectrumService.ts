interface UTXO {
  txid: string;
  vout: number;
  value: number;
  height?: number;
}

/** An asset UTXO — a plain UTXO plus the asset name it carries (null for a base-coin UTXO). */
export interface AssetUTXO extends UTXO {
  asset: string | null;
}

/** Asset metadata from blockchain.asset.get_meta. `divisions` is the unit count (0–8). */
export interface AssetMeta {
  name: string;
  divisions: number;
  reissuable: boolean;
  hasIpfs: boolean;
  ipfs: string | null;
  satsInCirculation: number;
}

/** Where a reported balance came from — see getBalanceDetailed. */
export type BalanceSource = 'live' | 'cache' | 'stored' | 'unknown';

export interface DetailedBalance {
  balance: number;
  source: BalanceSource;
}

interface BalanceResponse {
  confirmed: number;
  unconfirmed: number;
}

interface ElectrumServer {
  host: string;
  port: number;
  protocol: 'wss' | 'ws' | 'tcp';
  region?: string;
}

interface ElectrumRequest {
  id: number;
  method: string;
  params: any[];
}

interface ElectrumResponse {
  id: number;
  result?: any;
  error?: {
    code: number;
    message: string;
  };
}

interface ElectrumNotification {
  method: string;
  params: any[];
}

/** One pre-classified history row from the `get_history_rich` extension. Amounts are in satoshis. */
export interface RichHistoryTx {
  txid: string;
  height: number;
  time: number;
  type: 'send' | 'receive';
  amount: number;
  /** The other party, or null when none resolves (e.g. a coinbase payout — see `coinbase`). */
  counterparty: string | null;
  /** True for a coinbase / mining payout. Optional: older servers omit it (infer from a null
   *  counterparty on a receive instead). */
  coinbase?: boolean;
  fee: number;
  confirmations: number;
}

/** One page of `get_history_rich` results, newest-first, with the total for pagination. */
export interface RichHistoryPage {
  total: number;
  page: number;
  page_size: number;
  order: string;
  txs: RichHistoryTx[];
}

import * as bitcoin from 'bitcoinjs-lib';
import { electrumLogger } from '@/lib/Logger';

// Avian network configuration (same as in WalletService)
const avianNetwork: bitcoin.Network = {
  messagePrefix: '\x16Raven Signed Message:\n',
  bech32: 'avn',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0x3c, // Avian addresses start with 'R'
  scriptHash: 0x7a,
  wif: 0x80,
};

export class ElectrumService {
  private servers: ElectrumServer[];
  private currentServer: ElectrumServer | null = null;
  private websocket: WebSocket | null = null;
  private isConnected: boolean = false;
  private isConnecting: boolean = false;
  private requestId: number = 0;
  private pendingRequests: Map<
    number,
    { resolve: (value: any) => void; reject: (reason: any) => void }
  > = new Map();
  private subscriptions: Map<string, (data: any) => void> = new Map();
  private realBalanceCache: Map<string, number> = new Map(); // Cache real balances from subscriptions
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectTimeout: NodeJS.Timeout | null = null;
  // Whether the current server advertises our get_history_rich extension. null = not yet probed;
  // reset whenever the server changes so a switch re-detects.
  private richHistorySupported: boolean | null = null;

  constructor() {
    // Array of Avian ElectrumX servers
    this.servers = [
      { host: 'electrum-us.avn.network', port: 50003, protocol: 'wss', region: 'US' },
      { host: 'electrum-eu.avn.network', port: 50003, protocol: 'wss', region: 'EU' },
      { host: 'electrum-ca.avn.network', port: 50003, protocol: 'wss', region: 'CA' },
    ];

    // Select the first server as default
    this.currentServer = this.servers[0];
  }

  async connect(): Promise<void> {
    try {
      if (!this.currentServer) {
        throw new Error('No server selected');
      }

      // Don't attempt to connect if already connected or connecting
      if (this.isConnected && this.websocket) {
        return;
      }

      if (this.isConnecting) {
        return;
      }

      // Set connecting state
      this.isConnecting = true;

      // Clean up any existing connection
      if (this.websocket) {
        this.websocket.close();
        this.websocket = null;
      }

      const url = `${this.currentServer.protocol}://${this.currentServer.host}:${this.currentServer.port}`;
      electrumLogger.debug(`Connecting to Electrum server: ${url}`);

      return new Promise((resolve, reject) => {
        this.websocket = new WebSocket(url);

        this.websocket.onopen = () => {
          this.isConnected = true;
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          electrumLogger.debug(`Connected to Electrum server: ${url}`);

          resolve();

          // Server-side subscriptions die with the socket, so after a reconnect every address
          // we were watching must be re-subscribed or balance updates silently stop arriving.
          // Fire-and-forget: the connection is usable regardless of how re-subscription fares.
          void this.resubscribeAll();
        };

        this.websocket.onclose = (event) => {
          this.isConnected = false;
          this.isConnecting = false;
          electrumLogger.debug(
            `WebSocket closed: code=${event.code}, reason=${event.reason || 'unknown'}`,
          );

          // Fail every in-flight request now. The socket is gone, so no response will ever arrive;
          // without this each pending request would hang until its own 30s timeout, stalling a sync
          // for half a minute every time a rate-limiting server drops the connection. Rejecting now
          // lets callers fail fast and retry once we reconnect.
          this.failPendingRequests(`Connection closed (code ${event.code})`);

          // If the socket closed before it ever opened, nothing else will settle the connect()
          // promise: onopen never fires, and this handler clears isConnecting, which defuses
          // the connection-timeout guard below. Without this reject, callers await forever and
          // the app hangs on its loading screen whenever the server refuses the connection.
          // (Rejecting an already-settled promise is a no-op, so later closes are harmless.)
          reject(new Error(`Connection closed before opening (code ${event.code})`));

          // Attempt to reconnect if not manually closed and not already reconnecting
          if (
            event.code !== 1000 &&
            this.reconnectAttempts < this.maxReconnectAttempts &&
            !this.isConnecting
          ) {
            this.attemptReconnect();
          }
        };

        this.websocket.onerror = (error) => {
          electrumLogger.error('WebSocket error:', error);
          this.isConnected = false;
          this.isConnecting = false;
          reject(new Error('WebSocket connection failed'));
        };

        this.websocket.onmessage = (event) => {
          this.handleMessage(event.data);
        };

        // Connection timeout
        setTimeout(() => {
          if (!this.isConnected && this.isConnecting) {
            this.isConnecting = false;
            this.websocket?.close();
            reject(new Error('Connection timeout'));
          }
        }, 10000); // 10 second timeout
      });
    } catch (error) {
      this.isConnecting = false;
      electrumLogger.error('Failed to connect to Electrum server:', error);
      throw new Error('Connection failed');
    }
  }

  /**
   * Re-issues blockchain.scripthash.subscribe for every tracked subscription and delivers the
   * current status to its callback. Downstream compares the status and refetches the balance,
   * which also covers anything that changed while the connection was down.
   */
  private async resubscribeAll(): Promise<void> {
    if (this.subscriptions.size === 0) {
      return;
    }

    electrumLogger.info(
      `Re-establishing ${this.subscriptions.size} address subscription(s) after reconnect`,
    );

    for (const [scriptHash, callback] of Array.from(this.subscriptions.entries())) {
      try {
        const status = await this.makeRequest('blockchain.scripthash.subscribe', [scriptHash]);
        callback({
          scripthash: scriptHash,
          status,
          method: 'blockchain.scripthash.subscribe',
        });
      } catch (error) {
        electrumLogger.error(
          `Failed to re-subscribe ${scriptHash.substring(0, 8)}… after reconnect:`,
          error,
        );
        // Keep going: one failed re-subscription must not strand the others.
      }
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000); // Exponential backoff, max 30s

    electrumLogger.debug(
      `Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`,
    );

    this.reconnectTimeout = setTimeout(() => {
      this.connect().catch((error) => {
        electrumLogger.error('Reconnection failed:', error);
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          this.attemptReconnect();
        }
      });
    }, delay);
  }

  private handleMessage(data: string): void {
    try {
      const message = JSON.parse(data);

      // Handle responses to requests
      if (message.id !== undefined) {
        const pending = this.pendingRequests.get(message.id);
        if (pending) {
          this.pendingRequests.delete(message.id);

          if (message.error) {
            pending.reject(
              new Error(`ElectrumX error ${message.error.code}: ${message.error.message}`),
            );
          } else {
            pending.resolve(message.result);
          }
        }
      }
      // Handle notifications (subscriptions)
      else if (message.method) {
        this.handleNotification(message);
      }
    } catch (error) {
      electrumLogger.error('Error parsing WebSocket message:', error);
    }
  }

  private handleNotification(notification: ElectrumNotification): void {
    electrumLogger.debug(`Received notification: ${notification.method}`);

    if (notification.method === 'blockchain.scripthash.subscribe') {
      const [scripthash, status] = notification.params;
      const callback = this.subscriptions.get(scripthash);

      electrumLogger.debug(
        `Subscription update for scripthash: ${scripthash.substring(0, 8)}... status: ${status}`,
      );

      if (callback) {
        callback({
          scripthash,
          status,
          method: notification.method,
        });
      }
    }
  }

  // Get list of available servers
  getAvailableServers(): ElectrumServer[] {
    return this.servers;
  }

  // Get current server
  getCurrentServer(): ElectrumServer | null {
    return this.currentServer;
  }

  // Select server by index
  selectServer(index: number): void {
    if (index >= 0 && index < this.servers.length) {
      // Store information about whether we were connected
      const wasConnected = this.isConnected;

      // Disconnect from current server if connected
      if (wasConnected) {
        this.disconnect();
      }

      // Update current server
      this.currentServer = this.servers[index];
      this.richHistorySupported = null; // re-detect on the new server
      electrumLogger.debug(
        `Selected server: ${this.currentServer.host} (${this.currentServer.region || 'Unknown region'})`,
      );

      // Note: Connection must be initiated by the caller
    } else {
      throw new Error('Invalid server index');
    }
  }

  // Select server by host
  selectServerByHost(host: string): void {
    const server = this.servers.find((s) => s.host === host);
    if (server) {
      // Store information about whether we were connected
      const wasConnected = this.isConnected;

      // Disconnect from current server if connected
      if (wasConnected) {
        this.disconnect();
      }

      // Update current server
      this.currentServer = server;
      this.richHistorySupported = null; // re-detect on the new server
      electrumLogger.debug(
        `Selected server by host: ${this.currentServer.host} (${this.currentServer.region || 'Unknown region'})`,
      );

      // Note: Connection must be initiated by the caller
    } else {
      throw new Error(`Server not found: ${host}`);
    }
  }

  // Auto-select best server (for future implementation)
  async selectBestServer(): Promise<void> {
    try {
      // For now, just select the first server
      // In production, implement ping/latency testing
      this.currentServer = this.servers[0];
    } catch (error) {
      electrumLogger.error('Failed to auto-select server:', error);
      throw error;
    }
  }

  // Get server URL for display
  getServerUrl(): string {
    if (!this.currentServer) return 'No server selected';
    return `${this.currentServer.protocol}://${this.currentServer.host}:${this.currentServer.port}`;
  }

  async getBalance(address: string, forceRefresh: boolean = false): Promise<number> {
    return (await this.getBalanceDetailed(address, forceRefresh)).balance;
  }

  /**
   * Like getBalance, but reports where the number came from. The fallback chain means a plain
   * number is ambiguous — a 0 could be the server's answer or "we have no idea" — and the UI
   * must not present the second as the first.
   *
   * - live:    the server answered just now
   * - cache:   pushed to us by a subscription earlier in this session
   * - stored:  persisted from a previous session; real, but possibly stale
   * - unknown: nothing to go on — the balance should be shown as unavailable, not as 0
   */
  async getBalanceDetailed(address: string, forceRefresh: boolean = false): Promise<DetailedBalance> {
    try {
      // Log the balance request for debugging
      electrumLogger.debug(
        `Getting balance for address: ${address.substring(0, 5)}...${address.substring(address.length - 5)} (force: ${forceRefresh})`,
      );

      // First check if we have real balance data from subscriptions (unless force refresh is requested)
      const cachedBalance = this.realBalanceCache.get(address);
      if (cachedBalance !== undefined && !forceRefresh) {
        electrumLogger.debug(
          `Using cached balance for ${address.substring(0, 5)}...: ${cachedBalance}`,
        );
        return { balance: cachedBalance, source: 'cache' };
      }

      // Convert address to script hash for Electrum protocol
      const scriptHash = this.addressToScriptHash(address);

      // Make real request to ElectrumX server

      const response = await this.makeRequest('blockchain.scripthash.get_balance', [scriptHash]);

      const totalBalance = response.confirmed + response.unconfirmed;

      // Update cache with real balance
      this.realBalanceCache.set(address, totalBalance);
      electrumLogger.debug(
        `Balance retrieved for ${address.substring(0, 5)}...: ${totalBalance} (confirmed: ${response.confirmed}, unconfirmed: ${response.unconfirmed})`,
      );

      return { balance: totalBalance, source: 'live' };
    } catch (error) {
      // Return cached balance if available
      const cachedBalance = this.realBalanceCache.get(address);
      if (cachedBalance !== undefined) {
        electrumLogger.debug(
          `Failed to get balance from server, using cached balance for ${address.substring(0, 5)}...: ${cachedBalance}`,
        );
        return { balance: cachedBalance, source: 'cache' };
      }

      // Next: a balance persisted by a previous session. A stored zero is indistinguishable
      // from "nothing was ever stored" (the storage layer defaults to 0), so only a positive
      // value counts as real data here.
      try {
        const { StorageService } = await import('./StorageService');
        const walletBalance = await StorageService.getWalletBalance(address);
        if (walletBalance > 0) {
          return { balance: walletBalance, source: 'stored' };
        }
      } catch (storageError) {
        const storedBalance = localStorage.getItem('avian_wallet_last_balance');
        if (storedBalance && parseInt(storedBalance, 10) > 0) {
          return { balance: parseInt(storedBalance, 10), source: 'stored' };
        }
      }

      return { balance: 0, source: 'unknown' };
    }
  }

  async getUTXOs(address: string): Promise<UTXO[]> {
    try {
      const scriptHash = this.addressToScriptHash(address);
      const response = await this.makeRequest('blockchain.scripthash.listunspent', [scriptHash]);

      return response.map((utxo: any) => ({
        txid: utxo.tx_hash,
        vout: utxo.tx_pos,
        value: utxo.value,
        height: utxo.height,
      }));
    } catch (error) {
      return [];
    }
  }

  /**
   * Asset balances held at an address, keyed by asset name. Calls get_balance with asset=true, which
   * returns every balance at once; the base coin comes back keyed as "rvn" (ElectrumX's null-asset
   * alias) and is dropped here — AVN is the plain balance shown elsewhere. Amounts are integers
   * scaled by the asset's divisions (see getAssetMeta); formatting is the caller's job.
   */
  async getAssetBalances(address: string): Promise<Record<string, { confirmed: number; unconfirmed: number }>> {
    try {
      const scriptHash = this.addressToScriptHash(address);
      const response = await this.makeRequest('blockchain.scripthash.get_balance', [scriptHash, true]);
      const balances: Record<string, { confirmed: number; unconfirmed: number }> = {};
      for (const [name, bal] of Object.entries(response || {})) {
        if (name === 'rvn') continue; // the base coin (AVN), shown as the ordinary balance
        const b = bal as { confirmed?: number; unconfirmed?: number };
        balances[name] = { confirmed: b.confirmed || 0, unconfirmed: b.unconfirmed || 0 };
      }
      return balances;
    } catch (error) {
      electrumLogger.debug(`Failed to get asset balances for ${address.substring(0, 5)}...:`, error);
      // Deliberately rethrown. Answering {} makes a dropped connection indistinguishable from a
      // wallet holding nothing, and callers render that as "you have no assets" — which is how a
      // refresh during a wobble wiped the list.
      throw error instanceof Error ? error : new Error('Failed to load asset balances');
    }
  }

  /** Metadata for an asset, or null if it doesn't exist. */
  async getAssetMeta(name: string): Promise<AssetMeta | null> {
    try {
      const response = await this.makeRequest('blockchain.asset.get_meta', [name]);
      // ElectrumX returns an empty object ({}) for an asset that doesn't exist — a real asset always
      // carries a numeric `divisions`. Treat anything without it as "not found" so callers (e.g. the
      // create-asset availability check) don't read a non-existent name as taken.
      if (!response || typeof response.divisions !== 'number') return null;
      return {
        name,
        divisions: typeof response.divisions === 'number' ? response.divisions : 0,
        reissuable: !!response.reissuable,
        hasIpfs: !!response.has_ipfs,
        ipfs: response.has_ipfs ? response.ipfs || null : null,
        satsInCirculation: response.sats_in_circulation || 0,
      };
    } catch (error) {
      electrumLogger.debug(`Failed to get asset meta for ${name}:`, error);
      return null;
    }
  }

  /** UTXOs at an address for a specific asset (or, with `false`, the AVN-only UTXOs). */
  async getAssetUTXOs(address: string, asset: string): Promise<AssetUTXO[]> {
    try {
      const scriptHash = this.addressToScriptHash(address);
      const response = await this.makeRequest('blockchain.scripthash.listunspent', [scriptHash, asset]);
      return (response || []).map((utxo: any) => ({
        txid: utxo.tx_hash,
        vout: utxo.tx_pos,
        value: utxo.value,
        height: utxo.height,
        asset: utxo.asset ?? null,
      }));
    } catch (error) {
      electrumLogger.debug(`Failed to get asset UTXOs for ${asset}:`, error);
      return [];
    }
  }

  async broadcastTransaction(txHex: string): Promise<string> {
    try {
      // Parse the transaction to validate its structure before broadcasting
      try {
        const bitcoin = await import('bitcoinjs-lib');
        const tx = bitcoin.Transaction.fromHex(txHex);

        // Check each input has a script
        for (let i = 0; i < tx.ins.length; i++) {
          const scriptLength = tx.ins[i].script ? tx.ins[i].script.length : 0;
        }
      } catch (parseError) {
        electrumLogger.error('Transaction parsing error:', parseError);
        // Continue with broadcast attempt despite parsing error
      }

      const response = await this.makeRequest('blockchain.transaction.broadcast', [txHex]);

      return response;
    } catch (error) {
      electrumLogger.error('Failed to broadcast transaction:', error);

      // Provide more detailed error information
      let errorMessage = 'Unknown error';
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (typeof error === 'string') {
        errorMessage = error;
      } else if (error && typeof error === 'object') {
        errorMessage = JSON.stringify(error);
      }

      // Add hints for common Electrum errors
      if (errorMessage.includes('bad-txns-inputs-missingorspent')) {
        errorMessage += ' (Inputs already spent or invalid)';
      } else if (errorMessage.includes('non-mandatory-script-verify-flag')) {
        errorMessage += ' (Script verification failed, possibly incorrect signature)';
      } else if (errorMessage.includes('min relay fee not met')) {
        errorMessage += ' (Transaction fee too low)';
      }

      throw new Error(`Transaction broadcast failed: ${errorMessage}`);
    }
  }

  async getTransactionHistory(address: string): Promise<any[]> {
    try {
      const scriptHash = this.addressToScriptHash(address);
      const response = await this.makeRequest('blockchain.scripthash.get_history', [scriptHash]);

      return response;
    } catch (error) {
      electrumLogger.error('Failed to get transaction history:', error);
      return [];
    }
  }

  /**
   * Whether the current server advertises our `get_history_rich` extension (via a `avn_rich_history`
   * flag in server.features). Memoised per connection; reset when the server changes. On any error,
   * treated as unsupported so callers fall back to the standard reconstruction path.
   */
  async supportsRichHistory(): Promise<boolean> {
    if (this.richHistorySupported !== null) {
      return this.richHistorySupported;
    }
    try {
      const features = await this.getServerFeatures();
      // Cache the definitive answer (true, or false for a server that genuinely lacks it).
      this.richHistorySupported = !!features?.avn_rich_history;
      return this.richHistorySupported;
    } catch {
      // Transient failure (e.g. probed mid-disconnect): don't cache, so we re-detect next time
      // rather than disabling the fast path for the whole session.
      return false;
    }
  }

  /**
   * Fetch one page of pre-classified history from our `get_history_rich` extension. The server
   * returns rows already resolved to direction/amount/counterparty, newest-first, so the client
   * does not have to fetch each transaction and its inputs. `pageSize` is clamped to 1..100 because
   * the server rejects anything outside that range.
   */
  async getRichHistoryPage(
    address: string,
    page: number,
    pageSize: number,
  ): Promise<RichHistoryPage> {
    const scriptHash = this.addressToScriptHash(address);
    const size = Math.min(100, Math.max(1, Math.floor(pageSize)));
    return await this.makeRequest('blockchain.scripthash.get_history_rich', [
      scriptHash,
      Math.max(0, Math.floor(page)),
      size,
    ]);
  }

  /**
   * The network's fee rate in satoshis per vByte, from `blockchain.relayfee` (falling back to
   * `estimatefee`). Both report coins per kB, so convert. Returns 0 if neither is available, letting
   * the caller apply its own floor.
   */
  async getFeeRateSatPerVByte(): Promise<number> {
    const toSatPerVByte = (coinsPerKb: unknown): number => {
      const rate = (Number(coinsPerKb) * 100_000_000) / 1000;
      return Number.isFinite(rate) && rate > 0 ? rate : 0;
    };
    try {
      const relay = toSatPerVByte(await this.makeRequest('blockchain.relayfee', []));
      if (relay > 0) return relay;
    } catch {
      /* fall through to estimatefee */
    }
    try {
      return toSatPerVByte(await this.makeRequest('blockchain.estimatefee', [2]));
    } catch {
      return 0;
    }
  }

  async getTransaction(txHash: string, verbose: boolean = false): Promise<any> {
    try {
      const response = await this.makeRequest('blockchain.transaction.get', [txHash, verbose]);
      return response;
    } catch (error) {
      electrumLogger.error('Failed to get transaction:', error);
      throw error;
    }
  }

  async getServerVersion(): Promise<{ server: string; protocol: string }> {
    try {
      const response = await this.makeRequest('server.version', [
        'Avian FlightDeck Wallet 1.0',
        '1.4',
      ]);
      return response;
    } catch (error) {
      electrumLogger.error('Failed to get server version:', error);
      throw error;
    }
  }

  /**
   * server.features — reports the server's capabilities, including the chain's genesis hash.
   * Used by Avian Connect to answer getNetwork() without hard-coding a chain constant.
   */
  async getServerFeatures(): Promise<Record<string, any>> {
    try {
      return await this.makeRequest('server.features', []);
    } catch (error) {
      electrumLogger.error('Failed to get server features:', error);
      throw error;
    }
  }

  async ping(): Promise<void> {
    try {
      await this.makeRequest('server.ping', []);
    } catch (error) {
      electrumLogger.error('Failed to ping server:', error);
      throw error;
    }
  }

  async getCurrentBlockHeight(): Promise<number> {
    try {
      const result = await this.makeRequest('blockchain.headers.subscribe', []);
      return result.height;
    } catch (error) {
      electrumLogger.error('Failed to get current block height:', error);
      // Fallback: try alternative method
      try {
        const estimateResult = await this.makeRequest('blockchain.estimatefee', [1]);
        // If estimatefee works, try to get block count
        const blockCount = await this.makeRequest('blockchain.block.headers', [0, 1]);
        if (blockCount && blockCount.count) {
          return blockCount.count;
        }
      } catch (fallbackError) {
        electrumLogger.error('Fallback method also failed:', fallbackError);
      }
      // Return 0 if we can't get the height
      return 0;
    }
  }

  // Method to update real balance from external sources (like subscription updates)
  updateRealBalance(address: string, balance: number): void {
    electrumLogger.debug(`Updating cached balance for ${address.substring(0, 5)}...: ${balance}`);
    this.realBalanceCache.set(address, balance);
  }

  // Method to check if we have real balance data
  hasRealBalance(address: string): boolean {
    return this.realBalanceCache.has(address);
  }

  public addressToScriptHash(address: string): string {
    try {
      // Convert Avian address to output script
      const outputScript = bitcoin.address.toOutputScript(address, avianNetwork);

      // Calculate SHA256 hash of the output script
      const hash = bitcoin.crypto.sha256(outputScript);

      // Reverse the hash bytes (ElectrumX protocol requirement)
      const reversed = Buffer.from(hash).reverse();

      // Convert to hex string
      const scriptHash = reversed.toString('hex');

      return scriptHash;
    } catch (error) {
      electrumLogger.error('Error converting address to script hash:', error);
      // Fallback to a deterministic hash for development
      const fallbackHash = bitcoin.crypto.sha256(Buffer.from(address, 'utf8'));
      return Buffer.from(fallbackHash).reverse().toString('hex');
    }
  }

  private async makeRequest(method: string, params: any[]): Promise<any> {
    if (!this.isConnected || !this.websocket) {
      throw new Error('Not connected to Electrum server');
    }

    const id = ++this.requestId;
    const request: ElectrumRequest = { id, method, params };

    return new Promise((resolve, reject) => {
      // Store the pending request
      this.pendingRequests.set(id, { resolve, reject });

      // Send the request
      this.websocket!.send(JSON.stringify(request));

      // Set timeout for the request
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Request timeout: ${method}`));
        }
      }, 30000); // 30 second timeout
    });
  }

  // Reject and clear every in-flight request. Called when the socket closes so callers fail fast
  // instead of waiting out each request's 30s timeout on a connection that is already gone.
  private failPendingRequests(reason: string): void {
    if (this.pendingRequests.size === 0) return;
    const error = new Error(reason);
    for (const { reject } of this.pendingRequests.values()) {
      reject(error);
    }
    this.pendingRequests.clear();
  }

  /**
   * Resolve once the socket is connected again, or reject after `timeoutMs`. The close handler
   * already schedules reconnection with backoff; this lets a caller (e.g. a history sync that lost
   * a request to a dropped connection) wait for that reconnect and retry on the fresh socket.
   */
  async waitForConnection(timeoutMs = 15000): Promise<void> {
    if (this.isConnected) return;
    const start = Date.now();
    while (!this.isConnected) {
      if (Date.now() - start > timeoutMs) {
        throw new Error('Timed out waiting for Electrum reconnection');
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }

  async subscribeToAddress(address: string, callback: (data: any) => void): Promise<void> {
    try {
      electrumLogger.debug(`Subscribing to address: ${address.substring(0, 5)}...`);
      const scriptHash = this.addressToScriptHash(address);

      // Store the subscription callback
      this.subscriptions.set(scriptHash, callback);

      // Send subscription request to ElectrumX server
      try {
        const initialStatus = await this.makeRequest('blockchain.scripthash.subscribe', [
          scriptHash,
        ]);
        electrumLogger.debug(
          `Successfully subscribed to ${address.substring(0, 5)}..., initial status: ${initialStatus}`,
        );

        // Call the callback with initial status
        callback({
          scripthash: scriptHash,
          status: initialStatus,
          method: 'blockchain.scripthash.subscribe',
        });
      } catch (subscribeError) {
        const errorMessage =
          subscribeError instanceof Error ? subscribeError.message : String(subscribeError);

        // Handle "history too large" error specifically
        if (
          errorMessage.includes('history too large') ||
          errorMessage.includes('too many history entries')
        ) {
          electrumLogger.warn(
            `Address has too much history for subscription: ${address}. Using polling fallback.`,
          );

          // Get initial balance directly instead of subscribing
          const balance = await this.makeRequest('blockchain.scripthash.get_balance', [scriptHash]);
          const totalBalance = balance.confirmed + (balance.unconfirmed || 0);

          // Update cache with the balance
          this.updateRealBalance(address, totalBalance);

          // Call callback with manual status to simulate subscription
          callback({
            scripthash: scriptHash,
            status: `balance:${totalBalance}`,
            method: 'blockchain.scripthash.subscribe',
            useFallback: true,
          });

          // Set up polling fallback for addresses with large history
          this.setupPollingFallback(address, scriptHash, callback);
          return;
        }

        // For other errors, propagate them
        throw subscribeError;
      }
    } catch (error) {
      electrumLogger.error('Failed to subscribe to address:', error);
      throw error;
    }
  }

  // Fallback polling mechanism for addresses with too large history
  private pollingIntervals: Map<string, NodeJS.Timeout> = new Map();

  private setupPollingFallback(
    address: string,
    scriptHash: string,
    callback: (data: any) => void,
  ): void {
    // Clear any existing polling interval for this address
    if (this.pollingIntervals.has(address)) {
      clearInterval(this.pollingIntervals.get(address)!);
    }

    // Set up polling every 30 seconds
    const intervalId = setInterval(async () => {
      try {
        if (!this.isConnected) {
          return; // Skip if not connected
        }

        // Get balance directly
        const balance = await this.makeRequest('blockchain.scripthash.get_balance', [scriptHash]);
        const totalBalance = balance.confirmed + (balance.unconfirmed || 0);

        // Get previously cached balance
        const previousBalance = this.realBalanceCache.get(address) || 0;

        // If balance changed, update cache and trigger callback
        if (totalBalance !== previousBalance) {
          this.updateRealBalance(address, totalBalance);

          callback({
            scripthash: scriptHash,
            status: `balance:${totalBalance}`,
            method: 'blockchain.scripthash.subscribe',
            useFallback: true,
            previousBalance,
          });
        }
      } catch (error) {
        electrumLogger.error('Error in polling fallback for address:', address, error);
      }
    }, 30000); // Poll every 30 seconds

    // Store the interval ID for cleanup
    this.pollingIntervals.set(address, intervalId);
  }

  async unsubscribeFromAddress(address: string): Promise<void> {
    try {
      const scriptHash = this.addressToScriptHash(address);

      // Remove from local subscriptions
      this.subscriptions.delete(scriptHash);

      // Clear any polling fallback for this address
      if (this.pollingIntervals.has(address)) {
        clearInterval(this.pollingIntervals.get(address)!);
        this.pollingIntervals.delete(address);
      }

      try {
        // Send unsubscribe request to server - might fail if using polling fallback
        await this.makeRequest('blockchain.scripthash.unsubscribe', [scriptHash]);
      } catch (unsubscribeError) {
        // Ignore errors when unsubscribing, as the subscription might not exist
        // if we're using the polling fallback
        electrumLogger.debug(
          `Unsubscribe request failed for ${address}, possibly using fallback: ${unsubscribeError}`,
        );
      }
    } catch (error) {
      electrumLogger.error('Failed to unsubscribe from address:', error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    electrumLogger.debug('Disconnecting from Electrum server');

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    // Clear all polling fallback intervals
    this.pollingIntervals.forEach((intervalId, address) => {
      clearInterval(intervalId);
    });
    this.pollingIntervals.clear();
    electrumLogger.debug(`Cleared ${this.pollingIntervals.size} polling intervals`);

    if (this.websocket) {
      this.websocket.close(1000, 'User disconnect'); // Normal closure
      this.websocket = null;
    }

    this.isConnected = false;
    this.isConnecting = false;
    this.failPendingRequests('Disconnected from Electrum server');
    this.subscriptions.clear();
    this.reconnectAttempts = 0;

    electrumLogger.debug('Disconnect complete');
  }

  isConnectedToServer(): boolean {
    return this.isConnected;
  }

  // Return the current connection status
  getConnectionStatus(): boolean {
    return this.isConnected && this.websocket !== null;
  }

  // Get server info
  async getServerInfo(): Promise<any> {
    try {
      const response = await this.makeRequest('server.banner', []);
      return response;
    } catch (error) {
      electrumLogger.error('Failed to get server info:', error);
      throw error;
    }
  }

  /**
   * Get the public key for a given address by searching for transactions
   * where it was revealed.
   * @param address - The Avian address to find the public key for
   * @returns The public key as a hex string if found, null otherwise
   */
  async getPublicKeyForAddress(address: string): Promise<string | null> {
    try {
      // ecpair + tiny-secp256k1 are loaded lazily here — this is the only method in the service
      // that needs them, and it is rarely called, so keeping them out of the module's static
      // imports removes ~1.7 MB from the read-only balance path that every route mounts.
      const { ECPairFactory } = await import('ecpair');
      const ecc = await import('tiny-secp256k1');
      const ECPair = ECPairFactory(ecc);

      // Make sure we're connected
      if (!this.isConnected || !this.websocket) {
        await this.connect();
      }

      // First, get transaction history for the address
      const scriptHash = this.addressToScriptHash(address);
      const history = await this.makeRequest('blockchain.scripthash.get_history', [scriptHash]);

      if (!history || history.length === 0) {
        electrumLogger.warn('No transaction history found for address:', address);
        return null;
      }

      // Sort transactions from newest to oldest
      history.sort((a: any, b: any) => b.height - a.height);

      // Try to find a transaction where the public key was revealed (usually in the input)
      for (const tx of history) {
        const txDetails = await this.makeRequest('blockchain.transaction.get', [tx.tx_hash, true]);

        // Typically, public keys are revealed in transaction inputs
        if (txDetails.vin && txDetails.vin.length > 0) {
          for (const input of txDetails.vin) {
            // If this input is from our address, it might have the public key
            if (input.scriptSig && input.scriptSig.hex) {
              // Extract public key from the script signature
              // This is a simplified approach; in a real implementation,
              // we would need to properly parse the script signature
              // Public key is usually after the signature in P2PKH transactions
              const scriptSig = Buffer.from(input.scriptSig.hex, 'hex');

              // Look for a standard pattern where the public key would be
              // This is simplified and might need adjustments for Avian specifics
              if (scriptSig.length > 70) {
                // Rough estimate, signature ~70-72 bytes + public key 33 bytes
                // For compressed public keys (33 bytes)
                const potentialPubKey = scriptSig.slice(-33).toString('hex');

                // Verify that this is indeed our address's public key
                try {
                  // Use bitcoinjs-lib to convert public key to address
                  const keyPair = ECPair.fromPublicKey(Buffer.from(potentialPubKey, 'hex'));
                  const { address: derivedAddress } = bitcoin.payments.p2pkh({
                    pubkey: Buffer.from(keyPair.publicKey),
                    network: avianNetwork,
                  });

                  if (derivedAddress === address) {
                    return potentialPubKey;
                  }
                } catch (e) {
                  // Not a valid public key, continue searching
                  electrumLogger.debug('Invalid public key candidate:', e);
                }
              }
            }
          }
        }
      }

      electrumLogger.warn('Could not find public key for address in transaction history:', address);
      return null;
    } catch (error) {
      electrumLogger.error('Error getting public key from address via Electrum:', error);
      return null;
    }
  }
}
