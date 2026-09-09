'use client';

import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { AlertTriangle, ArrowRight, CheckCircle2, Globe, Loader2, ShieldCheck } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import GradientBackground from '@/components/GradientBackground';
import ConnectApprovalDialog, {
  ConnectAccountOption,
} from '@/components/connect/ConnectApprovalDialog';
import SignMessageApprovalDialog from '@/components/connect/SignMessageApprovalDialog';
import SignPsbtApprovalDialog from '@/components/connect/SignPsbtApprovalDialog';
import SignAssetListingApprovalDialog from '@/components/connect/SignAssetListingApprovalDialog';
import BuyAssetApprovalDialog from '@/components/connect/BuyAssetApprovalDialog';
import type { PsbtSummary } from '@/services/wallet/psbt';

import { useWallet } from '@/contexts/WalletContext';
import { useSecurity } from '@/contexts/SecurityContext';
import { StorageService } from '@/services/core/StorageService';
import { PermissionService } from '@/services/provider';
import { WalletService, type AssetListingPreview } from '@/services/wallet/WalletService';
import { providerLogger } from '@/lib/Logger';
import {
  ConnectApprovalDecision,
  ProviderHost,
  ProviderService,
  buildRedirectUrl,
  decodeRequestParam,
  getNetworkDescriptor,
  makeError,
  makeEvent,
  normalizeOrigin,
  validateRedirectUri,
} from '@/services/provider';
import { ConnectEventName, ConnectResponse } from '@/types/avianConnect';

type Transport = 'idle' | 'popup' | 'redirect' | 'standalone';

interface SignPrompt {
  origin: string;
  account: string;
  message: string;
}

interface PsbtPrompt {
  origin: string;
  account: string;
  summary: PsbtSummary;
  /** The site asked the wallet to broadcast, not just sign. */
  broadcast: boolean;
}

interface ListingPrompt {
  origin: string;
  account: string;
  assetName: string;
  priceSats: number;
}

interface BuyPrompt {
  origin: string;
  account: string;
  listing: AssetListingPreview;
}

/** Channel used by Settings → Connected Sites to tell a live session its grants changed. */
const PERMISSION_CHANNEL = 'avian-connect';

function ConnectClient() {
  const searchParams = useSearchParams();
  const { electrum } = useWallet();
  const { requireAuth } = useSecurity();

  const [walletService] = useState(() => new WalletService());

  // The service is created on mount, before the app's ElectrumService exists. Signing needs no
  // network, but building a listing or completing a purchase reads UTXOs and broadcasts — so point
  // it at the live connection as soon as there is one.
  useEffect(() => {
    if (electrum) walletService.attachElectrum(electrum);
  }, [electrum, walletService]);
  const [transport, setTransport] = useState<Transport>('idle');
  const [status, setStatus] = useState<string>('Waiting for the site to send a request…');
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [pinnedOrigin, setPinnedOrigin] = useState<string | null>(null);
  const [accounts, setAccounts] = useState<ConnectAccountOption[]>([]);
  const [activeAddress, setActiveAddress] = useState<string>('');
  const [hasWallet, setHasWallet] = useState<boolean | null>(null);
  const [connectPromptOrigin, setConnectPromptOrigin] = useState<string | null>(null);
  const [signPrompt, setSignPrompt] = useState<SignPrompt | null>(null);
  const [psbtPrompt, setPsbtPrompt] = useState<PsbtPrompt | null>(null);
  const [listingPrompt, setListingPrompt] = useState<ListingPrompt | null>(null);
  const [buyPrompt, setBuyPrompt] = useState<BuyPrompt | null>(null);
  /** True while the account picker is up in place of a still-unanswered approval. */
  const [switching, setSwitching] = useState(false);
  const [completed, setCompleted] = useState<{ origin: string; method: string } | null>(null);

  // Live values the (stable) provider host closures read from.
  const electrumRef = useRef(electrum);
  const requireAuthRef = useRef(requireAuth);
  const hasWalletRef = useRef<boolean | null>(null);
  const pinnedOriginRef = useRef<string | null>(null);
  electrumRef.current = electrum;
  requireAuthRef.current = requireAuth;

  const connectResolverRef = useRef<
    ((decision: ConnectApprovalDecision) => void | Promise<void>) | null
  >(null);
  const signResolverRef = useRef<((approved: boolean) => void) | null>(null);
  const psbtResolverRef = useRef<((approved: boolean) => void) | null>(null);
  const listingResolverRef = useRef<((approved: boolean) => void) | null>(null);
  const buyResolverRef = useRef<((approved: boolean) => void) | null>(null);
  const providerRef = useRef<ProviderService | null>(null);
  const pendingIdsRef = useRef<Set<string>>(new Set());
  const answeredRef = useRef<Map<string, ConnectResponse>>(new Map());
  const queueRef = useRef<Promise<void>>(Promise.resolve());
  const startedRef = useRef(false);

  /** Keeps a bounded record of answers so a resent request is replayed, not re-prompted. */
  const rememberAnswer = useCallback((id: string, response: ConnectResponse) => {
    const answered = answeredRef.current;
    answered.set(id, response);
    if (answered.size > 50) {
      answered.delete(answered.keys().next().value as string);
    }
  }, []);

  // ---------------------------------------------------------------------
  // Wallet inventory
  // ---------------------------------------------------------------------

  const loadAccounts = useCallback(async () => {
    try {
      const wallets = await StorageService.getAllWallets();
      const options = wallets.map((wallet) => ({
        name: wallet.name,
        address: wallet.address,
      }));
      const active = wallets.find((wallet) => wallet.isActive);

      setAccounts(options);
      setActiveAddress(active?.address || options[0]?.address || '');
      setHasWallet(options.length > 0);
      hasWalletRef.current = options.length > 0;
    } catch (error) {
      providerLogger.error('Failed to load wallets for Avian Connect:', error);
      setHasWallet(false);
      hasWalletRef.current = false;
    }
  }, []);

  useEffect(() => {
    loadAccounts();
  }, [loadAccounts]);

  // ---------------------------------------------------------------------
  // Approval prompts, surfaced to the engine as promises
  // ---------------------------------------------------------------------

  const requestConnectApproval = useCallback(
    (origin: string) =>
      new Promise<ConnectApprovalDecision>((resolve) => {
        connectResolverRef.current = resolve;
        setConnectPromptOrigin(origin);
      }),
    [],
  );

  const resolveConnectPrompt = useCallback((decision: ConnectApprovalDecision) => {
    setConnectPromptOrigin(null);
    const resolver = connectResolverRef.current;
    connectResolverRef.current = null;
    // The switch-account flow installs an async resolver; a connect request's is plain.
    void resolver?.(decision);
  }, []);

  const requestSignApproval = useCallback(
    (origin: string, message: string, account: string) =>
      new Promise<boolean>((resolve) => {
        signResolverRef.current = resolve;
        setSignPrompt({ origin, message, account });
      }),
    [],
  );

  const resolveSignPrompt = useCallback((approved: boolean) => {
    setSignPrompt(null);
    const resolver = signResolverRef.current;
    signResolverRef.current = null;
    resolver?.(approved);
  }, []);

  const requestSignAssetListingApproval = useCallback(
    (origin: string, assetName: string, priceSats: number, account: string) =>
      new Promise<boolean>((resolve) => {
        listingResolverRef.current = resolve;
        setListingPrompt({ origin, account, assetName, priceSats });
      }),
    [],
  );

  const resolveListingPrompt = useCallback((approved: boolean) => {
    setListingPrompt(null);
    const resolver = listingResolverRef.current;
    listingResolverRef.current = null;
    resolver?.(approved);
  }, []);

  const requestBuyAssetApproval = useCallback(
    async (origin: string, listingPsbt: string, account: string) => {
      // Decode the seller's own bytes: the price shown is the one they signed, not a site's claim.
      let listing: AssetListingPreview;
      try {
        listing = await walletService.previewSellerListing(listingPsbt);
      } catch (error) {
        providerLogger.warn('Rejected an unusable listing from a site:', error);
        return false;
      }
      return new Promise<boolean>((resolve) => {
        buyResolverRef.current = resolve;
        setBuyPrompt({ origin, account, listing });
      });
    },
    [walletService],
  );

  const resolveBuyPrompt = useCallback((approved: boolean) => {
    setBuyPrompt(null);
    const resolver = buyResolverRef.current;
    buyResolverRef.current = null;
    resolver?.(approved);
  }, []);

  const requestSignPsbtApproval = useCallback(
    async (origin: string, psbt: string, account: string, broadcast: boolean) => {
      // Decode the PSBT before showing the screen so the user sees exactly what they are signing.
      // A PSBT that will not even parse is rejected without a prompt.
      let summary: PsbtSummary;
      try {
        summary = await walletService.summarizePsbt(psbt, account);
      } catch (error) {
        providerLogger.warn('Rejected an unparseable PSBT from a site:', error);
        return false;
      }
      return new Promise<boolean>((resolve) => {
        psbtResolverRef.current = resolve;
        setPsbtPrompt({ origin, account, summary, broadcast });
      });
    },
    [walletService],
  );

  const resolvePsbtPrompt = useCallback((approved: boolean) => {
    setPsbtPrompt(null);
    const resolver = psbtResolverRef.current;
    psbtResolverRef.current = null;
    resolver?.(approved);
  }, []);

  // ---------------------------------------------------------------------
  // Provider host
  // ---------------------------------------------------------------------

  const emit = useCallback((event: ConnectEventName, data: unknown) => {
    const origin = pinnedOriginRef.current;
    // Events only exist on the popup transport, and only ever go to the pinned origin.
    if (!origin || !window.opener) return;
    try {
      window.opener.postMessage(makeEvent(event, data), origin);
    } catch (error) {
      providerLogger.warn('Failed to emit Avian Connect event:', error);
    }
  }, []);

  /**
   * Sign with a different wallet than the one this site is connected with.
   *
   * The pending request is rejected rather than quietly re-pointed: the site asked this account to
   * sign, and handing back a signature from another one would fail whatever check it does against
   * the address `connect` gave it. Instead the grant is moved, `accountsChanged` is emitted, and
   * the site can ask again — now against the wallet the user actually wants.
   */
  /** Decline whichever approval is waiting, and clear it. */
  const declinePendingApproval = useCallback(() => {
    for (const ref of [signResolverRef, psbtResolverRef, listingResolverRef, buyResolverRef]) {
      const resolver = ref.current;
      ref.current = null;
      resolver?.(false);
    }
    setSignPrompt(null);
    setPsbtPrompt(null);
    setListingPrompt(null);
    setBuyPrompt(null);
  }, []);

  /**
   * Sign with a different wallet than the one this site is connected with.
   *
   * The pending request must stay unanswered until the new wallet is chosen. Answering ends the
   * session — the redirect transport navigates away, and a popup is usually closed by the dApp the
   * moment it has a response — so a rejection sent first takes the picker down with it.
   *
   * So the approval is only hidden here. Once a wallet is picked the grant moves, `accountsChanged`
   * goes out, and only then is the request declined, leaving the site to ask again against the
   * wallet the user actually wants. Dismissing the picker puts the original approval back.
   */
  const switchAccount = useCallback(() => {
    if (!pinnedOriginRef.current) return;
    setSwitching(true);
    setStatus('Choosing a different wallet…');
  }, []);

  useEffect(() => {
    if (!switching) return;

    const origin = pinnedOriginRef.current;
    if (!origin) {
      setSwitching(false);
      return;
    }

    // The approval dialog is on its way out; a Radix dialog keeps the page inert through its exit
    // transition, so let it finish before mounting the picker.
    const timer = setTimeout(() => {
      connectResolverRef.current = async (decision: ConnectApprovalDecision) => {
        if (!decision.approved || decision.accounts.length === 0) {
          // Nothing chosen: put the original approval back rather than answering for the user.
          setSwitching(false);
          setStatus('Waiting for the site to send a request…');
          return;
        }
        try {
          await PermissionService.grant(origin, decision.accounts);
          await providerRef.current?.refreshAccounts();
          emit('accountsChanged', { accounts: decision.accounts });
          setStatus(`Now using ${decision.accounts[0]} — ask the site to try again.`);
        } catch (error) {
          providerLogger.error('Failed to switch the connected account:', error);
          setStatus('Could not switch wallet. Try again from the site.');
        }
        // Answer last: this is what closes the popup or redirects away.
        setSwitching(false);
        declinePendingApproval();
      };
      setConnectPromptOrigin(origin);
    }, 250);

    return () => clearTimeout(timer);
  }, [switching, emit, declinePendingApproval]);

  const host = useMemo<ProviderHost>(
    () => ({
      isLocked: () => hasWalletRef.current !== true,

      requestConnectApproval,

      requestSignApproval,

      signMessage: async (account: string, message: string) => {
        const wallet = await StorageService.getWalletByAddress(account);
        if (!wallet?.privateKey) {
          providerLogger.warn('No private key available for the requested account');
          return null;
        }

        // Every signature is authenticated afresh — remembering a site never skips this.
        const auth = await requireAuthRef.current(
          `Authenticate to sign a message for ${pinnedOriginRef.current || 'this site'}`,
        );
        if (!auth.success) return null;

        const signature = await walletService.signMessage(wallet.privateKey, message, auth.password);

        // Recover and cache the public key so later connect() calls can include it. The public
        // key is not secret and is derived from a signature the user just authorised.
        try {
          const verified = await walletService.verifyMessage(account, message, signature, true);
          if (typeof verified === 'object' && verified.publicKey) {
            await StorageService.setKnownPublicKey(account, verified.publicKey);
          }
        } catch (error) {
          providerLogger.warn('Could not cache the public key for this account:', error);
        }

        return signature;
      },

      requestSignPsbtApproval,

      signPsbt: async (account: string, psbt: string, broadcast: boolean) => {
        const wallet = await StorageService.getWalletByAddress(account);
        if (!wallet?.privateKey) {
          providerLogger.warn('No private key available for the requested account');
          return null;
        }

        // Authenticated afresh — remembering a site never skips this.
        const auth = await requireAuthRef.current(
          `Authenticate to sign a transaction for ${pinnedOriginRef.current || 'this site'}`,
        );
        if (!auth.success) return null;

        // Sign for the connected account, not the active wallet — they differ once the user
        // switches wallets, and the approval screen was scored against this account.
        if (!broadcast) {
          const signed = await walletService.signPsbt(psbt, auth.password, account);
          return { ...signed, broadcast: false };
        }
        // The user approved a broadcast: finalise and push when our signature completes it. A
        // failure still returns the signature, so the site can retry or broadcast itself.
        return await walletService.signAndBroadcastPsbt(psbt, auth.password, account);
      },

      requestSignAssetListingApproval,

      createAssetListing: async (
        account: string,
        listing: { assetName: string; priceSats: number; amount?: string },
      ) => {
        const auth = await requireAuthRef.current(
          `Authenticate to list ${listing.assetName} via ${pinnedOriginRef.current || 'this site'}`,
        );
        if (!auth.success) return null;

        const signed = await walletService.createAssetListing({
          assetName: listing.assetName,
          priceSats: listing.priceSats,
          amount: listing.amount === undefined ? undefined : BigInt(listing.amount),
          password: auth.password,
          account,
        });
        return {
          psbt: signed.psbt,
          assetName: signed.assetName,
          // JSON has no bigint, so quantities cross the boundary as decimal strings.
          assetAmount: signed.assetAmount.toString(),
          priceSats: signed.priceSats,
          payTo: signed.payTo,
          assetUtxo: signed.assetUtxo,
        };
      },

      completeAssetListing: async (account: string, listingPsbt: string) => {
        const auth = await requireAuthRef.current(
          `Authenticate to buy from ${pinnedOriginRef.current || 'this site'}`,
        );
        if (!auth.success) return null;

        const bought = await walletService.completeAssetListing({
          listingPsbt,
          password: auth.password,
          account,
        });
        return {
          psbt: bought.psbt,
          broadcast: bought.broadcast,
          txid: bought.txid,
          broadcastError: bought.broadcastError,
          assetName: bought.assetName,
          assetAmount: bought.assetAmount.toString(),
          pricePaidSats: bought.pricePaidSats,
          feeSats: bought.feeSats,
        };
      },

      requestBuyAssetApproval,

      getPublicKey: async (account: string) => {
        const publicKey = await StorageService.getKnownPublicKey(account);
        return publicKey || undefined;
      },

      getNetwork: () => getNetworkDescriptor(electrumRef.current),

      emit,
    }),
    [emit, requestConnectApproval, requestSignApproval, requestSignPsbtApproval, walletService],
  );

  const pinOrigin = useCallback(
    (origin: string) => {
      pinnedOriginRef.current = origin;
      setPinnedOrigin(origin);
      providerRef.current = new ProviderService(origin, host);
      return providerRef.current;
    },
    [host],
  );

  // ---------------------------------------------------------------------
  // Popup transport
  // ---------------------------------------------------------------------

  const respondToOpener = useCallback((response: ConnectResponse) => {
    const origin = pinnedOriginRef.current;
    if (!origin || !window.opener) return;
    try {
      // Never "*": responses go to the origin the browser attested on the first message.
      window.opener.postMessage(response, origin);
    } catch (error) {
      providerLogger.warn('Failed to deliver an Avian Connect response:', error);
    }
  }, []);

  useEffect(() => {
    if (transport !== 'popup') return;

    const handleMessage = (event: MessageEvent) => {
      // Only the window that opened us may talk to us.
      if (!window.opener || event.source !== window.opener) return;

      const data = event.data;
      if (typeof data !== 'object' || data === null || (data as { avianConnect?: unknown }).avianConnect !== 1) {
        return;
      }

      const messageOrigin = normalizeOrigin(event.origin);
      if (!messageOrigin) return;

      let provider = providerRef.current;
      if (!provider) {
        provider = pinOrigin(messageOrigin);
        setStatus('Reviewing the request…');
      } else if (messageOrigin !== pinnedOriginRef.current) {
        // The session is pinned to the first origin for the lifetime of this window.
        providerLogger.warn('Ignoring an Avian Connect message from an unexpected origin');
        return;
      }

      const id = typeof (data as { id?: unknown }).id === 'string' ? (data as { id: string }).id : null;
      if (id) {
        // dApps resend a request until it is answered, so the same id arrives repeatedly while
        // an approval screen is open. Answer from the record, never open a second dialog.
        const answered = answeredRef.current.get(id);
        if (answered) {
          respondToOpener(answered);
          return;
        }
        if (pendingIdsRef.current.has(id)) return;
        pendingIdsRef.current.add(id);
      }

      const boundProvider = provider;
      queueRef.current = queueRef.current
        .then(async () => {
          const response = await boundProvider.handle(data);
          if (id) {
            pendingIdsRef.current.delete(id);
            rememberAnswer(id, response);
          }
          respondToOpener(response);
          const method = (data as { method?: unknown }).method;
          setCompleted({
            origin: boundProvider.getOrigin(),
            method: typeof method === 'string' ? method : 'request',
          });
          setStatus('Waiting for the site to send a request…');
        })
        .catch((error) => {
          providerLogger.error('Avian Connect popup request failed:', error);
          if (id) {
            pendingIdsRef.current.delete(id);
            const failure = makeError(
              id,
              'INVALID_REQUEST',
              'The wallet could not complete this request',
            );
            rememberAnswer(id, failure);
            respondToOpener(failure);
          }
        });
    };

    // A closed wallet window must not leave the dApp hanging.
    const handlePageHide = () => {
      pendingIdsRef.current.forEach((id) => {
        respondToOpener(makeError(id, 'USER_REJECTED', 'The wallet window was closed'));
      });
      pendingIdsRef.current.clear();
      emit('disconnect', { reason: 'Wallet window closed' });
    };

    window.addEventListener('message', handleMessage);
    window.addEventListener('pagehide', handlePageHide);
    return () => {
      window.removeEventListener('message', handleMessage);
      window.removeEventListener('pagehide', handlePageHide);
    };
  }, [transport, pinOrigin, respondToOpener, emit, rememberAnswer]);

  // ---------------------------------------------------------------------
  // Redirect transport
  // ---------------------------------------------------------------------

  const runRedirectFlow = useCallback(
    async (reqParam: string, redirectUri: string) => {
      const parsed = decodeRequestParam(reqParam);
      if (!parsed.ok) {
        setFatalError(parsed.error.message);
        return;
      }

      const check = validateRedirectUri(redirectUri, parsed.request.origin);
      if (!check.ok) {
        // Nothing is sent anywhere: a mismatch is exactly the case we must not redirect on.
        setFatalError(check.reason || 'redirect_uri does not match the request origin');
        return;
      }

      const origin = normalizeOrigin(parsed.request.origin as string)!;
      const provider = pinOrigin(origin);
      setStatus('Reviewing the request…');

      const response = await provider.handle(parsed.request);
      setStatus(`Returning to ${origin}…`);
      setCompleted({ origin, method: parsed.request.method });
      window.location.replace(buildRedirectUrl(redirectUri, response));
    },
    [pinOrigin],
  );

  // ---------------------------------------------------------------------
  // Transport selection
  // ---------------------------------------------------------------------

  useEffect(() => {
    if (startedRef.current || hasWallet === null) return;
    startedRef.current = true;

    const reqParam = searchParams.get('req');
    const redirectUri = searchParams.get('redirect_uri');

    if (reqParam) {
      setTransport('redirect');
      if (!redirectUri) {
        setFatalError('This request is missing a redirect_uri parameter');
        return;
      }
      runRedirectFlow(reqParam, redirectUri).catch((error) => {
        providerLogger.error('Avian Connect redirect flow failed:', error);
        setFatalError('The wallet could not complete this request');
      });
      return;
    }

    if (typeof window !== 'undefined' && window.opener) {
      setTransport('popup');
      return;
    }

    setTransport('standalone');
  }, [searchParams, hasWallet, runRedirectFlow]);

  // ---------------------------------------------------------------------
  // Keep a live session in step with wallet switches and revocations
  // ---------------------------------------------------------------------

  useEffect(() => {
    const refresh = async () => {
      await loadAccounts();
      await providerRef.current?.refreshAccounts();
    };

    const handleWalletSwitched = () => {
      refresh().catch((error) => providerLogger.error('Failed to refresh after wallet switch:', error));
    };

    window.addEventListener('wallet-switched', handleWalletSwitched);

    let channel: BroadcastChannel | null = null;
    if (typeof BroadcastChannel !== 'undefined') {
      channel = new BroadcastChannel(PERMISSION_CHANNEL);
      channel.onmessage = (event) => {
        if (event.data?.type === 'permissions-changed') {
          providerRef.current
            ?.refreshAccounts()
            .catch((error) => providerLogger.error('Failed to refresh permissions:', error));
        }
      };
    }

    return () => {
      window.removeEventListener('wallet-switched', handleWalletSwitched);
      channel?.close();
    };
  }, [loadAccounts]);

  // ---------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------

  const heading = (
    <div className="flex items-center gap-3">
      <Image src="/icons/icon-192x192.png" alt="" width={40} height={40} className="rounded-lg" />
      <div>
        <CardTitle className="text-lg">Avian Connect</CardTitle>
        <CardDescription>FlightDeck wallet connection</CardDescription>
      </div>
    </div>
  );

  const body = () => {
    if (fatalError) {
      return (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription className="break-words">{fatalError}</AlertDescription>
        </Alert>
      );
    }

    if (hasWallet === false) {
      return (
        <div className="space-y-4">
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              This wallet has no accounts yet. Create or restore a wallet before connecting a site.
            </AlertDescription>
          </Alert>
          <Button asChild className="w-full">
            <Link href="/onboarding">Set up a wallet</Link>
          </Button>
        </div>
      );
    }

    if (transport === 'standalone') {
      return (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            This page is the connection endpoint dApps use to ask for your address and for signed
            login challenges. It does nothing on its own — open it from a site, or try the demo.
          </p>
          <Alert className="bg-muted/50">
            <ShieldCheck className="h-4 w-4" />
            <AlertDescription className="text-xs">
              Only an address, an optional public key and signatures ever leave this wallet. Keys,
              mnemonics and passwords never do.
            </AlertDescription>
          </Alert>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Button asChild variant="outline" className="flex-1">
              <Link href="/settings/connected-sites">Connected sites</Link>
            </Button>
            <Button asChild className="flex-1">
              <Link href="/connect/demo">
                Open the demo
                <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
          </div>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        {pinnedOrigin && (
          <div className="rounded-lg border bg-muted/40 p-3">
            <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
              <Globe className="h-3.5 w-3.5" />
              Connected site
            </div>
            <p className="mt-1 break-all font-mono text-sm font-semibold">{pinnedOrigin}</p>
          </div>
        )}

        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          {completed && !connectPromptOrigin && !signPrompt && !psbtPrompt ? (
            <CheckCircle2 className="h-4 w-4 text-primary" />
          ) : (
            <Loader2 className="h-4 w-4 animate-spin" />
          )}
          <span>
            {completed && !connectPromptOrigin && !signPrompt && !psbtPrompt
              ? `Answered ${completed.method}. ${transport === 'popup' ? 'You can close this window.' : ''}`
              : status}
          </span>
        </div>

        {transport === 'popup' && (
          <p className="text-xs text-muted-foreground">
            Keep this window open while you use the site. Closing it ends the session.
          </p>
        )}
      </div>
    );
  };

  return (
    <GradientBackground>
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>{heading}</CardHeader>
          <CardContent>{body()}</CardContent>
        </Card>
      </div>

      <ConnectApprovalDialog
        open={connectPromptOrigin !== null}
        origin={connectPromptOrigin || ''}
        accounts={accounts}
        defaultAddress={activeAddress}
        singleRequest={transport === 'redirect'}
        onDecision={resolveConnectPrompt}
      />

      <SignMessageApprovalDialog
        onSwitchAccount={accounts.length > 1 ? switchAccount : undefined}
        open={signPrompt !== null && !switching}
        origin={signPrompt?.origin || ''}
        account={signPrompt?.account || ''}
        message={signPrompt?.message || ''}
        onDecision={resolveSignPrompt}
      />

      <SignPsbtApprovalDialog
        onSwitchAccount={accounts.length > 1 ? switchAccount : undefined}
        open={psbtPrompt !== null && !switching}
        origin={psbtPrompt?.origin || ''}
        account={psbtPrompt?.account || ''}
        summary={psbtPrompt?.summary || null}
        broadcast={psbtPrompt?.broadcast ?? false}
        onDecision={resolvePsbtPrompt}
      />

      <SignAssetListingApprovalDialog
        onSwitchAccount={accounts.length > 1 ? switchAccount : undefined}
        open={listingPrompt !== null && !switching}
        origin={listingPrompt?.origin || ''}
        account={listingPrompt?.account || ''}
        assetName={listingPrompt?.assetName || ''}
        priceSats={listingPrompt?.priceSats ?? 0}
        onDecision={resolveListingPrompt}
      />

      <BuyAssetApprovalDialog
        onSwitchAccount={accounts.length > 1 ? switchAccount : undefined}
        open={buyPrompt !== null && !switching}
        origin={buyPrompt?.origin || ''}
        account={buyPrompt?.account || ''}
        listing={buyPrompt?.listing || null}
        onDecision={resolveBuyPrompt}
      />
    </GradientBackground>
  );
}

export default function ConnectPage() {
  return (
    <Suspense
      fallback={
        <GradientBackground>
          <div className="flex min-h-screen items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        </GradientBackground>
      }
    >
      <ConnectClient />
    </Suspense>
  );
}
