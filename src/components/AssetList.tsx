'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Coins, Plus, PlusCircle, RefreshCw, Search, Send } from 'lucide-react';

import { toast } from 'sonner';

import { useWallet } from '@/contexts/WalletContext';
import { walletLogger } from '@/lib/Logger';
import {
  getHeldAssets,
  resolveAssetMedia,
  type AssetMedia,
  type HeldAsset,
} from '@/services/wallet/AssetService';
import { isAssetIssuanceEnabled, ASSET_ISSUANCE_DISABLED_MESSAGE } from '@/lib/featureFlags';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import SendAssetDialog from './SendAssetDialog';
import CreateAssetDialog from './CreateAssetDialog';
import ReissueAssetDialog from './ReissueAssetDialog';

/**
 * A small asset avatar: the asset's image when it has one (click to enlarge), else a coin glyph.
 *
 * The IPFS hash may be the image itself or a JSON document pointing at one, so the URL is resolved
 * asynchronously rather than being handed straight to `<img>`.
 */
function AssetThumbnail({
  asset,
  onPreview,
}: {
  asset: HeldAsset;
  onPreview: (url: string, title: string) => void;
}) {
  const [failed, setFailed] = useState(false);
  const [media, setMedia] = useState<AssetMedia | null>(null);

  useEffect(() => {
    let current = true;
    if (!asset.meta?.hasIpfs) {
      setMedia({ imageUrl: null });
      return;
    }
    void resolveAssetMedia(asset.meta.ipfs).then((resolved) => {
      if (current) setMedia(resolved);
    });
    return () => {
      current = false;
    };
  }, [asset.meta?.hasIpfs, asset.meta?.ipfs]);

  const url = media?.imageUrl ?? null;

  if (!url || failed) {
    return (
      <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-md bg-muted/60 text-muted-foreground">
        <Coins className="h-4 w-4" />
      </div>
    );
  }
  return (
    <button
      type="button"
      onClick={() => onPreview(url, media?.name || asset.name)}
      className="h-9 w-9 flex-shrink-0 overflow-hidden rounded-md"
      aria-label={`View ${media?.name || asset.name} image`}
    >
      {/* Plain <img> (not next/image) — external content, lazily loaded, hidden gracefully if the
          host is unreachable. no-referrer keeps the wallet's page out of the image host's logs. */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={url}
        alt=""
        loading="lazy"
        referrerPolicy="no-referrer"
        onError={() => setFailed(true)}
        className="h-full w-full object-cover"
      />
    </button>
  );
}

/** The kind of Avian asset name, for a small type badge. */
function assetKind(name: string): 'owner' | 'unique' | 'sub' | 'restricted' | 'qualifier' | null {
  if (name.endsWith('!')) return 'owner'; // administrative token — grants reissue/management rights
  if (name.includes('#')) return name.startsWith('#') ? 'qualifier' : 'unique';
  if (name.startsWith('$')) return 'restricted';
  if (name.includes('/')) return 'sub';
  return null;
}

/**
 * Read-only list of Avian assets held by the active wallet, mirroring Core's Asset Balances panel.
 * Renders nothing until we know the wallet holds assets, so an AVN-only wallet sees no extra chrome.
 * Sending assets is a separate flow (see docs/proposals/avian-assets.md).
 */
export function AssetList({ className }: { className?: string }) {
  const { electrum, address, isConnected } = useWallet();
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);
  /** The last refresh could not reach the network, so what is listed may be stale. */
  const [loadFailed, setLoadFailed] = useState(false);
  const [query, setQuery] = useState('');
  const [sending, setSending] = useState<HeldAsset | null>(null);
  const [reissuing, setReissuing] = useState<HeldAsset | null>(null);
  const [creating, setCreating] = useState(false);
  const [preview, setPreview] = useState<{ url: string; name: string } | null>(null);

  const load = useCallback(
    async (announceFailure = false) => {
      if (!electrum || !address) return;
      setLoading(true);
      try {
        setAssets(await getHeldAssets(electrum, address));
        setLoadFailed(false);
      } catch (error) {
        // Keep whatever is already on screen. A failed refresh means we do not know what is held,
        // which is not the same as knowing nothing is — and replacing a list of assets with an
        // empty one reads as "they are gone".
        walletLogger.warn('Could not refresh assets:', error);
        setLoadFailed(true);
        if (announceFailure) {
          toast.error('Could not reach the network', {
            description: 'Your assets are unchanged — this is just the refresh failing.',
          });
        }
      } finally {
        setLoading(false);
        setLoaded(true);
      }
    },
    [electrum, address],
  );

  // Reload now and again shortly after — a just-spent/created asset only drops off (or appears)
  // once ElectrumX reflects the new tx, which lags the broadcast by a moment.
  const reloadSoon = useCallback(() => {
    void load();
    setTimeout(() => void load(), 2500);
  }, [load]);

  useEffect(() => {
    if (isConnected && address) void load();
  }, [isConnected, address, load]);

  // Assets are legacy-address-only; a legacy wallet can create even with nothing held yet — unless
  // issuance has been switched off for this build.
  const issuanceEnabled = isAssetIssuanceEnabled();
  const canCreate = !!address && address.startsWith('R') && issuanceEnabled;
  // Owner tokens we hold (NAME!) → the roots we can create sub/unique assets under.
  const ownedRoots = assets
    .filter((a) => a.name.endsWith('!'))
    .map((a) => a.name.slice(0, -1));

  // Stay invisible until loaded; then only hide when there's nothing to show and nothing to create.
  if (!loaded && !loading) return null;
  if (loaded && assets.length === 0 && !canCreate) return null;

  const filtered = query
    ? assets.filter((a) => a.name.toLowerCase().includes(query.toLowerCase()))
    : assets;

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 border-b border-border/60 bg-card px-4 py-3 text-foreground [&_svg]:text-primary rounded-t-md">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Coins className="h-5 w-5 flex-shrink-0" />
          Assets
          {assets.length > 0 && (
            <span className="text-sm font-normal text-muted-foreground">({assets.length})</span>
          )}
        </CardTitle>
        <span className="flex items-center gap-1">
          {canCreate && (
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1.5"
              onClick={() => setCreating(true)}
            >
              <Plus className="h-4 w-4" /> Create
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => void load(true)}
            disabled={loading}
            aria-label="Refresh assets"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </span>
      </CardHeader>
      <CardContent className="p-0">
        {loadFailed && (
          <div className="flex items-start gap-2 border-b border-caution/30 bg-caution/10 px-4 py-3 text-sm text-caution">
            <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
            <span>
              Could not reach the network, so this list may be out of date. Your assets are on chain
              and unaffected.
            </span>
          </div>
        )}
        {!issuanceEnabled && (
          <div className="flex items-start gap-2 border-b border-caution/30 bg-caution/10 px-4 py-3 text-sm text-caution">
            <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
            <span>{ASSET_ISSUANCE_DISABLED_MESSAGE}</span>
          </div>
        )}
        {assets.length > 6 && (
          <div className="relative border-b border-border/60 p-3">
            <Search className="absolute left-5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search asset name…"
              className="pl-9"
            />
          </div>
        )}

        {loading && assets.length === 0 ? (
          <div className="space-y-2 p-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-12 animate-pulse rounded-md bg-muted/50" />
            ))}
          </div>
        ) : (
          <ul className="divide-y divide-border/60">
            {filtered.map((asset) => {
              const kind = assetKind(asset.name);
              return (
                <li
                  key={asset.name}
                  className="flex items-center gap-3 px-4 py-3"
                >
                  <AssetThumbnail
                    asset={asset}
                    onPreview={(url, title) => setPreview({ url, name: title })}
                  />
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate font-medium">{asset.name}</span>
                      <span className="mt-0.5 flex flex-wrap gap-1">
                        {kind && (
                          <Badge variant="secondary" className="h-4 px-1.5 text-[10px] capitalize">
                            {kind}
                          </Badge>
                        )}
                        {asset.meta?.reissuable && (
                          <Badge variant="outline" className="h-4 px-1.5 text-[10px]">
                            Reissuable
                          </Badge>
                        )}
                        {asset.unconfirmedSats !== 0 && (
                          <Badge className="h-4 bg-caution/15 px-1.5 text-[10px] text-caution hover:bg-caution/15">
                            Pending
                          </Badge>
                        )}
                      </span>
                    </span>
                  <span className="flex flex-shrink-0 items-center gap-1">
                    <span className="mr-1 font-mono text-sm">{asset.amount}</span>
                    {issuanceEnabled && asset.meta?.reissuable && ownedRoots.includes(asset.name) && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-muted-foreground hover:text-primary"
                        onClick={() => setReissuing(asset)}
                        aria-label={`Reissue ${asset.name}`}
                        title={`Reissue ${asset.name}`}
                      >
                        <PlusCircle className="h-4 w-4" />
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-muted-foreground hover:text-primary"
                      onClick={() => setSending(asset)}
                      disabled={asset.confirmedSats <= 0}
                      aria-label={`Send ${asset.name}`}
                      title={`Send ${asset.name}`}
                    >
                      <Send className="h-4 w-4" />
                    </Button>
                  </span>
                </li>
              );
            })}
            {filtered.length === 0 && (
              <li className="px-4 py-6 text-center text-sm text-muted-foreground">
                {query
                  ? `No assets match “${query}”.`
                  : issuanceEnabled
                    ? 'No assets yet — create one to get started.'
                    : 'No assets yet.'}
              </li>
            )}
          </ul>
        )}
      </CardContent>

      <SendAssetDialog
        open={sending !== null}
        onOpenChange={(next) => !next && setSending(null)}
        asset={sending}
        onSuccess={reloadSoon}
      />

      <ReissueAssetDialog
        open={issuanceEnabled && reissuing !== null}
        onOpenChange={(next) => !next && setReissuing(null)}
        asset={reissuing}
        onSuccess={reloadSoon}
      />

      <CreateAssetDialog
        open={issuanceEnabled && creating}
        onOpenChange={setCreating}
        ownedRoots={ownedRoots}
        onSuccess={reloadSoon}
      />

      <Dialog open={preview !== null} onOpenChange={(next) => !next && setPreview(null)}>
        <DialogContent className="sm:max-w-2xl md:max-w-3xl lg:max-w-4xl">
          <DialogHeader>
            <DialogTitle className="break-all font-mono text-sm">{preview?.name}</DialogTitle>
          </DialogHeader>
          {preview && (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={preview.url}
              alt={preview.name}
              referrerPolicy="no-referrer"
              className="mx-auto max-h-[80vh] w-auto max-w-full rounded-md object-contain"
            />
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
