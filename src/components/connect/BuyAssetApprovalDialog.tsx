'use client';

import React from 'react';
import { AlertTriangle, Globe, ShoppingCart } from 'lucide-react';
import { useMediaQuery } from '@/hooks/use-media-query';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Drawer,
  DrawerContent,
  DrawerDescription,
  DrawerHeader,
  DrawerTitle,
} from '@/components/ui/drawer';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import type { AssetListingPreview } from '@/services/wallet/WalletService';

interface BuyAssetApprovalDialogProps {
  open: boolean;
  origin: string;
  account: string;
  /** Decoded from the seller-signed listing, never from what the site claims it costs. */
  listing: AssetListingPreview | null;
  /** Offered when more than one wallet could sign; switching rejects this request. */
  onSwitchAccount?: () => void;

  onDecision: (approved: boolean) => void;
}

const avn = (sats: number) => (sats / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });

/** Asset quantities are 10^8-scaled like AVN; whole units are the common case. */
const quantity = (scaled: bigint) => {
  const whole = scaled / 100_000_000n;
  const fraction = scaled % 100_000_000n;
  return fraction === 0n
    ? whole.toString()
    : `${whole}.${fraction.toString().padStart(8, '0').replace(/0+$/, '')}`;
};

export default function BuyAssetApprovalDialog({
  open,
  origin,
  account,
  listing,
  onSwitchAccount,
  onDecision,
}: BuyAssetApprovalDialogProps) {
  const isMobile = useMediaQuery('(max-width: 768px)');

  const body = (
    <div className="space-y-4">
      <div className="rounded-lg border bg-muted/40 p-4">
        <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
          <Globe className="h-3.5 w-3.5" />
          Requesting site
        </div>
        <p className="mt-1 break-all font-mono text-base font-semibold">{origin}</p>
      </div>

      {listing && (
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
            <ShoppingCart className="h-3.5 w-3.5" />
            You are buying
          </div>
          <p className="mt-2 break-all font-mono text-lg font-semibold">
            {quantity(listing.assetAmount)} × {listing.assetName}
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            for{' '}
            <span className="font-mono font-semibold text-foreground">
              {avn(listing.priceSats)} AVN
            </span>{' '}
            plus the network fee
          </p>
        </div>
      )}

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <Label className="text-sm font-medium">Paying from</Label>
          {onSwitchAccount && (
            <Button
              type="button"
              variant="link"
              size="sm"
              className="h-auto p-0 text-xs"
              onClick={onSwitchAccount}
            >
              Use a different wallet
            </Button>
          )}
        </div>
        <p className="break-all rounded-md border bg-muted/20 p-2 font-mono text-xs">{account}</p>
      </div>

      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="text-sm">
          This price comes from the seller&apos;s own signed listing, not from the site — it is what
          you will pay. Approving pays the seller and sends the transaction, which cannot be
          recalled. If someone else buys this item first, the purchase simply fails and you pay
          nothing.
        </AlertDescription>
      </Alert>
    </div>
  );

  const actions = (
    <div className="flex gap-2 pt-2">
      <Button variant="outline" className="flex-1" onClick={() => onDecision(false)}>
        Reject
      </Button>
      <Button className="flex-1" onClick={() => onDecision(true)} disabled={!listing}>
        Buy and send
      </Button>
    </div>
  );

  const title = 'Buy an asset';
  const description = 'Pay a seller and receive their asset in one transaction.';

  if (isMobile) {
    return (
      <Drawer open={open} onOpenChange={(next) => !next && onDecision(false)}>
        <DrawerContent className="max-h-[95vh]">
          <DrawerHeader className="text-left">
            <DrawerTitle>{title}</DrawerTitle>
            <DrawerDescription>{description}</DrawerDescription>
          </DrawerHeader>
          <div className="overflow-y-auto px-4 pb-4">
            {body}
            {actions}
          </div>
        </DrawerContent>
      </Drawer>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onDecision(false)}>
      <DialogContent className="max-h-[95vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {body}
        {actions}
      </DialogContent>
    </Dialog>
  );
}
