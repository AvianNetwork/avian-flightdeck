'use client';

import React from 'react';
import { AlertTriangle, Globe, Tag } from 'lucide-react';
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
interface SignAssetListingApprovalDialogProps {
  open: boolean;
  origin: string;
  account: string;
  assetName: string;
  priceSats: number;
  /** Offered when more than one wallet could sign; switching rejects this request. */
  onSwitchAccount?: () => void;

  onDecision: (approved: boolean) => void;
}

const avn = (sats: number) => (sats / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });

export default function SignAssetListingApprovalDialog({
  open,
  origin,
  account,
  assetName,
  priceSats,
  onSwitchAccount,
  onDecision,
}: SignAssetListingApprovalDialogProps) {
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

      <div className="rounded-lg border border-primary/30 bg-primary/5 p-4">
        <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
          <Tag className="h-3.5 w-3.5" />
          You are selling
        </div>
        <p className="mt-2 break-all font-mono text-lg font-semibold">{assetName}</p>
        <p className="mt-1 text-sm text-muted-foreground">
          for <span className="font-mono font-semibold text-foreground">{avn(priceSats)} AVN</span>
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <Label className="text-sm font-medium">Payment goes to</Label>
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
          Signing publishes an offer anyone can accept: whoever takes it gets the asset and you are
          paid the amount above. The signature covers only that trade — a buyer cannot change your
          payment — but it stays valid until the asset is spent, so cancel the listing on the site if
          you change your mind.
        </AlertDescription>
      </Alert>
    </div>
  );

  const actions = (
    <div className="flex gap-2 pt-2">
      <Button variant="outline" className="flex-1" onClick={() => onDecision(false)}>
        Reject
      </Button>
      <Button className="flex-1" onClick={() => onDecision(true)} disabled={!assetName}>
        Sign listing
      </Button>
    </div>
  );

  const title = 'Sell an asset';
  const description = 'Sign a marketplace listing so a buyer can complete the trade.';

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
