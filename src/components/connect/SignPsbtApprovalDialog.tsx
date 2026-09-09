'use client';

import React from 'react';
import { AlertTriangle, ArrowDownToLine, ArrowUpFromLine, FileSignature, Globe } from 'lucide-react';
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
import { ScrollArea } from '@/components/ui/scroll-area';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import type { PsbtSummary } from '@/services/wallet/psbt';

interface SignPsbtApprovalDialogProps {
  open: boolean;
  origin: string;
  account: string;
  summary: PsbtSummary | null;
  /** The site asked the wallet to broadcast once signing completes the transaction. */
  broadcast?: boolean;
  /** Offered when more than one wallet could sign; switching rejects this request. */
  onSwitchAccount?: () => void;

  onDecision: (approved: boolean) => void;
}

const avn = (sats: number) => (sats / 1e8).toFixed(8);
const shorten = (a: string) => (a.length > 24 ? `${a.slice(0, 12)}…${a.slice(-10)}` : a);

export default function SignPsbtApprovalDialog({
  open,
  origin,
  account,
  summary,
  broadcast = false,
  onSwitchAccount,
  onDecision,
}: SignPsbtApprovalDialogProps) {
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

      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <Label className="text-sm font-medium">Signing with</Label>
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

      {summary?.hasAsset && (
        <Alert className="border-amber-500/40 bg-amber-500/10 [&>svg]:text-amber-500">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription className="text-xs">
            This transaction touches an Avian asset. Asset inputs are never signed.
          </AlertDescription>
        </Alert>
      )}

      {summary && (
        <ScrollArea className="max-h-64 rounded-md border">
          <div className="space-y-3 p-3">
            <PartyList
              icon={<ArrowDownToLine className="h-3.5 w-3.5" />}
              label="Inputs"
              rows={summary.inputs.map((i) => ({
                address: i.address,
                value: i.value,
                isMine: i.isMine,
                isAsset: i.isAsset,
                fallback: 'Unknown input',
              }))}
            />
            <PartyList
              icon={<ArrowUpFromLine className="h-3.5 w-3.5" />}
              label="Outputs"
              rows={summary.outputs.map((o) => ({
                address: o.address,
                value: o.value,
                isMine: o.isMine,
                isAsset: o.isAsset,
                fallback: 'Non-standard output',
              }))}
            />
          </div>
        </ScrollArea>
      )}

      {summary && (
        <div className="rounded-lg border">
          <SummaryRow k="Total out" v={`${avn(summary.totalOut)} AVN`} />
          <SummaryRow
            k="Network fee"
            v={summary.fee === null ? 'Unknown' : `${avn(summary.fee)} AVN`}
            strong
          />
          <SummaryRow k="Inputs we'll sign" v={String(summary.signableByUs)} />
        </div>
      )}

      <Alert className="border-caution/30 bg-caution/10 [&>svg]:text-caution">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="text-xs">
          {broadcast ? (
            <>
              This site is asking you to sign a transaction that spends your coins{' '}
              <strong>and send it to the network</strong>. Once broadcast it cannot be recalled, so
              check the amounts and fee before you approve.
            </>
          ) : (
            <>
              This site is asking you to sign a transaction that spends your coins. The wallet signs
              only — the site broadcasts it. Check the amounts and fee before you sign.
            </>
          )}
        </AlertDescription>
      </Alert>

      <div className="flex gap-2 pt-1">
        <Button variant="outline" className="flex-1" onClick={() => onDecision(false)}>
          Reject
        </Button>
        <Button
          className="flex-1"
          onClick={() => onDecision(true)}
          disabled={!summary || summary.signableByUs === 0}
        >
          <FileSignature className="mr-2 h-4 w-4" />
          {broadcast ? 'Sign and send' : 'Sign'}
        </Button>
      </div>
    </div>
  );

  const title = broadcast ? 'Send transaction request' : 'Transaction signature request';
  const description = broadcast
    ? 'A site is asking you to sign an Avian transaction (PSBT) and broadcast it.'
    : 'A site is asking you to sign an Avian transaction (PSBT).';

  if (isMobile) {
    return (
      <Drawer open={open} onOpenChange={(next) => !next && onDecision(false)}>
        <DrawerContent className="max-h-[95vh]">
          <DrawerHeader className="text-left">
            <DrawerTitle>{title}</DrawerTitle>
            <DrawerDescription>{description}</DrawerDescription>
          </DrawerHeader>
          <div className="overflow-y-auto px-4 pb-6">{body}</div>
        </DrawerContent>
      </Drawer>
    );
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onDecision(false)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {body}
      </DialogContent>
    </Dialog>
  );
}

interface PartyRowData {
  address: string | null;
  value: number | null;
  isMine: boolean;
  isAsset: boolean;
  fallback: string;
}

function PartyList({
  icon,
  label,
  rows,
}: {
  icon: React.ReactNode;
  label: string;
  rows: PartyRowData[];
}) {
  return (
    <div>
      <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        <span className="text-primary">{icon}</span>
        {label}
      </div>
      <div className="rounded-md border">
        {rows.map((row, i) => (
          <div
            key={i}
            className="flex items-center justify-between gap-3 border-t px-2.5 py-2 text-sm first:border-t-0"
          >
            <span className="flex min-w-0 items-center gap-1.5">
              <span className="truncate font-mono text-xs">
                {row.address ? shorten(row.address) : row.fallback}
              </span>
              {row.isMine && (
                <Badge variant="secondary" className="h-4 px-1.5 text-[10px]">
                  Yours
                </Badge>
              )}
              {row.isAsset && (
                <Badge className="h-4 bg-amber-500/15 px-1.5 text-[10px] text-amber-600 hover:bg-amber-500/15">
                  Asset
                </Badge>
              )}
            </span>
            <span className="flex-shrink-0 font-mono text-xs">
              {row.value === null ? '—' : `${avn(row.value)} AVN`}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SummaryRow({ k, v, strong }: { k: string; v: string; strong?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 border-t px-3 py-2 text-sm first:border-t-0">
      <span className="text-muted-foreground">{k}</span>
      <span className={strong ? 'font-mono font-semibold' : 'font-mono'}>{v}</span>
    </div>
  );
}
