'use client';

import React from 'react';
import { Globe, PenTool, ShieldAlert } from 'lucide-react';
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

interface SignMessageApprovalDialogProps {
  open: boolean;
  origin: string;
  account: string;
  message: string;
  /** Offered when more than one wallet could sign; switching rejects this request. */
  onSwitchAccount?: () => void;

  onDecision: (approved: boolean) => void;
}

export default function SignMessageApprovalDialog({
  open,
  origin,
  account,
  message,
  onSwitchAccount,
  onDecision,
}: SignMessageApprovalDialogProps) {
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

      <div className="space-y-2">
        <Label className="text-sm font-medium">Message</Label>
        {/* Shown verbatim and in full: never truncate what the user is being asked to sign. */}
        <ScrollArea className="max-h-64 rounded-md border bg-muted/20">
          <pre className="whitespace-pre-wrap break-words p-3 font-mono text-xs leading-relaxed">
            {message}
          </pre>
        </ScrollArea>
        <p className="text-xs text-muted-foreground">{message.length} characters</p>
      </div>

      <Alert className="border-caution/30 bg-caution/10 [&>svg]:text-caution">
        <ShieldAlert className="h-4 w-4" />
        <AlertDescription className="text-xs">
          Signing proves you control this address. Read the whole message — only sign what you
          understand.
        </AlertDescription>
      </Alert>

      <div className="flex gap-2 pt-1">
        <Button variant="outline" className="flex-1" onClick={() => onDecision(false)}>
          Reject
        </Button>
        <Button className="flex-1" onClick={() => onDecision(true)}>
          <PenTool className="mr-2 h-4 w-4" />
          Sign
        </Button>
      </div>
    </div>
  );

  const title = 'Signature request';
  const description = 'A site is asking you to sign a message with your Avian address.';

  if (isMobile) {
    return (
      <Drawer open={open} onOpenChange={(next) => !next && onDecision(false)}>
        <DrawerContent>
          <DrawerHeader className="text-left">
            <DrawerTitle>{title}</DrawerTitle>
            <DrawerDescription>{description}</DrawerDescription>
          </DrawerHeader>
          <div className="px-4 pb-6">{body}</div>
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
