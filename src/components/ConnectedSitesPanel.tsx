'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Globe, Link2Off, PlugZap, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import ConfirmationModal from '@/components/ConfirmationModal';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { PermissionService } from '@/services/provider';
import { StorageService } from '@/services/core/StorageService';
import { OriginPermission } from '@/types/avianConnect';
import { providerLogger } from '@/lib/Logger';

/** Kept in step with the /connect page so a live session learns about revocations. */
const PERMISSION_CHANNEL = 'avian-connect';

const announceChange = () => {
  if (typeof BroadcastChannel === 'undefined') return;
  try {
    const channel = new BroadcastChannel(PERMISSION_CHANNEL);
    channel.postMessage({ type: 'permissions-changed' });
    channel.close();
  } catch (error) {
    providerLogger.warn('Could not announce a permission change:', error);
  }
};

const formatDate = (timestamp: number) =>
  timestamp ? new Date(timestamp).toLocaleString() : 'Unknown';

const shorten = (address: string) =>
  address.length > 24 ? `${address.slice(0, 12)}…${address.slice(-10)}` : address;

export default function ConnectedSitesPanel() {
  const [permissions, setPermissions] = useState<OriginPermission[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [pendingRevoke, setPendingRevoke] = useState<string | null>(null);
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false);
  const [wallets, setWallets] = useState<Array<{ name: string; address: string }>>([]);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const [stored, allWallets] = await Promise.all([
        PermissionService.list(),
        StorageService.getAllWallets(),
      ]);
      setPermissions([...stored].sort((a, b) => b.lastUsedAt - a.lastUsedAt));
      setWallets(allWallets.map((wallet) => ({ name: wallet.name, address: wallet.address })));
    } catch (error) {
      providerLogger.error('Failed to load connected sites:', error);
      toast.error('Error', { description: 'Failed to load connected sites' });
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  /**
   * Point a site at a different wallet.
   *
   * A grant is deliberately independent of the active wallet — switching wallets must not silently
   * hand a site an address it was never given — so this is the only place a site's account can be
   * changed without disconnecting it entirely.
   */
  const changeAccount = async (origin: string, address: string) => {
    try {
      await PermissionService.grant(origin, [address]);
      announceChange();
      await load();
      toast.success('Wallet changed', {
        description: `${origin} will now see ${shorten(address)}.`,
      });
    } catch (error) {
      providerLogger.error('Failed to change the connected wallet:', error);
      toast.error('Error', { description: 'Failed to change the connected wallet' });
    }
  };

  const revoke = async (origin: string) => {
    try {
      await PermissionService.revoke(origin);
      announceChange();
      await load();
      toast.success('Access revoked', { description: `${origin} must ask again to connect.` });
    } catch (error) {
      providerLogger.error('Failed to revoke site access:', error);
      toast.error('Error', { description: 'Failed to revoke access' });
    }
  };

  const revokeAll = async () => {
    try {
      await PermissionService.revokeAll();
      announceChange();
      await load();
      toast.success('All sites disconnected');
    } catch (error) {
      providerLogger.error('Failed to revoke all site access:', error);
      toast.error('Error', { description: 'Failed to disconnect sites' });
    }
  };

  return (
    <Card className="border-0 shadow-none">
      <CardHeader className="flex flex-col space-y-3 pb-4 px-4 sm:px-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between space-y-2 sm:space-y-0">
          <CardTitle className="text-lg sm:text-xl font-bold">Connected Sites</CardTitle>
          <div className="flex w-full gap-2 sm:w-auto">
            <Button onClick={load} disabled={isLoading} variant="outline" size="sm" className="h-8 flex-1 sm:flex-initial">
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            {permissions.length > 0 && (
              <Button
                onClick={() => setConfirmRevokeAll(true)}
                variant="outline"
                size="sm"
                className="h-8 flex-1 sm:flex-initial text-destructive hover:text-destructive"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Disconnect all
              </Button>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4 px-4 sm:px-6">
        <Alert className="bg-muted/50">
          <ShieldCheck className="h-4 w-4" />
          <AlertDescription className="text-xs">
            These sites can see the address you shared with them and can ask you to sign messages.
            Every signature still needs your explicit approval and authentication. A site keeps the
            wallet you connected with — it does not follow the wallet you are using — so change it
            here if you want it to see a different one. See{' '}
            <Link href="/connect" className="underline underline-offset-2">
              Avian Connect
            </Link>
            .
          </AlertDescription>
        </Alert>

        {isLoading && permissions.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">Loading…</p>
        ) : permissions.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-10 text-center">
            <PlugZap className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm font-medium">No connected sites</p>
            <p className="max-w-sm text-xs text-muted-foreground">
              When you connect this wallet to a dApp and choose to remember it, it will appear here.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {permissions.map((permission) => (
              <div key={permission.origin} className="rounded-lg border p-3 sm:p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0 flex-1 space-y-2">
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
                      <span className="break-all font-mono text-sm font-semibold">
                        {permission.origin}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5">
                      {wallets.length > 1 ? (
                        <Select
                          value={permission.accounts[0] ?? ''}
                          onValueChange={(address) => changeAccount(permission.origin, address)}
                        >
                          <SelectTrigger className="h-7 w-auto gap-2 px-2 font-mono text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {wallets.map((wallet) => (
                              <SelectItem
                                key={wallet.address}
                                value={wallet.address}
                                className="font-mono text-xs"
                              >
                                {wallet.name} · {shorten(wallet.address)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        permission.accounts.map((account) => (
                          <Badge key={account} variant="secondary" className="font-mono text-xs">
                            {shorten(account)}
                          </Badge>
                        ))
                      )}
                    </div>

                    <div className="grid gap-0.5 text-xs text-muted-foreground sm:grid-cols-2">
                      <span>Connected: {formatDate(permission.grantedAt)}</span>
                      <span>Last used: {formatDate(permission.lastUsedAt)}</span>
                    </div>
                  </div>

                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 w-full text-destructive hover:text-destructive sm:w-auto"
                    onClick={() => setPendingRevoke(permission.origin)}
                  >
                    <Link2Off className="mr-2 h-4 w-4" />
                    Revoke
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>

      <ConfirmationModal
        isOpen={pendingRevoke !== null}
        onClose={() => setPendingRevoke(null)}
        onConfirm={() => {
          const origin = pendingRevoke;
          if (origin) revoke(origin);
        }}
        title="Revoke access"
        message={`${pendingRevoke} will lose access to your address. It will have to ask again the next time it wants to connect.`}
        confirmText="Revoke"
        isDestructive
      />

      <ConfirmationModal
        isOpen={confirmRevokeAll}
        onClose={() => setConfirmRevokeAll(false)}
        onConfirm={revokeAll}
        title="Disconnect all sites"
        message="Every remembered site will lose access to your address and will have to ask again."
        confirmText="Disconnect all"
        isDestructive
      />
    </Card>
  );
}
