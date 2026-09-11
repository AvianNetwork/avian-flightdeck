'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { StorageService } from '@/services/core/StorageService';
import { openTransactionInExplorer } from '@/lib/explorer';
import { useWallet } from '@/contexts/WalletContext';
import {
  ArrowUpRight,
  ArrowDownLeft,
  Clock,
  Check,
  AlertCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  Inbox,
  Coins,
} from 'lucide-react';

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/EmptyState';
import { toast } from 'sonner';
import { useAssetTxOutputs } from '@/hooks/useAssetTxOutputs';
import { describeAssetTx, formatAssetQty, type AssetTxLabel } from '@/services/wallet/assetHistory';

// Loading placeholder that mirrors the transaction-row layout, so the list settles into place
// rather than flashing a bare spinner.
function TxRowSkeleton() {
  return (
    <div className="p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 flex-1 items-start gap-3">
          <Skeleton className="h-10 w-10 flex-shrink-0 rounded-full" />
          <div className="min-w-0 flex-1 space-y-2 py-1">
            <Skeleton className="h-3.5 w-24" />
            <Skeleton className="h-3 w-44" />
            <Skeleton className="h-3 w-20" />
          </div>
        </div>
        <Skeleton className="h-4 w-20 flex-shrink-0" />
      </div>
    </div>
  );
}

// A compact chip summarising the asset side of a transaction (e.g. "+5 SMAUG", "Issued
// FLIGHTDECK#desktop"). Gains (receive/issue/reissue) read in the primary colour, sends in sodium.
function AssetChips({ label }: { label: AssetTxLabel }) {
  const positive = label.action !== 'send';
  const color = positive ? 'bg-primary/10 text-primary' : 'bg-sodium/10 text-sodium';
  return (
    <div className="mt-1 flex flex-wrap gap-1">
      {label.entries.map((e) => {
        let text: string;
        if (label.action === 'issue') {
          text = `Issued ${e.name}`;
        } else if (label.action === 'reissue') {
          text =
            e.amount && e.amount > 0n
              ? `Reissued ${e.name} (+${formatAssetQty(e.amount)})`
              : `Reissued ${e.name}`;
        } else {
          text = `${label.action === 'receive' ? '+' : '−'}${formatAssetQty(e.amount ?? 0n)} ${e.name}`;
        }
        return (
          <span
            key={`${label.action}-${e.name}`}
            className={`inline-flex max-w-full items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium ${color}`}
            title={text}
          >
            <Coins className="h-3 w-3 flex-shrink-0" />
            <span className="truncate font-mono">{text}</span>
          </span>
        );
      })}
    </div>
  );
}

interface TransactionData {
  id?: number;
  txid: string;
  amount: number;
  address: string;
  fromAddress?: string;
  walletAddress?: string; // The wallet this transaction belongs to
  type: 'send' | 'receive';
  timestamp: Date | string; // Can be string when retrieved from database
  confirmations: number;
  blockHeight?: number;
}

// Extended interface to support virtual transaction entries for self-transfers
interface EnhancedTransactionData extends TransactionData {
  isVirtual?: boolean; // Marks this as a UI-only transaction entry
}

// Helper function to check if a transaction is a self-transfer
const isSelfTransfer = (tx: TransactionData, walletAddress: string): boolean => {
  return (
    (tx.address === tx.fromAddress && tx.address === walletAddress) ||
    (tx.walletAddress === tx.fromAddress && tx.fromAddress === tx.address)
  );
};

// Helper function to process transactions for display
const processTransactionsForDisplay = (
  txs: TransactionData[],
  walletAddress: string,
): EnhancedTransactionData[] => {
  const result: EnhancedTransactionData[] = [];

  // Group transactions by txid to help identify self-transfers with potential duplicates
  const txsByTxid = new Map<string, TransactionData[]>();

  // Group all transactions by txid
  txs.forEach((tx) => {
    // Make sure we're only processing transactions that belong to this wallet
    if (tx.walletAddress && tx.walletAddress !== walletAddress) {
      return; // Skip transactions that belong to other wallets
    }

    if (!txsByTxid.has(tx.txid)) {
      txsByTxid.set(tx.txid, []);
    }
    txsByTxid.get(tx.txid)!.push(tx);
  });

  // Process each transaction group
  txsByTxid.forEach((transactions, txid) => {
    // Check if any transaction in this group is a self-transfer
    const selfTransferTxs = transactions.filter((tx) => isSelfTransfer(tx, walletAddress));
    const hasSelfTransfer = selfTransferTxs.length > 0;

    // For self-transfers, we'll add exactly one send and one receive entry
    if (hasSelfTransfer) {
      // Get all unique transactions by type (in case of duplicates)
      // For each type, take only the first transaction to avoid duplicates
      const sendTxs = transactions.filter((tx) => tx.type === 'send');
      const receiveTxs = transactions.filter((tx) => tx.type === 'receive');

      // Take only the first of each type to avoid duplicates
      const sendTx = sendTxs.length > 0 ? sendTxs[0] : null;
      const receiveTx = receiveTxs.length > 0 ? receiveTxs[0] : null;

      // If we don't have a send transaction, create a virtual one from the receive
      if (!sendTx && receiveTx) {
        result.push({
          ...receiveTx,
          type: 'send',
          isVirtual: true,
          id: receiveTx.id ? receiveTx.id * -1 : undefined, // Ensure unique ID
        });
      }
      // If we have a send transaction, add only the first one
      else if (sendTx) {
        result.push(sendTx);
      }

      // If we don't have a receive transaction, create a virtual one from the send
      if (!receiveTx && sendTx) {
        result.push({
          ...sendTx,
          type: 'receive',
          isVirtual: true,
          id: sendTx.id ? sendTx.id * -1 : undefined, // Ensure unique ID
        });
      }
      // If we have a receive transaction, add only the first one
      else if (receiveTx) {
        result.push(receiveTx);
      }
    } else {
      // For regular transactions, deduplicate by type
      // Create a map to track if we've seen a transaction of each type for this txid
      const typesAdded = new Set<string>();

      // Add only the first instance of each transaction type
      transactions.forEach((tx) => {
        // Only add this transaction if we haven't seen its type before
        if (!typesAdded.has(tx.type)) {
          result.push(tx);
          typesAdded.add(tx.type);
        }
      });
    }
  });

  return result;
};

interface TransactionHistoryProps {
  className?: string;
}

export function TransactionHistory({ className }: TransactionHistoryProps) {
  const { address, electrum, refreshTransactionHistory, processingProgress } = useWallet();
  /**
   * Chain tip, for working out confirmations at render time.
   *
   * A transaction's stored `confirmations` is a snapshot taken when it was written, so it stays at
   * whatever it was — "1/6" on a transaction eighty blocks deep — unless a sync happens to rewrite
   * that row. The block height is already stored, so the live count is just arithmetic against the
   * current tip, and cannot go stale.
   */
  const [chainTip, setChainTip] = useState<number | null>(null);
  const [transactions, setTransactions] = useState<EnhancedTransactionData[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [filter, setFilter] = useState<'all' | 'send' | 'receive'>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(20); // Show 20 transactions per page    // Function to refresh transaction history with progress updates
  /** Read the chain tip, quietly: a failure just leaves confirmations on their stored value. */
  const refreshChainTip = useCallback(async () => {
    if (!electrum?.isConnectedToServer()) return;
    try {
      const height = await electrum.getCurrentBlockHeight();
      if (height > 0) setChainTip(height);
    } catch {
      /* leave the last known tip in place */
    }
  }, [electrum]);

  const refreshTransactionHistoryWithProgress = useCallback(async () => {
    if (!address) return;

    try {
      setIsRefreshing(true);

      // The tip first: even when the sync brings back nothing new, every confirmation count on
      // screen still moves, which is the usual reason to press Refresh.
      await refreshChainTip();

      // Incremental refresh: pull only new transactions rather than re-fetching the entire
      // history. A full re-sync (reclassify everything) is still available via the balance
      // card's long-press.
      await refreshTransactionHistory();

      // Final reload after processing is complete
      const finalTxHistory = await StorageService.getTransactionHistory(address);
      const finalSorted = finalTxHistory.sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );

      // Process transactions to handle self-transfers
      const enhancedTransactions = processTransactionsForDisplay(finalSorted, address);
      setTransactions(enhancedTransactions);
    } catch (error) {
      throw error;
    } finally {
      setIsRefreshing(false);
    }
  }, [address, refreshTransactionHistory, refreshChainTip]);

  const loadTransactions = useCallback(async () => {
    if (!address) return;

    void refreshChainTip();

    try {
      setIsLoading(true);

      // Load from local storage first
      const txHistory = await StorageService.getTransactionHistory(address);
      const sortedTx = txHistory.sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );

      // Process transactions to handle self-transfers
      const enhancedTransactions = processTransactionsForDisplay(sortedTx, address);
      setTransactions(enhancedTransactions);
      setIsLoading(false);

      // Only refresh from blockchain if we have no local data
      if (txHistory.length === 0) {
        try {
          await refreshTransactionHistory();
          // Reload after refresh
          const updatedTxHistory = await StorageService.getTransactionHistory(address);
          const updatedSorted = updatedTxHistory.sort(
            (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
          );

          // Process transactions to handle self-transfers
          const enhancedTransactions = processTransactionsForDisplay(updatedSorted, address);
          setTransactions(enhancedTransactions);
        } catch (refreshError) {
          toast.warning('Failed to refresh transaction history from blockchain', {
            description: refreshError instanceof Error ? refreshError.message : 'Unknown error',
          });
        }
      }
    } catch (error) {
      setIsLoading(false);
    }
  }, [address, refreshTransactionHistory, refreshChainTip]);

  useEffect(() => {
    const loadTransactionsEffect = async () => {
      await loadTransactions();
      setCurrentPage(1); // Reset to first page when first loading
    };

    loadTransactionsEffect();
  }, [loadTransactions]);

  // Separate effect to handle real-time updates during processing
  useEffect(() => {
    if (!address || !processingProgress.isProcessing) {
      return;
    }

    const updateInterval = setInterval(async () => {
      try {
        const txHistory = await StorageService.getTransactionHistory(address);
        const sortedTx = txHistory.sort(
          (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
        );

        // Process transactions to handle self-transfers
        const enhancedTransactions = processTransactionsForDisplay(sortedTx, address);
        setTransactions(enhancedTransactions);
      } catch (error) {
        toast.error('Failed to update transactions during processing', {
          description: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }, 3000); // Update every 3 seconds during processing

    return () => clearInterval(updateInterval);
  }, [address, processingProgress.isProcessing]);

  // Reset page when filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [filter]);

  const filteredTransactions = transactions.filter((tx) => {
    if (filter === 'all') return true;
    return tx.type === filter;
  });

  // Pagination calculations
  const totalPages = Math.ceil(filteredTransactions.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedTransactions = filteredTransactions.slice(startIndex, endIndex);

  // Re-derive the asset side of each visible transaction (the history store keeps only the AVN side).
  const assetOutputs = useAssetTxOutputs(paginatedTransactions.map((tx) => tx.txid));

  const nextPage = () => {
    if (currentPage < totalPages) {
      setCurrentPage(currentPage + 1);
    }
  };

  const prevPage = () => {
    if (currentPage > 1) {
      setCurrentPage(currentPage - 1);
    }
  };

  const goToPage = (page: number) => {
    if (page >= 1 && page <= totalPages) {
      setCurrentPage(page);
    }
  };

  const formatAmount = (amount: number, type: 'send' | 'receive') => {
    const sign = type === 'send' ? '-' : '+';
    const color = type === 'send' ? 'text-foreground' : 'text-primary';
    return (
      <span className={`font-medium font-mono tabular-nums ${color}`}>
        {sign}
        {amount.toFixed(8)} AVN
      </span>
    );
  };

  const formatDate = (date: Date | string) => {
    const now = new Date();
    // Ensure we have a proper Date object
    const txDate = new Date(date);

    // Check if the date is valid
    if (isNaN(txDate.getTime())) {
      return 'Unknown date';
    }

    const diffMs = now.getTime() - txDate.getTime();
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMinutes < 1) return 'Just now';
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;

    return txDate.toLocaleDateString();
  };

  /** Confirmations now, not when the row was stored. Falls back for anything unconfirmed. */
  const confirmationsOf = (tx: { blockHeight?: number; confirmations?: number }) =>
    chainTip && tx.blockHeight && tx.blockHeight > 0
      ? Math.max(0, chainTip - tx.blockHeight + 1)
      : (tx.confirmations ?? 0);

  const getStatusIcon = (confirmations: number | undefined) => {
    const numConfirmations = Number(confirmations) || 0;
    if (numConfirmations === 0) {
      return <Clock className="w-4 h-4 text-muted-foreground" />;
    } else if (numConfirmations < 6) {
      return <AlertCircle className="w-4 h-4 text-caution" />;
    } else {
      return <Check className="w-4 h-4 text-primary" />;
    }
  };

  const getStatusText = (confirmations: number | undefined) => {
    const numConfirmations = Number(confirmations) || 0;

    if (numConfirmations === 0) return 'Pending';
    if (numConfirmations < 6) return `${numConfirmations}/6 confirmations`;
    return 'Confirmed';
  };

  const openExplorer = (txid: string) => {
    // Open the transaction in the Avian block explorer
    openTransactionInExplorer(txid);
  };

  return (
    <Card className={`w-full max-w-4xl mx-auto ${className}`}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Transaction History</CardTitle>
          <Button
            onClick={refreshTransactionHistoryWithProgress}
            disabled={isRefreshing || processingProgress.isProcessing}
            variant="outline"
            size="sm"
            className="flex items-center gap-2"
          >
            <RefreshCw
              className={`w-4 h-4 ${isRefreshing || processingProgress.isProcessing ? 'animate-spin' : ''}`}
            />
            <span className="hidden sm:inline">
              {isRefreshing || processingProgress.isProcessing ? 'Refreshing...' : 'Refresh'}
            </span>
          </Button>
        </div>
      </CardHeader>

      {/* Filter Controls */}
      <div className="p-4 border-b border-border flex-shrink-0">
        <Tabs
          defaultValue={filter}
          onValueChange={(value) => setFilter(value as 'all' | 'send' | 'receive')}
        >
          <TabsList className="w-full h-auto rounded-none border-b bg-transparent p-0">
            <TabsTrigger
              value="all"
              className="flex-1 data-[state=active]:after:bg-primary relative rounded-none py-2 after:absolute after:inset-x-0 after:bottom-0 after:h-0.5 data-[state=active]:bg-transparent data-[state=active]:shadow-none"
            >
              All ({transactions.length})
            </TabsTrigger>
            <TabsTrigger
              value="receive"
              className="flex-1 data-[state=active]:after:bg-primary relative rounded-none py-2 after:absolute after:inset-x-0 after:bottom-0 after:h-0.5 data-[state=active]:bg-transparent data-[state=active]:shadow-none"
            >
              <span className="text-primary">
                Received ({transactions.filter((tx) => tx.type === 'receive').length})
              </span>
            </TabsTrigger>
            <TabsTrigger
              value="send"
              className="flex-1 data-[state=active]:after:bg-primary relative rounded-none py-2 after:absolute after:inset-x-0 after:bottom-0 after:h-0.5 data-[state=active]:bg-transparent data-[state=active]:shadow-none"
            >
              <span className="text-sodium">
                Sent ({transactions.filter((tx) => tx.type === 'send').length})
              </span>
            </TabsTrigger>
          </TabsList>
        </Tabs>

        {/* Processing Progress */}
        {processingProgress.isProcessing && processingProgress.total > 0 && (
          <div className="bg-primary/5 rounded-lg p-3 mt-4 border border-primary/20">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-foreground">
                Processing transaction history...
              </span>
              <span className="text-xs text-muted-foreground">
                {processingProgress.processed}/{processingProgress.total}
              </span>
            </div>
            <Progress
              value={
                processingProgress.total > 0
                  ? (processingProgress.processed / processingProgress.total) * 100
                  : 0
              }
              className="h-2"
            />
            <div className="text-xs text-muted-foreground mt-1">
              New transactions will appear as they&apos;re processed
            </div>
            {processingProgress.currentTx && (
              <div className="text-xs text-muted-foreground mt-1 font-mono">
                Processing: {processingProgress.currentTx.slice(0, 16)}...
              </div>
            )}
          </div>
        )}
      </div>

      {/* Transaction List */}
      <CardContent className="p-0">
        <div className="max-h-[500px] overflow-y-auto">
          {isLoading ? (
            <div className="divide-y divide-border" aria-busy="true" aria-label="Loading transactions">
              {Array.from({ length: 5 }).map((_, i) => (
                <TxRowSkeleton key={i} />
              ))}
            </div>
          ) : paginatedTransactions.length === 0 ? (
            <EmptyState
              icon={Inbox}
              title={filter === 'all' ? 'No transactions yet' : `No ${filter} transactions`}
              description={
                filter === 'all'
                  ? 'When you receive or send AVN, it shows up here with live confirmations.'
                  : `Nothing matches the ${filter} filter yet.`
              }
            />
          ) : (
            <div className="divide-y divide-border">
              {paginatedTransactions.map((tx) => {
                const outs = assetOutputs.get(tx.txid);
                const assetLabel =
                  outs && outs.length ? describeAssetTx(outs, address || '', tx.type) : null;
                return (
                <div
                  key={`${tx.id || tx.txid}-${tx.type}${tx.isVirtual ? '-virtual' : ''}`}
                  className="p-4 hover:bg-muted/50"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3 min-w-0 flex-1">
                      {/* Transaction Icon */}
                      <div
                        className={`flex-shrink-0 p-2 rounded-full ${tx.type === 'send'
                          ? 'bg-sodium/10'
                          : 'bg-primary/10'
                          }`}
                      >
                        {tx.type === 'send' ? (
                          <ArrowUpRight className="w-4 h-4 text-sodium" />
                        ) : (
                          <ArrowDownLeft className="w-4 h-4 text-primary" />
                        )}
                      </div>

                      {/* Transaction Details */}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-medium text-foreground capitalize">
                            {tx.type}
                          </span>
                          {getStatusIcon(confirmationsOf(tx))}
                          <span className="text-sm text-muted-foreground">
                            {getStatusText(confirmationsOf(tx))}
                          </span>
                        </div>

                        <div className="text-sm text-muted-foreground mb-1">
                          {tx.type === 'send' ? 'To: ' : 'From: '}
                          <span className="font-mono break-all">
                            {(() => {
                              // Some transactions have no resolvable counterparty (e.g. mining
                              // payouts) — never assume a string here or the whole list crashes.
                              const displayAddress =
                                (tx.type === 'send' ? tx.address : tx.fromAddress || tx.address) ||
                                'Unknown';
                              return displayAddress.length > 40
                                ? `${displayAddress.slice(0, 20)}...${displayAddress.slice(-20)}`
                                : displayAddress;
                            })()}
                          </span>
                        </div>

                        {assetLabel && <AssetChips label={assetLabel} />}

                        <div className="flex items-center gap-3">
                          <span className="text-sm text-muted-foreground">
                            {formatDate(tx.timestamp)}
                          </span>
                          <button
                            onClick={() => openExplorer(tx.txid)}
                            className="text-xs text-primary hover:underline flex items-center gap-1"
                          >
                            <ExternalLink className="w-3 h-3" />
                            View Details
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Amount */}
                    <div className="flex-shrink-0 text-right">
                      {formatAmount(tx.amount, tx.type)}
                      {tx.blockHeight && (
                        <div className="text-xs text-muted-foreground mt-1">
                          Block #{tx.blockHeight}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                );
              })}
            </div>
          )}
        </div>
      </CardContent>

      {/* Footer with Pagination */}
      <CardFooter className="p-4 border-t border-border bg-muted/40">
        <div className="flex flex-col sm:flex-row justify-between items-center w-full gap-3 text-sm text-muted-foreground">
          <span>
            Showing {startIndex + 1}-{Math.min(endIndex, filteredTransactions.length)} of{' '}
            {filteredTransactions.length}{' '}
            {filter === 'all' ? 'transactions' : `${filter} transactions`}
          </span>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="flex items-center gap-2">
              <Button
                onClick={prevPage}
                disabled={currentPage === 1}
                variant="outline"
                size="sm"
                className="h-8 w-8 p-0"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>

              {/* Page Numbers */}
              <div className="flex items-center gap-1">
                {(() => {
                  const maxVisiblePages = 5;
                  let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
                  let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

                  if (endPage - startPage + 1 < maxVisiblePages) {
                    startPage = Math.max(1, endPage - maxVisiblePages + 1);
                  }

                  const pages = [];

                  if (startPage > 1) {
                    pages.push(
                      <Button
                        key={1}
                        onClick={() => goToPage(1)}
                        variant="outline"
                        size="sm"
                        className="h-8 w-8 p-0"
                      >
                        1
                      </Button>,
                    );
                    if (startPage > 2) {
                      pages.push(
                        <span key="ellipsis1" className="px-1">
                          ...
                        </span>,
                      );
                    }
                  }

                  for (let i = startPage; i <= endPage; i++) {
                    pages.push(
                      <Button
                        key={i}
                        onClick={() => goToPage(i)}
                        variant={i === currentPage ? 'default' : 'outline'}
                        size="sm"
                        className="h-8 w-8 p-0"
                      >
                        {i}
                      </Button>,
                    );
                  }

                  if (endPage < totalPages) {
                    if (endPage < totalPages - 1) {
                      pages.push(
                        <span key="ellipsis2" className="px-1">
                          ...
                        </span>,
                      );
                    }
                    pages.push(
                      <Button
                        key={totalPages}
                        onClick={() => goToPage(totalPages)}
                        variant="outline"
                        size="sm"
                        className="h-8 w-8 p-0"
                      >
                        {totalPages}
                      </Button>,
                    );
                  }

                  return pages;
                })()}
              </div>

              <Button
                onClick={nextPage}
                disabled={currentPage === totalPages}
                variant="outline"
                size="sm"
                className="h-8 w-8 p-0"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )}

          <Button
            onClick={async () => {
              // If we have many transactions, use progressive refresh
              if (transactions.length > 100) {
                await refreshTransactionHistoryWithProgress();
              } else {
                await loadTransactions();
              }
            }}
            disabled={processingProgress.isProcessing}
            variant="link"
            size="sm"
          >
            {processingProgress.isProcessing ? 'Processing...' : 'Refresh'}
          </Button>
        </div>
      </CardFooter>
    </Card>
  );
}
