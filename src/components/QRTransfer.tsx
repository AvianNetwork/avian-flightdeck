'use client';

import { useState, useRef, useEffect } from 'react';
import { Camera, ArrowLeft, ArrowRight, X, AlertCircle, ChevronLeft, Download, Eye, EyeOff } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import jsQR from 'jsqr';
import { toast } from 'sonner';
import { BackupService } from '@/services/core/BackupService';
import { Logger } from '@/lib/Logger';

// Import Shadcn UI components
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useMediaQuery } from '@/hooks/use-media-query';

// Create a logger instance for QR backup/restore
const qrBackupLogger = Logger.getLogger('qr_backup');

type QRTransferMode = 'both' | 'restore-only' | 'backup-only';

interface QRTransferProps {
    /** Which tabs to show. Defaults to both. */
    mode?: QRTransferMode;
    /** Starting tab when mode is 'both'. */
    initialTab?: 'backup' | 'restore';
    /** Called after a successful restore (e.g. navigate home, or close the host modal + reload). */
    onRestored?: () => void;
}

/**
 * The QR wallet-transfer UI (generate backup QR codes / scan to restore), extracted from the
 * /backup/qr page so it can be embedded inline anywhere — the page wraps it in the app shell, and
 * BackupQRModal renders it in a dialog/drawer so onboarding no longer has to navigate away.
 */
export default function QRTransfer({ mode = 'both', initialTab = 'backup', onRestored }: QRTransferProps) {
    const [activeTab, setActiveTab] = useState<'backup' | 'restore'>(
        mode === 'restore-only' ? 'restore' : mode === 'backup-only' ? 'backup' : initialTab,
    );
    const [backupPassword, setBackupPassword] = useState('');
    const [restorePassword, setRestorePassword] = useState('');
    const [showBackupPassword, setShowBackupPassword] = useState(false);
    const [showRestorePassword, setShowRestorePassword] = useState(false);
    const [backupChunks, setBackupChunks] = useState<string[]>([]);
    const [currentChunkIndex, setCurrentChunkIndex] = useState(0);
    const [isGenerating, setIsGenerating] = useState(false);
    const [isScanning, setIsScanning] = useState(false);
    const [isCameraActive, setIsCameraActive] = useState(false);
    const [scanProgress, setScanProgress] = useState(0);
    const [scannedChunks, setScannedChunks] = useState<string[]>([]);
    const [scannedChunkIndices, setScannedChunkIndices] = useState<Set<number>>(new Set());
    const [totalExpectedChunks, setTotalExpectedChunks] = useState<number | null>(null);
    const [isRestoring, setIsRestoring] = useState(false);
    const [restoreError, setRestoreError] = useState<string | null>(null);
    const [lastScannedChunk, setLastScannedChunk] = useState<string | null>(null);
    const [scanPaused, setScanPaused] = useState(false);
    const [isProcessingChunk, setIsProcessingChunk] = useState(false);
    const [duplicateAlert, setDuplicateAlert] = useState<string | null>(null);
    const isMobile = useMediaQuery('(max-width: 640px)');

    const videoRef = useRef<HTMLVideoElement>(null);
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const requestRef = useRef<number | null>(null);

    // Use refs to track current state synchronously to prevent race conditions
    const currentScannedChunks = useRef<string[]>([]);
    const currentScannedIndices = useRef<Set<number>>(new Set());
    const isCurrentlyProcessing = useRef<boolean>(false);
    const isCameraActiveRef = useRef<boolean>(false);
    const scanPausedRef = useRef<boolean>(false);

    // Generate QR code chunks for backup
    const generateBackupQR = async () => {
        try {
            setIsGenerating(true);

            // For QR codes, always use wallets-only backup to keep size manageable
            const backup = await BackupService.createWalletsOnlyBackup();

            // Export backup with optional encryption
            const backupBlob = await BackupService.exportBackup(
                backup,
                backupPassword.length > 0 ? backupPassword : undefined,
            );

            // Convert to base64 string for QR code
            const backupBase64 = await new Promise<string>((resolve) => {
                const reader = new FileReader();
                reader.onloadend = () => resolve(reader.result as string);
                reader.readAsDataURL(backupBlob);
            });

            // Split into chunks if needed (QR codes have limited capacity)
            const chunks = BackupService.splitBackupForQR(backupBase64);
            setBackupChunks(chunks);
            setCurrentChunkIndex(0);

            toast.success('Wallets backup QR codes generated', {
                description: `Created ${chunks.length} QR code${chunks.length > 1 ? 's' : ''} for your wallet backup`,
            });
        } catch (error) {
            toast.error('Failed to generate backup QR code', {
                description: error instanceof Error ? error.message : 'Unknown error',
            });
        } finally {
            setIsGenerating(false);
        }
    };

    // Download all QR codes as images
    const downloadAllQRCodes = async () => {
        try {
            if (backupChunks.length === 0) {
                toast.error('No QR codes to download');
                return;
            }

            const qrSize = 512; // High resolution for downloads
            const timestamp = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-');

            // If there's only one QR code, download it directly
            if (backupChunks.length === 1) {
                await downloadSingleQRCode(backupChunks[0], `avian-wallet-backup-${timestamp}.png`);
                toast.success('QR code downloaded successfully');
                return;
            }

            // For multiple QR codes, download them individually with a delay
            toast.info(`Downloading ${backupChunks.length} QR codes...`, {
                description: 'Files will download one by one'
            });

            for (let i = 0; i < backupChunks.length; i++) {
                const filename = `avian-wallet-backup-${timestamp}-${String(i + 1).padStart(2, '0')}-of-${String(backupChunks.length).padStart(2, '0')}.png`;
                await downloadSingleQRCode(backupChunks[i], filename);

                // Add a small delay between downloads to prevent browser blocking
                if (i < backupChunks.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
            }

            toast.success(`Downloaded ${backupChunks.length} QR codes successfully`, {
                description: 'You can now print or share these QR codes safely'
            });

        } catch (error) {
            console.error('Download error:', error);
            toast.error('Failed to download QR codes', {
                description: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    };

    // Helper function to download a single QR code
    const downloadSingleQRCode = async (qrData: string, filename: string): Promise<void> => {
        return new Promise((resolve, reject) => {
            try {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                if (!ctx) {
                    reject(new Error('Canvas context not available'));
                    return;
                }

                const qrSize = 512;
                canvas.width = qrSize;
                canvas.height = qrSize;

                // Use the qrcode library for reliable QR code generation
                import('qrcode').then((QRCode) => {
                    QRCode.toCanvas(canvas, qrData, {
                        width: qrSize,
                        margin: 4,
                        color: {
                            dark: '#000000',
                            light: '#FFFFFF'
                        },
                        errorCorrectionLevel: 'L'
                    }, (error) => {
                        if (error) {
                            reject(error);
                            return;
                        }

                        canvas.toBlob((blob) => {
                            if (blob) {
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = filename;
                                document.body.appendChild(a);
                                a.click();
                                document.body.removeChild(a);
                                URL.revokeObjectURL(url);
                                resolve();
                            } else {
                                reject(new Error('Failed to create blob'));
                            }
                        }, 'image/png');
                    });
                }).catch(reject);
            } catch (error) {
                reject(error);
            }
        });
    };

    // Handle camera scanning for restore
    const startScanner = async () => {
        try {
            setIsCameraActive(true);
            setIsScanning(true);
            setScanProgress(0);
            setScannedChunks([]);
            setScannedChunkIndices(new Set());
            setTotalExpectedChunks(null);
            setRestoreError(null);
            setScanPaused(false);
            setLastScannedChunk(null);
            setIsProcessingChunk(false);
            setDuplicateAlert(null);

            // Reset refs to ensure synchronous state tracking
            currentScannedChunks.current = [];
            currentScannedIndices.current = new Set();
            isCurrentlyProcessing.current = false;
            isCameraActiveRef.current = true;
            scanPausedRef.current = false;

            qrBackupLogger.info('Starting QR scanner');

            // Access device camera with better constraints
            const constraints = {
                video: {
                    facingMode: 'environment',
                    width: { ideal: 1280 },
                    height: { ideal: 720 }
                },
            };

            const stream = await navigator.mediaDevices.getUserMedia(constraints);

            if (videoRef.current) {
                videoRef.current.srcObject = stream;

                // Wait for video to be ready before starting scan loop
                videoRef.current.onloadedmetadata = () => {
                    qrBackupLogger.info('Video metadata loaded, starting scan loop');
                    if (videoRef.current) {
                        videoRef.current.play().then(() => {
                            qrBackupLogger.info('Video playing, scanner ready');
                            // Start scanning after a short delay to ensure video is fully ready
                            setTimeout(() => {
                                if (isCameraActiveRef.current && videoRef.current) {
                                    qrBackupLogger.info(`Video ready state: ${videoRef.current.readyState}, dimensions: ${videoRef.current.videoWidth}x${videoRef.current.videoHeight}`);
                                    scanQRCode();
                                }
                            }, 500);
                        }).catch((error) => {
                            qrBackupLogger.error('Error playing video:', error);
                            toast.error('Failed to start video playback');
                            setIsCameraActive(false);
                            setIsScanning(false);
                        });
                    }
                };

                videoRef.current.onerror = (error) => {
                    qrBackupLogger.error('Video error:', error);
                    toast.error('Video playback error');
                };
            }
        } catch (error) {
            qrBackupLogger.error('Failed to access camera:', error);
            setIsCameraActive(false);
            setIsScanning(false);
            toast.error('Failed to access camera', {
                description: 'Please ensure you have granted camera permissions and try again',
            });
        }
    };

    // Stop the camera scanning
    const stopScanner = () => {
        qrBackupLogger.info('Stopping QR scanner');

        if (requestRef.current) {
            cancelAnimationFrame(requestRef.current);
            requestRef.current = null;
        }

        if (videoRef.current?.srcObject) {
            try {
                const tracks = (videoRef.current.srcObject as MediaStream).getTracks();
                tracks.forEach((track) => {
                    track.stop();
                    qrBackupLogger.debug(`Stopped ${track.kind} track`);
                });
                videoRef.current.srcObject = null;
            } catch (error) {
                qrBackupLogger.error('Error stopping camera tracks:', error);
            }
        }

        setIsCameraActive(false);
        setIsScanning(false);
        setScanPaused(false);
        setIsProcessingChunk(false);
        isCurrentlyProcessing.current = false;
        isCameraActiveRef.current = false;
        scanPausedRef.current = false;
    };

    // Process each video frame to scan for QR codes
    const scanQRCode = () => {
        if (!videoRef.current || !canvasRef.current || !isCameraActiveRef.current || scanPausedRef.current || isCurrentlyProcessing.current) {
            qrBackupLogger.debug('Scanning stopped: missing refs, inactive camera, paused, or processing chunk');
            return;
        }

        const video = videoRef.current;
        const canvas = canvasRef.current;
        const context = canvas.getContext('2d');

        if (!context) {
            qrBackupLogger.error('Failed to get canvas context');
            requestRef.current = requestAnimationFrame(scanQRCode);
            return;
        }

        // Check if video is ready
        if (video.readyState !== video.HAVE_ENOUGH_DATA || video.videoWidth === 0 || video.videoHeight === 0) {
            // Video not ready yet, try again in the next frame
            requestRef.current = requestAnimationFrame(scanQRCode);
            return;
        }

        try {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;

            context.drawImage(video, 0, 0, canvas.width, canvas.height);

            const imageData = context.getImageData(0, 0, canvas.width, canvas.height);

            const qrCode = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: 'attemptBoth',
            });

            // If a QR code is found
            if (qrCode && qrCode.data) {
                qrBackupLogger.debug('QR Code detected:', qrCode.data.substring(0, 100) + '...');

                // Check if this chunk contains our backup header
                if (qrCode.data.includes('AVIAN_QR_CHUNK') || qrCode.data.includes('AVIAN_WALLET_BACKUP')) {
                    // Use ref to check processing status synchronously
                    if (isCurrentlyProcessing.current) {
                        qrBackupLogger.debug('Already processing a chunk, skipping');
                        requestRef.current = requestAnimationFrame(scanQRCode);
                        return;
                    }

                    // Immediately set processing flag in ref
                    isCurrentlyProcessing.current = true;
                    setIsProcessingChunk(true);

                    // Get chunk information first
                    const chunkInfo = BackupService.getQRChunkInfo(qrCode.data);

                    // Check duplicates using current ref values
                    const isDuplicateByIndex = chunkInfo && currentScannedIndices.current.has(chunkInfo.index);
                    const isDuplicateByContent = currentScannedChunks.current.includes(qrCode.data);

                    if (!isDuplicateByIndex && !isDuplicateByContent) {
                        qrBackupLogger.info(`Processing new chunk. Current state: ${currentScannedChunks.current.length} chunks, ${currentScannedIndices.current.size} indices`);

                        // Update refs immediately (synchronous)
                        const newChunk = qrCode.data;
                        currentScannedChunks.current = [...currentScannedChunks.current, newChunk];

                        if (chunkInfo) {
                            currentScannedIndices.current.add(chunkInfo.index);

                            // Set total expected chunks if not already set
                            if (totalExpectedChunks === null) {
                                setTotalExpectedChunks(chunkInfo.totalChunks);
                            }

                            qrBackupLogger.debug(`Added chunk ${chunkInfo.index} of ${chunkInfo.totalChunks}`);
                            qrBackupLogger.info(`Updated state: ${currentScannedChunks.current.length} chunks, ${currentScannedIndices.current.size} indices (${Array.from(currentScannedIndices.current).sort().join(', ')})`);
                        }

                        // Update React state to match refs
                        setScannedChunks([...currentScannedChunks.current]);
                        setScannedChunkIndices(new Set(currentScannedIndices.current));
                        setLastScannedChunk(newChunk);
                        // Keep scanning. A chunk already collected is rejected above by index and
                        // by content, so re-reading the code still on screen costs nothing — and
                        // pausing after every one made restoring an eight-part backup eight
                        // deliberate clicks. Scanning stops when the last chunk lands, or when the
                        // user stops it.
                        setDuplicateAlert(null); // Clear any duplicate alert

                        // Stop the animation frame to ensure scanning actually pauses
                        if (requestRef.current) {
                            cancelAnimationFrame(requestRef.current);
                            requestRef.current = null;
                        }

                        // Attempt to determine total chunks and progress
                        try {
                            if (chunkInfo) {
                                // Calculate progress based on current ref values
                                const currentChunkCount = currentScannedChunks.current.length;
                                const progress = (currentChunkCount / chunkInfo.totalChunks) * 100;
                                setScanProgress(progress);

                                qrBackupLogger.debug(`Progress: ${currentChunkCount}/${chunkInfo.totalChunks} (${progress.toFixed(1)}%)`);

                                // Show progress with specific chunk information
                                toast.info(`Scanned QR code ${chunkInfo.index} of ${chunkInfo.totalChunks}`, {
                                    description: currentChunkCount < chunkInfo.totalChunks ?
                                        'Show the next QR code' :
                                        'All chunks collected! Processing backup...',
                                });

                                // Check if we've completed scanning
                                if (currentChunkCount >= chunkInfo.totalChunks) {
                                    // We have all chunks, stop scanning and restore
                                    qrBackupLogger.info('All chunks collected, starting restore');
                                    // Reset processing flag
                                    isCurrentlyProcessing.current = false;
                                    setIsProcessingChunk(false);
                                    // Use the current ref values
                                    setTimeout(() => {
                                        handleCompleteRestore([...currentScannedChunks.current]);
                                    }, 100);
                                    return;
                                } else {
                                    // Reset processing flag after successful chunk processing
                                    isCurrentlyProcessing.current = false;
                                    setIsProcessingChunk(false);
                                }
                            } else {
                                qrBackupLogger.warn('Could not parse chunk info from QR data');
                                // This might be a single QR backup - try to process it immediately
                                toast.info('QR code scanned successfully', {
                                    description: 'Processing backup...',
                                });

                                // Reset processing flag
                                isCurrentlyProcessing.current = false;
                                setIsProcessingChunk(false);

                                // Try to restore immediately for single QR backups
                                setTimeout(() => {
                                    handleCompleteRestore([...currentScannedChunks.current]);
                                }, 100);
                            }
                        } catch (error) {
                            qrBackupLogger.error('Error parsing QR chunk info:', error);
                            // Fallback: try to process as single QR backup
                            toast.info('QR code scanned successfully', {
                                description: 'Processing backup...',
                            });

                            // Reset processing flag
                            isCurrentlyProcessing.current = false;
                            setIsProcessingChunk(false);

                            setTimeout(() => {
                                handleCompleteRestore([...currentScannedChunks.current]);
                            }, 100);
                        }
                    } else {
                        // Reset processing flag for duplicates
                        isCurrentlyProcessing.current = false;
                        setIsProcessingChunk(false);

                        qrBackupLogger.debug(`Chunk already scanned: ${chunkInfo ? `index ${chunkInfo.index}` : 'duplicate content'}, skipping`);
                        // Update alert instead of showing toast for duplicates
                        if (chunkInfo && isDuplicateByIndex) {
                            setDuplicateAlert(`QR code ${chunkInfo.index} already scanned. ${totalExpectedChunks ? `Still need ${totalExpectedChunks - currentScannedIndices.current.size} more codes.` : 'Scan a different QR code.'}`);
                        }
                    }
                } else {
                    qrBackupLogger.debug('QR code detected but not an Avian backup chunk');
                }
            }
        } catch (error) {
            qrBackupLogger.error('Error during QR scanning:', error);
        }

        // Continue scanning only if not paused and not processing
        if (!scanPausedRef.current && !isCurrentlyProcessing.current) {
            requestRef.current = requestAnimationFrame(scanQRCode);
        }
    };

    // Process all scanned chunks to restore the wallet
    const handleCompleteRestore = async (chunks: string[]) => {
        try {
            // Stop scanning
            stopScanner();
            setIsRestoring(true);

            // Attempt to combine and restore the backup
            const combinedBackup = await BackupService.combineQRChunks(chunks);

            // Parse the backup file
            const backupFile = BackupService.convertBase64ToFile(combinedBackup, 'restored-backup.json');

            // Try to parse the backup (with password if provided)
            const { backup, validation } = await BackupService.parseBackupFile(
                backupFile,
                restorePassword.length > 0 ? restorePassword : undefined,
            );

            // Check if backup is valid
            if (!validation.isValid) {
                setRestoreError('Invalid backup format: ' + validation.errors.join(', '));
                return;
            }

            // Restore the backup with default options
            await BackupService.restoreFromBackup(
                backup,
                {
                    includeWallets: true,
                    includeAddressBook: true,
                    includeSettings: true,
                    includeTransactions: true,
                    includeSecurityAudit: true,
                    includeWatchedAddresses: true,
                    overwriteExisting: false,
                },
                (step, progress) => {
                    setScanProgress(progress);
                },
            );

            // Success!
            toast.success('Wallet restored successfully', {
                description: `Restored ${validation.walletsCount} wallet(s) from QR backup`,
            });

            // Signal completion to the host (navigate home, or close the modal + reload).
            onRestored?.();
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';

            // Check for password-related errors
            if (errorMessage.includes('password') || errorMessage.includes('decrypt')) {
                setRestoreError('Invalid password for encrypted backup');
            } else {
                setRestoreError(errorMessage);
            }

            toast.error('Failed to restore wallet', {
                description: errorMessage,
            });
        } finally {
            setIsRestoring(false);
        }
    };

    // Clean up resources when component unmounts
    useEffect(() => {
        return () => {
            if (requestRef.current) {
                cancelAnimationFrame(requestRef.current);
            }
            stopScanner();
        };
    }, []);

    // Debug state changes
    useEffect(() => {
        qrBackupLogger.info(`State update - Chunks: ${scannedChunks.length}, Indices: ${scannedChunkIndices.size} (${Array.from(scannedChunkIndices).sort().join(', ')}), Paused: ${scanPaused}, Processing: ${isProcessingChunk}`);
        qrBackupLogger.info(`Ref values - Chunks: ${currentScannedChunks.current.length}, Indices: ${currentScannedIndices.current.size} (${Array.from(currentScannedIndices.current).sort().join(', ')}), Processing: ${isCurrentlyProcessing.current}, CameraActive: ${isCameraActiveRef.current}, Paused: ${scanPausedRef.current}`);
    }, [scannedChunks.length, scannedChunkIndices.size, scanPaused, isProcessingChunk]);

    return (
        <div className="space-y-6">
            <Card>
                        <CardHeader>
                            <CardTitle>Transfer Wallet with QR Codes</CardTitle>
                            <p className="text-muted-foreground">
                                Generate QR codes to backup your wallet or scan QR codes to restore from another device
                            </p>
                        </CardHeader>
                        <CardContent>
                            <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'backup' | 'restore')}>
                                {mode === 'both' && (
                                    <TabsList className="grid w-full grid-cols-2">
                                        <TabsTrigger value="backup">Generate Backup</TabsTrigger>
                                        <TabsTrigger value="restore">Restore from QR</TabsTrigger>
                                    </TabsList>
                                )}

                                {/* Backup Tab */}
                                {mode !== 'restore-only' && (
                                <TabsContent value="backup" className="space-y-6 mt-6">
                                    {backupChunks.length > 0 ? (
                                        <div className="space-y-6">
                                            <div className="flex flex-col items-center">
                                                <div className="bg-card p-6 rounded-lg shadow-sm border">
                                                    <QRCodeSVG
                                                        value={backupChunks[currentChunkIndex]}
                                                        size={isMobile ? 280 : 320}
                                                        level="L"
                                                        includeMargin
                                                        bgColor="#FFFFFF"
                                                        fgColor="#000000"
                                                    />
                                                </div>

                                                {backupChunks.length > 1 && (
                                                    <div className="mt-6 text-center space-y-4 w-full max-w-md">
                                                        <div>
                                                            <p className="text-lg font-medium">
                                                                QR Code {currentChunkIndex + 1} of {backupChunks.length}
                                                            </p>
                                                            <p className="text-sm text-muted-foreground">
                                                                Make sure to scan all {backupChunks.length} QR codes for complete backup
                                                            </p>
                                                        </div>

                                                        <div className="flex justify-center">
                                                            <div className="grid grid-cols-5 gap-2 max-w-[250px]">
                                                                {backupChunks.map((_, index) => (
                                                                    <div
                                                                        key={index}
                                                                        className={`w-10 h-10 rounded text-sm font-medium flex items-center justify-center border cursor-pointer transition-colors ${index === currentChunkIndex
                                                                            ? 'bg-primary text-primary-foreground border-primary'
                                                                            : 'bg-muted text-muted-foreground border-border hover:bg-muted/80'
                                                                            }`}
                                                                        onClick={() => setCurrentChunkIndex(index)}
                                                                        title={`View QR Code ${index + 1}`}
                                                                    >
                                                                        {index + 1}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>

                                                        <div className="flex gap-3">
                                                            <Button
                                                                variant="outline"
                                                                onClick={() => setCurrentChunkIndex((idx) => Math.max(0, idx - 1))}
                                                                disabled={currentChunkIndex === 0}
                                                                className="flex-1"
                                                            >
                                                                <ArrowLeft className="h-4 w-4 mr-2" /> Previous
                                                            </Button>
                                                            <Button
                                                                variant="outline"
                                                                onClick={() =>
                                                                    setCurrentChunkIndex((idx) => Math.min(backupChunks.length - 1, idx + 1))
                                                                }
                                                                disabled={currentChunkIndex === backupChunks.length - 1}
                                                                className="flex-1"
                                                            >
                                                                Next <ArrowRight className="h-4 w-4 ml-2" />
                                                            </Button>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>

                                            <Alert>
                                                <AlertDescription>
                                                    Scan this QR code with your other device to transfer your wallet.
                                                    {backupChunks.length > 1 && ' Navigate through all QR codes for complete backup.'}
                                                    QR codes are optimized for mobile scanning with high contrast and low error correction.
                                                </AlertDescription>
                                            </Alert>

                                            <div className="space-y-3">
                                                <Button
                                                    onClick={downloadAllQRCodes}
                                                    variant="default"
                                                    className="w-full"
                                                    size="lg"
                                                >
                                                    <Download className="h-4 w-4 mr-2" />
                                                    Download QR Code{backupChunks.length > 1 ? 's' : ''}
                                                    {backupChunks.length > 1 && ` (${backupChunks.length} files)`}
                                                </Button>

                                                <Button
                                                    variant="outline"
                                                    onClick={() => {
                                                        setBackupChunks([]);
                                                        setCurrentChunkIndex(0);
                                                    }}
                                                    className="w-full"
                                                >
                                                    <ChevronLeft className="h-4 w-4 mr-2" /> Generate New Backup
                                                </Button>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="space-y-6">
                                            <Alert>
                                                <AlertDescription>
                                                    This will generate QR codes containing your wallet keys and addresses. For security, consider
                                                    adding a password. QR codes are optimized for mobile scanning and only include essential wallet data.
                                                </AlertDescription>
                                            </Alert>

                                            <div className="space-y-4">
                                                <div className="space-y-2">
                                                    <Label htmlFor="backupPassword">Backup Password (Optional)</Label>
                                                    <div className="relative">
                                                        <Input
                                                            id="backupPassword"
                                                            type={showBackupPassword ? "text" : "password"}
                                                            value={backupPassword}
                                                            onChange={(e) => setBackupPassword(e.target.value)}
                                                            placeholder="Enter a password to encrypt your backup"
                                                            className="pr-10"
                                                        />
                                                        <Button
                                                            type="button"
                                                            variant="ghost"
                                                            size="sm"
                                                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                                            onClick={() => setShowBackupPassword(!showBackupPassword)}
                                                        >
                                                            {showBackupPassword ? (
                                                                <EyeOff className="h-4 w-4 text-muted-foreground" />
                                                            ) : (
                                                                <Eye className="h-4 w-4 text-muted-foreground" />
                                                            )}
                                                        </Button>
                                                    </div>
                                                    <p className="text-sm text-muted-foreground">
                                                        {backupPassword.length > 0
                                                            ? "You'll need this password when restoring"
                                                            : 'Without a password, anyone who scans your QR code can access your wallet'}
                                                    </p>
                                                </div>

                                                <Button onClick={generateBackupQR} disabled={isGenerating} className="w-full" size="lg">
                                                    {isGenerating
                                                        ? 'Generating...'
                                                        : 'Generate Wallet Backup QR Codes'}
                                                </Button>
                                            </div>
                                        </div>
                                    )}
                                </TabsContent>
                                )}

                                {/* Restore Tab */}
                                {mode !== 'backup-only' && (
                                <TabsContent value="restore" className="space-y-6 mt-6">
                                    {isCameraActive ? (
                                        <div className="space-y-6">
                                            <div className="relative">
                                                <div className="aspect-square w-full max-w-[400px] mx-auto overflow-hidden rounded-lg border bg-muted">
                                                    <video
                                                        ref={videoRef}
                                                        className="h-full w-full object-cover"
                                                        playsInline
                                                        muted
                                                        autoPlay
                                                        webkit-playsinline="true"
                                                    />
                                                </div>
                                                <canvas ref={canvasRef} className="hidden" />
                                            </div>

                                            <div className="space-y-4">
                                                <div className="flex justify-between text-sm">
                                                    <span className="font-medium">Scanning</span>
                                                    <span className="font-medium">{Math.round(scanProgress)}%</span>
                                                </div>
                                                <Progress value={scanProgress} className="h-3" />

                                                {/* QR Code Status Grid */}
                                                {totalExpectedChunks && totalExpectedChunks > 1 && (
                                                    <div className="p-4 bg-muted/50 rounded-lg">
                                                        <p className="text-sm font-medium mb-3 text-center">
                                                            QR Code Status ({scannedChunkIndices.size} of {totalExpectedChunks})
                                                        </p>
                                                        <div className="grid grid-cols-5 gap-2 max-w-[250px] mx-auto">
                                                            {Array.from({ length: totalExpectedChunks }, (_, index) => {
                                                                const chunkNumber = index + 1;
                                                                const isScanned = scannedChunkIndices.has(chunkNumber);
                                                                return (
                                                                    <div
                                                                        key={chunkNumber}
                                                                        className={`w-10 h-10 rounded text-sm font-medium flex items-center justify-center border ${isScanned
                                                                            ? 'bg-primary text-white border-primary/30'
                                                                            : 'bg-muted text-muted-foreground border-border'
                                                                            }`}
                                                                        title={`QR Code ${chunkNumber} - ${isScanned ? 'Scanned' : 'Not scanned'}`}
                                                                    >
                                                                        {chunkNumber}
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                        <p className="text-xs text-center mt-3 text-muted-foreground">
                                                            Green = Scanned, Gray = Still needed
                                                        </p>
                                                    </div>
                                                )}

                                                {/* Duplicate Alert */}
                                                {duplicateAlert && (
                                                    <Alert>
                                                        <AlertDescription className="text-center">
                                                            {duplicateAlert}
                                                        </AlertDescription>
                                                    </Alert>
                                                )}

                                                <p className="text-sm text-center text-muted-foreground">
                                                    {scannedChunks.length > 0
                                                        ? totalExpectedChunks && scannedChunkIndices.size < totalExpectedChunks
                                                            ? `Scanned ${scannedChunkIndices.size} of ${totalExpectedChunks} QR codes — show the next one`
                                                            : `Scanned ${scannedChunks.length} QR code${scannedChunks.length !== 1 ? 's' : ''}`
                                                        : 'Position your camera over the QR code'}
                                                </p>
                                            </div>

                                            {scannedChunks.length > 0 && (
                                                <Alert>
                                                    <AlertDescription>
                                                        {(() => {
                                                            const lastChunk = lastScannedChunk;
                                                            if (lastChunk) {
                                                                const chunkInfo = BackupService.getQRChunkInfo(lastChunk);
                                                                if (chunkInfo) {
                                                                    if (scannedChunkIndices.size >= chunkInfo.totalChunks) {
                                                                        return 'All QR codes scanned! Processing backup...';
                                                                    }

                                                                    // Show which specific QR codes are still needed
                                                                    const missingChunks = [];
                                                                    for (let i = 1; i <= chunkInfo.totalChunks; i++) {
                                                                        if (!scannedChunkIndices.has(i)) {
                                                                            missingChunks.push(i);
                                                                        }
                                                                    }

                                                                    if (missingChunks.length > 0) {
                                                                        const missingText = missingChunks.length <= 3
                                                                            ? missingChunks.join(', ')
                                                                            : `${missingChunks.slice(0, 3).join(', ')} and ${missingChunks.length - 3} more`;
                                                                        return `Successfully scanned QR code ${chunkInfo.index}! Still need QR code${missingChunks.length > 1 ? 's' : ''}: ${missingText}. Click "Continue Scanning" to scan another code.`;
                                                                    }
                                                                }
                                                            }
                                                            return 'Successfully scanned QR code. Click "Continue Scanning" to scan the next QR code.';
                                                        })()}
                                                    </AlertDescription>
                                                </Alert>
                                            )}

                                            {restoreError && (
                                                <Alert variant="destructive">
                                                    <AlertCircle className="h-4 w-4" />
                                                    <AlertDescription>{restoreError}</AlertDescription>
                                                </Alert>
                                            )}

                                            {restoreError && restoreError.includes('password') && (
                                                <div className="space-y-3">
                                                    <Label htmlFor="restorePassword">Backup Password</Label>
                                                    <div className="relative">
                                                        <Input
                                                            id="restorePassword"
                                                            type={showRestorePassword ? "text" : "password"}
                                                            value={restorePassword}
                                                            onChange={(e) => setRestorePassword(e.target.value)}
                                                            placeholder="Enter backup password"
                                                            className="pr-10"
                                                        />
                                                        <Button
                                                            type="button"
                                                            variant="ghost"
                                                            size="sm"
                                                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                                            onClick={() => setShowRestorePassword(!showRestorePassword)}
                                                        >
                                                            {showRestorePassword ? (
                                                                <EyeOff className="h-4 w-4 text-muted-foreground" />
                                                            ) : (
                                                                <Eye className="h-4 w-4 text-muted-foreground" />
                                                            )}
                                                        </Button>
                                                    </div>
                                                    <Button
                                                        className="w-full"
                                                        disabled={!restorePassword.trim() || isRestoring}
                                                        onClick={() => handleCompleteRestore(scannedChunks)}
                                                        size="lg"
                                                    >
                                                        {isRestoring ? 'Restoring...' : 'Try Again with Password'}
                                                    </Button>
                                                </div>
                                            )}

                                            <div className="space-y-3">
                                                <div className="flex gap-3">
                                                    <Button variant="outline" onClick={stopScanner} className="flex-1">
                                                        <X className="h-4 w-4 mr-2" /> Stop Scanner
                                                    </Button>

                                                    <Button
                                                        variant="outline"
                                                        onClick={() => {
                                                            // Reset and restart the scanner
                                                            stopScanner();
                                                            setTimeout(startScanner, 500);
                                                        }}
                                                        className="flex-1"
                                                    >
                                                        <ArrowLeft className="h-4 w-4 mr-2" /> Restart
                                                    </Button>
                                                </div>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="space-y-6">
                                            <Alert>
                                                <AlertDescription>
                                                    To restore your wallet from a QR code backup, you'll need to scan the QR code
                                                    from your other device. Hold your phone 8-12 inches away and ensure good lighting for best results.
                                                </AlertDescription>
                                            </Alert>

                                            {restoreError && (
                                                <Alert variant="destructive">
                                                    <AlertCircle className="h-4 w-4" />
                                                    <AlertDescription>{restoreError}</AlertDescription>
                                                </Alert>
                                            )}

                                            {!isScanning && (
                                                <div className="space-y-4">
                                                    <div className="space-y-2">
                                                        <Label htmlFor="restorePassword">Backup Password (if encrypted)</Label>
                                                        <div className="relative">
                                                            <Input
                                                                id="restorePassword"
                                                                type={showRestorePassword ? "text" : "password"}
                                                                value={restorePassword}
                                                                onChange={(e) => setRestorePassword(e.target.value)}
                                                                placeholder="Enter backup password (if needed)"
                                                                className="pr-10"
                                                            />
                                                            <Button
                                                                type="button"
                                                                variant="ghost"
                                                                size="sm"
                                                                className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                                                onClick={() => setShowRestorePassword(!showRestorePassword)}
                                                            >
                                                                {showRestorePassword ? (
                                                                    <EyeOff className="h-4 w-4 text-muted-foreground" />
                                                                ) : (
                                                                    <Eye className="h-4 w-4 text-muted-foreground" />
                                                                )}
                                                            </Button>
                                                        </div>
                                                    </div>

                                                    <Button onClick={startScanner} className="w-full" size="lg">
                                                        <Camera className="h-4 w-4 mr-2" /> Start Camera Scan
                                                    </Button>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </TabsContent>
                                )}
                            </Tabs>
                        </CardContent>
            </Card>
        </div>
    );
}
