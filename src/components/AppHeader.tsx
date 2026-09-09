'use client';

import React from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { ArrowLeft, Settings, Menu, Wallet, Bug, Code, Eye, Shield, Bell, Archive, PlugZap, HelpCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useSidebar } from '@/components/ui/sidebar';

interface AppHeaderProps {
    title?: string;
    subtitle?: string;
    showBackButton?: boolean;
    customBackAction?: () => void;
    icon?: React.ComponentType<React.ComponentProps<'svg'>>;
    actions?: React.ReactNode;
}

const getPageInfo = (pathname: string) => {
    const pathSegments = pathname.split('/').filter(Boolean);

    // Map routes to their display information
    const routeMap: Record<string, { title: string; icon: React.ComponentType<React.ComponentProps<'svg'>>; subtitle?: string }> = {
        '': { title: 'Avian FlightDeck', icon: Wallet, subtitle: 'Your cryptocurrency wallet' },
        'settings': { title: 'Settings', icon: Settings, subtitle: 'Configure your wallet' },
        'settings/wallet': { title: 'Wallet Management', icon: Wallet, subtitle: 'Manage wallets, addresses, and encryption' },
        'settings/security': { title: 'Security Settings', icon: Shield, subtitle: 'Authentication, biometrics, and security features' },
        'settings/backup': { title: 'Backup & Recovery', icon: Archive, subtitle: 'Export, import, and backup your wallet data' },
        'settings/notifications': { title: 'Notifications', icon: Bell, subtitle: 'Configure alerts and notification preferences' },
        'settings/advanced': { title: 'Advanced Settings', icon: Settings, subtitle: 'Developer tools, logs, and advanced configuration' },
        'settings/advanced/logs': { title: 'Debug Logs', icon: Bug, subtitle: 'View application logs and debugging information' },
        'settings/advanced/messages': { title: 'Message Utilities', icon: Code, subtitle: 'Sign and verify messages with your wallet' },
        'settings/connected-sites': { title: 'Connected Sites', icon: PlugZap, subtitle: 'Review and revoke dApps connected to this wallet' },
        'settings/watched-addresses': { title: 'Watched Addresses', icon: Eye, subtitle: 'Monitor addresses without importing private keys' },
        'settings/help': { title: 'Help & Support', icon: HelpCircle, subtitle: 'Documentation, support, and app information' },
        'onboarding': { title: 'Setup Wallet', icon: Wallet, subtitle: 'Create or restore your wallet' },
        'terms': { title: 'Terms of Service', icon: HelpCircle, subtitle: 'Legal terms and conditions' },
        'about': { title: 'About Avian', icon: HelpCircle, subtitle: 'Features, FAQ, and information' },
    };

    const routeKey = pathSegments.join('/');
    return routeMap[routeKey] || { title: 'Avian FlightDeck', icon: Wallet };
};

export function AppHeader({
    title,
    subtitle,
    showBackButton = true,
    customBackAction,
    icon: CustomIcon,
    actions
}: AppHeaderProps) {
    const router = useRouter();
    const pathname = usePathname();
    const { toggleSidebar, isMobile } = useSidebar();

    const pageInfo = getPageInfo(pathname);
    const displayTitle = title || pageInfo.title;
    const displaySubtitle = subtitle || pageInfo.subtitle;
    const IconComponent = CustomIcon || pageInfo.icon;

    const handleBack = () => {
        if (customBackAction) {
            customBackAction();
        } else {
            router.back();
        }
    };

    const shouldShowBackButton = showBackButton && pathname !== '/';

    return (
        <header className="sticky top-0 z-40 border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
            <div className="container flex h-16 max-w-screen-2xl items-center px-4">
                <div className="flex items-center gap-2 shrink-0">
                    {/* Mobile sidebar toggle */}
                    {isMobile && (
                        <Button
                            variant="ghost"
                            size="sm"
                            className="md:hidden p-2"
                            onClick={toggleSidebar}
                        >
                            <Menu className="h-4 w-4" />
                        </Button>
                    )}

                    {/* Back button */}
                    {shouldShowBackButton && (
                        <Button variant="ghost" size="sm" onClick={handleBack} className="p-2">
                            <ArrowLeft className="h-4 w-4" />
                        </Button>
                    )}
                </div>

                {/* Title and Icon */}
                <div className="flex items-center gap-3 flex-1 min-w-0 px-2">
                    <IconComponent className="h-5 w-5 md:h-6 md:w-6 text-primary shrink-0" />
                    <div className="flex flex-col min-w-0 flex-1">
                        <h1 className="text-base md:text-lg font-semibold leading-tight truncate">
                            {displayTitle}
                        </h1>
                        {displaySubtitle && (
                            <p className="text-xs text-muted-foreground leading-tight truncate hidden sm:block">
                                {displaySubtitle}
                            </p>
                        )}
                    </div>
                </div>

                {/* Actions */}
                {actions && (
                    <div className="flex items-center gap-1 shrink-0">
                        {actions}
                    </div>
                )}
            </div>
        </header>
    );
}
