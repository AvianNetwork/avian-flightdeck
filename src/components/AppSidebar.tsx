'use client';

import React from 'react';
import { useRouter, usePathname } from 'next/navigation';
import {
    Wallet,
    Settings,
    Shield,
    Archive,
    Bell,
    PlugZap,
    HelpCircle,
    Bug,
    Code,
    Eye,
    ChevronRight,
    Home
} from 'lucide-react';
import { WalletSelector } from './WalletSelector';
import {
    Sidebar,
    SidebarContent,
    SidebarFooter,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarMenuSub,
    SidebarMenuSubButton,
    SidebarMenuSubItem,
    useSidebar,
} from '@/components/ui/sidebar';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

interface NavItem {
    title: string;
    url: string;
    icon: React.ComponentType<React.ComponentProps<'svg'>>;
    badge?: string;
    items?: NavItem[];
}

const navigationItems: NavItem[] = [
    {
        title: 'Wallet',
        url: '/',
        icon: Home,
    },
    {
        title: 'Settings',
        url: '/settings',
        icon: Settings,
        items: [
            {
                title: 'Wallet Management',
                url: '/settings/wallet',
                icon: Wallet,
            },
            {
                title: 'Security Settings',
                url: '/settings/security',
                icon: Shield,
            },
            {
                title: 'Backup & Recovery',
                url: '/settings/backup',
                icon: Archive,
            },
            {
                title: 'Connected Sites',
                url: '/settings/connected-sites',
                icon: PlugZap,
            },
            {
                title: 'Notifications',
                url: '/settings/notifications',
                icon: Bell,
            },
            {
                title: 'Advanced Settings',
                url: '/settings/advanced',
                icon: Settings,
                items: [
                    {
                        title: 'Debug Logs',
                        url: '/settings/advanced',
                        icon: Bug,
                    },
                    {
                        title: 'Message Utilities',
                        url: '/settings/advanced',
                        icon: Code,
                    },
                    {
                        title: 'Watched Addresses',
                        url: '/settings/watched-addresses',
                        icon: Eye,
                    },
                ],
            },
            {
                title: 'Help & Support',
                url: '/settings/help',
                icon: HelpCircle,
            },
        ],
    },
];

interface AppSidebarProps {
    children?: React.ReactNode;
}

export function AppSidebar({ children, ...props }: AppSidebarProps & React.ComponentProps<typeof Sidebar>) {
    const router = useRouter();
    const pathname = usePathname();
    const { state } = useSidebar();

    const handleNavigation = (url: string) => {
        router.push(url);
    };

    const isActive = (url: string) => {
        if (url === '/') {
            return pathname === '/';
        }
        return pathname.startsWith(url);
    };

    const renderNavItem = (item: NavItem, level = 0) => {
        const hasSubItems = item.items && item.items.length > 0;
        const isItemActive = isActive(item.url);

        if (hasSubItems) {
            return (
                <Collapsible key={item.title} defaultOpen={item.title === 'Settings' || isItemActive} className="group/collapsible">
                    <SidebarMenuItem>
                        <CollapsibleTrigger asChild>
                            <SidebarMenuButton
                                tooltip={item.title}
                                isActive={isItemActive}
                                className="w-full"
                            >
                                <item.icon className="h-4 w-4" />
                                <span>{item.title}</span>
                                <ChevronRight className="ml-auto h-4 w-4 transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                            </SidebarMenuButton>
                        </CollapsibleTrigger>
                        <CollapsibleContent>
                            <SidebarMenuSub>
                                {item.items?.map((subItem) => (
                                    <SidebarMenuSubItem key={subItem.title}>
                                        <SidebarMenuSubButton
                                            onClick={() => handleNavigation(subItem.url)}
                                            isActive={isActive(subItem.url)}
                                            className="cursor-pointer"
                                        >
                                            <subItem.icon className="h-4 w-4" />
                                            <span>{subItem.title}</span>
                                        </SidebarMenuSubButton>
                                    </SidebarMenuSubItem>
                                ))}
                            </SidebarMenuSub>
                        </CollapsibleContent>
                    </SidebarMenuItem>
                </Collapsible>
            );
        }

        return (
            <SidebarMenuItem key={item.title}>
                <SidebarMenuButton
                    onClick={() => handleNavigation(item.url)}
                    tooltip={item.title}
                    isActive={isItemActive}
                    className="cursor-pointer"
                >
                    <item.icon className="h-4 w-4" />
                    <span>{item.title}</span>
                    {item.badge && (
                        <span className="ml-auto text-xs bg-primary text-primary-foreground px-1.5 py-0.5 rounded-full">
                            {item.badge}
                        </span>
                    )}
                </SidebarMenuButton>
            </SidebarMenuItem>
        );
    };

    return (
        <Sidebar collapsible="icon" {...props}>
            <SidebarHeader>
                <SidebarMenu>
                    <SidebarMenuItem>
                        <SidebarMenuButton
                            size="lg"
                            className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
                        >
                            <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-gradient-to-br from-[#34F5C6] to-[#17A7B6] text-[#06232A]">
                                {/* Aircraft reference symbol — the flight-deck instrument mark, matching the app icon */}
                                <svg
                                    className="size-6"
                                    viewBox="0 0 64 64"
                                    fill="none"
                                    stroke="currentColor"
                                    strokeWidth="4.5"
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                >
                                    <line x1="9" y1="32" x2="23" y2="32" />
                                    <line x1="41" y1="32" x2="55" y2="32" />
                                    <line x1="23" y1="32" x2="27" y2="39" />
                                    <line x1="41" y1="32" x2="37" y2="39" />
                                    <circle cx="32" cy="32" r="5" />
                                </svg>
                            </div>
                            <div className="grid flex-1 text-left text-sm leading-tight">
                                <span className="truncate font-semibold">Avian FlightDeck</span>
                                <span className="truncate text-xs">Cryptocurrency Wallet</span>
                            </div>
                        </SidebarMenuButton>
                    </SidebarMenuItem>
                </SidebarMenu>
            </SidebarHeader>

            <SidebarContent>
                <SidebarGroup>
                    <SidebarGroupLabel>Navigation</SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu>
                            {navigationItems.map(renderNavItem)}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>
            </SidebarContent>

            <SidebarFooter>
                <WalletSelector />
                {children}
            </SidebarFooter>
        </Sidebar>
    );
}
