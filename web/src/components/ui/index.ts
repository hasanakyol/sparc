// Core UI Components - Basic building blocks
export { Button } from './button';
export { Input } from './input';
export { Label } from './label';
export { Textarea } from './textarea';
export { Checkbox } from './checkbox';
export { RadioGroup, RadioGroupItem } from './radio-group';
export { Switch } from './switch';
export { Slider } from './slider';
export { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './select';
export { Badge } from './badge';
export { Avatar, AvatarFallback, AvatarImage } from './avatar';
export { Separator } from './separator';
export { Progress } from './progress';
export { Skeleton } from './skeleton';

// Layout Components
export { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './card';
export { Tabs, TabsContent, TabsList, TabsTrigger } from './tabs';
export { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from './accordion';
export { Collapsible, CollapsibleContent, CollapsibleTrigger } from './collapsible';
export { ScrollArea, ScrollBar } from './scroll-area';
export { ResizableHandle, ResizablePanel, ResizablePanelGroup } from './resizable';

// Navigation Components
export { NavigationMenu, NavigationMenuContent, NavigationMenuItem, NavigationMenuLink, NavigationMenuList, NavigationMenuTrigger } from './navigation-menu';
export { Menubar, MenubarContent, MenubarItem, MenubarMenu, MenubarSeparator, MenubarShortcut, MenubarSub, MenubarSubContent, MenubarSubTrigger, MenubarTrigger } from './menubar';
export { Breadcrumb, BreadcrumbEllipsis, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from './breadcrumb';
export { Pagination, PaginationContent, PaginationEllipsis, PaginationItem, PaginationLink, PaginationNext, PaginationPrevious } from './pagination';

// Overlay Components
export { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from './dialog';
export { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from './alert-dialog';
export { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetTrigger } from './sheet';
export { Popover, PopoverContent, PopoverTrigger } from './popover';
export { HoverCard, HoverCardContent, HoverCardTrigger } from './hover-card';
export { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './tooltip';
export { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuShortcut, DropdownMenuSub, DropdownMenuSubContent, DropdownMenuSubTrigger, DropdownMenuTrigger } from './dropdown-menu';
export { ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuLabel, ContextMenuSeparator, ContextMenuShortcut, ContextMenuSub, ContextMenuSubContent, ContextMenuSubTrigger, ContextMenuTrigger } from './context-menu';

// Feedback Components
export { Alert, AlertDescription, AlertTitle } from './alert';
export { Toast, ToastAction, ToastClose, ToastDescription, ToastProvider, ToastTitle, ToastViewport } from './toast';
export { useToast } from './use-toast';

// Form Components
export { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from './form';
export { Calendar } from './calendar';
export { DatePicker } from './date-picker';
export { TimePicker } from './time-picker';
export { DateRangePicker } from './date-range-picker';
export { Combobox } from './combobox';
export { MultiSelect } from './multi-select';
export { FileUpload } from './file-upload';
export { ImageUpload } from './image-upload';

// Data Display Components
export { Table, TableBody, TableCaption, TableCell, TableFooter, TableHead, TableHeader, TableRow } from './table';
export { DataTable } from './data-table';
export { VirtualizedTable } from './virtualized-table';
export { TreeView, TreeViewItem } from './tree-view';
export { Timeline, TimelineItem } from './timeline';
export { StatsCard } from './stats-card';
export { MetricCard } from './metric-card';
export { StatusIndicator } from './status-indicator';
export { LoadingSpinner } from './loading-spinner';
export { EmptyState } from './empty-state';
export { ErrorBoundary } from './error-boundary';

// Chart Components
export { LineChart } from './charts/line-chart';
export { BarChart } from './charts/bar-chart';
export { PieChart } from './charts/pie-chart';
export { AreaChart } from './charts/area-chart';
export { DonutChart } from './charts/donut-chart';
export { GaugeChart } from './charts/gauge-chart';
export { HeatmapChart } from './charts/heatmap-chart';
export { TimeSeriesChart } from './charts/time-series-chart';

// Layout & Grid Components
export { Grid, GridItem } from './grid';
export { Stack, HStack, VStack } from './stack';
export { Container } from './container';
export { Flex } from './flex';
export { Box } from './box';
export { Divider } from './divider';
export { Spacer } from './spacer';

// Media Components
export { VideoPlayer } from './video-player';
export { VideoGrid } from './video-grid';
export { VideoThumbnail } from './video-thumbnail';
export { VideoControls } from './video-controls';
export { VideoTimeline } from './video-timeline';
export { CameraFeed } from './camera-feed';
export { ImageViewer } from './image-viewer';
export { QRCodeGenerator } from './qr-code-generator';
export { QRCodeScanner } from './qr-code-scanner';

// Access Control Specialized Components
export { DoorStatusCard } from './access-control/door-status-card';
export { AccessEventList } from './access-control/access-event-list';
export { AccessGroupManager } from './access-control/access-group-manager';
export { CredentialManager } from './access-control/credential-manager';
export { FloorPlan } from './access-control/floor-plan';
export { DoorController } from './access-control/door-controller';
export { AccessScheduler } from './access-control/access-scheduler';
export { EmergencyControls } from './access-control/emergency-controls';
export { OfflineIndicator } from './access-control/offline-indicator';
export { AccessPermissionMatrix } from './access-control/access-permission-matrix';

// Video Management Specialized Components
export { CameraGrid } from './video/camera-grid';
export { CameraManager } from './video/camera-manager';
export { VideoRecordingList } from './video/video-recording-list';
export { VideoExportDialog } from './video/video-export-dialog';
export { PrivacyMaskEditor } from './video/privacy-mask-editor';
export { VideoAnalytics } from './video/video-analytics';
export { LiveStreamViewer } from './video/live-stream-viewer';
export { VideoPlayback } from './video/video-playback';
export { CameraStatusPanel } from './video/camera-status-panel';
export { VideoSearchFilters } from './video/video-search-filters';

// Dashboard Components
export { DashboardWidget } from './dashboard/dashboard-widget';
export { WidgetContainer } from './dashboard/widget-container';
export { DashboardGrid } from './dashboard/dashboard-grid';
export { KPIWidget } from './dashboard/kpi-widget';
export { AlertsWidget } from './dashboard/alerts-widget';
export { SystemStatusWidget } from './dashboard/system-status-widget';
export { OccupancyWidget } from './dashboard/occupancy-widget';
export { RecentEventsWidget } from './dashboard/recent-events-widget';
export { WeatherWidget } from './dashboard/weather-widget';
export { QuickActionsWidget } from './dashboard/quick-actions-widget';

// Tenant & Organization Components
export { TenantSelector } from './tenant/tenant-selector';
export { OrganizationTree } from './tenant/organization-tree';
export { SiteManager } from './tenant/site-manager';
export { BuildingSelector } from './tenant/building-selector';
export { FloorSelector } from './tenant/floor-selector';
export { TenantSettings } from './tenant/tenant-settings';
export { ResourceQuotaDisplay } from './tenant/resource-quota-display';

// User Management Components
export { UserProfile } from './user/user-profile';
export { UserRoleSelector } from './user/user-role-selector';
export { PermissionMatrix } from './user/permission-matrix';
export { UserActivityLog } from './user/user-activity-log';
export { UserPreferences } from './user/user-preferences';
export { TeamMemberList } from './user/team-member-list';

// Visitor Management Components
export { VisitorCheckIn } from './visitor/visitor-check-in';
export { VisitorBadgePrint } from './visitor/visitor-badge-print';
export { VisitorList } from './visitor/visitor-list';
export { HostNotification } from './visitor/host-notification';
export { VisitorPreRegistration } from './visitor/visitor-pre-registration';
export { WatchlistCheck } from './visitor/watchlist-check';
export { EvacuationList } from './visitor/evacuation-list';

// Environmental Monitoring Components
export { EnvironmentalSensorCard } from './environmental/environmental-sensor-card';
export { TemperatureGauge } from './environmental/temperature-gauge';
export { HumidityGauge } from './environmental/humidity-gauge';
export { EnvironmentalAlerts } from './environmental/environmental-alerts';
export { SensorStatusGrid } from './environmental/sensor-status-grid';
export { EnvironmentalTrends } from './environmental/environmental-trends';

// Analytics Components
export { AnalyticsDashboard } from './analytics/analytics-dashboard';
export { OccupancyAnalytics } from './analytics/occupancy-analytics';
export { SecurityAnalytics } from './analytics/security-analytics';
export { BehavioralAnalytics } from './analytics/behavioral-analytics';
export { PredictiveAlerts } from './analytics/predictive-alerts';
export { TrendAnalysis } from './analytics/trend-analysis';
export { AnomalyDetection } from './analytics/anomaly-detection';

// Device Management Components
export { DeviceDiscovery } from './device/device-discovery';
export { DeviceStatusGrid } from './device/device-status-grid';
export { DeviceConfiguration } from './device/device-configuration';
export { FirmwareManager } from './device/firmware-manager';
export { DeviceDiagnostics } from './device/device-diagnostics';
export { DeviceHealthMonitor } from './device/device-health-monitor';
export { NetworkTopology } from './device/network-topology';

// Reporting Components
export { ReportBuilder } from './reporting/report-builder';
export { ReportViewer } from './reporting/report-viewer';
export { ReportScheduler } from './reporting/report-scheduler';
export { ComplianceReports } from './reporting/compliance-reports';
export { AuditReports } from './reporting/audit-reports';
export { ExportOptions } from './reporting/export-options';
export { ReportTemplates } from './reporting/report-templates';

// Mobile Components
export { MobileCredentialEnrollment } from './mobile/mobile-credential-enrollment';
export { MobileDeviceManager } from './mobile/mobile-device-manager';
export { NfcReader } from './mobile/nfc-reader';
export { BluetoothManager } from './mobile/bluetooth-manager';
export { MobileAppQR } from './mobile/mobile-app-qr';

// Maintenance Components
export { MaintenanceScheduler } from './maintenance/maintenance-scheduler';
export { WorkOrderManager } from './maintenance/work-order-manager';
export { ServiceHistory } from './maintenance/service-history';
export { DiagnosticTools } from './maintenance/diagnostic-tools';
export { WarrantyTracker } from './maintenance/warranty-tracker';
export { PreventiveMaintenance } from './maintenance/preventive-maintenance';

// Security & Compliance Components
export { SecurityDashboard } from './security/security-dashboard';
export { ThreatIndicator } from './security/threat-indicator';
export { ComplianceStatus } from './security/compliance-status';
export { AuditTrail } from './security/audit-trail';
export { SecurityAlerts } from './security/security-alerts';
export { IncidentReporting } from './security/incident-reporting';
export { CybersecurityMonitor } from './security/cybersecurity-monitor';

// Integration Components
export { IntegrationStatus } from './integration/integration-status';
export { ApiEndpointTester } from './integration/api-endpoint-tester';
export { WebhookManager } from './integration/webhook-manager';
export { ThirdPartyConnections } from './integration/third-party-connections';
export { DataSyncStatus } from './integration/data-sync-status';

// Utility Components
export { SearchBar } from './search-bar';
export { FilterPanel } from './filter-panel';
export { SortableHeader } from './sortable-header';
export { BulkActions } from './bulk-actions';
export { ExportButton } from './export-button';
export { ImportButton } from './import-button';
export { RefreshButton } from './refresh-button';
export { HelpTooltip } from './help-tooltip';
export { KeyboardShortcuts } from './keyboard-shortcuts';
export { ThemeToggle } from './theme-toggle';
export { LanguageSelector } from './language-selector';
export { NotificationCenter } from './notification-center';
export { CommandPalette } from './command-palette';

// Accessibility Components
export { ScreenReaderOnly } from './accessibility/screen-reader-only';
export { FocusTrap } from './accessibility/focus-trap';
export { SkipLink } from './accessibility/skip-link';
export { AccessibilityAnnouncer } from './accessibility/accessibility-announcer';
export { HighContrastMode } from './accessibility/high-contrast-mode';
export { FontSizeAdjuster } from './accessibility/font-size-adjuster';

// Animation Components
export { FadeIn } from './animations/fade-in';
export { SlideIn } from './animations/slide-in';
export { ScaleIn } from './animations/scale-in';
export { Stagger } from './animations/stagger';
export { LoadingAnimation } from './animations/loading-animation';
export { SuccessAnimation } from './animations/success-animation';
export { ErrorAnimation } from './animations/error-animation';

// Real-time Components
export { RealTimeIndicator } from './realtime/real-time-indicator';
export { LiveDataFeed } from './realtime/live-data-feed';
export { ConnectionStatus } from './realtime/connection-status';
export { EventStream } from './realtime/event-stream';
export { NotificationBadge } from './realtime/notification-badge';

// Hooks and Utilities
export { useLocalStorage } from './hooks/use-local-storage';
export { useSessionStorage } from './hooks/use-session-storage';
export { useDebounce } from './hooks/use-debounce';
export { useThrottle } from './hooks/use-throttle';
export { useMediaQuery } from './hooks/use-media-query';
export { useKeyboardShortcut } from './hooks/use-keyboard-shortcut';
export { useClickOutside } from './hooks/use-click-outside';
export { useIntersectionObserver } from './hooks/use-intersection-observer';
export { usePrevious } from './hooks/use-previous';
export { useToggle } from './hooks/use-toggle';
export { useCopyToClipboard } from './hooks/use-copy-to-clipboard';
export { useWindowSize } from './hooks/use-window-size';
export { useOnlineStatus } from './hooks/use-online-status';
export { usePermissions } from './hooks/use-permissions';
export { useTenant } from './hooks/use-tenant';

// Type definitions and utilities
export type { ComponentProps, VariantProps } from './types';
export { cn } from './utils';
export { buttonVariants } from './button';
export { badgeVariants } from './badge';
export { alertVariants } from './alert';

// Theme and styling utilities
export { themes } from './themes';
export { colorPalette } from './colors';
export { spacing } from './spacing';
export { typography } from './typography';
export { shadows } from './shadows';
export { animations } from './animations';
export { breakpoints } from './breakpoints';

// Accessibility utilities
export { a11yProps } from './accessibility/utils';
export { announceToScreenReader } from './accessibility/announcer';
export { focusManagement } from './accessibility/focus-management';
export { keyboardNavigation } from './accessibility/keyboard-navigation';

// Component composition utilities
export { withTooltip } from './hoc/with-tooltip';
export { withLoading } from './hoc/with-loading';
export { withError } from './hoc/with-error';
export { withPermissions } from './hoc/with-permissions';
export { withTenant } from './hoc/with-tenant';
export { withAnalytics } from './hoc/with-analytics';

// Constants for the design system
export const COMPONENT_SIZES = {
  xs: 'xs',
  sm: 'sm',
  md: 'md',
  lg: 'lg',
  xl: 'xl',
} as const;

export const COMPONENT_VARIANTS = {
  default: 'default',
  primary: 'primary',
  secondary: 'secondary',
  destructive: 'destructive',
  outline: 'outline',
  ghost: 'ghost',
  link: 'link',
} as const;

export const ALERT_SEVERITIES = {
  info: 'info',
  warning: 'warning',
  error: 'error',
  success: 'success',
} as const;

export const ACCESS_CONTROL_STATES = {
  granted: 'granted',
  denied: 'denied',
  pending: 'pending',
  offline: 'offline',
  error: 'error',
} as const;

export const VIDEO_STATES = {
  live: 'live',
  recording: 'recording',
  offline: 'offline',
  error: 'error',
  loading: 'loading',
} as const;

export const DEVICE_STATES = {
  online: 'online',
  offline: 'offline',
  error: 'error',
  maintenance: 'maintenance',
  updating: 'updating',
} as const;

// Re-export commonly used types from dependencies
export type { VariantProps as CVAVariantProps } from 'class-variance-authority';
export type { ClassValue } from 'clsx';