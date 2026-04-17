import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import './App.css';

const API_BASE = 'http://localhost:3000';
const INVENTORY_VIEWS = ['active', 'archived', 'all'] as const;
const IDENTITY_FILTERS = [
  'all',
  'pending',
  'enrolled',
  'verified',
  'invalid',
  'locked',
] as const;
const EVENT_TYPE_OPTIONS = [
  'all',
  'discovery',
  'identity_verified',
  'identity_failed',
  'identity_key_rotated',
  'policy_change',
] as const;

type DeviceState = 'allowed' | 'denied' | 'unknown';
type IdentityStatus = 'pending' | 'enrolled' | 'verified' | 'invalid' | 'locked';
type InventoryView = (typeof INVENTORY_VIEWS)[number];
type IdentityFilter = (typeof IDENTITY_FILTERS)[number];
type EventTypeOption = (typeof EVENT_TYPE_OPTIONS)[number];
type ExportScope = 'audit' | 'enforcement' | 'events';
type ExportFormat = 'csv' | 'json';
type ProfileSource = 'manual' | 'report' | 'inferred' | 'unknown';
type HelpKey =
  | 'addDevice'
  | 'identityStatus'
  | 'manageDevice'
  | 'finishVerification';

type DeviceProfileSources = {
  hostname: ProfileSource;
  vendor: ProfileSource;
  model: ProfileSource;
  location: ProfileSource;
  macAddress: ProfileSource;
  fingerprint: ProfileSource;
};

type Device = {
  id: string;
  alias?: string | null;
  hostname?: string;
  vendor?: string;
  model?: string;
  location?: string | null;
  macAddress?: string | null;
  fingerprint?: string | null;
  archivedAt?: string | null;
  profileSources?: DeviceProfileSources;
  lastSeen: string;
  state: DeviceState;
  identityStatus: IdentityStatus;
  lastIdentityCheck?: string | null;
};

type AuditAction = 'allow' | 'deny';

type AuditEntry = {
  ts: string;
  deviceId: string;
  action: AuditAction;
  prev: DeviceState;
  next: DeviceState;
};

type EnforcementCode =
  | 'ok'
  | 'identity_not_verified'
  | 'identity_invalid'
  | 'identity_locked'
  | 'already_allowed'
  | 'already_denied';

type EnforcementEntry = {
  ts: string;
  deviceId: string;
  action: AuditAction;
  prevState: DeviceState;
  nextState: DeviceState;
  adapter: string;
  result: 'applied' | 'blocked';
  code: EnforcementCode;
  message: string;
};

type SecurityEvent = {
  id: number;
  ts: string;
  type: string;
  severity: 'info' | 'warning' | 'critical';
  deviceId: string | null;
  message: string;
};

type LifecycleEntry = {
  ts: string;
  deviceId: string;
  action:
    | 'pending_created'
    | 'device_enrolled'
    | 'key_rotated'
    | 'alias_updated'
    | 'profile_updated'
    | 'provisioning_token_issued'
    | 'provisioning_token_consumed'
    | 'device_archived'
    | 'device_restored';
  message: string;
};

type ProvisioningMetadata = {
  headerName: 'x-device-provisioning-token';
  requiredOnFirstHeartbeat: true;
  active: boolean;
  issuedAt: string | null;
  expiresAt: string | null;
  consumedAt: string | null;
};

type IdentityProfile = {
  deviceId: string;
  alias: string | null;
  hostname: string;
  vendor: string;
  model: string;
  location: string | null;
  macAddress: string | null;
  fingerprint: string | null;
  archivedAt: string | null;
  profileSources: DeviceProfileSources;
  identityStatus: IdentityStatus;
  lastIdentityCheck: string | null;
  keyConfigured: boolean;
  keySource: 'device' | 'fallback';
  keyUpdatedAt: string | null;
  hmac: {
    canonicalFormat: '<deviceId>.<timestamp>.<nonce>';
    maxSkewMs: number;
    nonceTtlMs: number;
  };
  security: {
    maxFailures: number;
    failureWindowMs: number;
    lockoutMs: number;
    recentFailures: number;
    lockedOut: boolean;
    lockoutUntil: string | null;
  };
  provisioning: ProvisioningMetadata;
  heartbeat: {
    endpoint: '/devices/report';
    method: 'POST';
    payloadFields: ['id', 'hostname', 'vendor', 'model', 'macAddress', 'fingerprint'];
    requiredHeaders: [
      'x-device-id',
      'x-device-ts',
      'x-device-nonce',
      'x-device-signature',
    ];
    provisioningHeader: 'x-device-provisioning-token';
  };
};

type ProvisioningTokenIssue = {
  token: string;
  issuedAt: string;
  expiresAt: string;
  headerName: 'x-device-provisioning-token';
};

type IdentityKeyResponse = {
  deviceId: string;
  alias: string | null;
  keyUpdatedAt: string;
  changeType: 'created' | 'updated';
  identityStatus: 'enrolled';
  provisioningToken: ProvisioningTokenIssue;
};

type CreateDeviceForm = {
  id: string;
  alias: string;
};

type ProfileForm = {
  hostname: string;
  vendor: string;
  model: string;
  location: string;
  macAddress: string;
};

type IssuedProvisioningToken = ProvisioningTokenIssue & {
  deviceId: string;
};

type ActivityItem = {
  ts: string;
  source: 'enforcement' | 'policy' | 'security' | 'lifecycle';
  label: string;
  badgeClass: string;
  title: string;
  detail: string;
};

function formatTs(value: string | null | undefined): string {
  if (!value) {
    return 'unknown';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}

function normalizeOptionalInput(value: string): string | null {
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function toIsoOrUndefined(value: string): string | undefined {
  if (!value.trim()) {
    return undefined;
  }

  return new Date(value).toISOString();
}

function stateClass(value: DeviceState): string {
  switch (value) {
    case 'allowed':
      return 'pill-good';
    case 'denied':
      return 'pill-bad';
    default:
      return 'pill-neutral';
  }
}

function identityClass(value: IdentityStatus): string {
  switch (value) {
    case 'verified':
      return 'pill-good';
    case 'enrolled':
      return 'pill-warn';
    case 'invalid':
    case 'locked':
      return 'pill-bad';
    default:
      return 'pill-neutral';
  }
}

function severityClass(value: SecurityEvent['severity']): string {
  switch (value) {
    case 'critical':
      return 'pill-bad';
    case 'warning':
      return 'pill-warn';
    default:
      return 'pill-neutral';
  }
}

function policyCodeLabel(code: EnforcementCode): string {
  switch (code) {
    case 'identity_not_verified':
      return 'not verified';
    case 'identity_invalid':
      return 'identity invalid';
    case 'identity_locked':
      return 'identity locked';
    case 'already_allowed':
      return 'already allowed';
    case 'already_denied':
      return 'already denied';
    default:
      return 'policy ok';
  }
}

function policyCodeClass(code: EnforcementCode): string {
  switch (code) {
    case 'identity_not_verified':
      return 'pill-warn';
    case 'identity_invalid':
    case 'identity_locked':
      return 'pill-bad';
    case 'already_allowed':
    case 'already_denied':
      return 'pill-neutral';
    default:
      return 'pill-good';
  }
}

function lifecycleActionLabel(action: LifecycleEntry['action']): string {
  switch (action) {
    case 'pending_created':
      return 'pending';
    case 'device_enrolled':
      return 'enrolled';
    case 'key_rotated':
      return 'rotated';
    case 'alias_updated':
      return 'alias';
    case 'profile_updated':
      return 'profile';
    case 'provisioning_token_issued':
      return 'token issued';
    case 'provisioning_token_consumed':
      return 'token used';
    case 'device_archived':
      return 'archived';
    case 'device_restored':
      return 'restored';
  }
}

function lifecycleActionClass(action: LifecycleEntry['action']): string {
  switch (action) {
    case 'device_enrolled':
    case 'provisioning_token_consumed':
    case 'device_restored':
      return 'pill-good';
    case 'key_rotated':
    case 'provisioning_token_issued':
    case 'profile_updated':
      return 'pill-warn';
    case 'device_archived':
      return 'pill-bad';
    default:
      return 'pill-neutral';
  }
}

function profileSourceClass(source: ProfileSource): string {
  switch (source) {
    case 'manual':
      return 'pill-good';
    case 'report':
      return 'pill-warn';
    case 'inferred':
      return 'pill-neutral';
    default:
      return 'pill-neutral';
  }
}

function profileSourceLabel(source: ProfileSource): string {
  switch (source) {
    case 'manual':
      return 'manual';
    case 'report':
      return 'report';
    case 'inferred':
      return 'inferred';
    default:
      return 'unknown';
  }
}

function readDeviceTitle(device: Device | null): string {
  if (!device) {
    return 'No device selected';
  }

  if (device.alias?.trim()) {
    return device.alias.trim();
  }

  if (device.hostname && device.hostname !== 'unknown') {
    return device.hostname;
  }

  return device.id;
}

function allowDisabledReason(device: Device): string | null {
  if (device.archivedAt) {
    return 'Restore the device before allowing access.';
  }

  if (device.state === 'allowed') {
    return 'Device is already allowed.';
  }

  if (device.identityStatus === 'pending') {
    return 'Allow is available after a device key is enrolled.';
  }

  if (device.identityStatus === 'invalid') {
    return 'Allow is blocked while the device identity is invalid.';
  }

  if (device.identityStatus === 'locked') {
    return 'Allow is blocked while the device is locked.';
  }

  return null;
}

function denyDisabledReason(device: Device): string | null {
  if (device.archivedAt) {
    return 'Archived devices stay denied until they are restored.';
  }

  if (device.state === 'denied') {
    return 'Device is already denied.';
  }

  return null;
}

function identityStatusMessage(status: IdentityStatus): string {
  switch (status) {
    case 'pending':
      return 'Inventory record exists, but no per-device key has been enrolled yet.';
    case 'enrolled':
      return 'Device key is enrolled. A first signed heartbeat with the one-time provisioning token is still required.';
    case 'verified':
      return 'Identity is trusted. The device completed provisioning and most recent signed heartbeat validated.';
    case 'invalid':
      return 'The most recent signed heartbeat failed validation. Allow decisions stay blocked until the device verifies again.';
    case 'locked':
      return 'Repeated identity failures triggered a temporary lockout. The device must wait out lockout and then verify successfully.';
  }
}

function HelpToggle({
  open,
  onClick,
}: {
  open: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`nac-help-btn ${open ? 'nac-help-btn-open' : ''}`}
      onClick={onClick}
      aria-label={open ? 'Hide help' : 'Show help'}
      title={open ? 'Hide help' : 'Show help'}
    >
      ?
    </button>
  );
}

function matchesSearch(device: Device, query: string): boolean {
  if (!query.trim()) {
    return true;
  }

  const haystack = [
    device.alias ?? '',
    device.id,
    device.hostname ?? '',
    device.vendor ?? '',
    device.model ?? '',
    device.location ?? '',
    device.macAddress ?? '',
  ]
    .join(' ')
    .toLowerCase();

  return haystack.includes(query.trim().toLowerCase());
}

async function readErrorMessage(response: Response): Promise<string> {
  const raw = await response.text();
  if (!raw) {
    return `HTTP ${response.status}`;
  }

  try {
    const parsed = JSON.parse(raw) as { message?: string | string[] };
    if (Array.isArray(parsed.message) && parsed.message.length > 0) {
      return parsed.message.join('; ');
    }
    if (typeof parsed.message === 'string' && parsed.message.trim()) {
      return parsed.message;
    }
  } catch {
    return raw;
  }

  return raw;
}

function readDownloadFilename(response: Response, fallback: string): string {
  const disposition = response.headers.get('Content-Disposition');
  if (!disposition) {
    return fallback;
  }

  const match = disposition.match(/filename="([^"]+)"/);
  return match?.[1] ?? fallback;
}

export default function App() {
  const lastInitializedDeviceId = useRef<string | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [lifecycle, setLifecycle] = useState<LifecycleEntry[]>([]);
  const [enforcement, setEnforcement] = useState<EnforcementEntry[]>([]);
  const [deviceAudit, setDeviceAudit] = useState<AuditEntry[]>([]);
  const [deviceEvents, setDeviceEvents] = useState<SecurityEvent[]>([]);
  const [deviceLifecycle, setDeviceLifecycle] = useState<LifecycleEntry[]>([]);
  const [identityProfile, setIdentityProfile] = useState<IdentityProfile | null>(null);

  const [selectedDeviceId, setSelectedDeviceId] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [identityFilter, setIdentityFilter] = useState<IdentityFilter>('all');
  const [inventoryView, setInventoryView] = useState<InventoryView>('active');

  const [secretInput, setSecretInput] = useState('');
  const [showSecretInput, setShowSecretInput] = useState(false);
  const [aliasInput, setAliasInput] = useState('');
  const [profileForm, setProfileForm] = useState<ProfileForm>({
    hostname: '',
    vendor: '',
    model: '',
    location: '',
    macAddress: '',
  });
  const [createForm, setCreateForm] = useState<CreateDeviceForm>({ id: '', alias: '' });
  const [lastProvisioningToken, setLastProvisioningToken] =
    useState<IssuedProvisioningToken | null>(null);

  const [editingAliasId, setEditingAliasId] = useState<string | null>(null);
  const [inlineAliasInput, setInlineAliasInput] = useState('');

  const [exportScope, setExportScope] = useState<ExportScope>('audit');
  const [exportFormat, setExportFormat] = useState<ExportFormat>('csv');
  const [exportSelectedOnly, setExportSelectedOnly] = useState(false);
  const [exportFrom, setExportFrom] = useState('');
  const [exportTo, setExportTo] = useState('');
  const [exportEventType, setExportEventType] = useState<EventTypeOption>('all');
  const [openHelp, setOpenHelp] = useState<HelpKey | null>(null);

  const [loading, setLoading] = useState(true);
  const [secretSaving, setSecretSaving] = useState(false);
  const [aliasSaving, setAliasSaving] = useState(false);
  const [profileSaving, setProfileSaving] = useState(false);
  const [inlineAliasSaving, setInlineAliasSaving] = useState(false);
  const [createSaving, setCreateSaving] = useState(false);
  const [provisioningBusy, setProvisioningBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [archiveBusy, setArchiveBusy] = useState(false);
  const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);

  const [lastRefreshAt, setLastRefreshAt] = useState<string | null>(null);
  const [identityMessage, setIdentityMessage] = useState<string | null>(null);
  const [policyMessage, setPolicyMessage] = useState<string | null>(null);
  const [createMessage, setCreateMessage] = useState<string | null>(null);
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedDevice = useMemo(
    () => devices.find((device) => device.id === selectedDeviceId) ?? null,
    [devices, selectedDeviceId],
  );

  const deviceLabelById = useMemo(() => {
    return new Map(devices.map((device) => [device.id, readDeviceTitle(device)]));
  }, [devices]);

  const inventoryDevices = useMemo(() => {
    if (inventoryView === 'archived') {
      return devices.filter((device) => Boolean(device.archivedAt));
    }

    if (inventoryView === 'all') {
      return devices;
    }

    return devices.filter((device) => !device.archivedAt);
  }, [devices, inventoryView]);

  const filteredDevices = useMemo(() => {
    return inventoryDevices.filter((device) => {
      if (identityFilter !== 'all' && device.identityStatus !== identityFilter) {
        return false;
      }

      return matchesSearch(device, searchQuery);
    });
  }, [identityFilter, inventoryDevices, searchQuery]);

  const metrics = useMemo(() => {
    const activeDevices = devices.filter((device) => !device.archivedAt);
    const pendingCount = activeDevices.filter((device) => device.identityStatus === 'pending').length;
    const enrolledCount = activeDevices.filter((device) => device.identityStatus === 'enrolled').length;
    const verifiedCount = activeDevices.filter((device) => device.identityStatus === 'verified').length;
    const invalidCount = activeDevices.filter((device) => device.identityStatus === 'invalid').length;
    const lockedCount = activeDevices.filter((device) => device.identityStatus === 'locked').length;
    const deniedCount = activeDevices.filter((device) => device.state === 'denied').length;

    return {
      total: activeDevices.length,
      pendingCount,
      enrolledCount,
      verifiedCount,
      invalidCount,
      lockedCount,
      deniedCount,
    };
  }, [devices]);

  const latestBlockedDecision = useMemo(() => {
    return [...enforcement].reverse().find((entry) => entry.result === 'blocked') ?? null;
  }, [enforcement]);

  const deviceActivityItems = useMemo<ActivityItem[]>(() => {
    const items: ActivityItem[] = [
      ...enforcement.map((entry) => ({
        ts: entry.ts,
        source: 'enforcement' as const,
        label: policyCodeLabel(entry.code),
        badgeClass: policyCodeClass(entry.code),
        title: `${entry.action} ${entry.prevState} -> ${entry.nextState}`,
        detail: entry.message,
      })),
      ...deviceAudit.map((entry) => ({
        ts: entry.ts,
        source: 'policy' as const,
        label: 'policy',
        badgeClass: 'pill-neutral',
        title: `${entry.action} ${entry.prev} -> ${entry.next}`,
        detail: `${deviceLabelById.get(entry.deviceId) ?? entry.deviceId}`,
      })),
      ...deviceEvents.map((event) => ({
        ts: event.ts,
        source: 'security' as const,
        label: event.severity,
        badgeClass: severityClass(event.severity),
        title: `${event.type} ${event.deviceId ? deviceLabelById.get(event.deviceId) ?? event.deviceId : 'system'}`,
        detail: event.message,
      })),
      ...deviceLifecycle.map((entry) => ({
        ts: entry.ts,
        source: 'lifecycle' as const,
        label: lifecycleActionLabel(entry.action),
        badgeClass: lifecycleActionClass(entry.action),
        title: lifecycleActionLabel(entry.action),
        detail: entry.message,
      })),
    ];

    return items.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
  }, [deviceAudit, deviceEvents, deviceLifecycle, deviceLabelById, enforcement]);

  const systemActivityItems = useMemo<ActivityItem[]>(() => {
    const items: ActivityItem[] = [
      ...audit.map((entry) => ({
        ts: entry.ts,
        source: 'policy' as const,
        label: 'policy',
        badgeClass: 'pill-neutral',
        title: `${deviceLabelById.get(entry.deviceId) ?? entry.deviceId} ${entry.action}`,
        detail: `${entry.prev} -> ${entry.next}`,
      })),
      ...events.map((event) => ({
        ts: event.ts,
        source: 'security' as const,
        label: event.severity,
        badgeClass: severityClass(event.severity),
        title: `${event.type} ${event.deviceId ? deviceLabelById.get(event.deviceId) ?? event.deviceId : 'system'}`,
        detail: event.message,
      })),
      ...lifecycle.map((entry) => ({
        ts: entry.ts,
        source: 'lifecycle' as const,
        label: lifecycleActionLabel(entry.action),
        badgeClass: lifecycleActionClass(entry.action),
        title: `${deviceLabelById.get(entry.deviceId) ?? entry.deviceId} ${lifecycleActionLabel(entry.action)}`,
        detail: entry.message,
      })),
    ];

    return items.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
  }, [audit, deviceLabelById, events, lifecycle]);

  const heartbeatSnippet = useMemo(() => {
    if (!selectedDevice || !identityProfile) {
      return '';
    }

    const provisioningToken =
      lastProvisioningToken?.deviceId === selectedDevice.id
        ? lastProvisioningToken.token
        : '<PROVISIONING_TOKEN>';
    const lines = [
      'TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")',
      'NONCE="nonce$(date +%s)"',
      `CANONICAL="${selectedDevice.id}.$TS.$NONCE"`,
      '# compute the SHA-256 HMAC of $CANONICAL with the enrolled device key',
      `curl -X POST ${API_BASE}${identityProfile.heartbeat.endpoint} \\`,
      '  -H "Content-Type: application/json" \\',
      `  -H "x-device-id: ${selectedDevice.id}" \\`,
      '  -H "x-device-ts: $TS" \\',
      '  -H "x-device-nonce: $NONCE" \\',
      '  -H "x-device-signature: <HEX_HMAC_SIGNATURE>" \\',
    ];

    if (identityProfile.identityStatus === 'enrolled') {
      lines.push(
        `  -H "${identityProfile.provisioning.headerName}: ${provisioningToken}" \\`,
      );
    }

    lines.push(
      `  -d '{"id":"${selectedDevice.id}","hostname":"device-host","vendor":"device-vendor","model":"device-model","macAddress":"AA:BB:CC:DD:EE:FF","fingerprint":"device-fingerprint"}'`,
    );

    return lines.join('\n');
  }, [identityProfile, lastProvisioningToken, selectedDevice]);

  const loadCore = useCallback(async (options?: { silent?: boolean }) => {
    try {
      if (!options?.silent) {
        setLoading(true);
      }
      setError(null);

      const [devicesRes, auditRes, eventsRes, lifecycleRes] = await Promise.all([
        fetch(`${API_BASE}/devices?view=all`),
        fetch(`${API_BASE}/audit`),
        fetch(`${API_BASE}/events/recent?limit=40`),
        fetch(`${API_BASE}/devices/lifecycle?limit=40`),
      ]);

      if (!devicesRes.ok) {
        throw new Error(await readErrorMessage(devicesRes));
      }
      if (!auditRes.ok) {
        throw new Error(await readErrorMessage(auditRes));
      }
      if (!eventsRes.ok) {
        throw new Error(await readErrorMessage(eventsRes));
      }
      if (!lifecycleRes.ok) {
        throw new Error(await readErrorMessage(lifecycleRes));
      }

      const nextDevices = (await devicesRes.json()) as Device[];
      const nextAudit = (await auditRes.json()) as AuditEntry[];
      const nextEvents = (await eventsRes.json()) as SecurityEvent[];
      const nextLifecycle = (await lifecycleRes.json()) as LifecycleEntry[];

      setDevices(nextDevices);
      setAudit(nextAudit);
      setEvents(nextEvents);
      setLifecycle(nextLifecycle);
      setLastRefreshAt(new Date().toISOString());

      setSelectedDeviceId((current) => {
        if (!current && nextDevices.length > 0) {
          return nextDevices[0].id;
        }

        if (current && !nextDevices.some((device) => device.id === current)) {
          return nextDevices[0]?.id ?? '';
        }

        return current;
      });
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Failed to load inventory data',
      );
    } finally {
      if (!options?.silent) {
        setLoading(false);
      }
    }
  }, []);

  const loadSelectedContext = useCallback(async (deviceId: string) => {
    if (!deviceId) {
      setEnforcement([]);
      setDeviceAudit([]);
      setDeviceEvents([]);
      setDeviceLifecycle([]);
      setIdentityProfile(null);
      return;
    }

    const [enforcementRes, identityRes, auditRes, eventsRes, lifecycleRes] = await Promise.all([
      fetch(`${API_BASE}/devices/${deviceId}/enforcement`),
      fetch(`${API_BASE}/devices/${deviceId}/identity`),
      fetch(`${API_BASE}/audit?deviceId=${encodeURIComponent(deviceId)}&limit=24`),
      fetch(`${API_BASE}/events/recent?deviceId=${encodeURIComponent(deviceId)}&limit=24`),
      fetch(`${API_BASE}/devices/lifecycle?deviceId=${encodeURIComponent(deviceId)}&limit=24`),
    ]);

    if (!enforcementRes.ok) {
      throw new Error(await readErrorMessage(enforcementRes));
    }

    if (!identityRes.ok) {
      throw new Error(await readErrorMessage(identityRes));
    }

    if (!auditRes.ok) {
      throw new Error(await readErrorMessage(auditRes));
    }

    if (!eventsRes.ok) {
      throw new Error(await readErrorMessage(eventsRes));
    }

    if (!lifecycleRes.ok) {
      throw new Error(await readErrorMessage(lifecycleRes));
    }

    const nextEnforcement = (await enforcementRes.json()) as EnforcementEntry[];
    const nextIdentity = (await identityRes.json()) as IdentityProfile;
    const nextAudit = (await auditRes.json()) as AuditEntry[];
    const nextEvents = (await eventsRes.json()) as SecurityEvent[];
    const nextLifecycle = (await lifecycleRes.json()) as LifecycleEntry[];

    setEnforcement(nextEnforcement);
    setIdentityProfile(nextIdentity);
    setDeviceAudit(nextAudit);
    setDeviceEvents(nextEvents);
    setDeviceLifecycle(nextLifecycle);
  }, []);

  const updateAliasForDevice = useCallback(async (deviceId: string, alias: string | null) => {
    const response = await fetch(`${API_BASE}/devices/${deviceId}/alias`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ alias }),
    });

    if (!response.ok) {
      throw new Error(await readErrorMessage(response));
    }

    return (await response.json()) as Device;
  }, []);

  const copyText = useCallback(async (value: string, successMessage: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setIdentityMessage(successMessage);
    } catch {
      setIdentityMessage('Clipboard access failed.');
    }
  }, []);

  const setDevicePolicy = useCallback(
    async (deviceId: string, action: AuditAction) => {
      try {
        setBusyDeviceId(deviceId);
        setPolicyMessage(null);
        setError(null);

        const response = await fetch(`${API_BASE}/devices/${deviceId}/${action}`, {
          method: 'POST',
        });

        if (!response.ok) {
          throw new Error(await readErrorMessage(response));
        }

        await loadCore({ silent: true });
        if (deviceId === selectedDeviceId) {
          await loadSelectedContext(deviceId);
        }

        const target = devices.find((device) => device.id === deviceId) ?? null;
        setPolicyMessage(`${readDeviceTitle(target)} ${action} applied.`);
      } catch (requestError) {
        const message =
          requestError instanceof Error
            ? requestError.message
            : `Failed to ${action} device`;
        setPolicyMessage(message);
        setError(message);
      } finally {
        setBusyDeviceId(null);
      }
    },
    [devices, loadCore, loadSelectedContext, selectedDeviceId],
  );

  const createDevice = useCallback(async () => {
    if (!createForm.id.trim()) {
      setCreateMessage('Device ID is required.');
      return;
    }

    try {
      setCreateSaving(true);
      setCreateMessage(null);
      setError(null);

      const response = await fetch(`${API_BASE}/devices`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          id: createForm.id.trim(),
          alias: normalizeOptionalInput(createForm.alias),
        }),
      });

      if (!response.ok) {
        throw new Error(await readErrorMessage(response));
      }

      const device = (await response.json()) as Device;
      setCreateForm({ id: '', alias: '' });
      setCreateMessage(`Pending device ${device.id} saved to inventory.`);

      await loadCore({ silent: true });
      setSelectedDeviceId(device.id);
      await loadSelectedContext(device.id);
    } catch (requestError) {
      setCreateMessage(
        requestError instanceof Error
          ? requestError.message
          : 'Failed to create pending device',
      );
    } finally {
      setCreateSaving(false);
    }
  }, [createForm, loadCore, loadSelectedContext]);

  const saveAlias = useCallback(async () => {
    if (!selectedDeviceId) {
      setIdentityMessage('Select a device first.');
      return;
    }

    try {
      setAliasSaving(true);
      setIdentityMessage(null);
      setError(null);

      const updated = await updateAliasForDevice(
        selectedDeviceId,
        normalizeOptionalInput(aliasInput),
      );

      setIdentityMessage(
        updated.alias ? `Alias updated to ${updated.alias}.` : 'Alias cleared.',
      );

      await loadCore({ silent: true });
      await loadSelectedContext(selectedDeviceId);
    } catch (requestError) {
      setIdentityMessage(
        requestError instanceof Error ? requestError.message : 'Failed to update alias',
      );
    } finally {
      setAliasSaving(false);
    }
  }, [aliasInput, loadCore, loadSelectedContext, selectedDeviceId, updateAliasForDevice]);

  const saveProfile = useCallback(async () => {
    if (!selectedDeviceId) {
      setIdentityMessage('Select a device first.');
      return;
    }

    try {
      setProfileSaving(true);
      setIdentityMessage(null);
      setError(null);

      const response = await fetch(`${API_BASE}/devices/${selectedDeviceId}/profile`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          hostname: normalizeOptionalInput(profileForm.hostname),
          vendor: normalizeOptionalInput(profileForm.vendor),
          model: normalizeOptionalInput(profileForm.model),
          location: normalizeOptionalInput(profileForm.location),
          macAddress: normalizeOptionalInput(profileForm.macAddress),
        }),
      });

      if (!response.ok) {
        throw new Error(await readErrorMessage(response));
      }

      setIdentityMessage('Device profile updated.');
      await loadCore({ silent: true });
      await loadSelectedContext(selectedDeviceId);
    } catch (requestError) {
      setIdentityMessage(
        requestError instanceof Error ? requestError.message : 'Failed to update device profile',
      );
    } finally {
      setProfileSaving(false);
    }
  }, [loadCore, loadSelectedContext, profileForm, selectedDeviceId]);

  const saveInlineAlias = useCallback(
    async (deviceId: string) => {
      try {
        setInlineAliasSaving(true);
        setIdentityMessage(null);
        setError(null);

        const updated = await updateAliasForDevice(
          deviceId,
          normalizeOptionalInput(inlineAliasInput),
        );

        setEditingAliasId(null);
        setInlineAliasInput('');
        setIdentityMessage(
          updated.alias ? `Alias updated to ${updated.alias}.` : 'Alias cleared.',
        );

        await loadCore({ silent: true });
        if (selectedDeviceId === deviceId) {
          await loadSelectedContext(deviceId);
        }
      } catch (requestError) {
        setIdentityMessage(
          requestError instanceof Error ? requestError.message : 'Failed to update alias',
        );
      } finally {
        setInlineAliasSaving(false);
      }
    },
    [inlineAliasInput, loadCore, loadSelectedContext, selectedDeviceId, updateAliasForDevice],
  );

  const saveIdentityKey = useCallback(async () => {
    if (!selectedDeviceId || !identityProfile) {
      setIdentityMessage('Select a device first.');
      return;
    }

    if (secretInput.trim().length < 16) {
      setIdentityMessage('Device key must be at least 16 characters.');
      return;
    }

    if (
      identityProfile.keyConfigured &&
      !window.confirm(
        'Rotating the key will reset this device to enrolled until it verifies again. Continue?',
      )
    ) {
      return;
    }

    try {
      setSecretSaving(true);
      setIdentityMessage(null);
      setError(null);

      const response = await fetch(`${API_BASE}/devices/${selectedDeviceId}/enroll`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          secret: secretInput.trim(),
          alias: normalizeOptionalInput(aliasInput),
        }),
      });

      if (!response.ok) {
        throw new Error(await readErrorMessage(response));
      }

      const body = (await response.json()) as IdentityKeyResponse;
      setSecretInput('');
      setLastProvisioningToken({ ...body.provisioningToken, deviceId: body.deviceId });
      setIdentityMessage(
        `${body.changeType === 'created' ? 'Enrollment key created' : 'Device key rotated'} at ${formatTs(body.keyUpdatedAt)}. A one-time provisioning token was issued for the first verified heartbeat.`,
      );

      await loadCore({ silent: true });
      await loadSelectedContext(selectedDeviceId);
    } catch (requestError) {
      setIdentityMessage(
        requestError instanceof Error
          ? requestError.message
          : 'Failed to save device key',
      );
    } finally {
      setSecretSaving(false);
    }
  }, [aliasInput, identityProfile, loadCore, loadSelectedContext, secretInput, selectedDeviceId]);

  const reissueProvisioningToken = useCallback(async () => {
    if (!selectedDeviceId) {
      setIdentityMessage('Select a device first.');
      return;
    }

    try {
      setProvisioningBusy(true);
      setIdentityMessage(null);
      setError(null);

      const response = await fetch(
        `${API_BASE}/devices/${selectedDeviceId}/provisioning-token`,
        { method: 'POST' },
      );

      if (!response.ok) {
        throw new Error(await readErrorMessage(response));
      }

      const body = (await response.json()) as ProvisioningTokenIssue;
      setLastProvisioningToken({ ...body, deviceId: selectedDeviceId });
      setIdentityMessage(
        `Provisioning token reissued. It expires at ${formatTs(body.expiresAt)}.`,
      );
      await loadSelectedContext(selectedDeviceId);
    } catch (requestError) {
      setIdentityMessage(
        requestError instanceof Error
          ? requestError.message
          : 'Failed to issue provisioning token',
      );
    } finally {
      setProvisioningBusy(false);
    }
  }, [loadSelectedContext, selectedDeviceId]);

  const toggleArchiveState = useCallback(async () => {
    if (!selectedDeviceId || !selectedDevice) {
      setIdentityMessage('Select a device first.');
      return;
    }

    try {
      setArchiveBusy(true);
      setIdentityMessage(null);
      setError(null);

      const action = selectedDevice.archivedAt ? 'restore' : 'archive';
      const response = await fetch(`${API_BASE}/devices/${selectedDeviceId}/${action}`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error(await readErrorMessage(response));
      }

      setIdentityMessage(
        action === 'archive'
          ? 'Device archived from active inventory.'
          : 'Device restored to active inventory.',
      );

      await loadCore({ silent: true });
      await loadSelectedContext(selectedDeviceId);
    } catch (requestError) {
      setIdentityMessage(
        requestError instanceof Error ? requestError.message : 'Failed to change archive state',
      );
    } finally {
      setArchiveBusy(false);
    }
  }, [loadCore, loadSelectedContext, selectedDevice, selectedDeviceId]);

  const downloadExport = useCallback(async () => {
    try {
      setExporting(true);
      setExportMessage(null);
      setError(null);

      if (exportSelectedOnly && !selectedDeviceId) {
        setExportMessage('Select a device or disable the selected-device export filter.');
        return;
      }

      const params = new URLSearchParams({
        scope: exportScope,
        format: exportFormat,
      });

      if (exportSelectedOnly && selectedDeviceId) {
        params.set('deviceId', selectedDeviceId);
      }

      const fromIso = toIsoOrUndefined(exportFrom);
      const toIso = toIsoOrUndefined(exportTo);
      if (fromIso) {
        params.set('from', fromIso);
      }
      if (toIso) {
        params.set('to', toIso);
      }

      if (exportScope === 'events' && exportEventType !== 'all') {
        params.set('eventType', exportEventType);
      }

      const response = await fetch(`${API_BASE}/exports/download?${params.toString()}`);
      if (!response.ok) {
        throw new Error(await readErrorMessage(response));
      }

      const blob = await response.blob();
      const fallback = `${exportScope}.${exportFormat}`;
      const filename = readDownloadFilename(response, fallback);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      setExportMessage(`Downloaded ${filename}.`);
    } catch (requestError) {
      setExportMessage(
        requestError instanceof Error ? requestError.message : 'Export failed',
      );
    } finally {
      setExporting(false);
    }
  }, [
    exportEventType,
    exportFormat,
    exportFrom,
    exportScope,
    exportSelectedOnly,
    exportTo,
    selectedDeviceId,
  ]);

  const toggleHelp = useCallback((key: HelpKey) => {
    setOpenHelp((current) => (current === key ? null : key));
  }, []);

  useEffect(() => {
    loadCore().catch(() => {});

    const poll = setInterval(() => {
      loadCore({ silent: true }).catch(() => {});
    }, 6000);

    return () => clearInterval(poll);
  }, [loadCore]);

  useEffect(() => {
    if (!selectedDeviceId) {
      setIdentityProfile(null);
      setEnforcement([]);
      setDeviceAudit([]);
      setDeviceEvents([]);
      setDeviceLifecycle([]);
      return;
    }

    loadSelectedContext(selectedDeviceId).catch((requestError: unknown) => {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Failed to load device details',
      );
    });
  }, [loadSelectedContext, selectedDeviceId]);

  useEffect(() => {
    if (lastInitializedDeviceId.current === selectedDeviceId) {
      return;
    }

    lastInitializedDeviceId.current = selectedDeviceId || null;
    setSecretInput('');
    setShowSecretInput(false);
    setIdentityMessage(null);
    setAliasInput(selectedDevice?.alias ?? '');
    setProfileForm({
      hostname: selectedDevice?.hostname && selectedDevice.hostname !== 'unknown' ? selectedDevice.hostname : '',
      vendor: selectedDevice?.vendor && selectedDevice.vendor !== 'unknown' ? selectedDevice.vendor : '',
      model: selectedDevice?.model && selectedDevice.model !== 'unknown' ? selectedDevice.model : '',
      location: selectedDevice?.location ?? '',
      macAddress: selectedDevice?.macAddress ?? '',
    });
    setEditingAliasId(null);
    setInlineAliasInput('');
  }, [
    selectedDevice?.alias,
    selectedDevice?.hostname,
    selectedDevice?.vendor,
    selectedDevice?.model,
    selectedDevice?.location,
    selectedDevice?.macAddress,
    selectedDeviceId,
  ]);

  return (
    <div className="nac-shell">
      <main className="nac-app">
        <header className="nac-header">
          <div className="nac-header-main">
            <div className="nac-header-eyebrow">
              <p className="nac-kicker">IoT NAC</p>
              <span className="nac-header-dot" aria-hidden="true" />
              <span className="nac-header-section">Control Plane</span>
            </div>
            <h1>Operations Console</h1>
          </div>
          <div className="nac-header-meta">
            <div className="nac-header-pill">{metrics.total} tracked</div>
            <div className="nac-sync-chip">Last sync: {formatTs(lastRefreshAt)}</div>
          </div>
        </header>

        {error ? <div className="nac-alert">{error}</div> : null}

        <section className="nac-metric-grid">
          <div className="nac-metric-card">
            <span>Total Devices</span>
            <strong>{metrics.total}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Pending</span>
            <strong>{metrics.pendingCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Enrolled</span>
            <strong>{metrics.enrolledCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Verified</span>
            <strong>{metrics.verifiedCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Invalid</span>
            <strong>{metrics.invalidCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Locked</span>
            <strong>{metrics.lockedCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Denied</span>
            <strong>{metrics.deniedCount}</strong>
          </div>
        </section>

        <section className="nac-dashboard-grid">
          <div className="nac-dashboard-col nac-dashboard-col-primary">
            <article className="nac-panel">
              <div className="nac-panel-head">
                <h2>Device Inventory</h2>
                <span>{loading ? 'Refreshing...' : `${filteredDevices.length} visible`}</span>
              </div>

              <div className="nac-toolbar">
                <input
                  className="nac-search"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Search alias, device ID, hostname, vendor, model, location, or MAC"
                />
                <div className="nac-filter-row nac-filter-row-tight">
                  {INVENTORY_VIEWS.map((view) => (
                    <button
                      key={view}
                      className={`nac-chip ${inventoryView === view ? 'nac-chip-active' : ''}`}
                      onClick={() => setInventoryView(view)}
                    >
                      {view}
                    </button>
                  ))}
                </div>
                <div className="nac-filter-row">
                  {IDENTITY_FILTERS.map((filter) => (
                    <button
                      key={filter}
                      className={`nac-chip ${identityFilter === filter ? 'nac-chip-active' : ''}`}
                      onClick={() => setIdentityFilter(filter)}
                    >
                      {filter}
                    </button>
                  ))}
                </div>
              </div>

              {policyMessage ? <p className="nac-feedback">{policyMessage}</p> : null}

              <div className="nac-table-scroll">
                <table className="nac-table">
                  <thead>
                    <tr>
                      <th>Device</th>
                      <th>Hostname</th>
                      <th>Vendor</th>
                      <th>Last Seen</th>
                      <th>State</th>
                      <th>Identity</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredDevices.length === 0 ? (
                      <tr>
                        <td className="nac-empty" colSpan={7}>
                          No devices match the current search and filter state.
                        </td>
                      </tr>
                    ) : (
                      filteredDevices.map((device) => {
                        const title = readDeviceTitle(device);
                        const inlineEditing = editingAliasId === device.id;
                        const allowReason = allowDisabledReason(device);

                        return (
                          <tr
                            key={device.id}
                            className={
                              device.id === selectedDeviceId ? 'nac-row-selected' : undefined
                            }
                            onClick={() => setSelectedDeviceId(device.id)}
                          >
                            <td>
                              {inlineEditing ? (
                                <div
                                  className="nac-inline-edit"
                                  onClick={(event) => event.stopPropagation()}
                                >
                                  <input
                                    value={inlineAliasInput}
                                    onChange={(event) => setInlineAliasInput(event.target.value)}
                                    placeholder="Alias"
                                  />
                                  <button
                                    className="nac-btn"
                                    disabled={inlineAliasSaving}
                                    onClick={() => {
                                      void saveInlineAlias(device.id);
                                    }}
                                  >
                                    Save
                                  </button>
                                  <button
                                    className="nac-btn nac-btn-subtle"
                                    disabled={inlineAliasSaving}
                                    onClick={() => {
                                      setEditingAliasId(null);
                                      setInlineAliasInput('');
                                    }}
                                  >
                                    Cancel
                                  </button>
                                </div>
                              ) : (
                                <div className="nac-device-cell">
                                  <strong>{title}</strong>
                                  <span className="nac-subtext">{device.id}</span>
                                  <button
                                    className="nac-link-btn"
                                    onClick={(event) => {
                                      event.stopPropagation();
                                      setEditingAliasId(device.id);
                                      setInlineAliasInput(device.alias ?? '');
                                    }}
                                  >
                                    Edit label
                                  </button>
                                </div>
                              )}
                            </td>
                            <td>{device.hostname ?? 'unknown'}</td>
                            <td>{device.vendor ?? 'unknown'}</td>
                            <td>{formatTs(device.lastSeen)}</td>
                            <td>
                              <span className={`pill ${stateClass(device.state)}`}>
                                {device.state}
                              </span>
                            </td>
                            <td>
                              <span className={`pill ${identityClass(device.identityStatus)}`}>
                                {device.identityStatus}
                              </span>
                            </td>
                            <td>
                              <div className="nac-actions">
                                <button
                                  className="nac-btn nac-btn-allow"
                                  disabled={busyDeviceId === device.id || allowReason !== null}
                                  title={allowReason ?? 'Allow device'}
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    void setDevicePolicy(device.id, 'allow');
                                  }}
                                >
                                  Allow
                                </button>
                                <button
                                  className="nac-btn nac-btn-deny"
                                  disabled={busyDeviceId === device.id || denyDisabledReason(device) !== null}
                                  title={denyDisabledReason(device) ?? 'Deny device'}
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    void setDevicePolicy(device.id, 'deny');
                                  }}
                                >
                                  Deny
                                </button>
                              </div>
                              {device.archivedAt ? (
                                <span className="nac-subtext">archived {formatTs(device.archivedAt)}</span>
                              ) : null}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </article>

            <article className="nac-panel nac-activity-panel">
              <div className="nac-panel-head">
                <h2>Device Activity</h2>
                <span>{selectedDeviceId || 'No device selected'}</span>
              </div>
              {deviceActivityItems.length === 0 ? (
                <p className="nac-placeholder">No selected-device activity recorded yet.</p>
              ) : (
                <ul className="nac-log-list nac-log-list-fill">
                  {deviceActivityItems.slice(0, 20).map((item, index) => (
                    <li key={`${item.source}-${item.ts}-${index}`}>
                      <div className="nac-log-top">
                        <span>{formatTs(item.ts)}</span>
                        <span className={`pill ${item.badgeClass}`}>{item.label}</span>
                      </div>
                      <div className="nac-log-line">
                        <strong>{item.source}</strong> {item.title}
                      </div>
                      <div className="nac-log-line nac-log-muted">{item.detail}</div>
                    </li>
                  ))}
                </ul>
              )}
            </article>

            <article className="nac-panel nac-activity-panel">
              <div className="nac-panel-head">
                <h2>System Activity</h2>
                <span>All devices</span>
              </div>
              {systemActivityItems.length === 0 ? (
                <p className="nac-placeholder">No system activity recorded yet.</p>
              ) : (
                <ul className="nac-log-list nac-log-list-fill">
                  {systemActivityItems.slice(0, 20).map((item, index) => (
                    <li key={`${item.source}-${item.ts}-${index}`}>
                      <div className="nac-log-top">
                        <span>{formatTs(item.ts)}</span>
                        <span className={`pill ${item.badgeClass}`}>{item.label}</span>
                      </div>
                      <div className="nac-log-line">
                        <strong>{item.source}</strong> {item.title}
                      </div>
                      <div className="nac-log-line nac-log-muted">{item.detail}</div>
                    </li>
                  ))}
                </ul>
              )}
            </article>
          </div>

          <div className="nac-dashboard-col nac-dashboard-col-secondary">
            <article className="nac-panel nac-panel-scroll">
              <div className="nac-panel-head">
                <h2>Enrollment and Identity</h2>
                <span>{selectedDeviceId || 'Select a device'}</span>
              </div>

              <section className="nac-subpanel">
                <div className="nac-subpanel-head">
                  <h3>Add Device</h3>
                  <HelpToggle
                    open={openHelp === 'addDevice'}
                    onClick={() => toggleHelp('addDevice')}
                  />
                </div>
                {openHelp === 'addDevice' ? (
                  <p className="nac-help-copy">
                    Create a pending device first if you want to label it or enroll a key before changing access.
                  </p>
                ) : null}
                <div className="nac-inline-form nac-inline-form-wide">
                  <input
                    value={createForm.id}
                    onChange={(event) =>
                      setCreateForm((current) => ({ ...current, id: event.target.value }))
                    }
                    placeholder="Device ID"
                  />
                  <input
                    value={createForm.alias}
                    onChange={(event) =>
                      setCreateForm((current) => ({ ...current, alias: event.target.value }))
                    }
                    placeholder="Alias (letters, numbers, spaces, . _ -)"
                  />
                  <button
                    className="nac-btn nac-btn-primary"
                    disabled={createSaving}
                    onClick={() => {
                      void createDevice();
                    }}
                  >
                    {createSaving ? 'Saving...' : 'Create Pending'}
                  </button>
                </div>
                {createMessage ? <p className="nac-feedback">{createMessage}</p> : null}
              </section>

              {!selectedDevice || !identityProfile ? (
                <p className="nac-placeholder">
                  Select a device to edit its label, enroll a key, and review policy or audit status.
                </p>
              ) : (
                <>
                  <section className="nac-subpanel">
                    <div className="nac-device-head">
                      <div>
                        <h3>{readDeviceTitle(selectedDevice)}</h3>
                        <p>{selectedDevice.id}</p>
                      </div>
                      <div className="nac-head-actions">
                        <span className={`pill ${identityClass(identityProfile.identityStatus)}`}>
                          {identityProfile.identityStatus}
                        </span>
                        <HelpToggle
                          open={openHelp === 'identityStatus'}
                          onClick={() => toggleHelp('identityStatus')}
                        />
                      </div>
                    </div>

                    <div className="nac-detail-grid">
                      <div>
                        <span>Alias</span>
                        <strong>{identityProfile.alias ?? 'none set'}</strong>
                      </div>
                      <div>
                        <span>Archive</span>
                        <strong>
                          {identityProfile.archivedAt
                            ? `archived ${formatTs(identityProfile.archivedAt)}`
                            : 'active'}
                        </strong>
                      </div>
                      <div>
                        <span>Hostname</span>
                        <strong>{identityProfile.hostname ?? 'unknown'}</strong>
                      </div>
                      <div>
                        <span>Vendor</span>
                        <strong>{identityProfile.vendor ?? 'unknown'}</strong>
                      </div>
                      <div>
                        <span>Model</span>
                        <strong>{identityProfile.model ?? 'unknown'}</strong>
                      </div>
                      <div>
                        <span>Location</span>
                        <strong>{identityProfile.location ?? 'unset'}</strong>
                      </div>
                      <div>
                        <span>MAC</span>
                        <strong>{identityProfile.macAddress ?? 'unset'}</strong>
                      </div>
                      <div>
                        <span>Policy State</span>
                        <strong>{selectedDevice.state}</strong>
                      </div>
                      <div>
                        <span>Key Source</span>
                        <strong>{identityProfile.keySource}</strong>
                      </div>
                      <div>
                        <span>Key Updated</span>
                        <strong>{formatTs(identityProfile.keyUpdatedAt)}</strong>
                      </div>
                      <div>
                        <span>Last Check</span>
                        <strong>{formatTs(identityProfile.lastIdentityCheck)}</strong>
                      </div>
                      <div>
                        <span>Recent Failures</span>
                        <strong>{identityProfile.security.recentFailures}</strong>
                      </div>
                    </div>

                    <div className="nac-tag-row">
                      <span className={`pill ${profileSourceClass(identityProfile.profileSources.hostname)}`}>
                        hostname {profileSourceLabel(identityProfile.profileSources.hostname)}
                      </span>
                      <span className={`pill ${profileSourceClass(identityProfile.profileSources.vendor)}`}>
                        vendor {profileSourceLabel(identityProfile.profileSources.vendor)}
                      </span>
                      <span className={`pill ${profileSourceClass(identityProfile.profileSources.model)}`}>
                        model {profileSourceLabel(identityProfile.profileSources.model)}
                      </span>
                    </div>

                    <div className="nac-tag-row">
                      <span className={`pill ${identityClass(identityProfile.identityStatus)}`}>
                        {identityProfile.identityStatus}
                      </span>
                      <span
                        className={`pill ${
                          identityProfile.keyConfigured ? 'pill-good' : 'pill-neutral'
                        }`}
                      >
                        {identityProfile.keyConfigured
                          ? 'device key configured'
                          : 'no device key enrolled'}
                      </span>
                      <span
                        className={`pill ${
                          identityProfile.provisioning.active ? 'pill-warn' : 'pill-neutral'
                        }`}
                      >
                        {identityProfile.provisioning.active
                          ? 'provisioning token active'
                          : 'no active provisioning token'}
                      </span>
                      <span
                        className={`pill ${
                          identityProfile.security.lockedOut ? 'pill-bad' : 'pill-neutral'
                        }`}
                      >
                        {identityProfile.security.lockedOut ? 'lockout active' : 'lockout clear'}
                      </span>
                    </div>

                    {openHelp === 'identityStatus' ? (
                      <div className="nac-help-stack">
                        <p className="nac-help-copy">
                          {identityStatusMessage(identityProfile.identityStatus)}
                        </p>
                        {selectedDevice.identityStatus === 'pending' ? (
                          <p className="nac-help-copy">
                            Allow stays unavailable until this device finishes enrollment.
                          </p>
                        ) : null}
                        {latestBlockedDecision ? (
                          <p className="nac-help-copy">
                            Latest blocked policy: <strong>{latestBlockedDecision.message}</strong>
                          </p>
                        ) : null}
                        {identityProfile.security.lockoutUntil ? (
                          <p className="nac-help-copy">
                            Lockout until: {formatTs(identityProfile.security.lockoutUntil)}
                          </p>
                        ) : null}
                      </div>
                    ) : null}
                  </section>

                  <section className="nac-subpanel">
                    <div className="nac-subpanel-head">
                      <h3>Manage Device</h3>
                      <HelpToggle
                        open={openHelp === 'manageDevice'}
                        onClick={() => toggleHelp('manageDevice')}
                      />
                    </div>
                    {openHelp === 'manageDevice' ? (
                      <div className="nac-help-stack">
                        <p className="nac-help-copy">
                          Alias supports letters, numbers, spaces, dots, underscores, and hyphens.
                        </p>
                        <p className="nac-help-copy">
                          Rotating the key moves the device back to enrolled until it verifies again.
                        </p>
                      </div>
                    ) : null}

                    <label className="nac-field">
                      <span>Alias</span>
                      <div className="nac-inline-form">
                        <input
                          value={aliasInput}
                          onChange={(event) => setAliasInput(event.target.value)}
                          placeholder="Friendly label"
                        />
                        <button
                          className="nac-btn"
                          disabled={aliasSaving}
                          onClick={() => {
                            void saveAlias();
                          }}
                        >
                          {aliasSaving ? 'Saving...' : 'Save Alias'}
                        </button>
                      </div>
                    </label>

                    <div className="nac-profile-grid">
                      <label className="nac-field">
                        <span>Hostname</span>
                        <input
                          value={profileForm.hostname}
                          onChange={(event) =>
                            setProfileForm((current) => ({ ...current, hostname: event.target.value }))
                          }
                          placeholder="Device hostname"
                        />
                      </label>
                      <label className="nac-field">
                        <span>Vendor</span>
                        <input
                          value={profileForm.vendor}
                          onChange={(event) =>
                            setProfileForm((current) => ({ ...current, vendor: event.target.value }))
                          }
                          placeholder="Device vendor"
                        />
                      </label>
                      <label className="nac-field">
                        <span>Model</span>
                        <input
                          value={profileForm.model}
                          onChange={(event) =>
                            setProfileForm((current) => ({ ...current, model: event.target.value }))
                          }
                          placeholder="Device model"
                        />
                      </label>
                      <label className="nac-field">
                        <span>Location</span>
                        <input
                          value={profileForm.location}
                          onChange={(event) =>
                            setProfileForm((current) => ({ ...current, location: event.target.value }))
                          }
                          placeholder="Rack, room, or area"
                        />
                      </label>
                      <label className="nac-field nac-profile-grid-wide">
                        <span>MAC Address</span>
                        <input
                          value={profileForm.macAddress}
                          onChange={(event) =>
                            setProfileForm((current) => ({ ...current, macAddress: event.target.value }))
                          }
                          placeholder="AA:BB:CC:DD:EE:FF"
                        />
                      </label>
                    </div>

                    <div className="nac-inline-form nac-inline-form-wide">
                      <button
                        className="nac-btn"
                        disabled={profileSaving}
                        onClick={() => {
                          void saveProfile();
                        }}
                      >
                        {profileSaving ? 'Saving...' : 'Save Profile'}
                      </button>
                      <button
                        className={`nac-btn ${selectedDevice.archivedAt ? 'nac-btn-primary' : 'nac-btn-deny'}`}
                        disabled={archiveBusy}
                        onClick={() => {
                          void toggleArchiveState();
                        }}
                      >
                        {archiveBusy
                          ? 'Working...'
                          : selectedDevice.archivedAt
                            ? 'Restore Device'
                            : 'Archive Device'}
                      </button>
                    </div>

                    <label className="nac-field">
                      <span>
                        {identityProfile.keyConfigured ? 'Rotate Device Key' : 'Enroll Device Key'}
                      </span>
                      <div className="nac-inline-form">
                        <input
                          type={showSecretInput ? 'text' : 'password'}
                          value={secretInput}
                          onChange={(event) => setSecretInput(event.target.value)}
                          placeholder="Minimum 16 characters"
                        />
                        <button
                          className="nac-btn nac-btn-subtle"
                          onClick={() => setShowSecretInput((current) => !current)}
                        >
                          {showSecretInput ? 'Hide' : 'Show'}
                        </button>
                        <button
                          className="nac-btn nac-btn-primary"
                          disabled={secretSaving}
                          onClick={() => {
                            void saveIdentityKey();
                          }}
                        >
                          {secretSaving
                            ? 'Saving...'
                            : identityProfile.keyConfigured
                              ? 'Rotate Key'
                              : 'Enroll Device'}
                        </button>
                      </div>
                    </label>

                    {identityMessage ? <p className="nac-feedback">{identityMessage}</p> : null}
                  </section>

                  {identityProfile.identityStatus === 'enrolled' ? (
                    <section className="nac-subpanel">
                      <div className="nac-subpanel-head">
                        <h3>Finish Verification</h3>
                        <HelpToggle
                          open={openHelp === 'finishVerification'}
                          onClick={() => toggleHelp('finishVerification')}
                        />
                      </div>

                      {openHelp === 'finishVerification' ? (
                        <p className="nac-help-copy">
                          This device has a key but still needs its first signed heartbeat before it can be allowed.
                        </p>
                      ) : null}

                      <div className="nac-inline-form nac-inline-form-wide">
                        <button
                          className="nac-btn"
                          disabled={provisioningBusy}
                          onClick={() => {
                            void reissueProvisioningToken();
                          }}
                        >
                          {provisioningBusy ? 'Issuing...' : 'Reissue Token'}
                        </button>
                        {lastProvisioningToken?.deviceId === selectedDeviceId ? (
                          <button
                            className="nac-btn nac-btn-subtle"
                            onClick={() => {
                              void copyText(
                                lastProvisioningToken.token,
                                'Provisioning token copied to clipboard.',
                              );
                            }}
                          >
                            Copy Token
                          </button>
                        ) : null}
                        <button
                          className="nac-btn nac-btn-subtle"
                          onClick={() => {
                            void copyText(
                              heartbeatSnippet,
                              'Heartbeat example copied to clipboard.',
                            );
                          }}
                        >
                          Copy Heartbeat Example
                        </button>
                      </div>

                      {lastProvisioningToken?.deviceId === selectedDeviceId ? (
                        <div className="nac-token-box">
                          <span>Provisioning token</span>
                          <code>{lastProvisioningToken.token}</code>
                        </div>
                      ) : null}
                    </section>
                  ) : null}
                </>
              )}
            </article>

            <article className="nac-panel">
              <div className="nac-panel-head">
                <h2>Export and Download</h2>
                <span>CSV or JSON</span>
              </div>

              <div className="nac-export-grid">
                <label className="nac-field">
                  <span>Scope</span>
                  <select
                    value={exportScope}
                    onChange={(event) => setExportScope(event.target.value as ExportScope)}
                  >
                    <option value="audit">Audit log</option>
                    <option value="enforcement">Enforcement history</option>
                    <option value="events">Security events</option>
                  </select>
                </label>

                <label className="nac-field">
                  <span>Format</span>
                  <select
                    value={exportFormat}
                    onChange={(event) => setExportFormat(event.target.value as ExportFormat)}
                  >
                    <option value="csv">CSV</option>
                    <option value="json">JSON</option>
                  </select>
                </label>

                <label className="nac-field">
                  <span>From</span>
                  <input
                    type="datetime-local"
                    value={exportFrom}
                    onChange={(event) => setExportFrom(event.target.value)}
                  />
                </label>

                <label className="nac-field">
                  <span>To</span>
                  <input
                    type="datetime-local"
                    value={exportTo}
                    onChange={(event) => setExportTo(event.target.value)}
                  />
                </label>

                {exportScope === 'events' ? (
                  <label className="nac-field">
                    <span>Event Type</span>
                    <select
                      value={exportEventType}
                      onChange={(event) =>
                        setExportEventType(event.target.value as EventTypeOption)
                      }
                    >
                      {EVENT_TYPE_OPTIONS.map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
              </div>

              <div className="nac-export-actions">
                <label className="nac-checkbox-row">
                  <input
                    type="checkbox"
                    checked={exportSelectedOnly}
                    onChange={(event) => setExportSelectedOnly(event.target.checked)}
                  />
                  <span>
                    Export only the selected device
                    {selectedDeviceId ? ` (${selectedDeviceId})` : ''}
                  </span>
                </label>

                <button
                  className="nac-btn nac-btn-primary"
                  disabled={exporting}
                  onClick={() => {
                    void downloadExport();
                  }}
                >
                  {exporting ? 'Preparing...' : 'Download Export'}
                </button>
              </div>

              {exportMessage ? <p className="nac-feedback">{exportMessage}</p> : null}
            </article>
          </div>
        </section>
      </main>
    </div>
  );
}
