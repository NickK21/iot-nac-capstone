import { useCallback, useEffect, useMemo, useState } from 'react';
import './App.css';

const API_BASE = 'http://localhost:3000';
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
type IdentityFilter = (typeof IDENTITY_FILTERS)[number];
type EventTypeOption = (typeof EVENT_TYPE_OPTIONS)[number];
type ExportScope = 'audit' | 'enforcement' | 'events';
type ExportFormat = 'csv' | 'json';

type Device = {
  id: string;
  alias?: string | null;
  hostname?: string;
  vendor?: string;
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

type EnrollmentEntry = {
  ts: string;
  deviceId: string;
  action:
    | 'pending_created'
    | 'device_enrolled'
    | 'key_rotated'
    | 'alias_updated'
    | 'provisioning_token_issued'
    | 'provisioning_token_consumed';
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
    payloadFields: ['id', 'hostname', 'vendor'];
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

type IssuedProvisioningToken = ProvisioningTokenIssue & {
  deviceId: string;
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

function enrollmentActionLabel(action: EnrollmentEntry['action']): string {
  switch (action) {
    case 'pending_created':
      return 'pending';
    case 'device_enrolled':
      return 'enrolled';
    case 'key_rotated':
      return 'rotated';
    case 'alias_updated':
      return 'alias';
    case 'provisioning_token_issued':
      return 'token issued';
    case 'provisioning_token_consumed':
      return 'token used';
  }
}

function enrollmentActionClass(action: EnrollmentEntry['action']): string {
  switch (action) {
    case 'device_enrolled':
    case 'provisioning_token_consumed':
      return 'pill-good';
    case 'key_rotated':
    case 'provisioning_token_issued':
      return 'pill-warn';
    default:
      return 'pill-neutral';
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

function matchesSearch(device: Device, query: string): boolean {
  if (!query.trim()) {
    return true;
  }

  const haystack = [
    device.alias ?? '',
    device.id,
    device.hostname ?? '',
    device.vendor ?? '',
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
  const [devices, setDevices] = useState<Device[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [enforcement, setEnforcement] = useState<EnforcementEntry[]>([]);
  const [enrollmentHistory, setEnrollmentHistory] = useState<EnrollmentEntry[]>([]);
  const [identityProfile, setIdentityProfile] = useState<IdentityProfile | null>(null);

  const [selectedDeviceId, setSelectedDeviceId] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [identityFilter, setIdentityFilter] = useState<IdentityFilter>('all');

  const [secretInput, setSecretInput] = useState('');
  const [showSecretInput, setShowSecretInput] = useState(false);
  const [aliasInput, setAliasInput] = useState('');
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

  const [loading, setLoading] = useState(true);
  const [secretSaving, setSecretSaving] = useState(false);
  const [aliasSaving, setAliasSaving] = useState(false);
  const [inlineAliasSaving, setInlineAliasSaving] = useState(false);
  const [createSaving, setCreateSaving] = useState(false);
  const [provisioningBusy, setProvisioningBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);

  const [lastRefreshAt, setLastRefreshAt] = useState<string | null>(null);
  const [identityMessage, setIdentityMessage] = useState<string | null>(null);
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

  const filteredDevices = useMemo(() => {
    return devices.filter((device) => {
      if (identityFilter !== 'all' && device.identityStatus !== identityFilter) {
        return false;
      }

      return matchesSearch(device, searchQuery);
    });
  }, [devices, identityFilter, searchQuery]);

  const metrics = useMemo(() => {
    const pendingCount = devices.filter((device) => device.identityStatus === 'pending').length;
    const enrolledCount = devices.filter((device) => device.identityStatus === 'enrolled').length;
    const verifiedCount = devices.filter((device) => device.identityStatus === 'verified').length;
    const invalidCount = devices.filter((device) => device.identityStatus === 'invalid').length;
    const lockedCount = devices.filter((device) => device.identityStatus === 'locked').length;
    const deniedCount = devices.filter((device) => device.state === 'denied').length;

    return {
      total: devices.length,
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
      `  -d '{"id":"${selectedDevice.id}","hostname":"device-host","vendor":"device-vendor"}'`,
    );

    return lines.join('\n');
  }, [identityProfile, lastProvisioningToken, selectedDevice]);

  const loadCore = useCallback(async (options?: { silent?: boolean }) => {
    try {
      if (!options?.silent) {
        setLoading(true);
      }
      setError(null);

      const [devicesRes, auditRes, eventsRes] = await Promise.all([
        fetch(`${API_BASE}/devices`),
        fetch(`${API_BASE}/audit`),
        fetch(`${API_BASE}/events/recent?limit=40`),
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

      const nextDevices = (await devicesRes.json()) as Device[];
      const nextAudit = (await auditRes.json()) as AuditEntry[];
      const nextEvents = (await eventsRes.json()) as SecurityEvent[];

      setDevices(nextDevices);
      setAudit(nextAudit);
      setEvents(nextEvents);
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
      setEnrollmentHistory([]);
      setIdentityProfile(null);
      return;
    }

    const [enforcementRes, identityRes, enrollmentRes] = await Promise.all([
      fetch(`${API_BASE}/devices/${deviceId}/enforcement`),
      fetch(`${API_BASE}/devices/${deviceId}/identity`),
      fetch(`${API_BASE}/devices/${deviceId}/enrollment-history`),
    ]);

    if (!enforcementRes.ok) {
      throw new Error(await readErrorMessage(enforcementRes));
    }

    if (!identityRes.ok) {
      throw new Error(await readErrorMessage(identityRes));
    }

    if (!enrollmentRes.ok) {
      throw new Error(await readErrorMessage(enrollmentRes));
    }

    const nextEnforcement = (await enforcementRes.json()) as EnforcementEntry[];
    const nextIdentity = (await identityRes.json()) as IdentityProfile;
    const nextEnrollment = (await enrollmentRes.json()) as EnrollmentEntry[];

    setEnforcement(nextEnforcement);
    setIdentityProfile(nextIdentity);
    setEnrollmentHistory(nextEnrollment);
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
      } catch (requestError) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : `Failed to ${action} device`,
        );
      } finally {
        setBusyDeviceId(null);
      }
    },
    [loadCore, loadSelectedContext, selectedDeviceId],
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
      setEnrollmentHistory([]);
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
    setSecretInput('');
    setShowSecretInput(false);
    setIdentityMessage(null);
    setAliasInput(selectedDevice?.alias ?? '');
    setEditingAliasId(null);
    setInlineAliasInput('');
  }, [selectedDevice]);

  return (
    <div className="nac-shell">
      <main className="nac-app">
        <header className="nac-header">
          <div>
            <p className="nac-kicker">IoT NAC Control Plane</p>
            <h1>Enrollment, Identity, Policy, and Audit Operations</h1>
            <p className="nac-subtitle">
              Search and filter inventory, label devices, issue provisioning tokens,
              verify signed heartbeats, and export audit data as CSV or JSON.
            </p>
          </div>
          <div className="nac-sync-chip">Last sync: {formatTs(lastRefreshAt)}</div>
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

        <section className="nac-main-grid">
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
                placeholder="Search alias, device ID, hostname, or vendor"
              />
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
                                disabled={
                                  busyDeviceId === device.id || device.state === 'allowed'
                                }
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void setDevicePolicy(device.id, 'allow');
                                }}
                              >
                                Allow
                              </button>
                              <button
                                className="nac-btn nac-btn-deny"
                                disabled={
                                  busyDeviceId === device.id || device.state === 'denied'
                                }
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void setDevicePolicy(device.id, 'deny');
                                }}
                              >
                                Deny
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </article>

          <article className="nac-panel">
            <div className="nac-panel-head">
              <h2>Enrollment and Identity</h2>
              <span>{selectedDeviceId || 'Register a device to begin'}</span>
            </div>

            <section className="nac-subpanel">
              <div className="nac-subpanel-head">
                <h3>Register Pending Device</h3>
                <span>Create an inventory placeholder before enrollment</span>
              </div>
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
                Select a device to review its lifecycle, edit its alias, or manage provisioning.
              </p>
            ) : (
              <>
                <section className="nac-subpanel">
                  <div className="nac-device-head">
                    <div>
                      <h3>{readDeviceTitle(selectedDevice)}</h3>
                      <p>{selectedDevice.id}</p>
                    </div>
                    <span className={`pill ${identityClass(identityProfile.identityStatus)}`}>
                      {identityProfile.identityStatus}
                    </span>
                  </div>

                  <div className="nac-detail-grid">
                    <div>
                      <span>Alias</span>
                      <strong>{identityProfile.alias ?? 'none set'}</strong>
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

                  <p className="nac-note">
                    {identityStatusMessage(identityProfile.identityStatus)}
                  </p>
                  {latestBlockedDecision ? (
                    <p className="nac-note">
                      Latest blocked policy: <strong>{latestBlockedDecision.message}</strong>
                    </p>
                  ) : null}
                  {identityProfile.security.lockoutUntil ? (
                    <p className="nac-note">
                      Lockout until: {formatTs(identityProfile.security.lockoutUntil)}
                    </p>
                  ) : null}
                </section>

                <section className="nac-subpanel">
                  <div className="nac-subpanel-head">
                    <h3>Lifecycle Guide</h3>
                    <span>How devices move through trust states</span>
                  </div>
                  <ul className="nac-guide-list">
                    <li>
                      <strong>Pending:</strong> inventory exists, but the device does not have an enrolled key yet.
                    </li>
                    <li>
                      <strong>Enrolled:</strong> key and provisioning token were issued; the first signed heartbeat is still required.
                    </li>
                    <li>
                      <strong>Verified:</strong> the device completed provisioning and the latest signed heartbeat validated.
                    </li>
                    <li>
                      <strong>Invalid:</strong> signature, timestamp, nonce, or provisioning checks failed.
                    </li>
                    <li>
                      <strong>Locked:</strong> repeated identity failures triggered temporary lockout.
                    </li>
                  </ul>
                </section>

                <section className="nac-subpanel">
                  <div className="nac-subpanel-head">
                    <h3>Operator Actions</h3>
                    <span>Edit alias, enroll key, and manage rotation</span>
                  </div>

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
                    <small className="nac-field-note">
                      Allowed: letters, numbers, spaces, dots, underscores, and hyphens.
                    </small>
                  </label>

                  <label className="nac-field">
                    <span>{identityProfile.keyConfigured ? 'Rotate Device Key' : 'Enroll Device Key'}</span>
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
                    <small className="nac-field-note">
                      Rotating a key resets the device to the enrolled state until it verifies again.
                    </small>
                  </label>

                  {identityMessage ? <p className="nac-feedback">{identityMessage}</p> : null}
                </section>

                <section className="nac-subpanel">
                  <div className="nac-subpanel-head">
                    <h3>Provisioning Contract</h3>
                    <span>First verified heartbeat requirements</span>
                  </div>

                  <div className="nac-detail-grid">
                    <div>
                      <span>Provisioning Header</span>
                      <strong>{identityProfile.provisioning.headerName}</strong>
                    </div>
                    <div>
                      <span>Token Expires</span>
                      <strong>{formatTs(identityProfile.provisioning.expiresAt)}</strong>
                    </div>
                    <div>
                      <span>HMAC Format</span>
                      <strong>{identityProfile.hmac.canonicalFormat}</strong>
                    </div>
                    <div>
                      <span>Heartbeat Endpoint</span>
                      <strong>{identityProfile.heartbeat.endpoint}</strong>
                    </div>
                  </div>

                  <p className="nac-note">
                    First successful verification while enrolled requires both a valid HMAC and the one-time provisioning token.
                  </p>
                  <p className="nac-note">
                    Timestamp skew {identityProfile.hmac.maxSkewMs}ms, nonce TTL{' '}
                    {identityProfile.hmac.nonceTtlMs}ms.
                  </p>

                  <div className="nac-inline-form">
                    <button
                      className="nac-btn"
                      disabled={provisioningBusy || identityProfile.identityStatus !== 'enrolled'}
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
                  </div>

                  {lastProvisioningToken?.deviceId === selectedDeviceId ? (
                    <div className="nac-token-box">
                      <span>One-time provisioning token</span>
                      <code>{lastProvisioningToken.token}</code>
                    </div>
                  ) : null}

                  <div className="nac-code-head">
                    <span>Heartbeat Example</span>
                    <button
                      className="nac-btn nac-btn-subtle"
                      onClick={() => {
                        void copyText(heartbeatSnippet, 'Heartbeat example copied to clipboard.');
                      }}
                    >
                      Copy Example
                    </button>
                  </div>
                  <pre className="nac-code-block">
                    <code>{heartbeatSnippet}</code>
                  </pre>
                </section>
              </>
            )}
          </article>
        </section>

        <section className="nac-log-grid">
          <article className="nac-panel">
            <div className="nac-panel-head">
              <h2>Enrollment History</h2>
              <span>{selectedDeviceId || 'No device selected'}</span>
            </div>

            {enrollmentHistory.length === 0 ? (
              <p className="nac-placeholder">No enrollment actions recorded yet.</p>
            ) : (
              <ul className="nac-log-list">
                {enrollmentHistory.slice(-24).reverse().map((entry, index) => (
                  <li key={`${entry.ts}-${index}`}>
                    <div className="nac-log-top">
                      <span>{formatTs(entry.ts)}</span>
                      <span className={`pill ${enrollmentActionClass(entry.action)}`}>
                        {enrollmentActionLabel(entry.action)}
                      </span>
                    </div>
                    <div className="nac-log-line nac-log-muted">{entry.message}</div>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="nac-panel">
            <div className="nac-panel-head">
              <h2>Enforcement History</h2>
              <span>{selectedDeviceId || 'No device selected'}</span>
            </div>

            {enforcement.length === 0 ? (
              <p className="nac-placeholder">No enforcement decisions recorded yet.</p>
            ) : (
              <ul className="nac-log-list">
                {enforcement.slice(-20).reverse().map((entry, index) => (
                  <li key={`${entry.ts}-${index}`}>
                    <div className="nac-log-top">
                      <span>{formatTs(entry.ts)}</span>
                      <span className={`pill ${policyCodeClass(entry.code)}`}>
                        {policyCodeLabel(entry.code)}
                      </span>
                    </div>
                    <div className="nac-log-line">
                      <strong>{entry.action}</strong> {entry.prevState} to {entry.nextState}{' '}
                      ({entry.result})
                    </div>
                    <div className="nac-log-line nac-log-muted">{entry.message}</div>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="nac-panel">
            <div className="nac-panel-head">
              <h2>Security Events</h2>
              <span>Recent activity</span>
            </div>

            {events.length === 0 ? (
              <p className="nac-placeholder">No security events recorded yet.</p>
            ) : (
              <ul className="nac-log-list">
                {events.slice(-24).reverse().map((event) => (
                  <li key={event.id}>
                    <div className="nac-log-top">
                      <span>{formatTs(event.ts)}</span>
                      <span className={`pill ${severityClass(event.severity)}`}>
                        {event.severity}
                      </span>
                    </div>
                    <div className="nac-log-line">
                      <strong>{event.type}</strong>{' '}
                      {event.deviceId
                        ? deviceLabelById.get(event.deviceId) ?? event.deviceId
                        : 'system'}
                    </div>
                    <div className="nac-log-line nac-log-muted">{event.message}</div>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="nac-panel">
            <div className="nac-panel-head">
              <h2>Policy Audit</h2>
              <span>Applied transitions</span>
            </div>

            {audit.length === 0 ? (
              <p className="nac-placeholder">No policy changes yet.</p>
            ) : (
              <ul className="nac-log-list">
                {audit.slice(-20).reverse().map((entry, index) => (
                  <li key={`${entry.ts}-${index}`}>
                    <div className="nac-log-line">
                      <span>{formatTs(entry.ts)}</span>
                    </div>
                    <div className="nac-log-line">
                      <strong>{deviceLabelById.get(entry.deviceId) ?? entry.deviceId}</strong>{' '}
                      {entry.action} ({entry.prev} to {entry.next})
                    </div>
                  </li>
                ))}
              </ul>
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

            {exportMessage ? <p className="nac-feedback">{exportMessage}</p> : null}
          </article>
        </section>
      </main>
    </div>
  );
}
