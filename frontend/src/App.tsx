import { useCallback, useEffect, useMemo, useState } from 'react';
import './App.css';

const API_BASE = 'http://localhost:3000';

type DeviceState = 'allowed' | 'denied' | 'unknown';
type IdentityStatus = 'unverified' | 'verified' | 'invalid';

type Device = {
  id: string;
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
  | 'identity_invalid'
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

type IdentityProfile = {
  deviceId: string;
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
};

type IdentityKeyResponse = {
  deviceId: string;
  keyUpdatedAt: string;
  changeType: 'created' | 'updated';
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
    case 'invalid':
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
    case 'identity_invalid':
      return 'identity invalid';
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
    case 'identity_invalid':
      return 'pill-bad';
    case 'already_allowed':
    case 'already_denied':
      return 'pill-warn';
    default:
      return 'pill-good';
  }
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

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [enforcement, setEnforcement] = useState<EnforcementEntry[]>([]);
  const [identityProfile, setIdentityProfile] = useState<IdentityProfile | null>(null);

  const [selectedDeviceId, setSelectedDeviceId] = useState('');
  const [secretInput, setSecretInput] = useState('');

  const [loading, setLoading] = useState(true);
  const [secretSaving, setSecretSaving] = useState(false);
  const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);

  const [lastRefreshAt, setLastRefreshAt] = useState<string | null>(null);
  const [secretMessage, setSecretMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedDevice = useMemo(
    () => devices.find((device) => device.id === selectedDeviceId) ?? null,
    [devices, selectedDeviceId],
  );

  const metrics = useMemo(() => {
    const verifiedCount = devices.filter((device) => device.identityStatus === 'verified').length;
    const invalidCount = devices.filter((device) => device.identityStatus === 'invalid').length;
    const deniedCount = devices.filter((device) => device.state === 'denied').length;
    const warningCount = events.filter((event) => event.severity !== 'info').length;

    return {
      total: devices.length,
      verifiedCount,
      invalidCount,
      deniedCount,
      warningCount,
    };
  }, [devices, events]);

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
      setIdentityProfile(null);
      return;
    }

    const [enforcementRes, identityRes] = await Promise.all([
      fetch(`${API_BASE}/devices/${deviceId}/enforcement`),
      fetch(`${API_BASE}/devices/${deviceId}/identity`),
    ]);

    if (!enforcementRes.ok) {
      throw new Error(await readErrorMessage(enforcementRes));
    }

    if (!identityRes.ok) {
      throw new Error(await readErrorMessage(identityRes));
    }

    const nextEnforcement = (await enforcementRes.json()) as EnforcementEntry[];
    const nextIdentity = (await identityRes.json()) as IdentityProfile;

    setEnforcement(nextEnforcement);
    setIdentityProfile(nextIdentity);
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

  const saveIdentityKey = useCallback(async () => {
    if (!selectedDeviceId) {
      setSecretMessage('Select a device first.');
      return;
    }

    if (secretInput.trim().length < 16) {
      setSecretMessage('Device key must be at least 16 characters.');
      return;
    }

    try {
      setSecretSaving(true);
      setSecretMessage(null);
      setError(null);

      const response = await fetch(`${API_BASE}/devices/${selectedDeviceId}/identity/key`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ secret: secretInput.trim() }),
      });

      if (!response.ok) {
        throw new Error(await readErrorMessage(response));
      }

      const body = (await response.json()) as IdentityKeyResponse;
      setSecretInput('');
      setSecretMessage(
        `Identity key ${body.changeType} at ${formatTs(body.keyUpdatedAt)}`,
      );

      await loadCore({ silent: true });
      await loadSelectedContext(selectedDeviceId);
    } catch (requestError) {
      setSecretMessage(
        requestError instanceof Error
          ? requestError.message
          : 'Failed to save identity key',
      );
    } finally {
      setSecretSaving(false);
    }
  }, [loadCore, loadSelectedContext, secretInput, selectedDeviceId]);

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
    setSecretMessage(null);
  }, [selectedDeviceId]);

  return (
    <div className="nac-shell">
      <main className="nac-app">
        <header className="nac-header">
          <div>
            <p className="nac-kicker">IoT NAC Control Plane</p>
            <h1>Device Identity and Policy Operations</h1>
            <p className="nac-subtitle">
              Persistent inventory, signed heartbeat validation, and policy
              enforcement records.
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
            <span>Verified Identity</span>
            <strong>{metrics.verifiedCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Invalid Identity</span>
            <strong>{metrics.invalidCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Denied Devices</span>
            <strong>{metrics.deniedCount}</strong>
          </div>
          <div className="nac-metric-card">
            <span>Active Warnings</span>
            <strong>{metrics.warningCount}</strong>
          </div>
        </section>

        <section className="nac-main-grid">
          <article className="nac-panel">
            <div className="nac-panel-head">
              <h2>Device Inventory</h2>
              <span>{loading ? 'Refreshing...' : `${devices.length} tracked`}</span>
            </div>

            <div className="nac-table-scroll">
              <table className="nac-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Hostname</th>
                    <th>Vendor</th>
                    <th>Last Seen</th>
                    <th>State</th>
                    <th>Identity</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.length === 0 ? (
                    <tr>
                      <td className="nac-empty" colSpan={7}>
                        No devices discovered yet.
                      </td>
                    </tr>
                  ) : (
                    devices.map((device) => (
                      <tr
                        key={device.id}
                        className={
                          device.id === selectedDeviceId ? 'nac-row-selected' : undefined
                        }
                        onClick={() => setSelectedDeviceId(device.id)}
                      >
                        <td className="nac-id">{device.id}</td>
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
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </article>

          <article className="nac-panel">
            <div className="nac-panel-head">
              <h2>Device Identity</h2>
              <span>{selectedDeviceId || 'No device selected'}</span>
            </div>

            {!selectedDevice || !identityProfile ? (
              <p className="nac-placeholder">Select a device to manage identity settings.</p>
            ) : (
              <>
                <div className="nac-detail-grid">
                  <div>
                    <span>Identity Status</span>
                    <strong>{identityProfile.identityStatus}</strong>
                  </div>
                  <div>
                    <span>Key Source</span>
                    <strong>{identityProfile.keySource}</strong>
                  </div>
                  <div>
                    <span>Last Check</span>
                    <strong>{formatTs(identityProfile.lastIdentityCheck)}</strong>
                  </div>
                  <div>
                    <span>Key Updated</span>
                    <strong>{formatTs(identityProfile.keyUpdatedAt)}</strong>
                  </div>
                </div>

                <div className="nac-tag-row">
                  <span className={`pill ${identityClass(identityProfile.identityStatus)}`}>
                    {identityProfile.identityStatus}
                  </span>
                  <span className={`pill ${identityProfile.keyConfigured ? 'pill-good' : 'pill-neutral'}`}>
                    {identityProfile.keyConfigured ? 'device key configured' : 'fallback key in use'}
                  </span>
                  <span
                    className={`pill ${
                      identityProfile.security.lockedOut ? 'pill-bad' : 'pill-neutral'
                    }`}
                  >
                    {identityProfile.security.lockedOut ? 'temporarily locked' : 'not locked'}
                  </span>
                </div>

                <p className="nac-note">
                  Canonical signature input:{' '}
                  <code>{identityProfile.hmac.canonicalFormat}</code>
                </p>
                <p className="nac-note">
                  Allowed skew {identityProfile.hmac.maxSkewMs}ms, nonce TTL{' '}
                  {identityProfile.hmac.nonceTtlMs}ms.
                </p>
                <p className="nac-note">
                  Failure window {identityProfile.security.failureWindowMs}ms with max{' '}
                  {identityProfile.security.maxFailures} attempts. Recent failures:{' '}
                  {identityProfile.security.recentFailures}.
                </p>
                {identityProfile.security.lockoutUntil ? (
                  <p className="nac-note">
                    Lockout until: {formatTs(identityProfile.security.lockoutUntil)}
                  </p>
                ) : null}

                <div className="nac-secret-row">
                  <input
                    value={secretInput}
                    onChange={(event) => setSecretInput(event.target.value)}
                    placeholder="Set or update device key (min 16 chars)"
                  />
                  <button
                    className="nac-btn nac-btn-primary"
                    disabled={secretSaving}
                    onClick={() => {
                      void saveIdentityKey();
                    }}
                  >
                    {secretSaving ? 'Saving...' : 'Save Key'}
                  </button>
                </div>

                {secretMessage ? <p className="nac-feedback">{secretMessage}</p> : null}
              </>
            )}
          </article>
        </section>

        <section className="nac-log-grid">
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
                      <strong>{event.type}</strong> {event.deviceId ?? 'system'}
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
                      <strong>{entry.deviceId}</strong> {entry.action} ({entry.prev} to{' '}
                      {entry.next})
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </article>
        </section>
      </main>
    </div>
  );
}
