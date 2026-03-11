import { useEffect, useState } from "react";
import "./App.css";

type DeviceState = "allowed" | "denied" | "unknown";

type Device = {
  id: string;
  hostname?: string;
  vendor?: string;
  lastSeen: string;
  state: DeviceState;
  identityStatus: "unverified" | "verified" | "invalid";
  lastIdentityCheck?: string | null;
};

type AuditAction = "allow" | "deny";

type AuditEntry = {
  ts: string;
  deviceId: string;
  action: AuditAction;
  prev: DeviceState;
  next: DeviceState;
};

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);

  async function loadDevices(options?: { silent?: boolean }) {
    try {
      if (!options?.silent) {
        setLoading(true);
      }
      setError(null);

      const res = await fetch("http://localhost:3000/devices");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = (await res.json()) as Device[];
      setDevices(data);
      loadAudit().catch(() => {});
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load devices");
    } finally {
      if (!options?.silent) {
        setLoading(false);
      }
    }
  }

  async function loadAudit() {
    const res = await fetch("http://localhost:3000/audit");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as AuditEntry[];
    setAudit(data);
  }

  async function setDeviceState(id: string, next: "allow" | "deny") {
    const res = await fetch(`http://localhost:3000/devices/${id}/${next}`, {
      method: "POST",
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    await loadDevices();
  }

  useEffect(() => {
    loadDevices();
    const timer = setInterval(() => {
      loadDevices({ silent: true }).catch(() => {});
    }, 6000);

    return () => clearInterval(timer);
  }, []);

  return (
    <div className="nac-container">
      <div className="nac-card">
        <h1 style={{ margin: 0 }}>IoT NAC Dashboard</h1>
        <p style={{ marginTop: 8, color: "rgba(255,255,255,0.6)" }}>
          {loading ? "Loading devices..." : "Device inventory"}
        </p>

        {error ? (
          <div style={{ marginTop: 12 }}>Error: {error}</div>
        ) : (
          <table className="nac-table">
            <thead>
              <tr>
                {["ID", "Hostname", "Vendor", "Last Seen", "State", "Identity", "Actions"].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>

            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td>{d.id}</td>
                  <td>{d.hostname ?? "unknown"}</td>
                  <td>{d.vendor ?? "unknown"}</td>
                  <td>{d.lastSeen}</td>
                  <td>{d.state}</td>
                  <td>{d.identityStatus}</td>
                  <td>
                    <div className="nac-actions">
                      <button
                        onClick={() => setDeviceState(d.id, "allow")}
                        disabled={d.state === "allowed"}
                        style={{
                          backgroundColor: d.state === "allowed" ? "#2e7d32" : undefined,
                          borderColor: d.state === "allowed" ? "#2e7d32" : undefined,
                        }}
                      >
                        Allow
                      </button>

                      <button
                        onClick={() => setDeviceState(d.id, "deny")}
                        disabled={d.state === "denied"}
                        style={{
                          backgroundColor: d.state === "denied" ? "#c62828" : undefined,
                          borderColor: d.state === "denied" ? "#c62828" : undefined,
                        }}
                      >
                        Deny
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div style={{ marginTop: 16 }}>
          <h2 style={{ margin: "8px 0", fontSize: "1.1rem" }}>Audit</h2>
          {audit.length === 0 ? (
            <div style={{ color: "rgba(255,255,255,0.6)" }}>No policy changes yet.</div>
          ) : (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {audit.slice(-10).reverse().map((e, idx) => (
                <li key={`${e.ts}-${idx}`} style={{ marginBottom: 6 }}>
                  <span style={{ color: "rgba(255,255,255,0.7)" }}>{e.ts}</span>{" "}
                  — <b>{e.deviceId}</b> {e.action} ({e.prev} → {e.next})
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
