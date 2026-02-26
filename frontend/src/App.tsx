import { useEffect, useState } from "react";
import "./App.css";

type DeviceState = "allowed" | "denied" | "unknown";

type Device = {
  id: string;
  hostname?: string;
  vendor?: string;
  lastSeen: string;
  state: DeviceState;
};

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadDevices() {
    try {
      setLoading(true);
      setError(null);

      const res = await fetch("http://localhost:3000/devices");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = (await res.json()) as Device[];
      setDevices(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load devices");
    } finally {
      setLoading(false);
    }
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
                {["ID", "Hostname", "Vendor", "Last Seen", "State", "Actions"].map((h) => (
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
                  <td>
                    <div className="nac-actions">
                      <button onClick={() => setDeviceState(d.id, "allow")}>Allow</button>
                      <button onClick={() => setDeviceState(d.id, "deny")}>Deny</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}