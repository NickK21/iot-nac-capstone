type DeviceState = "allowed" | "denied" | "unknown";

type Device = {
  id: string;
  hostname: string;
  vendor: string;
  lastSeen: string;
  state: DeviceState;
};

const DEVICES: Device[] = [
  { id: "dev_01", hostname: "iphone-nick", vendor: "Apple", lastSeen: "2026-02-11T00:10:00Z", state: "unknown" },
  { id: "dev_02", hostname: "smart-tv", vendor: "Samsung", lastSeen: "2026-02-11T00:08:30Z", state: "allowed" },
  { id: "dev_03", hostname: "esp32-sensor", vendor: "Espressif", lastSeen: "2026-02-11T00:06:12Z", state: "denied" },
];

export default function App() {
  return (
    <div className="nac-container">
      <div className="nac-card">
        <h1 style={{ margin: 0 }}>IoT NAC Dashboard</h1>
        <p style={{ marginTop: 8, color: "rgba(255,255,255,0.6)" }}>Placeholder device inventory</p>

        <table className="nac-table">
          <thead>
            <tr>
              {["ID", "Hostname", "Vendor", "Last Seen", "State"].map((h) => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          
          <tbody>
            {DEVICES.map((d) => (
              <tr key={d.id}>
                <td>{d.id}</td>
                <td>{d.hostname}</td>
                <td>{d.vendor}</td>
                <td>{d.lastSeen}</td>
                <td>{d.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
