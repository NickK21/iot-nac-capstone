export interface Device {
  id: string;
  vendor?: string;
  hostname?: string;
  lastSeen: string;
  state: 'unknown' | 'allowed' | 'denied';
}