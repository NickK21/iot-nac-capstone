export type DeviceState = 'unknown' | 'allowed' | 'denied';
export type DeviceIdentityStatus = 'unverified' | 'verified' | 'invalid';

export interface Device {
  id: string;
  vendor?: string;
  hostname?: string;
  lastSeen: string;
  state: DeviceState;
  identityStatus: DeviceIdentityStatus;
  lastIdentityCheck?: string | null;
}
