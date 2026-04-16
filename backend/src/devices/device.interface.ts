export type DeviceState = 'unknown' | 'allowed' | 'denied';
export type DeviceIdentityStatus =
  | 'pending'
  | 'enrolled'
  | 'verified'
  | 'invalid'
  | 'locked';

export interface Device {
  id: string;
  alias?: string | null;
  vendor?: string;
  hostname?: string;
  lastSeen: string;
  state: DeviceState;
  identityStatus: DeviceIdentityStatus;
  lastIdentityCheck?: string | null;
}
