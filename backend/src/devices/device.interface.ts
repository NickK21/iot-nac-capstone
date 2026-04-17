export type DeviceState = 'unknown' | 'allowed' | 'denied';
export type DeviceIdentityStatus =
  | 'pending'
  | 'enrolled'
  | 'verified'
  | 'invalid'
  | 'locked';

export type DeviceProfileSource = 'manual' | 'report' | 'inferred' | 'unknown';

export type DeviceProfileSources = {
  hostname: DeviceProfileSource;
  vendor: DeviceProfileSource;
  model: DeviceProfileSource;
  location: DeviceProfileSource;
  macAddress: DeviceProfileSource;
  fingerprint: DeviceProfileSource;
};

export interface Device {
  id: string;
  alias?: string | null;
  vendor?: string;
  hostname?: string;
  model?: string;
  location?: string | null;
  macAddress?: string | null;
  fingerprint?: string | null;
  archivedAt?: string | null;
  profileSources?: DeviceProfileSources;
  lastSeen: string;
  state: DeviceState;
  identityStatus: DeviceIdentityStatus;
  lastIdentityCheck?: string | null;
}
