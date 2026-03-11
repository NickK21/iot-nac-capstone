import type { DeviceState } from '../devices/device.interface';

export type AuditAction = 'allow' | 'deny';

export type AuditEntry = {
  ts: string;
  deviceId: string;
  action: AuditAction;
  prev: DeviceState;
  next: DeviceState;
};
