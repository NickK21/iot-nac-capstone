export type EventType =
  | 'discovery'
  | 'identity_verified'
  | 'identity_failed'
  | 'identity_key_rotated'
  | 'policy_change';

export type EventSeverity = 'info' | 'warning' | 'critical';

export type EventLog = {
  id: number;
  ts: string;
  type: EventType;
  severity: EventSeverity;
  deviceId: string | null;
  message: string;
  details: Record<string, unknown> | null;
};

export type CreateEventLog = {
  ts?: string;
  type: EventType;
  severity: EventSeverity;
  deviceId?: string;
  message: string;
  details?: Record<string, unknown>;
};
