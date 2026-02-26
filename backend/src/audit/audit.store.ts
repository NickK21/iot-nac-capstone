export type AuditAction = "allow" | "deny";

export type AuditEntry = {
  ts: string;
  deviceId: string;
  action: AuditAction;
  prev: "unknown" | "allowed" | "denied";
  next: "unknown" | "allowed" | "denied";
};

export const AUDIT: AuditEntry[] = [];