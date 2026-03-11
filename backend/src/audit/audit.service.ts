import { Injectable } from '@nestjs/common';
import { SqliteService } from '../persistence/sqlite.service';
import type { AuditAction, AuditEntry } from './audit.store';

type AuditRow = {
  ts: string;
  device_id: string;
  action: AuditAction;
  prev_state: AuditEntry['prev'];
  next_state: AuditEntry['next'];
};

@Injectable()
export class AuditService {
  constructor(private readonly sqlite: SqliteService) {}

  getAudit(limit = 100): AuditEntry[] {
    const rows = (
      this.sqlite.db
        .prepare(
          `
        SELECT ts, device_id, action, prev_state, next_state
        FROM audit_logs
        ORDER BY ts DESC, id DESC
        LIMIT ?
      `,
        )
        .all(limit) as AuditRow[]
    ).reverse();

    return rows.map((row) => ({
      ts: row.ts,
      deviceId: row.device_id,
      action: row.action,
      prev: row.prev_state,
      next: row.next_state,
    }));
  }

  record(entry: AuditEntry): void {
    this.sqlite.db
      .prepare(
        `
        INSERT INTO audit_logs (ts, device_id, action, prev_state, next_state)
        VALUES (?, ?, ?, ?, ?)
      `,
      )
      .run(entry.ts, entry.deviceId, entry.action, entry.prev, entry.next);
  }
}
