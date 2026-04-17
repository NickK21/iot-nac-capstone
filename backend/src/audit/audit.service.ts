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

  getAudit(
    options: { deviceId?: string; limit?: number; beforeTs?: string } = {},
  ): AuditEntry[] {
    const safeLimit = Math.min(Math.max(options.limit ?? 100, 1), 200);
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (options.deviceId) {
      clauses.push('device_id = ?');
      params.push(options.deviceId);
    }

    if (options.beforeTs) {
      clauses.push('ts < ?');
      params.push(options.beforeTs);
    }

    const whereClause =
      clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = (
      this.sqlite.db
        .prepare(
          `
        SELECT ts, device_id, action, prev_state, next_state
        FROM audit_logs
        ${whereClause}
        ORDER BY ts DESC, id DESC
        LIMIT ?
      `,
        )
        .all(...params, safeLimit) as AuditRow[]
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
