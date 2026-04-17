import { Injectable } from '@nestjs/common';
import { SqliteService } from '../persistence/sqlite.service';

export type EnrollmentAction =
  | 'pending_created'
  | 'device_enrolled'
  | 'key_rotated'
  | 'alias_updated'
  | 'profile_updated'
  | 'provisioning_token_issued'
  | 'provisioning_token_consumed'
  | 'device_archived'
  | 'device_restored';

export type EnrollmentLogEntry = {
  ts: string;
  deviceId: string;
  action: EnrollmentAction;
  message: string;
  details?: Record<string, unknown>;
};

type EnrollmentLogRow = {
  ts: string;
  device_id: string;
  action: EnrollmentAction;
  message: string;
  details_json: string | null;
};

@Injectable()
export class EnrollmentLogService {
  constructor(private readonly sqlite: SqliteService) {}

  record(entry: EnrollmentLogEntry): void {
    this.sqlite.db
      .prepare(
        `
        INSERT INTO enrollment_logs (ts, device_id, action, message, details_json)
        VALUES (?, ?, ?, ?, ?)
      `,
      )
      .run(
        entry.ts,
        entry.deviceId,
        entry.action,
        entry.message,
        entry.details ? JSON.stringify(entry.details) : null,
      );
  }

  listForDevice(deviceId: string, limit = 40) {
    const rows = this.listRecent({ deviceId, limit });

    return rows;
  }

  listRecent(options?: {
    deviceId?: string;
    limit?: number;
    beforeTs?: string;
  }) {
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (options?.deviceId) {
      clauses.push('device_id = ?');
      params.push(options.deviceId);
    }

    if (options?.beforeTs) {
      clauses.push('ts < ?');
      params.push(options.beforeTs);
    }

    const safeLimit = Math.min(Math.max(options?.limit ?? 40, 1), 200);
    const whereClause =
      clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rows = (
      this.sqlite.db
        .prepare(
          `
          SELECT ts, device_id, action, message, details_json
          FROM enrollment_logs
          ${whereClause}
          ORDER BY ts DESC, id DESC
          LIMIT ?
        `,
        )
        .all(...params, safeLimit) as EnrollmentLogRow[]
    ).reverse();

    return rows.map((row) => ({
      ts: row.ts,
      deviceId: row.device_id,
      action: row.action,
      message: row.message,
      details: this.parseDetails(row.details_json),
    }));
  }

  private parseDetails(raw: string | null): Record<string, unknown> | null {
    if (!raw) {
      return null;
    }

    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
      return null;
    } catch {
      return null;
    }
  }
}
