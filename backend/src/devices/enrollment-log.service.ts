import { Injectable } from '@nestjs/common';
import { SqliteService } from '../persistence/sqlite.service';

export type EnrollmentAction =
  | 'pending_created'
  | 'device_enrolled'
  | 'key_rotated'
  | 'alias_updated'
  | 'provisioning_token_issued'
  | 'provisioning_token_consumed';

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
    const rows = (
      this.sqlite.db
        .prepare(
          `
          SELECT ts, device_id, action, message, details_json
          FROM enrollment_logs
          WHERE device_id = ?
          ORDER BY ts DESC, id DESC
          LIMIT ?
        `,
        )
        .all(deviceId, limit) as EnrollmentLogRow[]
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
