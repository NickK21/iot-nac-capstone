import { Injectable } from '@nestjs/common';
import { SqliteService } from '../persistence/sqlite.service';
import type {
  CreateEventLog,
  EventLog,
  EventSeverity,
  EventType,
} from './event.interface';

type EventRow = {
  id: number;
  ts: string;
  type: EventType;
  severity: EventSeverity;
  device_id: string | null;
  message: string;
  details_json: string | null;
};

type RecentEventOptions = {
  limit?: number;
  beforeTs?: string;
  type?: EventType;
  severities?: EventSeverity[];
  deviceId?: string;
};

@Injectable()
export class EventsService {
  constructor(private readonly sqlite: SqliteService) {}

  record(entry: CreateEventLog): EventLog {
    const ts = entry.ts ?? new Date().toISOString();

    const insertResult = this.sqlite.db
      .prepare(
        `
        INSERT INTO event_logs (ts, type, severity, device_id, message, details_json)
        VALUES (?, ?, ?, ?, ?, ?)
      `,
      )
      .run(
        ts,
        entry.type,
        entry.severity,
        entry.deviceId ?? null,
        entry.message,
        entry.details ? JSON.stringify(entry.details) : null,
      );

    const insertedId =
      typeof insertResult.lastInsertRowid === 'bigint'
        ? Number(insertResult.lastInsertRowid)
        : insertResult.lastInsertRowid;

    const row = this.sqlite.db
      .prepare(
        `
        SELECT id, ts, type, severity, device_id, message, details_json
        FROM event_logs
        WHERE id = ?
      `,
      )
      .get(insertedId) as EventRow;

    return this.toEvent(row);
  }

  getRecent(limitOrOptions: number | RecentEventOptions = 30): EventLog[] {
    const options =
      typeof limitOrOptions === 'number'
        ? ({ limit: limitOrOptions } satisfies RecentEventOptions)
        : limitOrOptions;
    const safeLimit = Math.min(Math.max(options.limit ?? 30, 1), 200);

    const clauses: string[] = [];
    const params: Array<number | string> = [];

    if (options.beforeTs) {
      clauses.push('ts < ?');
      params.push(options.beforeTs);
    }

    if (options.deviceId) {
      clauses.push('device_id = ?');
      params.push(options.deviceId);
    }

    if (options.type) {
      clauses.push('type = ?');
      params.push(options.type);
    }

    if (options.severities && options.severities.length > 0) {
      const placeholders = options.severities.map(() => '?').join(', ');
      clauses.push(`severity IN (${placeholders})`);
      params.push(...options.severities);
    }

    const whereClause =
      clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const sql = `
      SELECT id, ts, type, severity, device_id, message, details_json
      FROM event_logs
      ${whereClause}
      ORDER BY ts DESC, id DESC
      LIMIT ?
    `;
    params.push(safeLimit);

    const rows = (
      this.sqlite.db.prepare(sql).all(...params) as EventRow[]
    ).reverse();

    return rows.map((row) => this.toEvent(row));
  }

  countSince(options: {
    sinceIso: string;
    type?: EventType;
    severities?: EventSeverity[];
  }): number {
    if (
      !options.type &&
      (!options.severities || options.severities.length === 0)
    ) {
      const row = this.sqlite.db
        .prepare(
          `
          SELECT COUNT(*) as count
          FROM event_logs
          WHERE ts >= ?
        `,
        )
        .get(options.sinceIso) as { count: number };

      return row.count;
    }

    if (
      options.type &&
      (!options.severities || options.severities.length === 0)
    ) {
      const row = this.sqlite.db
        .prepare(
          `
          SELECT COUNT(*) as count
          FROM event_logs
          WHERE ts >= ? AND type = ?
        `,
        )
        .get(options.sinceIso, options.type) as { count: number };

      return row.count;
    }

    const severities = options.severities ?? [];
    const placeholders = severities.map(() => '?').join(', ');

    if (options.type) {
      const row = this.sqlite.db
        .prepare(
          `
          SELECT COUNT(*) as count
          FROM event_logs
          WHERE ts >= ?
            AND type = ?
            AND severity IN (${placeholders})
        `,
        )
        .get(options.sinceIso, options.type, ...severities) as {
        count: number;
      };

      return row.count;
    }

    const row = this.sqlite.db
      .prepare(
        `
        SELECT COUNT(*) as count
        FROM event_logs
        WHERE ts >= ?
          AND severity IN (${placeholders})
      `,
      )
      .get(options.sinceIso, ...severities) as { count: number };

    return row.count;
  }

  private toEvent(row: EventRow): EventLog {
    return {
      id: row.id,
      ts: row.ts,
      type: row.type,
      severity: row.severity,
      deviceId: row.device_id,
      message: row.message,
      details: this.parseDetails(row.details_json),
    };
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
