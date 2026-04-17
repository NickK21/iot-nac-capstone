import { Injectable } from '@nestjs/common';
import { SqliteService } from '../persistence/sqlite.service';

export type ExportScope = 'audit' | 'enforcement' | 'events';
export type ExportFormat = 'csv' | 'json';

type ExportQuery = {
  scope: ExportScope;
  format: ExportFormat;
  deviceId?: string;
  fromTs?: string;
  toTs?: string;
  eventType?: string;
};

type ExportPayload = {
  filename: string;
  contentType: string;
  body: string;
};

@Injectable()
export class ExportsService {
  constructor(private readonly sqlite: SqliteService) {}

  generate(query: ExportQuery): ExportPayload {
    const rows = this.loadRows(query);
    const extension = query.format === 'csv' ? 'csv' : 'json';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    return {
      filename: `${query.scope}-export-${timestamp}.${extension}`,
      contentType:
        query.format === 'csv'
          ? 'text/csv; charset=utf-8'
          : 'application/json; charset=utf-8',
      body:
        query.format === 'csv'
          ? this.toCsv(rows)
          : JSON.stringify(rows, null, 2),
    };
  }

  private loadRows(query: ExportQuery): Record<string, unknown>[] {
    switch (query.scope) {
      case 'audit':
        return this.loadAuditRows(query);
      case 'enforcement':
        return this.loadEnforcementRows(query);
      case 'events':
        return this.loadEventRows(query);
    }
  }

  private loadAuditRows(query: ExportQuery): Record<string, unknown>[] {
    const { whereClause, params } = this.buildWhere({
      deviceColumn: 'a.device_id',
      timestampColumn: 'a.ts',
      deviceId: query.deviceId,
      fromTs: query.fromTs,
      toTs: query.toTs,
    });

    const rows = this.sqlite.db
      .prepare(
        `
        SELECT
          a.ts as ts,
          a.device_id as device_id,
          d.alias as alias,
          d.hostname as hostname,
          d.vendor as vendor,
          d.model as model,
          d.location as location,
          d.mac_address as mac_address,
          d.fingerprint as fingerprint,
          d.archived_at as archived_at,
          a.action as action,
          a.prev_state as prev_state,
          a.next_state as next_state
        FROM audit_logs a
        LEFT JOIN devices d ON d.id = a.device_id
        ${whereClause}
        ORDER BY a.ts ASC, a.id ASC
      `,
      )
      .all(...params) as Array<{
      ts: string;
      device_id: string;
      alias: string | null;
      hostname: string;
      vendor: string;
      model: string;
      location: string | null;
      mac_address: string | null;
      fingerprint: string | null;
      archived_at: string | null;
      action: string;
      prev_state: string;
      next_state: string;
    }>;

    return rows.map((row) => ({
      ts: row.ts,
      deviceId: row.device_id,
      alias: row.alias,
      hostname: row.hostname,
      vendor: row.vendor,
      model: row.model,
      location: row.location,
      macAddress: row.mac_address,
      fingerprint: row.fingerprint,
      archivedAt: row.archived_at,
      action: row.action,
      prevState: row.prev_state,
      nextState: row.next_state,
    }));
  }

  private loadEnforcementRows(query: ExportQuery): Record<string, unknown>[] {
    const { whereClause, params } = this.buildWhere({
      deviceColumn: 'e.device_id',
      timestampColumn: 'e.ts',
      deviceId: query.deviceId,
      fromTs: query.fromTs,
      toTs: query.toTs,
    });

    const rows = this.sqlite.db
      .prepare(
        `
        SELECT
          e.ts as ts,
          e.device_id as device_id,
          d.alias as alias,
          d.hostname as hostname,
          d.vendor as vendor,
          d.model as model,
          d.location as location,
          d.mac_address as mac_address,
          d.fingerprint as fingerprint,
          d.archived_at as archived_at,
          e.action as action,
          e.prev_state as prev_state,
          e.next_state as next_state,
          e.adapter as adapter,
          e.result as result,
          e.policy_code as policy_code,
          e.message as message
        FROM enforcement_logs e
        LEFT JOIN devices d ON d.id = e.device_id
        ${whereClause}
        ORDER BY e.ts ASC, e.id ASC
      `,
      )
      .all(...params) as Array<{
      ts: string;
      device_id: string;
      alias: string | null;
      hostname: string;
      vendor: string;
      model: string;
      location: string | null;
      mac_address: string | null;
      fingerprint: string | null;
      archived_at: string | null;
      action: string;
      prev_state: string;
      next_state: string;
      adapter: string;
      result: string;
      policy_code: string;
      message: string;
    }>;

    return rows.map((row) => ({
      ts: row.ts,
      deviceId: row.device_id,
      alias: row.alias,
      hostname: row.hostname,
      vendor: row.vendor,
      model: row.model,
      location: row.location,
      macAddress: row.mac_address,
      fingerprint: row.fingerprint,
      archivedAt: row.archived_at,
      action: row.action,
      prevState: row.prev_state,
      nextState: row.next_state,
      adapter: row.adapter,
      result: row.result,
      policyCode: row.policy_code,
      message: row.message,
    }));
  }

  private loadEventRows(query: ExportQuery): Record<string, unknown>[] {
    const { whereClause, params } = this.buildWhere({
      deviceColumn: 'e.device_id',
      timestampColumn: 'e.ts',
      deviceId: query.deviceId,
      fromTs: query.fromTs,
      toTs: query.toTs,
      extraClause: query.eventType ? 'e.type = ?' : undefined,
      extraParams: query.eventType ? [query.eventType] : [],
    });

    const rows = this.sqlite.db
      .prepare(
        `
        SELECT
          e.ts as ts,
          e.type as type,
          e.severity as severity,
          e.device_id as device_id,
          d.alias as alias,
          d.hostname as hostname,
          d.vendor as vendor,
          d.model as model,
          d.location as location,
          d.mac_address as mac_address,
          d.fingerprint as fingerprint,
          d.archived_at as archived_at,
          e.message as message,
          e.details_json as details_json
        FROM event_logs e
        LEFT JOIN devices d ON d.id = e.device_id
        ${whereClause}
        ORDER BY e.ts ASC, e.id ASC
      `,
      )
      .all(...params) as Array<{
      ts: string;
      type: string;
      severity: string;
      device_id: string | null;
      alias: string | null;
      hostname: string | null;
      vendor: string | null;
      model: string | null;
      location: string | null;
      mac_address: string | null;
      fingerprint: string | null;
      archived_at: string | null;
      message: string;
      details_json: string | null;
    }>;

    return rows.map((row) => ({
      ts: row.ts,
      type: row.type,
      severity: row.severity,
      deviceId: row.device_id,
      alias: row.alias,
      hostname: row.hostname,
      vendor: row.vendor,
      model: row.model,
      location: row.location,
      macAddress: row.mac_address,
      fingerprint: row.fingerprint,
      archivedAt: row.archived_at,
      message: row.message,
      details: this.parseJson(row.details_json),
    }));
  }

  private buildWhere(options: {
    deviceColumn: string;
    timestampColumn: string;
    deviceId?: string;
    fromTs?: string;
    toTs?: string;
    extraClause?: string;
    extraParams?: Array<string>;
  }): { whereClause: string; params: Array<string> } {
    const clauses: string[] = [];
    const params: string[] = [];

    if (options.deviceId) {
      clauses.push(`${options.deviceColumn} = ?`);
      params.push(options.deviceId);
    }

    if (options.fromTs) {
      clauses.push(`${options.timestampColumn} >= ?`);
      params.push(options.fromTs);
    }

    if (options.toTs) {
      clauses.push(`${options.timestampColumn} <= ?`);
      params.push(options.toTs);
    }

    if (options.extraClause) {
      clauses.push(options.extraClause);
      params.push(...(options.extraParams ?? []));
    }

    return {
      whereClause: clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '',
      params,
    };
  }

  private toCsv(rows: Record<string, unknown>[]): string {
    if (rows.length === 0) {
      return '';
    }

    const headers = Array.from(
      rows.reduce((keys, row) => {
        Object.keys(row).forEach((key) => keys.add(key));
        return keys;
      }, new Set<string>()),
    );

    const lines = [
      headers.join(','),
      ...rows.map((row) =>
        headers
          .map((header) => this.escapeCsv(this.formatValue(row[header])))
          .join(','),
      ),
    ];

    return lines.join('\n');
  }

  private formatValue(value: unknown): string {
    if (value === null || value === undefined) {
      return '';
    }

    if (typeof value === 'object') {
      return JSON.stringify(value);
    }

    if (typeof value === 'string') {
      return value;
    }

    if (
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      typeof value === 'bigint'
    ) {
      return value.toString();
    }

    return '';
  }

  private escapeCsv(value: string): string {
    if (!/[",\n]/.test(value)) {
      return value;
    }

    return `"${value.replaceAll('"', '""')}"`;
  }

  private parseJson(raw: string | null): Record<string, unknown> | null {
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
