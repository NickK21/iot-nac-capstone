import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { DatabaseSync } from 'node:sqlite';
import * as fs from 'node:fs';
import * as path from 'node:path';

@Injectable()
export class SqliteService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SqliteService.name);
  private database?: DatabaseSync;

  onModuleInit(): void {
    const dbPath = this.resolveDatabasePath();

    if (dbPath !== ':memory:') {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }

    this.database = new DatabaseSync(dbPath);
    this.database.exec('PRAGMA journal_mode = WAL;');
    this.database.exec('PRAGMA foreign_keys = ON;');

    this.migrate();
    this.seedDefaults();

    this.logger.log(`SQLite ready at ${dbPath}`);
  }

  onModuleDestroy(): void {
    this.database?.close();
  }

  get db(): DatabaseSync {
    if (!this.database) {
      throw new Error('SQLite database is not initialized');
    }
    return this.database;
  }

  private resolveDatabasePath(): string {
    if (process.env.SQLITE_DB_PATH?.trim()) {
      return process.env.SQLITE_DB_PATH.trim();
    }

    if (process.env.NODE_ENV === 'test') {
      return ':memory:';
    }

    return path.join(process.cwd(), 'data', 'nac.db');
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        alias TEXT,
        vendor TEXT NOT NULL DEFAULT 'unknown',
        hostname TEXT NOT NULL DEFAULT 'unknown',
        last_seen TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('unknown', 'allowed', 'denied')),
        identity_status TEXT NOT NULL DEFAULT 'pending' CHECK (
          identity_status IN ('pending', 'enrolled', 'verified', 'invalid', 'locked')
        ),
        last_identity_check TEXT
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        device_id TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
        prev_state TEXT NOT NULL CHECK (prev_state IN ('unknown', 'allowed', 'denied')),
        next_state TEXT NOT NULL CHECK (next_state IN ('unknown', 'allowed', 'denied')),
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS enforcement_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        device_id TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
        prev_state TEXT NOT NULL CHECK (prev_state IN ('unknown', 'allowed', 'denied')),
        next_state TEXT NOT NULL CHECK (next_state IN ('unknown', 'allowed', 'denied')),
        adapter TEXT NOT NULL,
        result TEXT NOT NULL CHECK (result IN ('applied', 'blocked')),
        policy_code TEXT NOT NULL DEFAULT 'ok' CHECK (
          policy_code IN (
            'ok',
            'identity_not_verified',
            'identity_invalid',
            'identity_locked',
            'already_allowed',
            'already_denied'
          )
        ),
        message TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS device_identity_keys (
        device_id TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        rotated_at TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS device_identity_nonces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        ts TEXT NOT NULL,
        UNIQUE (device_id, nonce),
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS device_identity_failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        ts TEXT NOT NULL,
        reason TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS device_provisioning_tokens (
        device_id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS enrollment_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        device_id TEXT NOT NULL,
        action TEXT NOT NULL CHECK (
          action IN (
            'pending_created',
            'device_enrolled',
            'key_rotated',
            'alias_updated',
            'provisioning_token_issued',
            'provisioning_token_consumed'
          )
        ),
        message TEXT NOT NULL,
        details_json TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS event_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        type TEXT NOT NULL CHECK (
          type IN (
            'discovery',
            'identity_verified',
            'identity_failed',
            'identity_key_rotated',
            'policy_change'
          )
        ),
        severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
        device_id TEXT,
        message TEXT NOT NULL,
        details_json TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
      );
    `);

    this.ensureDevicesTableShape();
    this.ensureEnforcementLogsTableShape();
    this.ensureIndexes();
  }

  private seedDefaults(): void {
    const now = new Date().toISOString();

    this.db
      .prepare(
        `
        INSERT INTO devices (id, alias, vendor, hostname, last_seen, state, identity_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
      `,
      )
      .run('device-1', null, 'unknown', 'unknown', now, 'unknown', 'pending');
  }

  private ensureDevicesTableShape(): void {
    const tableSql = this.getTableSql('devices');
    const hasAlias = this.hasColumn('devices', 'alias');
    const supportsIdentityLifecycle =
      tableSql.includes("'pending'") &&
      tableSql.includes("'enrolled'") &&
      tableSql.includes("'locked'");

    if (hasAlias && supportsIdentityLifecycle) {
      return;
    }

    const aliasSelect = hasAlias ? 'alias' : 'NULL';
    this.rebuildTable(`
      CREATE TABLE devices_new (
        id TEXT PRIMARY KEY,
        alias TEXT,
        vendor TEXT NOT NULL DEFAULT 'unknown',
        hostname TEXT NOT NULL DEFAULT 'unknown',
        last_seen TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('unknown', 'allowed', 'denied')),
        identity_status TEXT NOT NULL DEFAULT 'pending' CHECK (
          identity_status IN ('pending', 'enrolled', 'verified', 'invalid', 'locked')
        ),
        last_identity_check TEXT
      );

      INSERT INTO devices_new (
        id, alias, vendor, hostname, last_seen, state, identity_status, last_identity_check
      )
      SELECT
        id,
        ${aliasSelect},
        vendor,
        hostname,
        last_seen,
        state,
        CASE identity_status
          WHEN 'unverified' THEN 'pending'
          WHEN 'pending' THEN 'pending'
          WHEN 'enrolled' THEN 'enrolled'
          WHEN 'verified' THEN 'verified'
          WHEN 'invalid' THEN 'invalid'
          WHEN 'locked' THEN 'locked'
          ELSE 'pending'
        END,
        last_identity_check
      FROM devices;

      DROP TABLE devices;
      ALTER TABLE devices_new RENAME TO devices;
    `);
  }

  private ensureEnforcementLogsTableShape(): void {
    const tableSql = this.getTableSql('enforcement_logs');
    const hasPolicyCode = this.hasColumn('enforcement_logs', 'policy_code');
    const supportsNewCodes =
      tableSql.includes("'identity_not_verified'") &&
      tableSql.includes("'identity_locked'");

    if (hasPolicyCode && supportsNewCodes) {
      return;
    }

    const policyCodeSelect = hasPolicyCode ? 'policy_code' : "'ok'";
    this.rebuildTable(`
      CREATE TABLE enforcement_logs_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        device_id TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
        prev_state TEXT NOT NULL CHECK (prev_state IN ('unknown', 'allowed', 'denied')),
        next_state TEXT NOT NULL CHECK (next_state IN ('unknown', 'allowed', 'denied')),
        adapter TEXT NOT NULL,
        result TEXT NOT NULL CHECK (result IN ('applied', 'blocked')),
        policy_code TEXT NOT NULL DEFAULT 'ok' CHECK (
          policy_code IN (
            'ok',
            'identity_not_verified',
            'identity_invalid',
            'identity_locked',
            'already_allowed',
            'already_denied'
          )
        ),
        message TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      INSERT INTO enforcement_logs_new (
        id, ts, device_id, action, prev_state, next_state, adapter, result, policy_code, message
      )
      SELECT
        id,
        ts,
        device_id,
        action,
        prev_state,
        next_state,
        adapter,
        result,
        CASE ${policyCodeSelect}
          WHEN 'identity_not_verified' THEN 'identity_not_verified'
          WHEN 'identity_invalid' THEN 'identity_invalid'
          WHEN 'identity_locked' THEN 'identity_locked'
          WHEN 'already_allowed' THEN 'already_allowed'
          WHEN 'already_denied' THEN 'already_denied'
          ELSE 'ok'
        END,
        message
      FROM enforcement_logs;

      DROP TABLE enforcement_logs;
      ALTER TABLE enforcement_logs_new RENAME TO enforcement_logs;
    `);
  }

  private ensureIndexes(): void {
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_enforcement_ts ON enforcement_logs(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_enforcement_device_ts ON enforcement_logs(device_id, ts DESC);
      CREATE INDEX IF NOT EXISTS idx_identity_nonces_device_ts ON device_identity_nonces(device_id, ts DESC);
      CREATE INDEX IF NOT EXISTS idx_identity_failures_device_ts ON device_identity_failures(device_id, ts DESC);
      CREATE INDEX IF NOT EXISTS idx_provisioning_tokens_expires_at ON device_provisioning_tokens(expires_at DESC);
      CREATE INDEX IF NOT EXISTS idx_enrollment_logs_device_ts ON enrollment_logs(device_id, ts DESC);
      CREATE INDEX IF NOT EXISTS idx_events_ts ON event_logs(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_events_type_ts ON event_logs(type, ts DESC);
    `);
  }

  private rebuildTable(sql: string): void {
    this.db.exec('PRAGMA foreign_keys = OFF;');
    try {
      this.db.exec('BEGIN;');
      this.db.exec(sql);
      this.db.exec('COMMIT;');
    } catch (error) {
      this.db.exec('ROLLBACK;');
      throw error;
    } finally {
      this.db.exec('PRAGMA foreign_keys = ON;');
    }
  }

  private getTableSql(tableName: string): string {
    const row = this.db
      .prepare(
        `
        SELECT sql
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
      `,
      )
      .get(tableName) as { sql: string } | undefined;

    return row?.sql ?? '';
  }

  private hasColumn(tableName: string, columnName: string): boolean {
    const columns = this.db
      .prepare(`PRAGMA table_info(${tableName})`)
      .all() as { name: string }[];

    return columns.some((column) => column.name === columnName);
  }
}
