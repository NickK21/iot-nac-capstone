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
        vendor TEXT NOT NULL DEFAULT 'unknown',
        hostname TEXT NOT NULL DEFAULT 'unknown',
        last_seen TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('unknown', 'allowed', 'denied')),
        identity_status TEXT NOT NULL DEFAULT 'unverified' CHECK (identity_status IN ('unverified', 'verified', 'invalid')),
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

      CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);
    `);
  }

  private seedDefaults(): void {
    const now = new Date().toISOString();

    this.db
      .prepare(
        `
        INSERT INTO devices (id, vendor, hostname, last_seen, state, identity_status)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO NOTHING
      `,
      )
      .run('device-1', 'unknown', 'unknown', now, 'unknown', 'unverified');
  }
}
