import { Injectable } from '@nestjs/common';
import { SqliteService } from '../persistence/sqlite.service';
import type {
  Device,
  DeviceIdentityStatus,
  DeviceState,
} from './device.interface';

type DeviceRow = {
  id: string;
  vendor: string;
  hostname: string;
  last_seen: string;
  state: DeviceState;
  identity_status: DeviceIdentityStatus;
  last_identity_check: string | null;
};

type UpsertDeviceInput = {
  id: string;
  hostname?: string;
  vendor?: string;
  lastSeen: string;
  state?: DeviceState;
  identityStatus?: DeviceIdentityStatus;
  lastIdentityCheck?: string | null;
};

@Injectable()
export class DevicesRepository {
  constructor(private readonly sqlite: SqliteService) {}

  listDevices(): Device[] {
    const rows = this.sqlite.db
      .prepare(
        `
        SELECT id, vendor, hostname, last_seen, state, identity_status, last_identity_check
        FROM devices
        ORDER BY last_seen DESC, id ASC
      `,
      )
      .all() as DeviceRow[];

    return rows.map((row) => this.toDevice(row));
  }

  findById(id: string): Device | undefined {
    const row = this.sqlite.db
      .prepare(
        `
        SELECT id, vendor, hostname, last_seen, state, identity_status, last_identity_check
        FROM devices
        WHERE id = ?
      `,
      )
      .get(id) as DeviceRow | undefined;

    if (!row) {
      return undefined;
    }

    return this.toDevice(row);
  }

  upsertDevice(input: UpsertDeviceInput): Device {
    const current = this.findById(input.id);

    this.sqlite.db
      .prepare(
        `
        INSERT INTO devices (id, vendor, hostname, last_seen, state, identity_status, last_identity_check)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          vendor = excluded.vendor,
          hostname = excluded.hostname,
          last_seen = excluded.last_seen,
          state = excluded.state,
          identity_status = excluded.identity_status,
          last_identity_check = excluded.last_identity_check
      `,
      )
      .run(
        input.id,
        input.vendor ?? current?.vendor ?? 'unknown',
        input.hostname ?? current?.hostname ?? 'unknown',
        input.lastSeen,
        input.state ?? current?.state ?? 'unknown',
        input.identityStatus ?? current?.identityStatus ?? 'unverified',
        input.lastIdentityCheck ?? current?.lastIdentityCheck ?? null,
      );

    return this.mustFind(input.id);
  }

  updateState(id: string, state: DeviceState, ts: string): Device | undefined {
    const current = this.findById(id);
    if (!current) {
      return undefined;
    }

    this.sqlite.db
      .prepare(
        `
        UPDATE devices
        SET state = ?, last_seen = ?
        WHERE id = ?
      `,
      )
      .run(state, ts, id);

    return this.mustFind(id);
  }

  updateIdentityStatus(
    id: string,
    identityStatus: DeviceIdentityStatus,
    checkedAt: string,
    lastSeen?: string,
  ): Device | undefined {
    const current = this.findById(id);
    if (!current) {
      return undefined;
    }

    this.sqlite.db
      .prepare(
        `
        UPDATE devices
        SET identity_status = ?, last_identity_check = ?, last_seen = ?
        WHERE id = ?
      `,
      )
      .run(identityStatus, checkedAt, lastSeen ?? current.lastSeen, id);

    return this.mustFind(id);
  }

  private mustFind(id: string): Device {
    const device = this.findById(id);
    if (!device) {
      throw new Error(`Expected device ${id} to exist`);
    }
    return device;
  }

  private toDevice(row: DeviceRow): Device {
    return {
      id: row.id,
      vendor: row.vendor,
      hostname: row.hostname,
      lastSeen: row.last_seen,
      state: row.state,
      identityStatus: row.identity_status,
      lastIdentityCheck: row.last_identity_check,
    };
  }
}
