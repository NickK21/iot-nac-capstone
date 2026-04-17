import { Injectable } from '@nestjs/common';
import { SqliteService } from '../persistence/sqlite.service';
import type {
  Device,
  DeviceIdentityStatus,
  DeviceProfileSource,
  DeviceProfileSources,
  DeviceState,
} from './device.interface';

export type DeviceInventoryView = 'active' | 'archived' | 'all';

type DeviceRow = {
  id: string;
  alias: string | null;
  vendor: string;
  hostname: string;
  model: string;
  location: string | null;
  mac_address: string | null;
  fingerprint: string | null;
  archived_at: string | null;
  profile_sources_json: string | null;
  last_seen: string;
  state: DeviceState;
  identity_status: DeviceIdentityStatus;
  last_identity_check: string | null;
};

type UpsertDeviceInput = {
  id: string;
  alias?: string | null;
  hostname?: string | null;
  vendor?: string | null;
  model?: string | null;
  location?: string | null;
  macAddress?: string | null;
  fingerprint?: string | null;
  archivedAt?: string | null;
  profileSources?: Partial<DeviceProfileSources>;
  lastSeen: string;
  state?: DeviceState;
  identityStatus?: DeviceIdentityStatus;
  lastIdentityCheck?: string | null;
};

const DEFAULT_PROFILE_SOURCES: DeviceProfileSources = {
  hostname: 'unknown',
  vendor: 'unknown',
  model: 'unknown',
  location: 'unknown',
  macAddress: 'unknown',
  fingerprint: 'unknown',
};

@Injectable()
export class DevicesRepository {
  constructor(private readonly sqlite: SqliteService) {}

  listDevices(view: DeviceInventoryView = 'active'): Device[] {
    const whereClause =
      view === 'active'
        ? 'WHERE archived_at IS NULL'
        : view === 'archived'
          ? 'WHERE archived_at IS NOT NULL'
          : '';

    const rows = this.sqlite.db
      .prepare(
        `
        SELECT
          id,
          alias,
          vendor,
          hostname,
          model,
          location,
          mac_address,
          fingerprint,
          archived_at,
          profile_sources_json,
          last_seen,
          state,
          identity_status,
          last_identity_check
        FROM devices
        ${whereClause}
        ORDER BY COALESCE(archived_at, last_seen) DESC, last_seen DESC, id ASC
      `,
      )
      .all() as DeviceRow[];

    return rows.map((row) => this.toDevice(row));
  }

  findById(id: string): Device | undefined {
    const row = this.sqlite.db
      .prepare(
        `
        SELECT
          id,
          alias,
          vendor,
          hostname,
          model,
          location,
          mac_address,
          fingerprint,
          archived_at,
          profile_sources_json,
          last_seen,
          state,
          identity_status,
          last_identity_check
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
    const profileSources = this.resolveProfileSources(input, current);

    this.sqlite.db
      .prepare(
        `
        INSERT INTO devices (
          id,
          alias,
          vendor,
          hostname,
          model,
          location,
          mac_address,
          fingerprint,
          archived_at,
          profile_sources_json,
          last_seen,
          state,
          identity_status,
          last_identity_check
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          alias = excluded.alias,
          vendor = excluded.vendor,
          hostname = excluded.hostname,
          model = excluded.model,
          location = excluded.location,
          mac_address = excluded.mac_address,
          fingerprint = excluded.fingerprint,
          archived_at = excluded.archived_at,
          profile_sources_json = excluded.profile_sources_json,
          last_seen = excluded.last_seen,
          state = excluded.state,
          identity_status = excluded.identity_status,
          last_identity_check = excluded.last_identity_check
      `,
      )
      .run(
        input.id,
        this.resolveAlias(input, current),
        this.resolveNamedField(input, current, 'vendor'),
        this.resolveNamedField(input, current, 'hostname'),
        this.resolveNamedField(input, current, 'model'),
        this.resolveNullableField(input, current, 'location'),
        this.resolveNullableField(input, current, 'macAddress'),
        this.resolveNullableField(input, current, 'fingerprint'),
        this.resolveArchivedAt(input, current),
        JSON.stringify(profileSources),
        input.lastSeen,
        input.state ?? current?.state ?? 'unknown',
        input.identityStatus ?? current?.identityStatus ?? 'pending',
        this.resolveLastIdentityCheck(input, current),
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

  updateAlias(id: string, alias: string | null): Device | undefined {
    const current = this.findById(id);
    if (!current) {
      return undefined;
    }

    this.sqlite.db
      .prepare(
        `
        UPDATE devices
        SET alias = ?
        WHERE id = ?
      `,
      )
      .run(alias, id);

    return this.mustFind(id);
  }

  setArchivedAt(id: string, archivedAt: string | null): Device | undefined {
    const current = this.findById(id);
    if (!current) {
      return undefined;
    }

    this.sqlite.db
      .prepare(
        `
        UPDATE devices
        SET archived_at = ?
        WHERE id = ?
      `,
      )
      .run(archivedAt, id);

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
      alias: row.alias,
      vendor: row.vendor,
      hostname: row.hostname,
      model: row.model,
      location: row.location,
      macAddress: row.mac_address,
      fingerprint: row.fingerprint,
      archivedAt: row.archived_at,
      profileSources: this.parseProfileSources(row.profile_sources_json),
      lastSeen: row.last_seen,
      state: row.state,
      identityStatus: row.identity_status,
      lastIdentityCheck: row.last_identity_check,
    };
  }

  private parseProfileSources(raw: string | null): DeviceProfileSources {
    if (!raw) {
      return { ...DEFAULT_PROFILE_SOURCES };
    }

    try {
      const parsed = JSON.parse(raw) as Partial<DeviceProfileSources>;
      return {
        ...DEFAULT_PROFILE_SOURCES,
        ...this.filterKnownSources(parsed),
      };
    } catch {
      return { ...DEFAULT_PROFILE_SOURCES };
    }
  }

  private filterKnownSources(
    value: Partial<DeviceProfileSources> | null | undefined,
  ): Partial<DeviceProfileSources> {
    if (!value || typeof value !== 'object') {
      return {};
    }

    const result: Partial<DeviceProfileSources> = {};
    for (const key of Object.keys(DEFAULT_PROFILE_SOURCES) as Array<
      keyof DeviceProfileSources
    >) {
      const candidate = value[key];
      if (this.isProfileSource(candidate)) {
        result[key] = candidate;
      }
    }

    return result;
  }

  private isProfileSource(value: unknown): value is DeviceProfileSource {
    return (
      value === 'manual' ||
      value === 'report' ||
      value === 'inferred' ||
      value === 'unknown'
    );
  }

  private resolveAlias(
    input: UpsertDeviceInput,
    current: Device | undefined,
  ): string | null {
    if (Object.prototype.hasOwnProperty.call(input, 'alias')) {
      return input.alias ?? null;
    }

    return current?.alias ?? null;
  }

  private resolveNamedField(
    input: UpsertDeviceInput,
    current: Device | undefined,
    field: 'hostname' | 'vendor' | 'model',
  ): string {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      return input[field] ?? 'unknown';
    }

    return current?.[field] ?? 'unknown';
  }

  private resolveNullableField(
    input: UpsertDeviceInput,
    current: Device | undefined,
    field: 'location' | 'macAddress' | 'fingerprint',
  ): string | null {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      return input[field] ?? null;
    }

    return current?.[field] ?? null;
  }

  private resolveArchivedAt(
    input: UpsertDeviceInput,
    current: Device | undefined,
  ): string | null {
    if (Object.prototype.hasOwnProperty.call(input, 'archivedAt')) {
      return input.archivedAt ?? null;
    }

    return current?.archivedAt ?? null;
  }

  private resolveProfileSources(
    input: UpsertDeviceInput,
    current: Device | undefined,
  ): DeviceProfileSources {
    if (Object.prototype.hasOwnProperty.call(input, 'profileSources')) {
      return {
        ...(current?.profileSources ?? DEFAULT_PROFILE_SOURCES),
        ...this.filterKnownSources(input.profileSources),
      };
    }

    return current?.profileSources ?? { ...DEFAULT_PROFILE_SOURCES };
  }

  private resolveLastIdentityCheck(
    input: UpsertDeviceInput,
    current: Device | undefined,
  ): string | null {
    if (Object.prototype.hasOwnProperty.call(input, 'lastIdentityCheck')) {
      return input.lastIdentityCheck ?? null;
    }

    return current?.lastIdentityCheck ?? null;
  }
}
