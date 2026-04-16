import { Injectable } from '@nestjs/common';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { SqliteService } from '../persistence/sqlite.service';

type ProvisioningTokenRow = {
  token_hash: string;
  issued_at: string;
  expires_at: string;
  consumed_at: string | null;
};

export type ProvisioningTokenIssue = {
  token: string;
  issuedAt: string;
  expiresAt: string;
  headerName: 'x-device-provisioning-token';
};

export type ProvisioningTokenMetadata = {
  headerName: 'x-device-provisioning-token';
  requiredOnFirstHeartbeat: true;
  active: boolean;
  issuedAt: string | null;
  expiresAt: string | null;
  consumedAt: string | null;
};

type TokenValidationResult = {
  valid: boolean;
  reason?: string;
  consumedAt?: string;
};

@Injectable()
export class DeviceProvisioningService {
  private readonly tokenTtlMs = Number(
    process.env.DEVICE_PROVISIONING_TOKEN_TTL_MS ?? 60 * 60 * 1000,
  );

  constructor(private readonly sqlite: SqliteService) {}

  issueToken(deviceId: string): ProvisioningTokenIssue {
    const token = randomBytes(24).toString('hex');
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + this.tokenTtlMs).toISOString();

    this.sqlite.db
      .prepare(
        `
        INSERT INTO device_provisioning_tokens (
          device_id, token_hash, issued_at, expires_at, consumed_at
        )
        VALUES (?, ?, ?, ?, NULL)
        ON CONFLICT(device_id) DO UPDATE SET
          token_hash = excluded.token_hash,
          issued_at = excluded.issued_at,
          expires_at = excluded.expires_at,
          consumed_at = NULL
      `,
      )
      .run(deviceId, this.hashToken(token), issuedAt, expiresAt);

    return {
      token,
      issuedAt,
      expiresAt,
      headerName: 'x-device-provisioning-token',
    };
  }

  getMetadata(deviceId: string): ProvisioningTokenMetadata {
    const row = this.getTokenRow(deviceId);
    const active =
      !!row &&
      !row.consumed_at &&
      Number.isFinite(Date.parse(row.expires_at)) &&
      Date.now() < Date.parse(row.expires_at);

    return {
      headerName: 'x-device-provisioning-token',
      requiredOnFirstHeartbeat: true,
      active,
      issuedAt: row?.issued_at ?? null,
      expiresAt: row?.expires_at ?? null,
      consumedAt: row?.consumed_at ?? null,
    };
  }

  consumeToken(deviceId: string, token?: string): TokenValidationResult {
    const row = this.getTokenRow(deviceId);
    if (!row) {
      return {
        valid: false,
        reason: 'no active provisioning token exists for this device',
      };
    }

    if (!token?.trim()) {
      return {
        valid: false,
        reason: 'missing provisioning token on first verified heartbeat',
      };
    }

    if (row.consumed_at) {
      return {
        valid: false,
        reason: 'provisioning token has already been consumed',
      };
    }

    const expiresAtMs = Date.parse(row.expires_at);
    if (!Number.isFinite(expiresAtMs) || Date.now() >= expiresAtMs) {
      return {
        valid: false,
        reason: 'provisioning token expired before first verified heartbeat',
      };
    }

    const provided = Buffer.from(this.hashToken(token.trim()), 'hex');
    const stored = Buffer.from(row.token_hash, 'hex');
    if (
      provided.length !== stored.length ||
      !timingSafeEqual(provided, stored)
    ) {
      return {
        valid: false,
        reason: 'invalid provisioning token',
      };
    }

    const consumedAt = new Date().toISOString();
    this.sqlite.db
      .prepare(
        `
        UPDATE device_provisioning_tokens
        SET consumed_at = ?
        WHERE device_id = ?
      `,
      )
      .run(consumedAt, deviceId);

    return {
      valid: true,
      consumedAt,
    };
  }

  private getTokenRow(deviceId: string): ProvisioningTokenRow | undefined {
    return this.sqlite.db
      .prepare(
        `
        SELECT token_hash, issued_at, expires_at, consumed_at
        FROM device_provisioning_tokens
        WHERE device_id = ?
      `,
      )
      .get(deviceId) as ProvisioningTokenRow | undefined;
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
