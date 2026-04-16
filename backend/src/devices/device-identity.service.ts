import { Injectable } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { SqliteService } from '../persistence/sqlite.service';

type VerificationResult = {
  valid: boolean;
  keySource: 'device' | 'fallback';
  security: DeviceIdentitySecurityState;
  reason?: string;
};

export type DeviceIdentityKeyMetadata = {
  keyConfigured: boolean;
  keySource: 'device' | 'fallback';
  keyUpdatedAt: string | null;
};

export type DeviceIdentityConfig = {
  canonicalFormat: '<deviceId>.<timestamp>.<nonce>';
  maxSkewMs: number;
  nonceTtlMs: number;
};

export type DeviceIdentitySecurityState = {
  maxFailures: number;
  failureWindowMs: number;
  lockoutMs: number;
  recentFailures: number;
  lockedOut: boolean;
  lockoutUntil: string | null;
};

type DeviceKeyRow = {
  secret: string;
  rotated_at: string;
};

type LockoutState = {
  recentFailures: number;
  lockedOut: boolean;
  lockoutUntil: string | null;
};

@Injectable()
export class DeviceIdentityService {
  private readonly fallbackSecret =
    process.env.DEVICE_HMAC_SECRET ?? 'dev-only-change-me';
  private readonly maxSkewMs = Number(
    process.env.DEVICE_HMAC_MAX_SKEW_MS ?? 5 * 60 * 1000,
  );
  private readonly nonceTtlMs = Number(
    process.env.DEVICE_HMAC_NONCE_TTL_MS ?? 10 * 60 * 1000,
  );
  private readonly failureWindowMs = Number(
    process.env.DEVICE_HMAC_FAILURE_WINDOW_MS ?? 5 * 60 * 1000,
  );
  private readonly maxFailures = Number(
    process.env.DEVICE_HMAC_MAX_FAILURES ?? 5,
  );
  private readonly lockoutMs = Number(
    process.env.DEVICE_HMAC_LOCKOUT_MS ?? 10 * 60 * 1000,
  );

  constructor(private readonly sqlite: SqliteService) {}

  setDeviceSecret(
    deviceId: string,
    secret: string,
  ): {
    deviceId: string;
    keyUpdatedAt: string;
    changeType: 'created' | 'updated';
  } {
    const previous = this.getDeviceKeyRow(deviceId);
    const keyUpdatedAt = new Date().toISOString();

    this.sqlite.db
      .prepare(
        `
        INSERT INTO device_identity_keys (device_id, secret, rotated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
          secret = excluded.secret,
          rotated_at = excluded.rotated_at
      `,
      )
      .run(deviceId, secret, keyUpdatedAt);

    return {
      deviceId,
      keyUpdatedAt,
      changeType: previous ? 'updated' : 'created',
    };
  }

  getDeviceIdentityKeyMetadata(deviceId: string): DeviceIdentityKeyMetadata {
    const row = this.sqlite.db
      .prepare(
        `
        SELECT rotated_at
        FROM device_identity_keys
        WHERE device_id = ?
      `,
      )
      .get(deviceId) as { rotated_at: string } | undefined;

    if (!row) {
      return {
        keyConfigured: false,
        keySource: 'fallback',
        keyUpdatedAt: null,
      };
    }

    return {
      keyConfigured: true,
      keySource: 'device',
      keyUpdatedAt: row.rotated_at,
    };
  }

  getConfig(): DeviceIdentityConfig {
    return {
      canonicalFormat: '<deviceId>.<timestamp>.<nonce>',
      maxSkewMs: this.maxSkewMs,
      nonceTtlMs: this.nonceTtlMs,
    };
  }

  getSecurityState(deviceId: string): DeviceIdentitySecurityState {
    this.evictExpiredFailures();
    const state = this.getLockoutState(deviceId, Date.now());

    return {
      maxFailures: this.maxFailures,
      failureWindowMs: this.failureWindowMs,
      lockoutMs: this.lockoutMs,
      recentFailures: state.recentFailures,
      lockedOut: state.lockedOut,
      lockoutUntil: state.lockoutUntil,
    };
  }

  verify(
    deviceId: string,
    timestamp: string,
    nonce: string,
    signatureHex: string,
  ): VerificationResult {
    const nowMs = Date.now();
    this.evictExpiredNonces();
    this.evictExpiredFailures();

    const lockoutState = this.getLockoutState(deviceId, nowMs);
    if (lockoutState.lockedOut && lockoutState.lockoutUntil) {
      return {
        valid: false,
        keySource: this.getDeviceSecret(deviceId) ? 'device' : 'fallback',
        security: this.toSecurityState(lockoutState),
        reason: `device temporarily locked until ${lockoutState.lockoutUntil}`,
      };
    }

    const keySource = this.getDeviceSecret(deviceId) ? 'device' : 'fallback';

    const tsMs = Date.parse(timestamp);
    if (!Number.isFinite(tsMs)) {
      return this.reject(deviceId, 'invalid timestamp format', keySource);
    }

    if (Math.abs(nowMs - tsMs) > this.maxSkewMs) {
      return this.reject(
        deviceId,
        'timestamp outside allowed skew window',
        keySource,
      );
    }

    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(nonce)) {
      return this.reject(deviceId, 'invalid nonce format', keySource);
    }

    if (!/^[a-fA-F0-9]{64}$/.test(signatureHex)) {
      return this.reject(deviceId, 'invalid signature format', keySource);
    }

    const secret = this.getDeviceSecret(deviceId);
    if (!secret) {
      return this.reject(
        deviceId,
        'device is not enrolled with a per-device key',
        'fallback',
      );
    }

    const canonical = `${deviceId}.${timestamp}.${nonce}`;
    const expected = createHmac('sha256', secret).update(canonical).digest();

    let provided: Buffer;
    try {
      provided = Buffer.from(signatureHex, 'hex');
    } catch {
      return this.reject(deviceId, 'invalid signature encoding', keySource);
    }

    if (provided.length !== expected.length) {
      return this.reject(deviceId, 'signature length mismatch', keySource);
    }

    if (!timingSafeEqual(expected, provided)) {
      return this.reject(deviceId, 'signature mismatch', keySource);
    }

    if (!this.registerNonce(deviceId, nonce, timestamp)) {
      return this.reject(deviceId, 'nonce replay detected', keySource);
    }

    this.clearFailures(deviceId);
    return {
      valid: true,
      keySource: 'device',
      security: this.getSecurityState(deviceId),
    };
  }

  sign(deviceId: string, timestamp: string, nonce: string): string {
    const secret = this.getDeviceSecret(deviceId) ?? this.fallbackSecret;
    const canonical = `${deviceId}.${timestamp}.${nonce}`;
    return createHmac('sha256', secret).update(canonical).digest('hex');
  }

  clearSecurityState(deviceId: string): void {
    this.clearFailures(deviceId);
  }

  private getDeviceSecret(deviceId: string): string | undefined {
    return this.getDeviceKeyRow(deviceId)?.secret;
  }

  private getDeviceKeyRow(deviceId: string): DeviceKeyRow | undefined {
    return this.sqlite.db
      .prepare(
        `
        SELECT secret, rotated_at
        FROM device_identity_keys
        WHERE device_id = ?
      `,
      )
      .get(deviceId) as DeviceKeyRow | undefined;
  }

  private registerNonce(deviceId: string, nonce: string, ts: string): boolean {
    try {
      this.sqlite.db
        .prepare(
          `
          INSERT INTO device_identity_nonces (device_id, nonce, ts)
          VALUES (?, ?, ?)
        `,
        )
        .run(deviceId, nonce, ts);
      return true;
    } catch {
      return false;
    }
  }

  private evictExpiredNonces(): void {
    const cutoffIso = new Date(Date.now() - this.nonceTtlMs).toISOString();
    this.sqlite.db
      .prepare(
        `
        DELETE FROM device_identity_nonces
        WHERE ts < ?
      `,
      )
      .run(cutoffIso);
  }

  private reject(
    deviceId: string,
    reason: string,
    keySource: 'device' | 'fallback',
  ): VerificationResult {
    this.recordFailure(deviceId, reason);
    return {
      valid: false,
      keySource,
      security: this.getSecurityState(deviceId),
      reason,
    };
  }

  private recordFailure(deviceId: string, reason: string): void {
    this.sqlite.db
      .prepare(
        `
        INSERT INTO device_identity_failures (device_id, ts, reason)
        VALUES (?, ?, ?)
      `,
      )
      .run(deviceId, new Date().toISOString(), reason);
  }

  private clearFailures(deviceId: string): void {
    this.sqlite.db
      .prepare(
        `
        DELETE FROM device_identity_failures
        WHERE device_id = ?
      `,
      )
      .run(deviceId);
  }

  private getLockoutState(deviceId: string, nowMs: number): LockoutState {
    const windowStartIso = new Date(nowMs - this.failureWindowMs).toISOString();

    const row = this.sqlite.db
      .prepare(
        `
        SELECT COUNT(*) as failure_count, MAX(ts) as latest_failure_ts
        FROM device_identity_failures
        WHERE device_id = ? AND ts >= ?
      `,
      )
      .get(deviceId, windowStartIso) as {
      failure_count: number;
      latest_failure_ts: string | null;
    };

    const recentFailures = row.failure_count ?? 0;
    if (recentFailures < this.maxFailures || !row.latest_failure_ts) {
      return {
        recentFailures,
        lockedOut: false,
        lockoutUntil: null,
      };
    }

    const lockoutUntilMs = Date.parse(row.latest_failure_ts) + this.lockoutMs;
    if (!Number.isFinite(lockoutUntilMs)) {
      return {
        recentFailures,
        lockedOut: false,
        lockoutUntil: null,
      };
    }

    const lockoutUntil = new Date(lockoutUntilMs).toISOString();
    return {
      recentFailures,
      lockedOut: nowMs < lockoutUntilMs,
      lockoutUntil,
    };
  }

  private evictExpiredFailures(): void {
    const retentionMs = Math.max(this.failureWindowMs, this.lockoutMs);
    const cutoffIso = new Date(Date.now() - retentionMs).toISOString();

    this.sqlite.db
      .prepare(
        `
        DELETE FROM device_identity_failures
        WHERE ts < ?
      `,
      )
      .run(cutoffIso);
  }

  private toSecurityState(
    lockoutState: LockoutState,
  ): DeviceIdentitySecurityState {
    return {
      maxFailures: this.maxFailures,
      failureWindowMs: this.failureWindowMs,
      lockoutMs: this.lockoutMs,
      recentFailures: lockoutState.recentFailures,
      lockedOut: lockoutState.lockedOut,
      lockoutUntil: lockoutState.lockoutUntil,
    };
  }
}
