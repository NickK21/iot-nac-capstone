import {
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import {
  type EnforcementAction,
  type EnforcementResult,
} from '../enforcement/enforcement.adapter';
import { EnforcementLogService } from '../enforcement/enforcement-log.service';
import { EnforcementService } from '../enforcement/enforcement.service';
import { PolicyEngineService } from '../enforcement/policy-engine.service';
import { EventsService } from '../events/events.service';
import type { DeviceReportDto } from './device-report.dto';
import type { Device } from './device.interface';
import { DeviceIdentityService } from './device-identity.service';
import { DevicesRepository } from './devices.repository';

type SignedDeviceHeaders = {
  deviceId: string;
  timestamp: string;
  nonce: string;
  signature: string;
};

type IdentityProfile = {
  deviceId: string;
  identityStatus: Device['identityStatus'];
  lastIdentityCheck: string | null;
  keyConfigured: boolean;
  keySource: 'device' | 'fallback';
  keyUpdatedAt: string | null;
  hmac: {
    canonicalFormat: '<deviceId>.<timestamp>.<nonce>';
    maxSkewMs: number;
    nonceTtlMs: number;
  };
  security: {
    maxFailures: number;
    failureWindowMs: number;
    lockoutMs: number;
    recentFailures: number;
    lockedOut: boolean;
    lockoutUntil: string | null;
  };
};

@Injectable()
export class DevicesService {
  private readonly logger = new Logger(DevicesService.name);
  private readonly discoveryVendors = [
    'Acme',
    'Nordic',
    'Espressif',
    'Raspberry Pi',
    'Shelly',
    'Tuya',
  ];
  private readonly discoveryPrefixes = [
    'sensor',
    'cam',
    'plug',
    'lock',
    'hub',
    'meter',
  ];
  private readonly maxSimDevices = Number(
    process.env.DISCOVERY_SIM_MAX_DEVICES ?? 20,
  );
  private readonly discoveryNewChance = Number(
    process.env.DISCOVERY_SIM_NEW_DEVICE_CHANCE ?? 0.35,
  );

  constructor(
    private readonly devicesRepository: DevicesRepository,
    private readonly auditService: AuditService,
    private readonly enforcementLogService: EnforcementLogService,
    private readonly eventsService: EventsService,
    private readonly identityService: DeviceIdentityService,
    private readonly policyEngine: PolicyEngineService,
    private readonly enforcementService: EnforcementService,
  ) {}

  listDevices(): Device[] {
    return this.devicesRepository.listDevices();
  }

  setIdentityKey(
    id: string,
    secret: string,
  ): {
    deviceId: string;
    keyUpdatedAt: string;
    changeType: 'created' | 'updated';
  } {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      this.devicesRepository.upsertDevice({
        id,
        lastSeen: new Date().toISOString(),
        state: 'unknown',
        identityStatus: 'unverified',
      });
    }

    const updated = this.identityService.setDeviceSecret(id, secret);
    this.eventsService.record({
      type: 'identity_key_rotated',
      severity: 'info',
      ts: updated.keyUpdatedAt,
      deviceId: id,
      message: `Identity key ${updated.changeType} for ${id}`,
      details: {
        keyScope: 'device',
        changeType: updated.changeType,
      },
    });
    return updated;
  }

  getIdentityProfile(id: string): IdentityProfile {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const keyMetadata = this.identityService.getDeviceIdentityKeyMetadata(id);
    const hmacConfig = this.identityService.getConfig();
    const securityState = this.identityService.getSecurityState(id);

    return {
      deviceId: id,
      identityStatus: existing.identityStatus,
      lastIdentityCheck: existing.lastIdentityCheck ?? null,
      keyConfigured: keyMetadata.keyConfigured,
      keySource: keyMetadata.keySource,
      keyUpdatedAt: keyMetadata.keyUpdatedAt,
      hmac: hmacConfig,
      security: securityState,
    };
  }

  getEnforcementHistory(id: string) {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    return this.enforcementLogService.listForDevice(id);
  }

  applyPolicy(id: string, action: EnforcementAction): EnforcementResult {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const now = new Date().toISOString();
    const context = {
      deviceId: id,
      prevState: existing.state,
      identityStatus: existing.identityStatus,
      requestedAt: now,
    };
    const policyEvaluation = this.policyEngine.evaluate(action, context);

    const decision = policyEvaluation.allowed
      ? (() => {
          const adapterDecision = this.enforcementService.apply(
            action,
            context,
          );
          return {
            ...adapterDecision,
            code: policyEvaluation.code,
            message:
              policyEvaluation.code === 'ok'
                ? adapterDecision.message
                : policyEvaluation.message,
          };
        })()
      : ({
          result: 'blocked',
          nextState: existing.state,
          source: 'policy-engine',
          message: policyEvaluation.message,
          code: policyEvaluation.code,
        } satisfies EnforcementResult);

    let nextState = existing.state;
    if (decision.result === 'applied') {
      const updated = this.devicesRepository.updateState(
        id,
        decision.nextState,
        now,
      );
      if (!updated) {
        throw new NotFoundException(`Device ${id} not found`);
      }
      nextState = updated.state;
    }

    if (decision.result === 'applied' && nextState !== existing.state) {
      this.auditService.record({
        ts: now,
        deviceId: id,
        action,
        prev: existing.state,
        next: nextState,
      });
    }

    this.enforcementLogService.record({
      ts: now,
      deviceId: id,
      action,
      prevState: existing.state,
      nextState,
      adapter: decision.source,
      result: decision.result,
      code: decision.code,
      message: decision.message,
    });

    this.eventsService.record({
      type: 'policy_change',
      severity: decision.result === 'applied' ? 'info' : 'warning',
      ts: now,
      deviceId: id,
      message:
        decision.result === 'applied'
          ? `Policy ${action} applied to ${id}: ${existing.state} -> ${nextState}`
          : `Policy ${action} blocked for ${id}`,
      details: {
        action,
        previousState: existing.state,
        nextState,
        source: decision.source,
        result: decision.result,
        code: decision.code,
      },
    });

    this.logger.log(
      `[DEVICE STATE CHANGE] ${id}: ${existing.state} -> ${nextState} via ${decision.source} (${decision.result}) @ ${now}`,
    );

    return decision;
  }

  reportSignedDeviceHeartbeat(
    payload: DeviceReportDto,
    headers: SignedDeviceHeaders,
  ): Device {
    const now = new Date().toISOString();
    const existing = this.devicesRepository.findById(payload.id);

    if (headers.deviceId !== payload.id) {
      this.eventsService.record({
        type: 'identity_failed',
        severity: 'warning',
        ts: now,
        deviceId: existing ? payload.id : undefined,
        message: `Identity check failed: header id ${headers.deviceId} does not match payload id ${payload.id}`,
        details: {
          reason: 'device id mismatch',
          headerDeviceId: headers.deviceId,
          payloadDeviceId: payload.id,
        },
      });
      throw new UnauthorizedException(
        'Header device id does not match payload device id',
      );
    }

    const verified = this.identityService.verify(
      payload.id,
      headers.timestamp,
      headers.nonce,
      headers.signature,
    );
    if (!verified.valid) {
      if (existing) {
        this.devicesRepository.updateIdentityStatus(payload.id, 'invalid', now);
      }
      this.eventsService.record({
        type: 'identity_failed',
        severity: 'warning',
        ts: now,
        deviceId: existing ? payload.id : undefined,
        message: `Identity check failed for ${payload.id}`,
        details: {
          payloadDeviceId: payload.id,
          reason: verified.reason ?? 'unknown',
          headerDeviceId: headers.deviceId,
          nonce: headers.nonce,
        },
      });
      if (verified.reason?.startsWith('device temporarily locked until ')) {
        throw new HttpException(
          `Identity verification temporarily locked: ${verified.reason}`,
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      throw new UnauthorizedException(
        `Invalid device signature: ${verified.reason}`,
      );
    }

    const current = this.devicesRepository.findById(payload.id);
    const upserted = this.devicesRepository.upsertDevice({
      id: payload.id,
      hostname: payload.hostname,
      vendor: payload.vendor,
      lastSeen: now,
      state: current?.state ?? 'unknown',
      identityStatus: 'verified',
      lastIdentityCheck: now,
    });

    this.eventsService.record({
      type: 'identity_verified',
      severity: 'info',
      ts: now,
      deviceId: payload.id,
      message: `Identity verified for ${payload.id}`,
      details: {
        headerDeviceId: headers.deviceId,
        nonce: headers.nonce,
      },
    });

    return upserted;
  }

  runDiscoveryTick(): Device {
    const devices = this.devicesRepository.listDevices();
    const shouldCreateNew =
      devices.length === 0 ||
      (devices.length < this.maxSimDevices &&
        Math.random() < this.discoveryNewChance);

    if (shouldCreateNew) {
      const created = this.devicesRepository.upsertDevice({
        id: this.generateSimDeviceId(),
        hostname: this.randomHostname(),
        vendor: this.randomVendor(),
        lastSeen: new Date().toISOString(),
        state: 'unknown',
        identityStatus: 'unverified',
      });

      this.logger.log(
        `[DISCOVERY] New simulated device discovered: ${created.id}`,
      );
      this.eventsService.record({
        type: 'discovery',
        severity: 'info',
        ts: created.lastSeen,
        deviceId: created.id,
        message: `Discovered new device ${created.id}`,
        details: {
          hostname: created.hostname ?? 'unknown',
          vendor: created.vendor ?? 'unknown',
          mode: 'automatic',
        },
      });
      return created;
    }

    const target = devices[Math.floor(Math.random() * devices.length)];
    const refreshed = this.devicesRepository.upsertDevice({
      id: target.id,
      hostname: target.hostname,
      vendor: target.vendor,
      lastSeen: new Date().toISOString(),
      state: target.state,
      identityStatus: target.identityStatus,
      lastIdentityCheck: target.lastIdentityCheck ?? null,
    });

    this.logger.debug(
      `[DISCOVERY] Refreshed simulated heartbeat for ${refreshed.id}`,
    );
    return refreshed;
  }

  private randomVendor(): string {
    return this.discoveryVendors[
      Math.floor(Math.random() * this.discoveryVendors.length)
    ];
  }

  private randomHostname(): string {
    const prefix =
      this.discoveryPrefixes[
        Math.floor(Math.random() * this.discoveryPrefixes.length)
      ];
    const suffix = Math.floor(1000 + Math.random() * 9000);
    return `${prefix}-${suffix}`;
  }

  private generateSimDeviceId(): string {
    return `sim-${Math.random().toString(36).slice(2, 10)}`;
  }
}
