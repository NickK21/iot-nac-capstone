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
import { DeviceIdentityService } from './device-identity.service';
import { DeviceProvisioningService } from './device-provisioning.service';
import type { Device, DeviceIdentityStatus } from './device.interface';
import { DevicesRepository } from './devices.repository';
import { EnrollmentLogService } from './enrollment-log.service';

type SignedDeviceHeaders = {
  deviceId: string;
  timestamp: string;
  nonce: string;
  signature: string;
  provisioningToken?: string;
};

type DevicePlaceholderInput = {
  id: string;
  alias?: string | null;
  hostname?: string;
  vendor?: string;
};

type IdentityProfile = {
  deviceId: string;
  alias: string | null;
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
  provisioning: {
    headerName: 'x-device-provisioning-token';
    requiredOnFirstHeartbeat: true;
    active: boolean;
    issuedAt: string | null;
    expiresAt: string | null;
    consumedAt: string | null;
  };
  heartbeat: {
    endpoint: '/devices/report';
    method: 'POST';
    payloadFields: ['id', 'hostname', 'vendor'];
    requiredHeaders: [
      'x-device-id',
      'x-device-ts',
      'x-device-nonce',
      'x-device-signature',
    ];
    provisioningHeader: 'x-device-provisioning-token';
  };
};

type IdentityKeyResponse = {
  deviceId: string;
  alias: string | null;
  keyUpdatedAt: string;
  changeType: 'created' | 'updated';
  identityStatus: 'enrolled';
  provisioningToken: {
    token: string;
    issuedAt: string;
    expiresAt: string;
    headerName: 'x-device-provisioning-token';
  };
};

@Injectable()
export class DevicesService {
  private readonly logger = new Logger(DevicesService.name);

  constructor(
    private readonly devicesRepository: DevicesRepository,
    private readonly auditService: AuditService,
    private readonly enforcementLogService: EnforcementLogService,
    private readonly eventsService: EventsService,
    private readonly identityService: DeviceIdentityService,
    private readonly provisioningService: DeviceProvisioningService,
    private readonly enrollmentLogService: EnrollmentLogService,
    private readonly policyEngine: PolicyEngineService,
    private readonly enforcementService: EnforcementService,
  ) {}

  listDevices(): Device[] {
    return this.devicesRepository.listDevices();
  }

  createPlaceholder(input: DevicePlaceholderInput): Device {
    const id = input.id.trim();
    const now = new Date().toISOString();
    const existing = this.devicesRepository.findById(id);
    const upsertInput: Parameters<DevicesRepository['upsertDevice']>[0] = {
      id,
      lastSeen: now,
      state: existing?.state ?? 'unknown',
      identityStatus: existing?.identityStatus ?? 'pending',
      lastIdentityCheck: existing?.lastIdentityCheck ?? null,
    };

    if (Object.prototype.hasOwnProperty.call(input, 'alias')) {
      upsertInput.alias = this.normalizeOptionalText(input.alias);
    }

    if (Object.prototype.hasOwnProperty.call(input, 'hostname')) {
      upsertInput.hostname =
        this.normalizeOptionalText(input.hostname) ?? undefined;
    }

    if (Object.prototype.hasOwnProperty.call(input, 'vendor')) {
      upsertInput.vendor =
        this.normalizeOptionalText(input.vendor) ?? undefined;
    }

    const device = this.devicesRepository.upsertDevice(upsertInput);
    if (!existing) {
      this.enrollmentLogService.record({
        ts: now,
        deviceId: id,
        action: 'pending_created',
        message: `Pending inventory record created for ${id}`,
        details: {
          alias: device.alias ?? null,
          hostname: device.hostname ?? 'unknown',
          vendor: device.vendor ?? 'unknown',
        },
      });
    }

    return device;
  }

  enrollDevice(
    id: string,
    secret: string,
    alias?: string | null,
  ): IdentityKeyResponse {
    return this.upsertIdentityKey(id, secret, alias);
  }

  setIdentityKey(
    id: string,
    secret: string,
    alias?: string | null,
  ): IdentityKeyResponse {
    return this.upsertIdentityKey(id, secret, alias);
  }

  issueProvisioningToken(id: string) {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    if (existing.identityStatus !== 'enrolled') {
      throw new HttpException(
        'Provisioning token can only be issued while the device is enrolled',
        HttpStatus.CONFLICT,
      );
    }

    const keyMetadata = this.identityService.getDeviceIdentityKeyMetadata(id);
    if (!keyMetadata.keyConfigured) {
      throw new HttpException(
        'Device must have a per-device key before issuing a provisioning token',
        HttpStatus.CONFLICT,
      );
    }

    return this.issueAndRecordProvisioningToken(id);
  }

  updateAlias(id: string, alias?: string | null): Device {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const normalizedAlias = this.normalizeOptionalText(alias);
    const updated = this.devicesRepository.updateAlias(id, normalizedAlias);
    if (!updated) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    if ((existing.alias ?? null) !== (updated.alias ?? null)) {
      this.enrollmentLogService.record({
        ts: new Date().toISOString(),
        deviceId: id,
        action: 'alias_updated',
        message: updated.alias
          ? `Alias updated to ${updated.alias}`
          : 'Alias cleared',
        details: {
          previousAlias: existing.alias ?? null,
          nextAlias: updated.alias ?? null,
        },
      });
    }

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
    const provisioningState = this.provisioningService.getMetadata(id);

    return {
      deviceId: id,
      alias: existing.alias ?? null,
      identityStatus: securityState.lockedOut
        ? 'locked'
        : existing.identityStatus,
      lastIdentityCheck: existing.lastIdentityCheck ?? null,
      keyConfigured: keyMetadata.keyConfigured,
      keySource: keyMetadata.keySource,
      keyUpdatedAt: keyMetadata.keyUpdatedAt,
      hmac: hmacConfig,
      security: securityState,
      provisioning: provisioningState,
      heartbeat: {
        endpoint: '/devices/report',
        method: 'POST',
        payloadFields: ['id', 'hostname', 'vendor'],
        requiredHeaders: [
          'x-device-id',
          'x-device-ts',
          'x-device-nonce',
          'x-device-signature',
        ],
        provisioningHeader: 'x-device-provisioning-token',
      },
    };
  }

  getEnforcementHistory(id: string) {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    return this.enforcementLogService.listForDevice(id);
  }

  getEnrollmentHistory(id: string) {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    return this.enrollmentLogService.listForDevice(id);
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
      identityStatus: this.currentIdentityStatus(existing),
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
      if (existing) {
        this.devicesRepository.updateIdentityStatus(payload.id, 'invalid', now);
      }
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
      const failedStatus: DeviceIdentityStatus = verified.security.lockedOut
        ? 'locked'
        : 'invalid';

      this.devicesRepository.upsertDevice({
        id: payload.id,
        alias: existing?.alias ?? null,
        hostname: this.normalizeOptionalText(payload.hostname) ?? undefined,
        vendor: this.normalizeOptionalText(payload.vendor) ?? undefined,
        lastSeen: now,
        state: existing?.state ?? 'unknown',
        identityStatus: failedStatus,
        lastIdentityCheck: now,
      });

      this.eventsService.record({
        type: 'identity_failed',
        severity: verified.security.lockedOut ? 'critical' : 'warning',
        ts: now,
        deviceId: payload.id,
        message: `Identity check failed for ${payload.id}`,
        details: {
          payloadDeviceId: payload.id,
          reason: verified.reason ?? 'unknown',
          headerDeviceId: headers.deviceId,
          nonce: headers.nonce,
          keySource: verified.keySource,
          identityStatus: failedStatus,
        },
      });

      if (verified.security.lockedOut && verified.security.lockoutUntil) {
        throw new HttpException(
          `Identity verification temporarily locked: device temporarily locked until ${verified.security.lockoutUntil}`,
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      throw new UnauthorizedException(
        `Invalid device signature: ${verified.reason}`,
      );
    }

    const current = this.devicesRepository.findById(payload.id);
    if (current?.identityStatus === 'enrolled') {
      const tokenResult = this.provisioningService.consumeToken(
        payload.id,
        headers.provisioningToken,
      );

      if (!tokenResult.valid) {
        this.devicesRepository.upsertDevice({
          id: payload.id,
          alias: current.alias ?? null,
          hostname: this.normalizeOptionalText(payload.hostname) ?? undefined,
          vendor: this.normalizeOptionalText(payload.vendor) ?? undefined,
          lastSeen: now,
          state: current.state,
          identityStatus: 'enrolled',
          lastIdentityCheck: now,
        });

        this.eventsService.record({
          type: 'identity_failed',
          severity: 'warning',
          ts: now,
          deviceId: payload.id,
          message: `Provisioning validation failed for ${payload.id}`,
          details: {
            payloadDeviceId: payload.id,
            reason: tokenResult.reason ?? 'unknown',
            headerDeviceId: headers.deviceId,
            nonce: headers.nonce,
            provisioningHeader: 'x-device-provisioning-token',
          },
        });

        throw new UnauthorizedException(
          `Provisioning validation failed: ${tokenResult.reason}`,
        );
      }

      if (tokenResult.consumedAt) {
        this.enrollmentLogService.record({
          ts: tokenResult.consumedAt,
          deviceId: payload.id,
          action: 'provisioning_token_consumed',
          message:
            'One-time provisioning token consumed on first verified heartbeat',
          details: {
            consumedAt: tokenResult.consumedAt,
          },
        });
      }
    }

    const upserted = this.devicesRepository.upsertDevice({
      id: payload.id,
      alias: current?.alias ?? null,
      hostname: this.normalizeOptionalText(payload.hostname) ?? undefined,
      vendor: this.normalizeOptionalText(payload.vendor) ?? undefined,
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
        keySource: verified.keySource,
      },
    });

    return upserted;
  }

  private upsertIdentityKey(
    id: string,
    secret: string,
    alias?: string | null,
  ): IdentityKeyResponse {
    const now = new Date().toISOString();
    const existing = this.devicesRepository.findById(id);
    const normalizedAlias = this.normalizeOptionalText(alias);

    if (!existing) {
      this.devicesRepository.upsertDevice({
        id,
        alias: normalizedAlias,
        lastSeen: now,
        state: 'unknown',
        identityStatus: 'pending',
        lastIdentityCheck: null,
      });
      this.enrollmentLogService.record({
        ts: now,
        deviceId: id,
        action: 'pending_created',
        message: `Pending inventory record created for ${id}`,
        details: {
          alias: normalizedAlias,
        },
      });
    } else if (normalizedAlias !== null || alias !== undefined) {
      this.updateAlias(id, normalizedAlias);
    }

    const updatedKey = this.identityService.setDeviceSecret(id, secret);
    this.identityService.clearSecurityState(id);
    const provisioningToken = this.issueAndRecordProvisioningToken(id);

    const current = this.devicesRepository.findById(id);
    const enrolled = this.devicesRepository.upsertDevice({
      id,
      alias:
        normalizedAlias !== null || alias !== undefined
          ? normalizedAlias
          : (current?.alias ?? null),
      hostname: current?.hostname,
      vendor: current?.vendor,
      lastSeen: now,
      state: current?.state ?? 'unknown',
      identityStatus: 'enrolled',
      lastIdentityCheck: null,
    });

    this.eventsService.record({
      type: 'identity_key_rotated',
      severity: 'info',
      ts: updatedKey.keyUpdatedAt,
      deviceId: id,
      message: `Identity key ${updatedKey.changeType} for ${id}`,
      details: {
        keyScope: 'device',
        changeType: updatedKey.changeType,
        identityStatus: enrolled.identityStatus,
      },
    });

    this.enrollmentLogService.record({
      ts: updatedKey.keyUpdatedAt,
      deviceId: id,
      action:
        updatedKey.changeType === 'created' ? 'device_enrolled' : 'key_rotated',
      message:
        updatedKey.changeType === 'created'
          ? `Device enrolled with a per-device key`
          : `Device key rotated and trust reset to enrolled`,
      details: {
        keyUpdatedAt: updatedKey.keyUpdatedAt,
        identityStatus: enrolled.identityStatus,
      },
    });

    return {
      deviceId: id,
      alias: enrolled.alias ?? null,
      keyUpdatedAt: updatedKey.keyUpdatedAt,
      changeType: updatedKey.changeType,
      identityStatus: 'enrolled',
      provisioningToken,
    };
  }

  private issueAndRecordProvisioningToken(id: string) {
    const token = this.provisioningService.issueToken(id);
    this.enrollmentLogService.record({
      ts: token.issuedAt,
      deviceId: id,
      action: 'provisioning_token_issued',
      message:
        'One-time provisioning token issued for first verified heartbeat',
      details: {
        expiresAt: token.expiresAt,
        headerName: token.headerName,
      },
    });
    return token;
  }

  private currentIdentityStatus(device: Device): DeviceIdentityStatus {
    const securityState = this.identityService.getSecurityState(device.id);
    return securityState.lockedOut ? 'locked' : device.identityStatus;
  }

  private normalizeOptionalText(value?: string | null): string | null {
    if (value === undefined || value === null) {
      return null;
    }

    const normalized = value.trim();
    return normalized ? normalized : null;
  }
}
