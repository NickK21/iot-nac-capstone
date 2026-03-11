import {
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import {
  ENFORCEMENT_ADAPTER,
  type EnforcementAction,
  type EnforcementAdapter,
} from '../enforcement/enforcement.adapter';
import type { DeviceReportDto } from './device-report.dto';
import type { Device } from './device.interface';
import { DeviceIdentityService } from './device-identity.service';
import { DevicesRepository } from './devices.repository';

type SignedDeviceHeaders = {
  deviceId: string;
  timestamp: string;
  signature: string;
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
    private readonly identityService: DeviceIdentityService,
    @Inject(ENFORCEMENT_ADAPTER)
    private readonly enforcementAdapter: EnforcementAdapter,
  ) {}

  listDevices(): Device[] {
    return this.devicesRepository.listDevices();
  }

  applyPolicy(id: string, action: EnforcementAction): void {
    const existing = this.devicesRepository.findById(id);
    if (!existing) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const now = new Date().toISOString();
    const decision = this.enforcementAdapter.apply(action, {
      deviceId: id,
      prevState: existing.state,
      requestedAt: now,
    });

    const updated = this.devicesRepository.updateState(
      id,
      decision.nextState,
      now,
    );
    if (!updated) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    this.auditService.record({
      ts: now,
      deviceId: id,
      action,
      prev: existing.state,
      next: updated.state,
    });

    this.logger.log(
      `[DEVICE STATE CHANGE] ${id}: ${existing.state} -> ${updated.state} via ${decision.source} @ ${now}`,
    );
  }

  reportSignedDeviceHeartbeat(
    payload: DeviceReportDto,
    headers: SignedDeviceHeaders,
  ): Device {
    const now = new Date().toISOString();
    const existing = this.devicesRepository.findById(payload.id);

    const verified = this.identityService.verify(
      headers.deviceId,
      headers.timestamp,
      headers.signature,
    );
    if (!verified.valid) {
      if (existing) {
        this.devicesRepository.updateIdentityStatus(payload.id, 'invalid', now);
      }
      throw new UnauthorizedException(
        `Invalid device signature: ${verified.reason}`,
      );
    }

    if (headers.deviceId !== payload.id) {
      throw new UnauthorizedException(
        'Header device id does not match payload device id',
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
