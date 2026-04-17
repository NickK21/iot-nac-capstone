import {
  BadRequestException,
  ConflictException,
  Controller,
  Get,
  Headers,
  Post,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  Query,
} from '@nestjs/common';
import type { Device } from './device.interface';
import { DeviceIdPipe } from './device-id.pipe';
import type { DeviceReportDto } from './device-report.dto';
import { DevicesService } from './devices.service';
import type { DeviceInventoryView } from './devices.repository';

type SecretBody = {
  secret?: string;
  alias?: string | null;
};

@Controller('devices')
export class DevicesController {
  constructor(private readonly devicesService: DevicesService) {}

  @Get()
  getDevices(@Query('view') view?: string): Device[] {
    return this.devicesService.listDevices(this.parseInventoryView(view));
  }

  @Get('lifecycle')
  getLifecycle(
    @Query('deviceId') deviceId?: string,
    @Query('limit') limit?: string,
    @Query('before') before?: string,
  ) {
    const parsedLimit = Number(limit);
    const safeLimit = Number.isFinite(parsedLimit)
      ? Math.min(Math.max(Math.floor(parsedLimit), 1), 200)
      : 40;

    if (before?.trim() && Number.isNaN(Date.parse(before))) {
      throw new BadRequestException('Invalid before timestamp');
    }

    return this.devicesService.getLifecycleHistory({
      deviceId: deviceId?.trim() || undefined,
      limit: safeLimit,
      beforeTs: before?.trim() || undefined,
    });
  }

  @Post()
  createDevice(
    @Body()
    body: {
      id?: string;
      alias?: string | null;
      hostname?: string | null;
      vendor?: string | null;
      model?: string | null;
      location?: string | null;
      macAddress?: string | null;
    },
  ): Device {
    const id = body?.id?.trim();
    if (!id) {
      throw new BadRequestException('Request body must include a device id');
    }

    const input = {
      id,
      ...(Object.prototype.hasOwnProperty.call(body, 'alias')
        ? { alias: this.validateAlias(body.alias) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'hostname')
        ? { hostname: this.validateOptionalText(body.hostname, 'Hostname', 64) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'vendor')
        ? { vendor: this.validateOptionalText(body.vendor, 'Vendor', 64) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'model')
        ? { model: this.validateOptionalText(body.model, 'Model', 64) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'location')
        ? { location: this.validateOptionalText(body.location, 'Location', 80) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'macAddress')
        ? { macAddress: this.validateMacAddress(body.macAddress) }
        : {}),
    };

    return this.devicesService.createPlaceholder(input);
  }

  @Post('report')
  reportHeartbeat(
    @Body() body: DeviceReportDto,
    @Headers('x-device-id') headerDeviceId?: string,
    @Headers('x-device-ts') headerTs?: string,
    @Headers('x-device-nonce') headerNonce?: string,
    @Headers('x-device-signature') headerSignature?: string,
    @Headers('x-device-provisioning-token') provisioningToken?: string,
  ): Device {
    if (!body?.id?.trim()) {
      throw new BadRequestException('Request body must include a device id');
    }

    if (!headerDeviceId || !headerTs || !headerNonce || !headerSignature) {
      throw new BadRequestException(
        'Missing required HMAC headers: x-device-id, x-device-ts, x-device-nonce, x-device-signature',
      );
    }

    return this.devicesService.reportSignedDeviceHeartbeat(
      {
        ...body,
        ...(Object.prototype.hasOwnProperty.call(body, 'hostname')
          ? {
              hostname:
                this.validateOptionalText(body.hostname, 'Hostname', 64) ??
                undefined,
            }
          : {}),
        ...(Object.prototype.hasOwnProperty.call(body, 'vendor')
          ? {
              vendor:
                this.validateOptionalText(body.vendor, 'Vendor', 64) ??
                undefined,
            }
          : {}),
        ...(Object.prototype.hasOwnProperty.call(body, 'model')
          ? {
              model:
                this.validateOptionalText(body.model, 'Model', 64) ?? undefined,
            }
          : {}),
        ...(Object.prototype.hasOwnProperty.call(body, 'macAddress')
          ? {
              macAddress: this.validateMacAddress(body.macAddress) ?? undefined,
            }
          : {}),
        ...(Object.prototype.hasOwnProperty.call(body, 'fingerprint')
          ? {
              fingerprint:
                this.validateOptionalText(
                  body.fingerprint,
                  'Fingerprint',
                  96,
                ) ?? undefined,
            }
          : {}),
      },
      {
        deviceId: headerDeviceId,
        timestamp: headerTs,
        nonce: headerNonce,
        signature: headerSignature,
        provisioningToken,
      },
    );
  }

  @Get(':id/identity')
  getDeviceIdentityProfile(@Param('id', DeviceIdPipe) id: string) {
    return this.devicesService.getIdentityProfile(id);
  }

  @Get(':id/enrollment-history')
  getEnrollmentHistory(@Param('id', DeviceIdPipe) id: string) {
    return this.devicesService.getEnrollmentHistory(id);
  }

  @Post(':id/enroll')
  enrollDevice(
    @Param('id', DeviceIdPipe) id: string,
    @Body() body: SecretBody,
  ) {
    const secret = body?.secret?.trim();
    if (!secret || secret.length < 16) {
      throw new BadRequestException('Secret must be at least 16 characters');
    }

    return this.devicesService.enrollDevice(
      id,
      secret,
      this.validateAlias(body.alias),
    );
  }

  @Post(':id/provisioning-token')
  issueProvisioningToken(@Param('id', DeviceIdPipe) id: string) {
    return this.devicesService.issueProvisioningToken(id);
  }

  @Post(':id/identity/key')
  setDeviceIdentityKey(
    @Param('id', DeviceIdPipe) id: string,
    @Body() body: SecretBody,
  ) {
    const secret = body?.secret?.trim();
    if (!secret || secret.length < 16) {
      throw new BadRequestException('Secret must be at least 16 characters');
    }

    return this.devicesService.setIdentityKey(
      id,
      secret,
      this.validateAlias(body.alias),
    );
  }

  @Post(':id/identity/secret')
  setDeviceIdentitySecretLegacy(
    @Param('id', DeviceIdPipe) id: string,
    @Body() body: SecretBody,
  ) {
    const secret = body?.secret?.trim();
    if (!secret || secret.length < 16) {
      throw new BadRequestException('Secret must be at least 16 characters');
    }

    return this.devicesService.setIdentityKey(
      id,
      secret,
      this.validateAlias(body.alias),
    );
  }

  @Post(':id/alias')
  updateDeviceAlias(
    @Param('id', DeviceIdPipe) id: string,
    @Body() body: { alias?: string | null },
  ): Device {
    if (
      body === undefined ||
      !Object.prototype.hasOwnProperty.call(body, 'alias')
    ) {
      throw new BadRequestException('Request body must include an alias field');
    }

    return this.devicesService.updateAlias(id, this.validateAlias(body.alias));
  }

  @Post(':id/profile')
  updateDeviceProfile(
    @Param('id', DeviceIdPipe) id: string,
    @Body()
    body: {
      hostname?: string | null;
      vendor?: string | null;
      model?: string | null;
      location?: string | null;
      macAddress?: string | null;
    },
  ): Device {
    if (body === undefined) {
      throw new BadRequestException('Request body must include profile fields');
    }

    return this.devicesService.updateProfile(id, {
      ...(Object.prototype.hasOwnProperty.call(body, 'hostname')
        ? { hostname: this.validateOptionalText(body.hostname, 'Hostname', 64) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'vendor')
        ? { vendor: this.validateOptionalText(body.vendor, 'Vendor', 64) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'model')
        ? { model: this.validateOptionalText(body.model, 'Model', 64) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'location')
        ? { location: this.validateOptionalText(body.location, 'Location', 80) }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, 'macAddress')
        ? { macAddress: this.validateMacAddress(body.macAddress) }
        : {}),
    });
  }

  @Post(':id/archive')
  archiveDevice(@Param('id', DeviceIdPipe) id: string): Device {
    return this.devicesService.archiveDevice(id);
  }

  @Post(':id/restore')
  restoreDevice(@Param('id', DeviceIdPipe) id: string): Device {
    return this.devicesService.restoreDevice(id);
  }

  @Get(':id/enforcement')
  getDeviceEnforcementHistory(@Param('id', DeviceIdPipe) id: string) {
    return this.devicesService.getEnforcementHistory(id);
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(':id/allow')
  allowDevice(@Param('id', DeviceIdPipe) id: string): void {
    const decision = this.devicesService.applyPolicy(id, 'allow');
    if (decision.result === 'blocked') {
      throw new ConflictException(decision.message);
    }
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(':id/deny')
  denyDevice(@Param('id', DeviceIdPipe) id: string): void {
    const decision = this.devicesService.applyPolicy(id, 'deny');
    if (decision.result === 'blocked') {
      throw new ConflictException(decision.message);
    }
  }

  private parseInventoryView(value?: string): DeviceInventoryView {
    if (!value?.trim()) {
      return 'active';
    }

    if (value === 'active' || value === 'archived' || value === 'all') {
      return value;
    }

    throw new BadRequestException('Invalid device inventory view');
  }

  private validateAlias(value?: string | null): string | null | undefined {
    if (value === undefined) {
      return undefined;
    }

    if (value === null) {
      return null;
    }

    const normalized = value.trim();
    if (!normalized) {
      return null;
    }

    if (normalized.length > 48) {
      throw new BadRequestException('Alias must be 48 characters or fewer');
    }

    if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]*$/.test(normalized)) {
      throw new BadRequestException(
        'Alias may contain letters, numbers, spaces, dots, underscores, and hyphens',
      );
    }

    return normalized;
  }

  private validateOptionalText(
    value: string | null | undefined,
    label: string,
    maxLength: number,
  ): string | null | undefined {
    if (value === undefined) {
      return undefined;
    }

    if (value === null) {
      return null;
    }

    const normalized = value.trim();
    if (!normalized) {
      return null;
    }

    if (normalized.length > maxLength) {
      throw new BadRequestException(
        `${label} must be ${maxLength} characters or fewer`,
      );
    }

    return normalized;
  }

  private validateMacAddress(
    value: string | null | undefined,
  ): string | null | undefined {
    if (value === undefined) {
      return undefined;
    }

    if (value === null) {
      return null;
    }

    const normalized = value.trim();
    if (!normalized) {
      return null;
    }

    const compact = normalized.replace(/[^A-Fa-f0-9]/g, '');
    if (compact.length !== 12) {
      throw new BadRequestException(
        'MAC address must contain 12 hexadecimal characters',
      );
    }

    return (
      compact
        .match(/.{1,2}/g)
        ?.join(':')
        .toUpperCase() ?? normalized.toUpperCase()
    );
  }
}
