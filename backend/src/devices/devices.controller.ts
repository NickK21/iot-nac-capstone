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
} from '@nestjs/common';
import type { Device } from './device.interface';
import { DeviceIdPipe } from './device-id.pipe';
import type { DeviceReportDto } from './device-report.dto';
import { DevicesService } from './devices.service';

type SecretBody = {
  secret?: string;
  alias?: string | null;
};

@Controller('devices')
export class DevicesController {
  constructor(private readonly devicesService: DevicesService) {}

  @Get()
  getDevices(): Device[] {
    return this.devicesService.listDevices();
  }

  @Post()
  createDevice(
    @Body()
    body: {
      id?: string;
      alias?: string | null;
      hostname?: string;
      vendor?: string;
    },
  ): Device {
    const id = body?.id?.trim();
    if (!id) {
      throw new BadRequestException('Request body must include a device id');
    }

    return this.devicesService.createPlaceholder({
      id,
      alias: this.validateAlias(body.alias),
      hostname: body.hostname,
      vendor: body.vendor,
    });
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

    return this.devicesService.reportSignedDeviceHeartbeat(body, {
      deviceId: headerDeviceId,
      timestamp: headerTs,
      nonce: headerNonce,
      signature: headerSignature,
      provisioningToken,
    });
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
}
