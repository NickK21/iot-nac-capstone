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

@Controller('devices')
export class DevicesController {
  constructor(private readonly devicesService: DevicesService) {}

  @Get()
  getDevices(): Device[] {
    return this.devicesService.listDevices();
  }

  @Post('report')
  reportHeartbeat(
    @Body() body: DeviceReportDto,
    @Headers('x-device-id') headerDeviceId?: string,
    @Headers('x-device-ts') headerTs?: string,
    @Headers('x-device-nonce') headerNonce?: string,
    @Headers('x-device-signature') headerSignature?: string,
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
    });
  }

  @Get(':id/identity')
  getDeviceIdentityProfile(@Param('id', DeviceIdPipe) id: string) {
    return this.devicesService.getIdentityProfile(id);
  }

  @Post(':id/identity/key')
  setDeviceIdentityKey(
    @Param('id', DeviceIdPipe) id: string,
    @Body() body: { secret?: string },
  ): {
    deviceId: string;
    keyUpdatedAt: string;
    changeType: 'created' | 'updated';
  } {
    const secret = body?.secret?.trim();
    if (!secret || secret.length < 16) {
      throw new BadRequestException('Secret must be at least 16 characters');
    }

    return this.devicesService.setIdentityKey(id, secret);
  }

  @Post(':id/identity/secret')
  setDeviceIdentitySecretLegacy(
    @Param('id', DeviceIdPipe) id: string,
    @Body() body: { secret?: string },
  ): {
    deviceId: string;
    keyUpdatedAt: string;
    changeType: 'created' | 'updated';
  } {
    const secret = body?.secret?.trim();
    if (!secret || secret.length < 16) {
      throw new BadRequestException('Secret must be at least 16 characters');
    }

    return this.devicesService.setIdentityKey(id, secret);
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
}
