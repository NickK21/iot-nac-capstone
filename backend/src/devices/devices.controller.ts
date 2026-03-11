import {
  BadRequestException,
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
    @Headers('x-device-signature') headerSignature?: string,
  ): Device {
    if (!body?.id?.trim()) {
      throw new BadRequestException('Request body must include a device id');
    }

    if (!headerDeviceId || !headerTs || !headerSignature) {
      throw new BadRequestException(
        'Missing required HMAC headers: x-device-id, x-device-ts, x-device-signature',
      );
    }

    return this.devicesService.reportSignedDeviceHeartbeat(body, {
      deviceId: headerDeviceId,
      timestamp: headerTs,
      signature: headerSignature,
    });
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(':id/allow')
  allowDevice(@Param('id', DeviceIdPipe) id: string): void {
    this.devicesService.applyPolicy(id, 'allow');
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(':id/deny')
  denyDevice(@Param('id', DeviceIdPipe) id: string): void {
    this.devicesService.applyPolicy(id, 'deny');
  }
}
