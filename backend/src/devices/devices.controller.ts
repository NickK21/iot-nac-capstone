import { Controller, Get } from '@nestjs/common';
import { Device } from './device.interface';

@Controller('devices')
export class DevicesController {
  @Get()
  getDevices(): Device[] {
    return [
      {
        id: 'device-1',
        vendor: 'unknown',
        hostname: 'unknown',
        lastSeen: new Date().toISOString(),
        state: 'unknown',
      },
    ];
  }
}