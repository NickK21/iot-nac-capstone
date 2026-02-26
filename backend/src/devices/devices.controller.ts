import { 
  Controller,
  Get,
  Post,
  Param,
  NotFoundException
 } from '@nestjs/common';
import { AUDIT } from "../audit/audit.store";
import type { Device } from './device.interface';

@Controller('devices')
export class DevicesController {
  private devices: Device[] = [
    {
      id: 'device-1',
      vendor: 'unknown',
      hostname: 'unknown',
      lastSeen: new Date().toISOString(),
      state: 'unknown',
    },
  ];

  @Get()
  getDevices(): Device[] {
    return this.devices;
  }

  @Post(':id/allow')
  allowDevice(@Param('id') id: string): Device {
    const device = this.devices.find((d) => d.id === id);

    if (!device) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const prev = device.state;
    device.state = 'allowed';

    AUDIT.push({
      ts: new Date().toISOString(),
      deviceId: id,
      action: "allow",
      prev: prev,
      next: device.state,
    });

    console.log(
      `[DEVICE STATE CHANGE] ${id}: ${prev} -> allowed @ ${new Date().toISOString()}`
    );

    return device;
  }

  @Post(':id/deny')
  denyDevice(@Param('id') id: string): Device {
    const device = this.devices.find((d) => d.id === id);

    if (!device) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const prev = device.state;
    device.state = 'denied';

    AUDIT.push({
      ts: new Date().toISOString(),
      deviceId: id,
      action: "deny",
      prev: prev,
      next: device.state,
    });

    console.log(
      `[DEVICE STATE CHANGE] ${id}: ${prev} -> denied @ ${new Date().toISOString()}`
    );

    return device;
  }
}