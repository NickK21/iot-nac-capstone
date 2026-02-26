import {
  Controller,
  Get,
  Post,
  Param,
  NotFoundException,
  HttpCode,
  HttpStatus,
} from "@nestjs/common";
import type { Device } from "./device.interface";
import { AUDIT } from "../audit/audit.store";
import { DeviceIdPipe } from "./device-id.pipe";

@Controller("devices")
export class DevicesController {
  private devices: Device[] = [
    {
      id: "device-1",
      vendor: "unknown",
      hostname: "unknown",
      lastSeen: new Date().toISOString(),
      state: "unknown",
    },
  ];

  @Get()
  getDevices(): Device[] {
    return this.devices;
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(":id/allow")
  allowDevice(@Param("id", DeviceIdPipe) id: string): void {
    const device = this.devices.find((d) => d.id === id);

    if (!device) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const prev = device.state;
    device.state = "allowed";

    AUDIT.push({
      ts: new Date().toISOString(),
      deviceId: id,
      action: "allow",
      prev,
      next: device.state,
    });

    console.log(
      `[DEVICE STATE CHANGE] ${id}: ${prev} -> allowed @ ${new Date().toISOString()}`
    );
  }

  @HttpCode(HttpStatus.NO_CONTENT)
  @Post(":id/deny")
  denyDevice(@Param("id", DeviceIdPipe) id: string): void {
    const device = this.devices.find((d) => d.id === id);

    if (!device) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    const prev = device.state;
    device.state = "denied";

    AUDIT.push({
      ts: new Date().toISOString(),
      deviceId: id,
      action: "deny",
      prev,
      next: device.state,
    });

    console.log(
      `[DEVICE STATE CHANGE] ${id}: ${prev} -> denied @ ${new Date().toISOString()}`
    );
  }
}