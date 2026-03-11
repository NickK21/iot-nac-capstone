import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { DevicesService } from './devices.service';

@Injectable()
export class DeviceDiscoveryService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DeviceDiscoveryService.name);
  private timer?: NodeJS.Timeout;

  constructor(private readonly devicesService: DevicesService) {}

  onModuleInit(): void {
    if (this.discoveryDisabled()) {
      this.logger.log('Dynamic discovery simulation disabled');
      return;
    }

    const intervalMs = Number(process.env.DISCOVERY_SIM_INTERVAL_MS ?? 8000);
    this.timer = setInterval(() => {
      this.devicesService.runDiscoveryTick();
    }, intervalMs);
    this.timer.unref();

    this.logger.log(
      `Dynamic discovery simulation enabled (interval ${intervalMs}ms)`,
    );
    this.devicesService.runDiscoveryTick();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
    }
  }

  private discoveryDisabled(): boolean {
    if (process.env.NODE_ENV === 'test') {
      return true;
    }

    const flag = process.env.DISCOVERY_SIM_DISABLED;
    if (!flag) {
      return false;
    }

    return ['1', 'true', 'yes', 'on'].includes(flag.toLowerCase());
  }
}
