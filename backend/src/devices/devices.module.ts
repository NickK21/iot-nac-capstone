import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { EnforcementModule } from '../enforcement/enforcement.module';
import { DeviceDiscoveryService } from './device-discovery.service';
import { DeviceIdentityService } from './device-identity.service';
import { DevicesController } from './devices.controller';
import { DevicesRepository } from './devices.repository';
import { DevicesService } from './devices.service';

@Module({
  imports: [AuditModule, EnforcementModule],
  controllers: [DevicesController],
  providers: [
    DevicesService,
    DevicesRepository,
    DeviceIdentityService,
    DeviceDiscoveryService,
  ],
})
export class DevicesModule {}
