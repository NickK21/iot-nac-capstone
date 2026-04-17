import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { EnforcementModule } from '../enforcement/enforcement.module';
import { EventsModule } from '../events/events.module';
import { DeviceIdentityService } from './device-identity.service';
import { DeviceProfileInferenceService } from './device-profile-inference.service';
import { DeviceProvisioningService } from './device-provisioning.service';
import { DevicesController } from './devices.controller';
import { EnrollmentLogService } from './enrollment-log.service';
import { DevicesRepository } from './devices.repository';
import { DevicesService } from './devices.service';

@Module({
  imports: [AuditModule, EnforcementModule, EventsModule],
  controllers: [DevicesController],
  providers: [
    DevicesService,
    DevicesRepository,
    DeviceIdentityService,
    DeviceProfileInferenceService,
    DeviceProvisioningService,
    EnrollmentLogService,
  ],
  exports: [
    DevicesService,
    DeviceIdentityService,
    DeviceProfileInferenceService,
    DeviceProvisioningService,
    EnrollmentLogService,
  ],
})
export class DevicesModule {}
