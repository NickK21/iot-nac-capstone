import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DevicesModule } from './devices/devices.module';
import { AuditModule } from './audit/audit.module';
import { PersistenceModule } from './persistence/persistence.module';
import { EnforcementModule } from './enforcement/enforcement.module';

@Module({
  imports: [PersistenceModule, EnforcementModule, DevicesModule, AuditModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
