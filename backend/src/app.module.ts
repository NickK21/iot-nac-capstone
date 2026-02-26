import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DevicesModule } from './devices/devices.module';
import { AuditModule } from './audit/audit.module';

@Module({
  imports: [DevicesModule, AuditModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
