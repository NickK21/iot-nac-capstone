import { Module } from '@nestjs/common';
import { ENFORCEMENT_ADAPTER } from './enforcement.adapter';
import { EnforcementController } from './enforcement.controller';
import { EnforcementLogService } from './enforcement-log.service';
import { EnforcementService } from './enforcement.service';
import { LocalStateAdapter } from './local-state.adapter';
import { PolicyEngineService } from './policy-engine.service';

@Module({
  controllers: [EnforcementController],
  providers: [
    EnforcementLogService,
    EnforcementService,
    PolicyEngineService,
    LocalStateAdapter,
    {
      provide: ENFORCEMENT_ADAPTER,
      useExisting: LocalStateAdapter,
    },
  ],
  exports: [
    ENFORCEMENT_ADAPTER,
    EnforcementLogService,
    EnforcementService,
    PolicyEngineService,
  ],
})
export class EnforcementModule {}
