import { Module } from '@nestjs/common';
import { ENFORCEMENT_ADAPTER } from './enforcement.adapter';
import { LocalStateAdapter } from './local-state.adapter';

@Module({
  providers: [
    LocalStateAdapter,
    {
      provide: ENFORCEMENT_ADAPTER,
      useExisting: LocalStateAdapter,
    },
  ],
  exports: [ENFORCEMENT_ADAPTER],
})
export class EnforcementModule {}
