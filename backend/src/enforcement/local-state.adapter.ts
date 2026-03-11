import { Injectable } from '@nestjs/common';
import type {
  EnforcementAction,
  EnforcementAdapter,
  EnforcementContext,
  EnforcementResult,
} from './enforcement.adapter';

@Injectable()
export class LocalStateAdapter implements EnforcementAdapter {
  name(): string {
    return 'local-state-adapter';
  }

  capabilities() {
    return {
      networkIsolation: false,
      supportsDryRun: true,
      identityAware: false,
    } as const;
  }

  health() {
    return {
      status: 'ok',
      detail: 'Local state adapter is available',
    } as const;
  }

  apply(
    action: EnforcementAction,
    context: EnforcementContext,
  ): EnforcementResult {
    void context;

    return {
      result: 'applied',
      nextState: action === 'allow' ? 'allowed' : 'denied',
      source: this.name(),
      message: `Applied ${action} through local state adapter`,
      code: 'ok',
    };
  }
}
