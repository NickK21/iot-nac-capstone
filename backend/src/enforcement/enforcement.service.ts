import { Inject, Injectable } from '@nestjs/common';
import type {
  EnforcementAction,
  EnforcementContext,
  EnforcementResult,
} from './enforcement.adapter';
import { ENFORCEMENT_ADAPTER } from './enforcement.adapter';
import type { EnforcementAdapter } from './enforcement.adapter';

type EnforcementAdapterStatus = {
  adapter: string;
  mode: 'active' | 'dry-run';
  health: {
    status: 'ok' | 'degraded';
    detail: string;
  };
  capabilities: {
    networkIsolation: boolean;
    supportsDryRun: boolean;
    identityAware: boolean;
  };
};

@Injectable()
export class EnforcementService {
  private readonly dryRunMode = this.parseBoolean(
    process.env.ENFORCEMENT_DRY_RUN,
  );

  constructor(
    @Inject(ENFORCEMENT_ADAPTER)
    private readonly adapter: EnforcementAdapter,
  ) {}

  getStatus(): EnforcementAdapterStatus {
    return {
      adapter: this.adapter.name(),
      mode: this.dryRunMode ? 'dry-run' : 'active',
      health: this.adapter.health(),
      capabilities: this.adapter.capabilities(),
    };
  }

  apply(
    action: EnforcementAction,
    context: EnforcementContext,
  ): EnforcementResult {
    if (!this.dryRunMode) {
      return this.adapter.apply(action, context);
    }

    const simulatedNextState = action === 'allow' ? 'allowed' : 'denied';

    return {
      result: 'applied',
      nextState: context.prevState,
      source: `${this.adapter.name()} (dry-run)`,
      message: `Dry-run mode: would set device state to ${simulatedNextState}`,
      code: 'ok',
    };
  }

  private parseBoolean(value: string | undefined): boolean {
    if (!value) {
      return false;
    }

    return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
  }
}
