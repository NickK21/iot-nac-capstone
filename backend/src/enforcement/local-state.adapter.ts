import { Injectable } from '@nestjs/common';
import type {
  EnforcementAction,
  EnforcementAdapter,
  EnforcementContext,
  EnforcementResult,
} from './enforcement.adapter';

@Injectable()
export class LocalStateAdapter implements EnforcementAdapter {
  apply(
    action: EnforcementAction,
    _context: EnforcementContext,
  ): EnforcementResult {
    void _context;

    return {
      nextState: action === 'allow' ? 'allowed' : 'denied',
      source: 'local-state-adapter',
    };
  }
}
