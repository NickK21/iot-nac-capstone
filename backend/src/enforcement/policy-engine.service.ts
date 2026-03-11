import { Injectable } from '@nestjs/common';
import type {
  EnforcementAction,
  EnforcementContext,
  PolicyDecisionCode,
} from './enforcement.adapter';

export type PolicyEvaluation = {
  allowed: boolean;
  code: PolicyDecisionCode;
  message: string;
};

@Injectable()
export class PolicyEngineService {
  evaluate(
    action: EnforcementAction,
    context: EnforcementContext,
  ): PolicyEvaluation {
    if (action === 'allow' && context.identityStatus === 'invalid') {
      return {
        allowed: false,
        code: 'identity_invalid',
        message: 'Allow blocked: device identity is invalid',
      };
    }

    if (action === 'allow' && context.prevState === 'allowed') {
      return {
        allowed: true,
        code: 'already_allowed',
        message: 'Device is already in allowed state',
      };
    }

    if (action === 'deny' && context.prevState === 'denied') {
      return {
        allowed: true,
        code: 'already_denied',
        message: 'Device is already in denied state',
      };
    }

    return {
      allowed: true,
      code: 'ok',
      message: 'Policy evaluation passed',
    };
  }
}
