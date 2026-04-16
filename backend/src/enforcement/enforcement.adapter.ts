import type { DeviceState } from '../devices/device.interface';
import type { DeviceIdentityStatus } from '../devices/device.interface';

export type EnforcementAction = 'allow' | 'deny';

export type PolicyDecisionCode =
  | 'ok'
  | 'identity_not_verified'
  | 'identity_invalid'
  | 'identity_locked'
  | 'already_allowed'
  | 'already_denied';

export type EnforcementContext = {
  deviceId: string;
  prevState: DeviceState;
  identityStatus: DeviceIdentityStatus;
  requestedAt: string;
};

export type EnforcementResult = {
  result: 'applied' | 'blocked';
  nextState: DeviceState;
  source: string;
  message: string;
  code: PolicyDecisionCode;
};

export type EnforcementAdapterCapabilities = {
  networkIsolation: boolean;
  supportsDryRun: boolean;
  identityAware: boolean;
};

export type EnforcementAdapterHealth = {
  status: 'ok' | 'degraded';
  detail: string;
};

export interface EnforcementAdapter {
  name(): string;
  capabilities(): EnforcementAdapterCapabilities;
  health(): EnforcementAdapterHealth;
  apply(
    action: EnforcementAction,
    context: EnforcementContext,
  ): EnforcementResult;
}

export const ENFORCEMENT_ADAPTER = Symbol('ENFORCEMENT_ADAPTER');
