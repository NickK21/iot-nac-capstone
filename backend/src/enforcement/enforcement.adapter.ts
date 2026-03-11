import type { DeviceState } from '../devices/device.interface';

export type EnforcementAction = 'allow' | 'deny';

export type EnforcementContext = {
  deviceId: string;
  prevState: DeviceState;
  requestedAt: string;
};

export type EnforcementResult = {
  nextState: DeviceState;
  source: string;
};

export interface EnforcementAdapter {
  apply(
    action: EnforcementAction,
    context: EnforcementContext,
  ): EnforcementResult;
}

export const ENFORCEMENT_ADAPTER = Symbol('ENFORCEMENT_ADAPTER');
