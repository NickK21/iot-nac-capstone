import { Injectable } from '@nestjs/common';
import type { DeviceState } from '../devices/device.interface';
import { SqliteService } from '../persistence/sqlite.service';
import type {
  EnforcementAction,
  PolicyDecisionCode,
  EnforcementResult,
} from './enforcement.adapter';

export type EnforcementLogEntry = {
  ts: string;
  deviceId: string;
  action: EnforcementAction;
  prevState: DeviceState;
  nextState: DeviceState;
  adapter: string;
  result: EnforcementResult['result'];
  code: PolicyDecisionCode;
  message: string;
};

type EnforcementLogRow = {
  ts: string;
  device_id: string;
  action: EnforcementAction;
  prev_state: DeviceState;
  next_state: DeviceState;
  adapter: string;
  result: EnforcementResult['result'];
  policy_code: PolicyDecisionCode;
  message: string;
};

@Injectable()
export class EnforcementLogService {
  constructor(private readonly sqlite: SqliteService) {}

  record(entry: EnforcementLogEntry): void {
    this.sqlite.db
      .prepare(
        `
        INSERT INTO enforcement_logs (
          ts, device_id, action, prev_state, next_state, adapter, result, policy_code, message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .run(
        entry.ts,
        entry.deviceId,
        entry.action,
        entry.prevState,
        entry.nextState,
        entry.adapter,
        entry.result,
        entry.code,
        entry.message,
      );
  }

  listForDevice(deviceId: string, limit = 25): EnforcementLogEntry[] {
    const rows = (
      this.sqlite.db
        .prepare(
          `
          SELECT ts, device_id, action, prev_state, next_state, adapter, result, policy_code, message
          FROM enforcement_logs
          WHERE device_id = ?
          ORDER BY ts DESC, id DESC
          LIMIT ?
        `,
        )
        .all(deviceId, limit) as EnforcementLogRow[]
    ).reverse();

    return rows.map((row) => ({
      ts: row.ts,
      deviceId: row.device_id,
      action: row.action,
      prevState: row.prev_state,
      nextState: row.next_state,
      adapter: row.adapter,
      result: row.result,
      code: row.policy_code,
      message: row.message,
    }));
  }
}
