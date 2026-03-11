import { BadRequestException, Controller, Get, Query } from '@nestjs/common';
import type { EventSeverity, EventType } from './event.interface';
import { EventsService } from './events.service';

const EVENT_TYPES: EventType[] = [
  'discovery',
  'identity_verified',
  'identity_failed',
  'identity_key_rotated',
  'policy_change',
];
const EVENT_SEVERITIES: EventSeverity[] = ['info', 'warning', 'critical'];

@Controller('events')
export class EventsController {
  constructor(private readonly eventsService: EventsService) {}

  @Get('recent')
  getRecentEvents(
    @Query('limit') limit?: string,
    @Query('before') before?: string,
    @Query('type') type?: string,
    @Query('severity') severity?: string,
    @Query('deviceId') deviceId?: string,
  ) {
    const parsed = Number(limit);
    const safeLimit = Number.isFinite(parsed)
      ? Math.min(Math.max(Math.floor(parsed), 1), 200)
      : 30;
    const safeType = this.parseEventType(type);
    const safeSeverities = this.parseSeverities(severity);
    const safeBefore = this.parseBefore(before);

    return this.eventsService.getRecent({
      limit: safeLimit,
      beforeTs: safeBefore,
      type: safeType,
      severities: safeSeverities,
      deviceId: deviceId?.trim() || undefined,
    });
  }

  private parseEventType(value?: string): EventType | undefined {
    if (!value?.trim()) {
      return undefined;
    }

    if (EVENT_TYPES.includes(value as EventType)) {
      return value as EventType;
    }

    throw new BadRequestException(
      `Invalid event type. Allowed types: ${EVENT_TYPES.join(', ')}`,
    );
  }

  private parseSeverities(value?: string): EventSeverity[] | undefined {
    if (!value?.trim()) {
      return undefined;
    }

    const values = value
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    if (values.length === 0) {
      return undefined;
    }

    for (const candidate of values) {
      if (!EVENT_SEVERITIES.includes(candidate as EventSeverity)) {
        throw new BadRequestException(
          `Invalid severity value: ${candidate}. Allowed values: ${EVENT_SEVERITIES.join(', ')}`,
        );
      }
    }

    return values as EventSeverity[];
  }

  private parseBefore(value?: string): string | undefined {
    if (!value?.trim()) {
      return undefined;
    }

    if (Number.isNaN(Date.parse(value))) {
      throw new BadRequestException('Invalid before timestamp');
    }

    return value;
  }
}
