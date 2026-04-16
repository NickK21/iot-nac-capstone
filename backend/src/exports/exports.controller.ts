import {
  BadRequestException,
  Controller,
  Get,
  Query,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import {
  ExportsService,
  type ExportFormat,
  type ExportScope,
} from './exports.service';

const EXPORT_SCOPES: ExportScope[] = ['audit', 'enforcement', 'events'];
const EXPORT_FORMATS: ExportFormat[] = ['csv', 'json'];
const EVENT_TYPES = [
  'discovery',
  'identity_verified',
  'identity_failed',
  'identity_key_rotated',
  'policy_change',
] as const;

@Controller('exports')
export class ExportsController {
  constructor(private readonly exportsService: ExportsService) {}

  @Get('download')
  download(
    @Query('scope') scope?: string,
    @Query('format') format?: string,
    @Query('deviceId') deviceId?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('eventType') eventType?: string,
    @Res({ passthrough: true }) res?: Response,
  ) {
    const safeScope = this.parseScope(scope);
    const safeFormat = this.parseFormat(format);
    const safeFrom = this.parseTs(from, 'from');
    const safeTo = this.parseTs(to, 'to');
    const safeEventType = this.parseEventType(eventType, safeScope);
    const payload = this.exportsService.generate({
      scope: safeScope,
      format: safeFormat,
      deviceId: deviceId?.trim() || undefined,
      fromTs: safeFrom,
      toTs: safeTo,
      eventType: safeEventType,
    });

    res?.setHeader('Content-Type', payload.contentType);
    res?.setHeader(
      'Content-Disposition',
      `attachment; filename="${payload.filename}"`,
    );

    return payload.body;
  }

  private parseScope(value?: string): ExportScope {
    if (value && EXPORT_SCOPES.includes(value as ExportScope)) {
      return value as ExportScope;
    }

    throw new BadRequestException(
      `Invalid export scope. Allowed values: ${EXPORT_SCOPES.join(', ')}`,
    );
  }

  private parseFormat(value?: string): ExportFormat {
    if (value && EXPORT_FORMATS.includes(value as ExportFormat)) {
      return value as ExportFormat;
    }

    throw new BadRequestException(
      `Invalid export format. Allowed values: ${EXPORT_FORMATS.join(', ')}`,
    );
  }

  private parseTs(value: string | undefined, label: 'from' | 'to') {
    if (!value?.trim()) {
      return undefined;
    }

    if (Number.isNaN(Date.parse(value))) {
      throw new BadRequestException(`Invalid ${label} timestamp`);
    }

    return value;
  }

  private parseEventType(value: string | undefined, scope: ExportScope) {
    if (!value?.trim()) {
      return undefined;
    }

    if (scope !== 'events') {
      throw new BadRequestException(
        'eventType filter is only supported for events exports',
      );
    }

    if ((EVENT_TYPES as readonly string[]).includes(value)) {
      return value;
    }

    throw new BadRequestException(
      `Invalid event type. Allowed values: ${EVENT_TYPES.join(', ')}`,
    );
  }
}
