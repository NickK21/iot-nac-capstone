import { BadRequestException, Controller, Get, Query } from '@nestjs/common';
import { AuditService } from './audit.service';

@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get()
  getAudit(
    @Query('deviceId') deviceId?: string,
    @Query('limit') limit?: string,
    @Query('before') before?: string,
  ) {
    const parsed = Number(limit);
    const safeLimit = Number.isFinite(parsed)
      ? Math.min(Math.max(Math.floor(parsed), 1), 200)
      : 100;

    if (before?.trim() && Number.isNaN(Date.parse(before))) {
      throw new BadRequestException('Invalid before timestamp');
    }

    return this.auditService.getAudit({
      deviceId: deviceId?.trim() || undefined,
      limit: safeLimit,
      beforeTs: before?.trim() || undefined,
    });
  }
}
