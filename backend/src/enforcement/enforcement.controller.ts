import { Controller, Get } from '@nestjs/common';
import { EnforcementService } from './enforcement.service';

@Controller('enforcement')
export class EnforcementController {
  constructor(private readonly enforcementService: EnforcementService) {}

  @Get('status')
  getStatus() {
    return this.enforcementService.getStatus();
  }
}
