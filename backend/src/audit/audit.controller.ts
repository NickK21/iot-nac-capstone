import { Controller, Get } from "@nestjs/common";
import { AUDIT } from "./audit.store";

@Controller("audit")
export class AuditController {
  @Get()
  getAudit() {
    return AUDIT;
  }
}