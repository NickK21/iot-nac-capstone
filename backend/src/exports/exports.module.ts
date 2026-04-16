import { Module } from '@nestjs/common';
import { PersistenceModule } from '../persistence/persistence.module';
import { ExportsController } from './exports.controller';
import { ExportsService } from './exports.service';

@Module({
  imports: [PersistenceModule],
  controllers: [ExportsController],
  providers: [ExportsService],
})
export class ExportsModule {}
