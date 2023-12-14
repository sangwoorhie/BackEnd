import { Module } from '@nestjs/common';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Report } from '../entities/report.entity';
import { ReportsRepository } from './reports.repository';
import { BlackList } from 'src/entities/blacklist.entity';
import { BlackListRepository } from '../blacklists/blacklist.repository';

@Module({
  imports: [TypeOrmModule.forFeature([Report, BlackList])],
  controllers: [ReportsController],
  providers: [ReportsService, ReportsRepository, BlackListRepository],
})
export class ReportsModule {}
