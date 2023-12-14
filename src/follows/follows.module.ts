import { Module } from '@nestjs/common';
import { FollowsService } from './follows.service';
import { FollowsController } from './follows.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Follow } from 'src/entities/follow.entity';
import { FollowsRepository } from './follows.repository';
import { UserRepository } from 'src/users/users.repository';
import { FollowMessage } from '../entities/followMessage.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Follow, FollowMessage])],
  controllers: [FollowsController],
  providers: [FollowsService, FollowsRepository, UserRepository],
})
export class FollowsModule {}
