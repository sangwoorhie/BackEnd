import { Challenger } from 'src/entities/challenger.entity';
import { Logger, Module } from '@nestjs/common';
import { ChallengesController } from './challenges.controller';
import { ChallengesService } from './challenges.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Challenge } from '../entities/challenge.entity';
import { ChallengesRepository } from './challenges.repository';
import { ChallengeScheduler } from './challenges.scheduler';
import { UserRepository } from 'src/users/users.repository';
import { Follow } from 'src/entities/follow.entity';
import { User } from 'src/entities/user.entity';
import { GoalsRepository } from './goals.repository';
import { ChallengersRepository } from './challengers.repository';
import { FollowsRepository } from 'src/follows/follows.repository';
import { ScheduleModule } from '@nestjs/schedule';
import { PostsRepository } from 'src/posts/posts.repository';
import { RecordsRepository } from 'src/records/records.repository';
import { InviteChallenge } from '../entities/inviteChallenge.entity';
import { InviteChallengesRepository } from './inviteChalleges.repository';
import { Notification } from '../entities/notification.entity';
import { NotificationsRepository } from './notifications.repository';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Challenge,
      Challenger,
      Follow,
      User,
      InviteChallenge,
      Notification,
    ]),
    ScheduleModule.forRoot(),
  ],
  controllers: [ChallengesController],
  providers: [
    ChallengesService,
    ChallengesRepository,
    GoalsRepository,
    ChallengersRepository,
    Logger,
    ChallengeScheduler,
    UserRepository,
    ChallengeScheduler,
    FollowsRepository,
    PostsRepository,
    RecordsRepository,
    InviteChallengesRepository,
    NotificationsRepository,
  ],
  exports: [
    ChallengesService,
    ChallengesRepository,
    GoalsRepository,
    ChallengersRepository,
    ChallengeScheduler,
    UserRepository,
    FollowsRepository,
    PostsRepository,
    RecordsRepository,
    InviteChallengesRepository,
    NotificationsRepository,
  ],
})
export class ChallengesModule {}
