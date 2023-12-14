import { Logger, Module } from '@nestjs/common';
import { LikesService } from './likes.service';
import { LikesController } from './likes.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Like } from '../entities/like.entity';
import { LikesRepository } from './likes.repository';
import { PostsRepository } from 'src/posts/posts.repository';
import { ChallengesRepository } from 'src/challenges/challenges.repository';
import { UserRepository } from 'src/users/users.repository';
import { ChallengersRepository } from 'src/challenges/challengers.repository';

@Module({
  imports: [TypeOrmModule.forFeature([Like])],
  controllers: [LikesController],
  providers: [
    UserRepository,
    Logger,
    LikesService,
    LikesRepository,
    PostsRepository,
    ChallengesRepository,
    ChallengersRepository,
  ],
})
export class LikesModule {}
