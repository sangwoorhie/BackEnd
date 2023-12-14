import { Module } from '@nestjs/common';
import { PostsController } from './posts.controller';
import { PostsService } from './posts.service';
import { PostsRepository } from './posts.repository';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Post } from '../entities/post.entity';
import { MulterModule } from '@nestjs/platform-express';
import * as multer from 'multer';
import { AwsService } from 'src/aws.service';
import { ChallengersRepository } from 'src/challenges/challengers.repository';
import { ChallengesRepository } from 'src/challenges/challenges.repository';

@Module({
  imports: [
    TypeOrmModule.forFeature([Post]),
    MulterModule.register({
      storage: multer.memoryStorage(),
    }),
  ],
  controllers: [PostsController],
  providers: [
    PostsService,
    PostsRepository,
    AwsService,
    ChallengersRepository,
    ChallengesRepository,
  ],
})
export class PostsModule {}
