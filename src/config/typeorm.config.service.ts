import { Injectable } from '@nestjs/common';
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { Challenge } from 'src/entities/challenge.entity';
import { Goal } from 'src/entities/goal.entity';
import { User } from 'src/entities/user.entity';
import { Follow } from 'src/entities/follow.entity';
import { Record } from 'src/entities/records.entity';
import { Report } from 'src/entities/report.entity';
import { Challenger } from 'src/entities/challenger.entity';
import { BlackList } from 'src/entities/blacklist.entity';
import { Post } from 'src/entities/post.entity';
import { Like } from 'src/entities/like.entity';
import { Comment } from 'src/entities/comment.entity';
import { FollowMessage } from 'src/entities/followMessage.entity';
import { InviteChallenge } from 'src/entities/inviteChallenge.entity';
import { Notification } from 'src/entities/notification.entity';

@Injectable()
export class TypeOrmConfigService implements TypeOrmOptionsFactory {
  constructor(private readonly configService: ConfigService) {}

  createTypeOrmOptions(): TypeOrmModuleOptions {
    return {
      type: 'mysql',
      host: this.configService.get<string>('DATABASE_HOST'),
      port: this.configService.get<number>('DATABASE_PORT'),
      username: this.configService.get<string>('DATABASE_USERNAME'),
      password: this.configService.get<string>('DATABASE_PASSWORD'),
      database: this.configService.get<string>('DATABASE_NAME'),
      entities: [
        User,
        Challenge,
        Goal,
        Follow,
        Record,
        Report,
        Challenger,
        BlackList,
        Post,
        Like,
        Comment,
        FollowMessage,
        InviteChallenge,
        Notification,
      ],
      synchronize: true,
      // logging: true,
    };
  }
}
