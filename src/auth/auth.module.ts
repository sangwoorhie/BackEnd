import { Module, forwardRef } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategies/local.strategy';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity';
import { JwtConfigService } from 'src/config/jwt.config.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserRepository } from 'src/users/users.repository';
import { UserService } from 'src/users/users.service';
import { BlackListRepository } from 'src/blacklists/blacklist.repository';
import { FollowsRepository } from 'src/follows/follows.repository';
import { UsersModule } from 'src/users/users.module';
import { AwsService } from 'src/aws.service';
import { ChallengesModule } from 'src/challenges/challenges.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useClass: JwtConfigService,
      inject: [ConfigService],
    }),
    forwardRef(() => UsersModule),
    ChallengesModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    UserRepository,
    UserService,
    BlackListRepository,
    FollowsRepository,
    JwtConfigService,
    AwsService,
  ],
  exports: [AuthService, JwtModule, JwtConfigService],
})
export class AuthsModule {}
