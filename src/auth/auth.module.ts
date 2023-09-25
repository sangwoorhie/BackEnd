import { Module, forwardRef } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './strategies/local.strategy';
import { AuthController } from './controllers/auth.controller';
import { AuthService } from './services/auth.service';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { JwtConfigService } from 'src/config/jwt.config.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserRepository } from 'src/users/repositories/users.repository';
import { UserService } from 'src/users/services/users.service';
import { BlackListRepository } from 'src/blacklists/repository/blacklist.repository';
import { FollowsRepository } from 'src/follows/repositories/follows.repository';
import { JwtRefreshStrategy } from './strategies/refreshToken.strategy';
import { UsersModule } from 'src/users/users.module';
import { AwsService } from 'src/aws.service';
import { ChallengesModule } from 'src/challenges/challenges.module';
import { GoogleStrategy } from './strategies/google.strategy';

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
    JwtRefreshStrategy,
    UserService,
    BlackListRepository,
    FollowsRepository,
    AwsService,
    GoogleStrategy,
  ],
  exports: [AuthService, JwtModule],
})
export class AuthsModule {}
