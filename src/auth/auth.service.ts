import {
  BadGatewayException,
  HttpException,
  HttpStatus,
  Injectable,
  NotAcceptableException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcrypt';
import { User } from 'src/entities/user.entity';
import { UserRepository } from 'src/users/users.repository';
import { JwtConfigService } from 'src/config/jwt.config.service';
import { GoogleRequest } from './auth.interface';
import { GoogleDto } from './dto/googleLogin.dto';
import { ConfigService } from '@nestjs/config';
import { Provider } from 'src/users/userInfo';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userRepository: UserRepository,
    private readonly jwtConfigService: JwtConfigService,
    private readonly configService: ConfigService,
  ) {}

  // 로그인
  async login(
    user: User,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const accessToken = this.getAccessToken(user.id, user.email);
    const refreshToken = this.getRefreshToken(user.id, user.email);
    await this.userRepository.update({ email: user.email }, { refreshToken });

    return { accessToken, refreshToken };
  }

  // 로그아웃
  async logout(email: string): Promise<void> {
    await this.userRepository.removeRefreshToken(email);
  }

  // Access토큰 발급
  getAccessToken(id: number, email: string) {
    const payload = { id, email };
    return this.jwtService.sign(
      payload,
      this.jwtConfigService.createJwtOptions(),
    );
  }

  // refresh토큰 발급
  getRefreshToken(id: number, email: string) {
    const payload = { id, email };
    return this.jwtService.sign(
      payload,
      this.jwtConfigService.createRefreshTokenOptions(),
    );
  }

  async validateRefreshToken(
    user: User,
    bearerToken: string,
  ): Promise<{ accessToken: string }> {
    const refreshToken = bearerToken.replace('Bearer', '').trim();

    if (user.refreshToken !== refreshToken) {
      throw new UnauthorizedException('Invalid token');
    }

    const accessToken = await this.getAccessToken(user.id, user.email);
    return { accessToken };
  }

  // 유저 확인
  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userRepository.getUserByEmail(email);
    if (!user) {
      throw new NotFoundException('존재하지 않는 회원입니다');
    }

    //관리자 확인
    if (
      user.status === 'admin' &&
      user.email === email &&
      user.password === password
    ) {
      return user;
    }

    //일반유저 확인
    const comparedPassword = await compare(password, user.password);
    if (!comparedPassword) {
      console.log('comparedPassword', comparedPassword);
      throw new HttpException('UNAUTHORIZED', HttpStatus.UNAUTHORIZED);
    }

    if (user && comparedPassword) {
      return user;
    }
    return null;
  }

  // 구글 로그인
  async googleLogin(req: GoogleRequest, res: Response): Promise<GoogleDto> {
    try {
      const {
        user: { email, name },
      } = req;
      let accessToken: string;
      let refreshToken: string;

      const findUser = await this.userRepository.getUserByEmail(email);
      if (findUser && findUser.provider === Provider.LOCAL) {
        throw new BadGatewayException(
          '현재 계정으로 가입한 이메일이 존재합니다.',
        );
      }
      if (!findUser) {
        const googleUser = this.userRepository.create({
          email,
          name,
          provider: Provider.GOOGLE,
        });
        await this.userRepository.save(googleUser);
        const googleUserPayload = { id: googleUser.id };
        accessToken = this.jwtService.sign(googleUserPayload, {
          secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
          expiresIn: +this.configService.get(
            'JWT_ACCESS_TOKEN_EXPIRATION_TIME',
          ),
        });
        refreshToken = this.jwtService.sign(googleUserPayload, {
          secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
          expiresIn: +this.configService.get(
            'JWT_REFRESH_TOKEN_EXPIRATION_TIME',
          ),
        });
        res.cookie('refreshToken', refreshToken, {
          expires: new Date(
            Date.now() +
              +this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
          ),
          httpOnly: true,
        });
        return {
          accessToken,
        };
      }
      // 구글 가입이 되어있는경우
      const findUserPayload = { id: findUser.id };
      accessToken = this.jwtService.sign(findUserPayload, {
        secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
        expiresIn: +this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
      });
      refreshToken = this.jwtService.sign(findUserPayload, {
        secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
        expiresIn: +this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
      });
      res.cookie('refreshToken', refreshToken, {
        expires: new Date(
          Date.now() +
            +this.configService.get('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
        ),
        httpOnly: true,
      });
      return {
        accessToken,
      };
    } catch (error) {
      console.log(error);
      throw new NotAcceptableException('구글 로그인에 실패하였습니다.');
    }
  }
}
