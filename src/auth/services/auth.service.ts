import { ConfigService } from '@nestjs/config';
import {
  BadGatewayException,
  Injectable,
  NotAcceptableException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcrypt';
import { User } from 'src/users/entities/user.entity';
import { UserRepository } from 'src/users/repositories/users.repository';
import { UserService } from 'src/users/services/users.service';
import { Provider } from 'src/users/userInfo';
import { GoogleRequest } from '../auth.interface';
import { GoogleDto } from './../dto/googleLogin.dto';
import { Response } from 'express';
import * as cookie from 'cookie';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userRepository: UserRepository,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {}

  // 유저 확인
  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userRepository.getUserByEmail(email);
    if (!user) {
      throw new NotFoundException('존재하지 않는 회원입니다');
    }

    if (
      user.status === 'admin' &&
      user.email === email &&
      user.password === password
    ) {
      return user;
    }

    const comparedPassword = await compare(password, user.password);
    if (!comparedPassword) {
      throw new NotAcceptableException('비밀번호가 일치하지 않습니다.');
    }

    if (user && comparedPassword) {
      return user;
    }
    return null;
  }

  // 로그인 (access토큰 발급)
  async getAccessToken(id: number) {
    const payload = { id };
    const token = this.jwtService.sign(payload, {
      secret: await this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: await this.configService.get(
        'JWT_ACCESS_TOKEN_EXPIRATION_TIME',
      ),
    });

    return {
      accessToken: token,
      domain: 'localhost',
      path: '/',
      httpOnly: true,
      maxAge: 60 * 60 * 24,
    };
  }

  // refresh토큰 발급
  async getRefreshToken(id: number) {
    const payload = { id };
    const token = this.jwtService.sign(payload, {
      secret: await this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: await this.configService.get(
        'JWT_REFRESH_TOKEN_EXPIRATION_TIME',
      ),
    });

    return {
      refreshToken: token,
      domain: 'localhost',
      path: '/',
      httpOnly: true,
      maxAge: 60 * 60 * 24,
    };
  }

  // 로그아웃
  logout() {
    return {
      accessOption: {
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        maxAge: 0,
      },
      refreshOption: {
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        maxAge: 0,
      },
    };
  }

  // 토큰 제거
  async removeRefreshToken(userId: number) {
    const logout = await this.userRepository.update(userId, {
      refreshToken: null,
    });
    return logout;
  }

  // Refresh 토큰 set, hash처리
  async setRefreshToken(refreshToken: string, id: number) {
    const hashedRefreshToken = await hash(refreshToken, 10);
    await this.userRepository.update(id, { refreshToken: hashedRefreshToken });
  }

  // 토큰값 동일할경우 유저반환
  async refreshTokenMatches(refreshToken: string, id: number) {
    const user = await this.userRepository.getUserById(id);
    const refreshTokenMatching = await compare(refreshToken, user.refreshToken);
    if (refreshTokenMatching) {
      return user;
    }
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
