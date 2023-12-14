import {
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcrypt';
import { User } from 'src/entities/user.entity';
import { UserRepository } from 'src/users/users.repository';
import { JwtConfigService } from 'src/config/jwt.config.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userRepository: UserRepository,
    private readonly jwtConfigService: JwtConfigService,
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
}
