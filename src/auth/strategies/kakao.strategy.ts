import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-kakao';
import { AuthService } from '../services/auth.service';

@Injectable()
export class KakaoStrategy extends PassportStrategy(Strategy, 'kakao') {
  constructor(private readonly authService: AuthService) {
    super({
      clientID: process.env.KAKAO_ID,
      clientSecret: process.env.KAKAO_PW,
      callbackURL: process.env.KAKAO_REDIRECT,
      scope: ['account_email', 'profile_nickname'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: any) {
    const email = profile._json.kakao_account.email;
    const name = profile._json.properties.nickname;

    const user = await this.authService.kakaoLogin(email, name);
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
