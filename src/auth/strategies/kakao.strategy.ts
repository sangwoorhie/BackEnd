import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-kakao';
import { AuthService } from '../services/auth.service';

@Injectable()
export class KakaoStrategy extends PassportStrategy(Strategy, 'kakao') {
  constructor(private readonly authService: AuthService) {
    super({
      clientID: '119d1ffdd9c1fa47cf09708aa7d536f8', //process.env.KAKAO_ID,
      clientSecret: 't42CyTFssiCRVJXo5UnEG9HnvznmERbQ', //process.env.KAKAO_PW,
      callbackURL: 'http://outbody.store/auth/google/login/callback', //process.env.KAKAO_REDIRECT,
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: any, user?: any, info?: any) => void,
  ) {
    try {
      const { _json } = profile;
      const user = {
        email: _json.kakao_account.email,
        name: _json.properties.nickname,
      };
      done(null, user);
    } catch (error) {
      done(error);
    }
  }
}
