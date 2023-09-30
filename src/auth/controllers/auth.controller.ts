import {
  Controller,
  Post,
  UseGuards,
  Get,
  Req,
  Res,
  Header,
  Query,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { Response } from 'express';
import { GoogleRequest, KakaoRequest } from '../auth.interface';
import { GoogleAuthGuard, KakaoAuthGuard } from '../guard/social.auth.guard';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  // 로컬 로그인
  // POST http://localhost:3000/auth/login
  @UseGuards(AuthGuard('local'))
  @Post('login')
  async login(@Req() req: any) {
    const userId = req.user.id;
    const status = req.user.status;

    const { accessToken, ...accessOption } =
      await this.authService.getAccessToken(userId);
    const { refreshToken, ...refreshOption } =
      await this.authService.getRefreshToken(userId);

    await this.authService.setRefreshToken(refreshToken, userId);

    return { userId, status, accessToken, refreshToken };
  }

  // 구글 로그인
  @Get('/google/login')
  @UseGuards(GoogleAuthGuard)
  async googleAuth(@Req() _req: Request) {}

  // 구글 콜백
  @Get('/google/login/callback')
  @UseGuards(GoogleAuthGuard)
  async googleAuthCallback(
    @Req() req: GoogleRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const googleLogin = await this.authService.googleLogin(req, res);
    return googleLogin;
  }

  // 카카오 로그인
  @Get('/kakao/login')
  @UseGuards(KakaoAuthGuard)
  async loginKakao() {}

  @Get('/kakao/login/callback')
  @UseGuards(KakaoAuthGuard)
  async callback(@Req() req, @Res() res) {
    const user = req.user;
    const token = await this.authService.generateJWT(user);
    res.cookie('Authorization', `Bearer ${token}`, {
      // secure: true, // HTTPS 사용 시 활성화
      // maxAge: 1000 * 60 * 60 * 24 * 7, // 쿠키 유효 기간 설정 (예: 1주일)
    });
    return res.redirect(`http://outbody.store`);
  }
}
