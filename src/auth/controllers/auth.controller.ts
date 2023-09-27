import { Controller, Post, UseGuards, Get, Req, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { Response } from 'express';
import { GoogleRequest, KakaoRequest } from '../auth.interface';
import { KakaoAuthGuard } from '../guard/kakao.auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
  @Get()
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() _req: Request) {}

  // 구글 콜백
  @Get('/callback')
  @UseGuards(AuthGuard('google'))
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
  async callback(@Req() req: KakaoRequest, @Res() res: Response) {
    const user = req.user;
    const token = await this.authService.generateJWT(user);
    res.cookie('Authorization', `Bearer ${token}`, {
      // secure: true, // HTTPS 사용 시 활성화
      // maxAge: 1000 * 60 * 60 * 24 * 7, // 쿠키 유효 기간 설정 (예: 1주일)
    });
    const kakaoLogin = await this.authService.kakaoLogin(req, res);
    return res.redirect(`http://outbody.store/`);
  }
}
