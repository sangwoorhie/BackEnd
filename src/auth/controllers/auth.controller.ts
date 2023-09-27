import { Controller, Post, UseGuards, Get, Req, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { Response } from 'express';
import { GoogleRequest, KakaoRequest } from '../auth.interface';

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
  @Get('/google/login')
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() _req: Request) {}

  // 구글 콜백
  @Get('/google/login/callback')
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
  @UseGuards(AuthGuard('kakao'))
  async KakaoAuth(@Req() _req: Request) {}

  // 카카오 콜백
  @Get('/kakao/login/callback')
  @UseGuards(AuthGuard('kakao'))
  async KakaoAuthCallback(
    @Req() req: KakaoRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const kakaoLogin = await this.authService.kakaoLogin(req, res);
    return kakaoLogin;
  }
}
