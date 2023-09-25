import { Controller, Post, UseGuards, Get, Req, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { Response } from 'express';
import { GoogleRequest } from '../auth.interface';

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

  // 로그아웃
  // POST http://localhost:3000/auth/logout
  @UseGuards(AuthGuard('local'))
  @Post('logout')
  async logout(@Req() req: any, @Res({ passthrough: true }) res: Response) {
    // const { accessOption, refreshOption } = this.authService.logout();
    await this.authService.removeRefreshToken(req.user.id);

    // res.clearCookie('accessToken');
    // res.clearCookie('refreshToken');
    return res.send({
      message: 'logout success',
    });

    // res.cookie('Authentication', '', accessOption);
    // res.cookie('Refresh', '', refreshOption);
  }

  // 구글 로그인
  @Get()
  @UseGuards(AuthGuard('google'))
  async googleAuth(@Req() _req: Request) {}

  // 구글 콜백
  @Get('callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(
    @Req() req: GoogleRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.googleLogin(req, res);
    return result;
  }
}
