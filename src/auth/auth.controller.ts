import { Controller, Post, UseGuards, Req, Get, Res } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { GoogleRequest } from './auth.interface';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  // 로컬 로그인
  // POST http://localhost:3000/auth/login
  @UseGuards(AuthGuard('local'))
  @Post('/login')
  async login(
    @Req() req: any,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    return this.authService.login(req.user);
  }

  // 로그아웃
  @UseGuards(AuthGuard('jwt'))
  @Post('/logout')
  async logout(@Req() req: any): Promise<void> {
    await this.authService.logout(req.email);
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
