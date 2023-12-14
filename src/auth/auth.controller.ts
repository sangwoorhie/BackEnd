import { Controller, Post, UseGuards, Req } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
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
}
