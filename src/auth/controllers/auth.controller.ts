import {
  Controller,
  Post,
  UseGuards,
  Get,
  Req,
  Res,
  Header,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { Response } from 'express';
import { GoogleRequest, KakaoRequest } from '../auth.interface';
import { GoogleAuthGuard, KakaoAuthGuard } from '../guard/social.auth.guard.ts';

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

  //------------------카카오 로그인 페이지----------------------------//
  @Get('/kakao/login')
  @Header('Content-Type', 'text/html')
  getKakaoLoginPage(): string {
    return `
      <div>
        <h1>카카오 로그인</h1>
        <form action="http://localhost:3000/auth/kakao/login" method="GET">
          <input type="submit" value="카카오 로그인" />
        </form>
        <form action="/kakao/logout" method="GET">
          <input type="submit" value="카카오 로그아웃" />
        </form>
      </div>
    `;
  }

  //------------------카카오 로그인 --------------------------//
  @Get('/kakao/login')
  @Header('Content-Type', 'text/html')
  kakaoLoginLogic(@Res() res): void {
    const _hostName = 'https://kauth.kakao.com';
    const _restApiKey = this.configService.get('KAKAO_ID');
    const _redirectUrl = this.configService.get('KAKAO_REDIRECT');
    const url = `${_hostName}/oauth/authorize?client_id=${_restApiKey}&redirect_uri=${_redirectUrl}&response_type=code`;
    console.log(url); // owner에게 허가를 받은 뒤 server에 client 정보를 담아 요청
    return res.redirect(url);
  }

  //----------------카카오 서버에서 받아오는 요청 ---------------//
  @Get('kakao/login/callback')
  @Header('Content-Type', 'text/html')
  async kakaoLoginLogicRedirect(@Query() qs, @Res() res) {
    console.log(qs.code); // server가 code를 줌
    const _restApiKey = this.configService.get('KAKAO_ID');
    const _redirect_uri = this.configService.get('KAKAO_REDIRECT');
    const _hostName = `https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id=${_restApiKey}&redirect_uri=${_redirect_uri}&code=${qs.code}`;
    const _headers = {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
      },
    }; // client가 code를 server에 보내서 요청
    const serverResult = await this.authService.oauthLogin(_hostName, _headers);
    // server는 owner가 허용한 client인지 검증
    return res.send(`
         <div>
           <h2>카카오 로그인 성공</h2>
         </div>
       `);
  }
}
