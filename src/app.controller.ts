import { AuthService } from 'src/auth/auth.service';
import {
  Controller,
  Get,
  Res,
  Param,
  UseGuards,
  Post,
  Request,
} from '@nestjs/common';
import { AppService } from './app.service';
import { join } from 'path';
import { Response } from 'express';
import { LocalAuthGuard } from './auth/guard/local.auth.guard';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly authService: AuthService,
  ) {}

  @Get(':pageName')
  renderPage(@Param('pageName') pageName: string, @Res() res: Response) {
    res.sendFile(join(process.cwd(), 'src', 'view', `${pageName}.html`));
  }

  @Get()
  renderHomePage(@Res() res: Response) {
    res.sendFile(join(process.cwd(), 'src', 'view', 'login.html'));
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }
}
