import { Controller, Get, Res, Param } from '@nestjs/common';
import { AppService } from './app.service';
import { join } from 'path';
import { Response } from 'express';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get(':pageName')
  renderPage(@Param('pageName') pageName: string, @Res() res: Response) {
    res.sendFile(join(process.cwd(), 'src', 'view', `${pageName}.html`));
  }

  @Get()
  renderHomePage(@Res() res: Response) {
    res.sendFile(join(process.cwd(), 'src', 'view', 'login.html'));
  }
}
