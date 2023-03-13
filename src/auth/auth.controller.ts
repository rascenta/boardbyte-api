import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AccessTokenGuard } from 'src/common/guards/access-token/access-token.guard';
import { RefreshTokenGuard } from 'src/common/guards/refresh-token/refresh-token.guard';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { RegisterDto } from './dtos/register.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return await this.authService.register(registerDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return await this.authService.login(loginDto);
  }

  @Post('logout')
  @UseGuards(AccessTokenGuard)
  async logout(@Req() req: Request, @Res() res: Response) {
    const result = await this.authService.logout(req.user['sub']);
    res.status(HttpStatus.OK).send(result);
  }

  @Get('refresh')
  @UseGuards(RefreshTokenGuard)
  async refreshAccessToken(@Req() req: Request) {
    const userId = req.user['sub'];
    const refreshToken = req.get('Authorization').replace('Bearer', '').trim();
    return await this.authService.refreshAccessToken(userId, refreshToken);
  }
}
