import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { Request } from 'express';
import { AccessTokenGuard } from 'src/common/guards/access-token/access-token.guard';
import { RefreshTokenGuard } from 'src/common/guards/refresh-token/refresh-token.guard';
import { TransformInterceptor } from 'src/transform/transform.interceptor';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { RegisterDto } from './dtos/register.dto';

@Controller('auth')
@UseInterceptors(TransformInterceptor)
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return {
      message: 'Register success',
      result: await this.authService.register(registerDto),
    };
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return {
      message: 'Login success',
      result: await this.authService.login(loginDto),
    };
  }

  @Post('logout')
  @UseGuards(AccessTokenGuard)
  async logout(@Req() req: Request) {
    const result = await this.authService.logout(req.user['sub']);
    return {
      message: 'Logout success',
      result,
    };
  }

  @Get('refresh')
  @UseGuards(RefreshTokenGuard)
  async refreshAccessToken(@Req() req: Request) {
    const userId = req.user['sub'];
    const refreshToken = req.get('Authorization').replace('Bearer', '').trim();
    return {
      message: 'Refresh token success',
      result: await this.authService.refreshAccessToken(userId, refreshToken),
    };
  }
}
