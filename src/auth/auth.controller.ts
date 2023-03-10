import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { AccessTokenGuard } from 'src/common/guards/access-token/access-token.guard';
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

  @Get('hello')
  @UseGuards(AccessTokenGuard)
  hello() {
    return {
      error: false,
      message: 'Hello World',
    };
  }

  // @Post('refresh-access-token')
  // async refreshAccessToken(
  //   @Body() refreshAccessTokenDto: RefreshAccessTokenDto,
  // ) {
  //   return await this.authService.refreshAccessToken(refreshAccessTokenDto);
  // }
}
