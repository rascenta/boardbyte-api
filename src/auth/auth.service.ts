import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { User } from 'src/interfaces/users.interface';
import { LoginDto } from './dtos/login.dto';
import { RegisterDto } from './dtos/register.dto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    @InjectModel('User') private readonly userModel: Model<User>,
  ) {}

  async register(registerDto: RegisterDto): Promise<any> {
    const checkUser = await this.findUserByEmail(registerDto.email);
    if (checkUser) {
      throw new BadRequestException('Email already in use.');
    }

    const usernameSalt = Math.floor(100000 + Math.random() * 900000);
    registerDto.username = 'user.' + usernameSalt;
    const user = new this.userModel(registerDto);
    await user.save();
    const tokens = await this.createAccessToken(user._id, user.username);
    await this.updateRefreshToken(user._id, tokens.refreshToken);
    return {
      user,
      tokens,
    };
  }

  async login(loginDto: LoginDto) {
    const user = await this.findUserByEmail(loginDto.email);
    if (!user) {
      throw new NotFoundException('Wrong email or password.');
    }
    await this.checkPassword(loginDto.password, user);
    const tokens = await this.createAccessToken(user._id, user.username);
    await this.updateRefreshToken(user._id, tokens.refreshToken);
    return {
      user,
      tokens,
    };
  }

  async logout(userId: string) {
    await this.updateRefreshToken(userId, null);
    return { message: 'OK' };
  }

  async refreshAccessToken(userId: string, refreshToken: string) {
    const user = await this.userModel.findOne({ _id: userId });
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Access Denied');
    }
    const isRefreshTokenMatch = await bcrypt.compare(
      refreshToken,
      user.refreshToken,
    );
    if (!isRefreshTokenMatch) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.createAccessToken(user._id, user.username);
    await this.updateRefreshToken(user._id, tokens.refreshToken);
    return { tokens };
  }

  private async findUserByEmail(email: string): Promise<User> {
    const user = await this.userModel.findOne({ email });
    return user;
  }

  private async checkPassword(attemptPass: string, user: User) {
    const match = await bcrypt.compare(attemptPass, user.password);
    if (!match) {
      throw new NotFoundException('Wrong email or password.');
    }
    return match;
  }

  private async createAccessToken(userId: string, username: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          username,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: '7d',
        },
      ),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  }

  private async updateRefreshToken(userId: string, refreshToken: string) {
    await this.userModel.findOneAndUpdate({ _id: userId }, { refreshToken });
  }
}
