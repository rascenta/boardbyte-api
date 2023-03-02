import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/interfaces/users.interface';
import { RegisterDto } from './dtos/register.dto';

@Injectable()
export class AuthService {
  constructor(@InjectModel('User') private readonly userModel: Model<User>) {}

  async register(registerDto: RegisterDto): Promise<User> {
    const user = new this.userModel(registerDto);
    await user.save();
    delete user.password;
    return user;
  }
}
