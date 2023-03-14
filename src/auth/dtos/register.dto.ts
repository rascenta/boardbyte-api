import { IsNotEmpty, IsEmail, MinLength } from '@nestjs/class-validator';

export class RegisterDto {
  @IsNotEmpty()
  name: string;

  username: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
