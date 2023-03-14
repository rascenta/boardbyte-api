import { IsNotEmpty, IsUUID } from 'class-validator';

export class RefreshAccessTokenDto {
  @IsNotEmpty()
  @IsUUID()
  readonly refreshToken: string;
}
