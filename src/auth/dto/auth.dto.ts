import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
/* eslint-disable @typescript-eslint/no-unsafe-call */
export class AuthDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
