import { IsString, IsEmail, isNumber, IsNumber } from 'class-validator';

export class JwtLoginDTO {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}

export class signUpDTO {
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsString()
  name: string;
}
