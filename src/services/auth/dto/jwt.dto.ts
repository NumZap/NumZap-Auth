import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SignUpDTO {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  name: string;
}

export class JwtLoginDTO {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}

export class RefreshTokenDTO {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}

export class ValidateTokenDTO {
  @IsString()
  @IsNotEmpty()
  token: string;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
}

export interface ValidateTokenResponse {
  isValid: boolean;
}
