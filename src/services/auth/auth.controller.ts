import { Controller } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import {
  JwtLoginDTO,
  SignUpDTO,
  RefreshTokenDTO,
  ValidateTokenDTO,
  AuthResponse,
  ValidateTokenResponse,
} from './dto/jwt.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @GrpcMethod('AuthService', 'SignUp')
  async signUp(data: SignUpDTO): Promise<AuthResponse> {
    return this.authService.signUp(data);
  }

  @GrpcMethod('AuthService', 'Login')
  async login(data: JwtLoginDTO): Promise<AuthResponse> {
    return this.authService.validate(data);
  }

  @GrpcMethod('AuthService', 'RefreshToken')
  async refreshToken(data: RefreshTokenDTO): Promise<AuthResponse> {
    return this.authService.refreshToken(data.refreshToken);
  }

  @GrpcMethod('AuthService', 'ValidateToken')
  async validateToken(data: ValidateTokenDTO): Promise<ValidateTokenResponse> {
    return this.authService.jwtValidate(data.token);
  }
}
