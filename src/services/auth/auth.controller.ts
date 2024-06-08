import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtLoginDTO, SignUpDTO } from './dto/jwt.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 회원가입
  @Post('signup')
  async signup(@Body() body: SignUpDTO) {
    return this.authService.signUp(body);
  }

  // 로그인
  @Post('login')
  async login(@Body() body: JwtLoginDTO) {
    return this.authService.validate(body);
  }
}
