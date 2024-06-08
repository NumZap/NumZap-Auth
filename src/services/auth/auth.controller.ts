import { Body, Controller, Post, Headers } from '@nestjs/common';
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

  // 검증
  @Post('validate')
  async validate(@Headers('Authorization') authHeader: string) {
    const token = authHeader.split(' ')[1];
    return this.authService.jwtValidate(token);
  }
}
