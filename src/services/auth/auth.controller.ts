import { Body, Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { signUpDTO } from './dto/jwt.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 로그인
  @Post('signup')
  async signup(@Body() body: signUpDTO) {
    return this.authService.validate(body);
  }
}
