import { Injectable, HttpException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import {
  JwtLoginDTO,
  SignUpDTO,
  RefreshTokenDTO,
  ValidateTokenDTO,
  AuthResponse,
  ValidateTokenResponse,
} from './dto/jwt.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async signUp(data: SignUpDTO): Promise<AuthResponse> {
    const { email, password, name } = data;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new HttpException('User already exists', 403);
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        refreshToken: '',
      },
    });

    const accessToken = this.jwtService.sign({ id: newUser.id });
    const refreshToken = this.jwtService.sign(
      { id: newUser.id },
      { expiresIn: '7d' },
    );

    await this.prisma.user.update({
      where: { id: newUser.id },
      data: { refreshToken },
    });

    return { accessToken, refreshToken };
  }

  async validate(data: JwtLoginDTO): Promise<AuthResponse> {
    const { email, password } = data;

    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      throw new HttpException('Invalid credentials', 403);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new HttpException('Invalid credentials', 403);
    }

    const accessToken = this.jwtService.sign({ id: user.id });
    const refreshToken = this.jwtService.sign(
      { id: user.id },
      { expiresIn: '7d' },
    );

    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken },
    });

    return { accessToken, refreshToken };
  }

  async refreshToken(refreshToken: string): Promise<AuthResponse> {
    try {
      const { id } = this.jwtService.verify(refreshToken);
      const user = await this.prisma.user.findUnique({ where: { id } });

      if (!user || user.refreshToken !== refreshToken) {
        throw new HttpException('Invalid refresh token', 403);
      }

      const newAccessToken = this.jwtService.sign({ id: user.id });
      const newRefreshToken = this.jwtService.sign(
        { id: user.id },
        { expiresIn: '7d' },
      );

      await this.prisma.user.update({
        where: { id: user.id },
        data: { refreshToken: newRefreshToken },
      });

      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch (e) {
      throw new HttpException('Invalid refresh token', 403);
    }
  }

  async jwtValidate(token: string): Promise<ValidateTokenResponse> {
    try {
      this.jwtService.verify(token);
      return { isValid: true };
    } catch (e) {
      return { isValid: false };
    }
  }
}
