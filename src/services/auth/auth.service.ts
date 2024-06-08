import { HttpException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtLoginDTO, SignUpDTO } from './dto/jwt.dto';
import { bcrypt } from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async validate(body: JwtLoginDTO): Promise<{ token: string } | undefined> {
    const { email, password } = body;

    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!user) {
      throw new HttpException('User not exists', 403);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new HttpException('User not exists', 403);
    }

    if (user && isPasswordValid) {
      return {
        token: this.jwtService.sign({ id: user.id }),
      };
    }
  }

  async signUp(body: SignUpDTO): Promise<{ token: string } | undefined> {
    const { email, password, name } = body;

    const user = await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (user) {
      throw new HttpException('User already exists', 403);
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.prisma.user.create({
      data: {
        email: email,
        password: hashedPassword,
        refreshToken: '',
      },
    });

    const refreshToken = this.jwtService.sign(
      { id: newUser.id },
      { expiresIn: '7d' },
    );

    await this.prisma.user.update({
      where: {
        id: newUser.id,
      },
      data: {
        refreshToken: refreshToken,
      },
    });

    return {
      token: this.jwtService.sign({ id: newUser.id }),
    };
  }

  async jwtValidate(token: string): Promise<{ id: number } | undefined> {
    try {
      const decoded = this.jwtService.verify(token);
      return decoded.id;
    } catch (e) {
      throw new HttpException('Invalid token', 403);
    }
  }
}
