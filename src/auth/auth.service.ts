import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateSignupDto } from 'src/auth/dto/create-signup.dto';
import * as bcrypt from 'bcrypt';
import { CreateLoginDto } from './dto/create-auth.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService
  ) { }

  async signup(signupData: CreateSignupDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: signupData.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    const hashedPassword = await bcrypt.hash(signupData.password, 12);

    const newUser = await this.prisma.user.create({
      data: {
        ...signupData,
        password: hashedPassword,
      },
    });

    return {
      user: newUser,
      message: 'User registered successfully',
    };
  }

  async login(credentials: CreateLoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: credentials.email },
    });

    if (!user) {
      throw new UnauthorizedException('Wrong credentials');
    }

    const passwordMatch = await bcrypt.compare(credentials.password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //  Generate tokens
    const tokens = await this.generateTokens(user.id, user.role, user.email);

    return {
      tokens,
      message: 'Login successful',
    };
  }

  // Generate both access and refresh tokens
  async generateTokens(userId: string, userRole: string, email: string) {
    const payload = { sub: userId, userRole: userRole, email: email };

    const accessToken = this.jwtService.sign(payload, { expiresIn: '1h' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    return { accessToken, refreshToken };
  }

}
