import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateSignupDto } from 'src/signup/dto/create-signup.dto';
import * as bcrypt from 'bcrypt';
import { CreateLoginDto } from 'src/login/dto/create-login.dto';
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
    const userExist = await this.prisma.user.findUnique({
      where: { email: credentials.email },
    });

    if (!userExist) {
      throw new UnauthorizedException('Wrong credentials');
    }

    const passwordMatch = await bcrypt.compare(
      credentials.password,
      userExist.password
    );

    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    // ✅ Call generateTokens correctly
    const token = await this.generateTokens(userExist.id);

    return {
      token,
      message: 'Login successful',
    };
  }

  async generateTokens(userId: string) {
    const accessToken = this.jwtService.sign(
      { userId },
      { expiresIn: '1h' }
    );

    return { accessToken };
  }
}
