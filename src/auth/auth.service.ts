import { Injectable, ConflictException, Post, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateSignupDto } from 'src/signup/dto/create-signup.dto';
import * as bcrypt from 'bcrypt';
import { CreateLoginDto } from 'src/login/dto/create-login.dto';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) { }
  @Post('signup')
  async signup(signupData: CreateSignupDto) {
    // Check if email is already used
    const existingUser = await this.prisma.user.findUnique({
      where: { email: signupData.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(signupData.password, 12);

    // Create new user
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

    const userExist = await this.prisma.user.findUnique({ where: { email: credentials.email } })
    if (!userExist) {
      throw new UnauthorizedException('wrong credentials')
    }
    const passwordMatch = await bcrypt.compare(credentials.password, userExist.password)
    if (!passwordMatch) {
      throw new UnauthorizedException('wrong credentials')
    }
    return {
      message: 'success'
    }
  }

}
