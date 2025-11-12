import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateSignupDto } from 'src/auth/dto/create-signup.dto';
import { CreateLoginDto } from './dto/create-auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import * as nodemailer from 'nodemailer';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) { }

  // ✅ SIGNUP
  async signup(signupData: CreateSignupDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: signupData.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    const hashedPassword = await bcrypt.hash(signupData.password, 12);

    const newUser = await this.prisma.user.create({
      data: { ...signupData, password: hashedPassword },
    });

    return {
      user: newUser,
      message: 'User registered successfully',
    };
  }

  // ✅ LOGIN — Step 1: Validate credentials & send OTP
  async login(credentials: CreateLoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: credentials.email },
    });

    if (!user) throw new UnauthorizedException('Wrong credentials');

    const passwordMatch = await bcrypt.compare(
      credentials.password,
      user.password,
    );
    if (!passwordMatch) throw new UnauthorizedException('Wrong credentials');

    // Generate OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Save OTP in separate table
    await this.prisma.otp.create({
      data: {
        code: otpCode,
        userId: user.id,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 mins expiry
      },
    });

    // Send OTP via email
    await this.sendOtpEmail(user.email, otpCode);

    return { message: 'OTP sent to your email' };
  }

  // ✅ VERIFY OTP — Step 2: Check OTP and issue token
  async verifyOtp(email: string, otpCode: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new BadRequestException('User not found');

    const otpRecord = await this.prisma.otp.findFirst({
      where: { userId: user.id, code: otpCode },
      orderBy: { createdAt: 'desc' },
    });

    if (!otpRecord) throw new BadRequestException('Invalid OTP');
    if (otpRecord.expiresAt < new Date()) {
      throw new BadRequestException('OTP expired');
    }

    // Delete the OTP after verification (optional but recommended)
    await this.prisma.otp.delete({ where: { id: otpRecord.id } });

    // Generate tokens
    const tokens = await this.generateTokens(user.id, user.role, user.email);

    return {
      message: 'OTP verified successfully',
      tokens,
    };
  }

  // ✅ Generate JWT tokens
  async generateTokens(userId: string, userRole: string, email: string) {
    const payload = { sub: userId, userRole, email };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '1h' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  }

  // ✅ Send OTP Email
  async sendOtpEmail(email: string, otp: string) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"Your App Name" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Login OTP Code',
      text: `Your OTP code is ${otp}. It expires in 5 minutes.`,
    });



    await transporter.sendMail({
      from: `"Your App Name" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Login OTP Code',
      text: `Your OTP code is ${otp}. It expires in 5 minutes.`,
    });
  }
}
