import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateSignupDto } from './dto/create-signup.dto';
import { CreateLoginDto } from './dto/create-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('signup')
  async signup(@Body() signupData: CreateSignupDto) {
    return this.authService.signup(signupData);
  }
  @Post('login')
  async login(@Body() credentials: CreateLoginDto) {
    return this.authService.login(credentials)
  }
}
