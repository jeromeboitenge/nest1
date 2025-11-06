import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateSignupDto } from 'src/signup/dto/create-signup.dto';
import { CreateLoginDto } from 'src/login/dto/create-login.dto';

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
