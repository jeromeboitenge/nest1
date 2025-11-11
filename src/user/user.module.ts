import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { PrismaModule } from '../prisma/prisma.module'; // import PrismaModule
import { VerifyTokenService } from 'src/auth/verify-token.service';

@Module({
  imports: [PrismaModule], // ← this is key
  providers: [UserService, VerifyTokenService],
  controllers: [UserController],
})
export class UserModule { }
