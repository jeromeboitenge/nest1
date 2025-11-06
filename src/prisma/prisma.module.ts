import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global() // Makes PrismaService available in all modules without importing each time
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule { }
