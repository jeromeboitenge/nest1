import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { QueryUserDto } from './dto/querry-user.dto';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) { }

  /** Create new user */
  async create(createUserDto: CreateUserDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: createUserDto.email },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 12);

    const user = await this.prisma.user.create({
      data: {
        ...createUserDto,
        password: hashedPassword,
      },
    });

    // Remove password before returning
    const { password, ...safeUser } = user;

    return {
      user: safeUser,
      message: 'User created successfully',
    };
  }

  /** Get all users with pagination, search, and sorting */
  async findAll(query: QueryUserDto) {
    const {
      search,
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = query;

    const skip = (page - 1) * limit;

    // Build search condition
    const where: Prisma.UserWhereInput = {};

    if (search && search.trim() !== '') {
      const searchValue = search.trim();

      where.OR = [
        { name: { contains: searchValue, mode: 'insensitive' } },
        { email: { contains: searchValue, mode: 'insensitive' } },
      ];
    }

    // Query options
    const queryOptions: Prisma.UserFindManyArgs = {
      where,
      orderBy: { [sortBy]: sortOrder },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
      skip,
      take: limit,
    };

    const users = await this.prisma.user.findMany(queryOptions);
    const total = await this.prisma.user.count({ where });

    return {
      data: users,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      message:
        search && search.trim() !== ''
          ? `Found ${total} user(s) matching "${search}"`
          : 'All users retrieved successfully',
    };
  }


  /** Find user by ID */
  async findOne(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  /** Update user info */
  async update(id: string, updateUserDto: UpdateUserDto) {
    const existingUser = await this.prisma.user.findUnique({ where: { id } });
    if (!existingUser) {
      throw new NotFoundException('User not found');
    }

    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 12);
    }

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data: updateUserDto,
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      user: updatedUser,
      message: 'User successfully updated',
    };
  }

  /** Delete user */
  async remove(id: string) {
    const existingUser = await this.prisma.user.findUnique({ where: { id } });
    if (!existingUser) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.user.delete({ where: { id } });

    return {
      message: 'User successfully deleted',
    };
  }
}
