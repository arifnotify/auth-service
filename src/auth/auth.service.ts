import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';

import * as bcrypt from 'bcrypt';

import { JwtService } from '@nestjs/jwt';

import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

async register(data: any) {

  const exists =
    await this.usersService.findByEmail(
      data.email,
    );

  if (exists) {
    throw new ConflictException(
      'Email already exists',
    );
  }

  const hashed =
    await bcrypt.hash(
      data.password,
      10,
    );

  return this.usersService.create({
    ...data,
    password: hashed,
  });
}

async login(
  email: string,
  password: string,
) {
  const user =
    await this.usersService.findByEmail(
      email,
    );

  if (!user) {
    throw new UnauthorizedException();
  }

  const match =
    await bcrypt.compare(
      password,
      user.password,
    );

  if (!match) {
    throw new UnauthorizedException();
  }

  const token =
    this.jwtService.sign({
      sub: user._id,
      email: user.email,
      role: user.role,
    });

  return {
    accessToken: token,
  };
}
}