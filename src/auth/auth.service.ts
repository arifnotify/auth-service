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

  async register(dto: any) {
    const exists = await this.usersService.findByEmail(dto.email);

    if (exists) {
      throw new ConflictException('Email already exists');
    }

    const hash = await bcrypt.hash(dto.password, 10);

    return this.usersService.create({
      ...dto,
      password: hash,
    });
  }

  async login(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);

    if (!user) throw new UnauthorizedException('Invalid credentials');

    const match = await bcrypt.compare(password, user.password);

    if (!match) throw new UnauthorizedException('Invalid credentials');

    const token = this.jwtService.sign({
      sub: user._id,
      email: user.email,
      role: user.role,
    });

    return {
      accessToken: token,
    };
  }
}