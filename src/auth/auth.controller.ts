import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';

import { AuthService } from './auth.service';

import { JwtGuard } from './guards/jwt.guard';

import { RegisterDto } from './dto/register.dto';

import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
  ) {}

  // ✅ Register User
  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  // ✅ Login User
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  // 🔐 Protected Route (JWT required)
  @Get('me')
  @UseGuards(JwtGuard)
  me(@Request() req) {
    return {
      message: 'Current user data',
      user: req.user,
    };
  }
}