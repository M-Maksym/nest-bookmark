import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';

import { AuthDto } from './dto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
        select: {
          id: true,
          email: true,
          createAt: true,
        },
      });
      return this.signToken(user.id, user.email);
    } catch (e) {
      if (e instanceof PrismaClientKnownRequestError) {
        if (e.code === 'P2002') {
          throw new ForbiddenException('Credentials are have used');
        }
      }
      throw e;
    }
  }

  async signin(dto: AuthDto) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Credendials incorrect');
    const { id, email, hash } = user;

    const pwMatches = await argon.verify(hash, dto.password);
    if (!pwMatches) throw new ForbiddenException('Password is incorrect');

    return this.signToken(id, email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get<string>('JWT_SECRET');
    const jwtToken = await this.jwt.signAsync(payload, {
      expiresIn: '15min',
      secret,
    });

    return {
      access_token: jwtToken,
    };
  }
}
