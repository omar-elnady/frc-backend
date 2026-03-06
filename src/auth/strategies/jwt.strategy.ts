import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

// Custom extractor: reads token from "<TOKEN_PREFIX> <token>" (secret scheme from env)
const buildFrcExtractor =
  (prefix: string) =>
  (req: Request): string | null => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith(`${prefix} `)) return null;
    return authHeader.slice(prefix.length + 1).trim() || null;
  };

export interface JwtPayload {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly configService: ConfigService) {
    const prefix = configService.get<string>('TOKEN_PREFIX', 'FRC');
    super({
      jwtFromRequest: buildFrcExtractor(prefix),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET')!,
    });
  }

  async validate(payload: JwtPayload) {
    if (!payload?.id) {
      throw new UnauthorizedException('Invalid token');
    }

    return {
      id: payload.id,
      email: payload.email,
      username: payload.username,
      firstName: payload.firstName,
      lastName: payload.lastName,
    };
  }
}
