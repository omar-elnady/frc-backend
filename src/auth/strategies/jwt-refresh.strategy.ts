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

export interface RefreshTokenPayload {
  id: string;
  username: string;
}

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private readonly configService: ConfigService) {
    const prefix = configService.get<string>('TOKEN_PREFIX', 'FRC');
    super({
      jwtFromRequest: buildFrcExtractor(prefix),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_REFRESH_SECRET')!,
    });
  }

  async validate(payload: RefreshTokenPayload) {
    if (!payload?.id) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return { id: payload.id, username: payload.username };
  }
}
