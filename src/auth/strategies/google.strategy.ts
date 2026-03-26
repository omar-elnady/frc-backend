import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID:
        configService.get<string>('GOOGLE_CLIENT_ID') ||
        'placeholder_client_id',
      clientSecret:
        configService.get<string>('GOOGLE_CLIENT_SECRET') ||
        'placeholder_client_secret',
      callbackURL: `${(configService.get<string>('APP_URL') || 'http://localhost:3000').replace(/\/$/, '')}/${(configService.get<string>('API_PREFIX') || '').replace(/^\//, '')}/auth/google/callback`.replace(/(?<!:)\/\//g, '/'),
      proxy: true,
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
  ): Promise<any> {
    const { name, emails, photos } = profile;
    const user = {
      email: emails?.[0]?.value || '',
      firstName: name?.givenName || 'Google',
      lastName: name?.familyName || 'User',
      picture: photos?.[0]?.value || '',
      accessToken,
      refreshToken,
    };
    return user;
  }
}
