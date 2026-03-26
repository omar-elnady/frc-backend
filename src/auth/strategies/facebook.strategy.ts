import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-facebook';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get<string>('FACEBOOK_APP_ID') || 'placeholder',
      clientSecret: configService.get<string>('FACEBOOK_APP_SECRET') || 'placeholder',
      callbackURL: `${(configService.get<string>('APP_URL') || 'http://localhost:3000').replace(/\/$/, '')}/${(configService.get<string>('API_PREFIX') || '').replace(/^\//, '')}/auth/facebook/callback`.replace(/(?<!:)\/\//g, '/'),
      scope: ['email', 'public_profile'],
      profileFields: ['id', 'emails', 'name', 'photos'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
  ): Promise<any> {
    const { id, name, emails, photos } = profile;
    const user = {
      facebookId: id,
      email: emails?.[0]?.value || '',
      firstName: name?.givenName || 'Facebook',
      lastName: name?.familyName || 'User',
      picture: photos?.[0]?.value || '',
      accessToken,
      refreshToken,
    };
    return user;
  }
}
