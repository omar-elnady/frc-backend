import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-linkedin-oauth2';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class LinkedInStrategy extends PassportStrategy(Strategy, 'linkedin') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get<string>('LINKEDIN_CLIENT_ID') || 'placeholder',
      clientSecret: configService.get<string>('LINKEDIN_CLIENT_SECRET') || 'placeholder',
      callbackURL: `${(configService.get<string>('APP_URL') || 'http://localhost:3000').replace(/\/$/, '')}/${(configService.get<string>('API_PREFIX') || '').replace(/^\//, '')}/auth/linkedin/callback`.replace(/(?<!:)\/\//g, '/'),
      scope: ['openid', 'profile', 'email'],
    });

    // Override internal passport-oauth2 state to enforce OIDC standards
    const oauth2 = (this as any)._oauth2;
    oauth2.useAuthorizationHeaderforGET(true);
    // Remove the mandatory linkedin custom access token name to fallback to standard Bearer token header
    oauth2.setAccessTokenName('access_token');

    (this as any).userProfile = (accessToken: string, done: any) => {
      oauth2.get('https://api.linkedin.com/v2/userinfo', accessToken, (err: any, body: any) => {
        if (err) {
          const errMsg = typeof err === 'object' ? JSON.stringify(err) : err;
          return done(new Error(`Failed to fetch user profile: ${errMsg}`));
        }
        try {
          const json = JSON.parse(body);
          const profile = {
            provider: 'linkedin',
            email: json.email,
            givenName: json.given_name,
            familyName: json.family_name,
            picture: json.picture,
            _raw: body,
            _json: json,
          };
          done(null, profile);
        } catch (e: any) {
          done(new Error(`Failed to parse profile: ${e.message}`));
        }
      });
    };
  }

  async validate(accessToken: string, refreshToken: string, profile: any): Promise<any> {
    const user = {
      email: profile.email,
      firstName: profile.givenName,
      lastName: profile.familyName,
      picture: profile.picture,
      accessToken,
      refreshToken,
    };
    return user;
  }
}
