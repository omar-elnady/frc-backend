import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {
  getAuthenticateOptions(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    return {
      state: req.query.redirectUrl || undefined,
    };
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext, status?: any) {
    if (err || !user) {
      // If authentication fails, redirect back to the state URL with an error
      const req = context.switchToHttp().getRequest();
      const res = context.switchToHttp().getResponse();
      const redirectBaseUrl = (req.query.state as string) || '/';
      const separator = redirectBaseUrl.includes('?') ? '&' : '?';
      res.redirect(`${redirectBaseUrl}${separator}error=oauth_failed`);
      return null;
    }
    return user;
  }
}

@Injectable()
export class LinkedInOAuthGuard extends AuthGuard('linkedin') {
  getAuthenticateOptions(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    return {
      state: req.query.redirectUrl || undefined,
    };
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext, status?: any) {
    if (err || !user) {
      const req = context.switchToHttp().getRequest();
      const res = context.switchToHttp().getResponse();
      const redirectBaseUrl = (req.query.state as string) || '/';
      const separator = redirectBaseUrl.includes('?') ? '&' : '?';
      res.redirect(`${redirectBaseUrl}${separator}error=oauth_failed`);
      return null;
    }
    return user;
  }
}
