import {
  Injectable,
  ConflictException,
  NotFoundException,
  BadRequestException,
  InternalServerErrorException,
  UnauthorizedException,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { customAlphabet } from 'nanoid';
import { PrismaService } from '../core/database/prisma/prisma.service';
import { EmailService } from '../core/email/email.service';
import { RedisService } from '../core/database/redis/redis.service';
import { InfobipService } from '../core/infobip/infobip.service';
import {
  sendActivationCodeTemplate,
  sendForgetCodeTemplate,
} from '../core/email/templates/email.templates';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyActivationDto } from './dto/verify-activation.dto';
import { ResendActivationDto } from './dto/resend-activation.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { VerifyForgotCodeDto } from './dto/verify-forgot-code.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { PhoneRegisterDto } from './dto/phone-register.dto';
import { PhoneLoginDto } from './dto/phone-login.dto';
import { VerifyPhoneOtpDto } from './dto/verify-phone-otp.dto';
import { PhoneForgotPasswordDto } from './dto/phone-forgot-password.dto';
import { PhoneResetPasswordDto } from './dto/phone-reset-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly redisService: RedisService,
    private readonly infobipService: InfobipService,
  ) {}

  private get saltRounds(): number {
    return parseInt(
      this.configService.get<string>('BCRYPT_SALT_ROUNDS', '10'),
      10,
    );
  }

  // ─── Register ───────────────────────────────────────────────────────────────
  async register(dto: RegisterDto) {
    const { fullName, email, password } = dto;

    // Extract first and strictly last name (e.g. "Ahmed Aly Gad" -> First: "Ahmed", Last: "Gad")
    const nameParts = fullName.trim().split(/\s+/);
    const firstName = nameParts[0];
    const lastName =
      nameParts.length > 1 ? nameParts[nameParts.length - 1] : '';

    const existingUser = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (existingUser) {
      throw new ConflictException('Email is Already Exist');
    }

    const nanoId = customAlphabet('123456789', 6);
    const activationCode = nanoId();
    const activationCodeExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    const html = sendActivationCodeTemplate(firstName, activationCode);
    const sent = await this.emailService.sendEmail({
      to: email,
      subject: 'Activation Code',
      html,
    });
    if (!sent) {
      throw new InternalServerErrorException('Send Email Error');
    }

    const passwordHash = await bcrypt.hash(password, this.saltRounds);
    const activationCodeHash = await bcrypt.hash(
      activationCode,
      this.saltRounds,
    );

    // Generate unique username: fullName (no spaces) + 4 random digits
    // e.g. "Omar Elnadi" -> "OmarElnadi3947"
    const baseUsername = fullName.trim().replace(/\s+/g, '');
    const digits = customAlphabet('0123456789', 4);
    let username: string;
    do {
      username = `${baseUsername}${digits()}`;
    } while (await this.prisma.user.findUnique({ where: { username } }));

    const createdUser = await this.prisma.user.create({
      data: {
        firstName,
        lastName,
        username,
        email: email.toLowerCase(),
        passwordHash,
        mfaSecret: `${activationCodeHash}|${activationCodeExpires.getTime()}`,
      },
    });

    return {
      message:
        'User Registered Successfully. Please check your email for activation code',
    };
  }

  // ─── Verify Activation Code ──────────────────────────────────────────────────
  async verifyActivationCode(dto: VerifyActivationDto) {
    const { email, activationCode } = dto;

    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (!user) {
      throw new NotFoundException('Not Register Account');
    }

    if (user.isEmailVerified) {
      return { message: 'Account already verified' };
    }

    const [storedHash, expiresAt] = (user.mfaSecret ?? '').split('|');
    if (!storedHash || !expiresAt) {
      throw new BadRequestException('Invalid Activation Code');
    }

    if (parseInt(expiresAt) < Date.now()) {
      throw new BadRequestException('Activation Code Expired');
    }

    const isCodeValid = await bcrypt.compare(activationCode, storedHash);
    if (!isCodeValid) {
      throw new BadRequestException('Invalid Activation Code');
    }

    const accessSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    const access_token = this.jwtService.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
      { secret: accessSecret, expiresIn: '1d' },
    );

    const refresh_token = this.jwtService.sign(
      { id: user.id, username: user.username },
      { secret: refreshSecret, expiresIn: '7d' },
    );

    // Save refresh token in sessions table
    await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshToken: refresh_token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isEmailVerified: true,
        mfaSecret: null,
        lastLoginAt: new Date(),
      },
    });

    return {
      message: 'Account Activated Successfully',
      access_token,
      refresh_token,
    };
  }

  // ─── Resend Activation Code ──────────────────────────────────────────────────
  async resendActivationCode(dto: ResendActivationDto) {
    const { email } = dto;
    const normalizedEmail = email.toLowerCase();

    // ─── Rate Limiting  ──────────────────────
    const lockKey = `resend_activation_lock:${normalizedEmail}`;
    const attemptsKey = `resend_activation_attempts:${normalizedEmail}`;
    const redisClient = this.redisService.getClient();

    const isLocked = await redisClient.get(lockKey);
    if (isLocked) {
      const ttl = await redisClient.ttl(lockKey);
      throw new HttpException(
        `Please wait ${ttl} seconds before requesting a new code`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const attemptsStr = await redisClient.get(attemptsKey);
    const attempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;

    if (attempts >= 5) {
      throw new HttpException(
        'Daily limit exceeded. You can only request 5 times per day. Please try again after 24 hours.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (!user) {
      throw new NotFoundException('Not Register Account');
    }
    if (user.isEmailVerified) {
      return { message: 'Account already verified' };
    }

    const nanoId = customAlphabet('123456789', 6);
    const activationCode = nanoId();
    const activationCodeExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    const activationCodeHash = await bcrypt.hash(
      activationCode,
      this.saltRounds,
    );

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        mfaSecret: `${activationCodeHash}|${activationCodeExpires.getTime()}`,
      },
    });

    const html = sendActivationCodeTemplate(user.firstName, activationCode);
    const sent = await this.emailService.sendEmail({
      to: normalizedEmail,
      subject: 'Activation Code',
      html,
    });
    if (!sent) {
      throw new InternalServerErrorException('Send Email Error');
    }

    // ─── Apply lock for next request ────────────────────────────────────────
    // Locks: 30s → 1m → 5m → 10m → 30m
    const lockDurations = [30, 60, 300, 600, 1800];
    const nextLockSec = lockDurations[attempts] || 1800;

    await redisClient.set(lockKey, 'locked', 'EX', nextLockSec);

    if (attempts === 0) {
      await redisClient.set(attemptsKey, 1, 'EX', 24 * 60 * 60);
    } else {
      await redisClient.incr(attemptsKey);
    }

    return { message: 'Activation Code Resent Successfully' };
  }

  // ─── Login ───────────────────────────────────────────────────────────────────
  async login(dto: LoginDto) {
    const { email: identifier, password } = dto; // Extract as identifier internally

    // Detect whether identifier is a phone number or email
    const isPhone = identifier.startsWith('+');

    const user = isPhone
      ? await this.prisma.user.findUnique({
          where: { phoneNumber: identifier },
        })
      : await this.prisma.user.findUnique({
          where: { email: identifier.toLowerCase() },
        });

    if (!user) {
      throw new NotFoundException('No account found with this email or phone');
    }

    // For email logins: require email verified
    if (!isPhone && !user.isEmailVerified) {
      throw new BadRequestException('Please verify your email first');
    }

    // For phone logins: require phone verified
    if (isPhone && !user.isPhoneVerified) {
      throw new BadRequestException('Please verify your phone number first');
    }

    if (!user.passwordHash) {
      throw new BadRequestException(
        'This account uses a different login method (OAuth or OTP)',
      );
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid credentials');
    }

    const accessSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    const access_token = this.jwtService.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
      { secret: accessSecret, expiresIn: '1d' },
    );

    const refresh_token = this.jwtService.sign(
      { id: user.id, username: user.username },
      { secret: refreshSecret, expiresIn: '7d' },
    );

    // Save refresh token in sessions table
    await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshToken: refresh_token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return {
      message: 'Login successful',
      access_token,
      refresh_token,
    };
  }

  // ─── Logout ──────────────────────────────────────────────────────────────────
  async logout(userId: string, refreshToken?: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Invalidate specific session if refresh token provided, otherwise all sessions
    if (refreshToken) {
      await this.prisma.session.updateMany({
        where: { userId, refreshToken },
        data: { isValid: false },
      });
    } else {
      await this.prisma.session.updateMany({
        where: { userId },
        data: { isValid: false },
      });
    }

    return { message: 'User Logout Successfully' };
  }

  // ─── Send Forgot Password Code ───────────────────────────────────────────────
  async sendForgotPasswordCode(dto: ForgotPasswordDto) {
    const { email } = dto;
    const normalizedEmail = email.toLowerCase();

    // 1. Check custom rate limit rule
    const lockKey = `forgot_pw_lock:${normalizedEmail}`;
    const attemptsKey = `forgot_pw_attempts:${normalizedEmail}`;
    const redisClient = this.redisService.getClient();

    const isLocked = await redisClient.get(lockKey);
    if (isLocked) {
      const ttl = await redisClient.ttl(lockKey);
      throw new HttpException(
        `Please wait ${ttl} seconds before requesting a new code`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const attemptsStr = await redisClient.get(attemptsKey);
    const attempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;

    if (attempts >= 5) {
      throw new HttpException(
        'Daily limit exceeded. You can only request 5 times per day. Please try again after 24 hours.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const nanoId = customAlphabet('123456789', 6);
    const forgetCode = nanoId();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    const forgetCodeHash = await bcrypt.hash(forgetCode, this.saltRounds);

    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (!user) {
      throw new NotFoundException('Not Register Account');
    }

    // Store hashed forget code temporarily in mfaSecret with "forget|hash|expires" prefix
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        mfaSecret: `forget|${forgetCodeHash}|${expiresAt.getTime()}`,
      },
    });

    const html = sendForgetCodeTemplate(user.firstName, forgetCode);
    const sent = await this.emailService.sendEmail({
      to: email,
      subject: 'Forget Password',
      html,
    });
    if (!sent) {
      throw new InternalServerErrorException('Send Email Error');
    }

    // 2. Lock for the next request based on attempts
    // Locks: 30s, 1m, 5m, 10m, 30m
    const lockDurations = [30, 60, 300, 600, 1800];
    const nextLockSec = lockDurations[attempts] || 1800; // fallback just in case

    await redisClient.set(lockKey, 'locked', 'EX', nextLockSec);

    if (attempts === 0) {
      // First attempt, set attempts key with 24 hours TTL
      await redisClient.set(attemptsKey, 1, 'EX', 24 * 60 * 60);
    } else {
      await redisClient.incr(attemptsKey);
    }

    return { message: 'Verification Code Sent Successfully' };
  }

  // ─── Verify Forgot Password Code ─────────────────────────────────────────────
  async verifyForgotPasswordCode(dto: VerifyForgotCodeDto) {
    const { email, forgetCode } = dto;

    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (!user) {
      throw new NotFoundException('Not Register Account');
    }

    const parts = (user.mfaSecret ?? '').split('|');
    if (parts.length !== 3 || parts[0] !== 'forget') {
      throw new BadRequestException('Invalid Reset Code');
    }

    const storedHash = parts[1];
    const expiresAt = parts[2];

    if (parseInt(expiresAt) < Date.now()) {
      throw new BadRequestException('Reset Code Expired');
    }

    const isCodeValid = await bcrypt.compare(forgetCode, storedHash);
    if (!isCodeValid) {
      throw new BadRequestException('Invalid Reset Code');
    }

    return { message: 'Code Verified Successfully' };
  }

  // ─── Reset Password ───────────────────────────────────────────────────────────
  async resetPassword(dto: ResetPasswordDto) {
    const { email, forgetCode, password, confirmPassword } = dto;

    if (password !== confirmPassword) {
      throw new BadRequestException("Passwords Don't Match");
    }

    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (!user) {
      throw new NotFoundException('Not Register Account');
    }

    const parts = (user.mfaSecret ?? '').split('|');
    if (parts.length !== 3 || parts[0] !== 'forget') {
      throw new BadRequestException('Invalid Reset Code');
    }

    const storedHash = parts[1];
    const expiresAt = parts[2];

    if (parseInt(expiresAt) < Date.now()) {
      throw new BadRequestException('Reset Code Expired');
    }

    const isCodeValid = await bcrypt.compare(forgetCode, storedHash);
    if (!isCodeValid) {
      throw new BadRequestException('Invalid Reset Code');
    }

    if (user.passwordHash) {
      const isSame = await bcrypt.compare(password, user.passwordHash);
      if (isSame) {
        throw new ConflictException(
          'New Password cannot be the same as the old one',
        );
      }
    }

    const newPasswordHash = await bcrypt.hash(password, this.saltRounds);
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: newPasswordHash,
        mfaSecret: null,
        updatedAt: new Date(),
      },
    });

    // Invalidate all sessions after password reset
    await this.prisma.session.updateMany({
      where: { userId: user.id },
      data: { isValid: false },
    });

    return { message: 'Password Changed Successfully' };
  }

  // ─── Refresh Token ────────────────────────────────────────────────────────────
  async refreshToken(userId: string, oldRefreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Validate session exists and is still valid in DB
    const session = await this.prisma.session.findFirst({
      where: {
        userId,
        refreshToken: oldRefreshToken,
        isValid: true,
        expiresAt: { gt: new Date() },
      },
    });
    if (!session) {
      throw new UnauthorizedException('Refresh token is invalid or expired');
    }

    const accessSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    // Issue new access token (full payload)
    const access_token = this.jwtService.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
      { secret: accessSecret, expiresIn: '1d' },
    );

    // Rotate refresh token — invalidate old, issue new
    const refresh_token = this.jwtService.sign(
      { id: user.id, username: user.username },
      { secret: refreshSecret, expiresIn: '7d' },
    );

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        refreshToken: refresh_token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    return { access_token, refresh_token };
  }

  // ─── Google Login ────────────────────────────────────────────────────────────
  async googleLogin(req: any) {
    if (!req.user) {
      throw new BadRequestException('No user returned from Google');
    }

    const { email, firstName, lastName, picture } = req.user;
    const normalizedEmail = email.toLowerCase();

    let user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      // User doesn't exist, create a new one using Google data
      const baseUsername = `${firstName}${lastName}`.trim().replace(/\s+/g, '');
      const digits = customAlphabet('0123456789', 4);
      let username: string;
      do {
        username = `${baseUsername}${digits()}`;
      } while (await this.prisma.user.findUnique({ where: { username } }));

      // Password is not required for google logged in users since they use OAuth
      // passwordHash? is optional according to schema
      user = await this.prisma.user.create({
        data: {
          email: normalizedEmail,
          firstName: firstName || 'Google',
          lastName: lastName || 'User',
          username,
          isEmailVerified: true,
          avatarUrl: picture, // Store the google photo
        },
      });
    } else {
      // Ensure email verified is true since they are coming from Google
      if (!user.isEmailVerified) {
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: { isEmailVerified: true },
        });
      }
    }

    const accessSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    const access_token = this.jwtService.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
      { secret: accessSecret, expiresIn: '1d' },
    );

    const refresh_token = this.jwtService.sign(
      { id: user.id, username: user.username },
      { secret: refreshSecret, expiresIn: '7d' },
    );

    // Save refresh token in sessions table
    await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshToken: refresh_token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return {
      message: 'Google Login Successfully',
      access_token,
      refresh_token,
    };
  }

  // ─── LinkedIn Login ──────────────────────────────────────────────────────────
  async linkedinLogin(req: any) {
    if (!req.user) {
      throw new BadRequestException('No user returned from LinkedIn');
    }

    const { email, firstName, lastName, picture } = req.user;
    const normalizedEmail = email.toLowerCase();

    let user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      const baseUsername = `${firstName}${lastName}`.trim().replace(/\s+/g, '');
      const digits = customAlphabet('0123456789', 4);
      let username: string;
      do {
        username = `${baseUsername}${digits()}`;
      } while (await this.prisma.user.findUnique({ where: { username } }));

      user = await this.prisma.user.create({
        data: {
          email: normalizedEmail,
          firstName: firstName || 'LinkedIn',
          lastName: lastName || 'User',
          username,
          isEmailVerified: true,
          avatarUrl: picture,
        },
      });
    } else {
      if (!user.isEmailVerified) {
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: { isEmailVerified: true },
        });
      }
    }

    const accessSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    const access_token = this.jwtService.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
      { secret: accessSecret, expiresIn: '1d' },
    );

    const refresh_token = this.jwtService.sign(
      { id: user.id, username: user.username },
      { secret: refreshSecret, expiresIn: '7d' },
    );

    // Save refresh token in sessions table
    await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshToken: refresh_token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return {
      message: 'LinkedIn Login Successfully',
      access_token,
      refresh_token,
    };
  }

  // ─── Facebook Login ──────────────────────────────────────────────────────────
  async facebookLogin(req: any) {
    if (!req.user) {
      throw new BadRequestException('No user returned from Facebook');
    }

    const { email, firstName, lastName, picture } = req.user;
    const normalizedEmail = email?.toLowerCase();

    // If email is missing (FB allows registration without email via phone), we might need a fallback
    // For now, if no email, we use facebookId as identifier if we had it, but let's assume email is provided.
    if (!normalizedEmail) {
       throw new BadRequestException('Facebook account must have an email associated.');
    }

    let user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      const baseUsername = `${firstName}${lastName}`.trim().replace(/\s+/g, '');
      const digits = customAlphabet('0123456789', 4);
      let username: string;
      do {
        username = `${baseUsername}${digits()}`;
      } while (await this.prisma.user.findUnique({ where: { username } }));

      user = await this.prisma.user.create({
        data: {
          email: normalizedEmail,
          firstName: firstName || 'Facebook',
          lastName: lastName || 'User',
          username,
          isEmailVerified: true,
          avatarUrl: picture,
        },
      });
    } else {
      if (!user.isEmailVerified) {
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: { isEmailVerified: true },
        });
      }
    }

    const tokens = await this.issueTokens(user);

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return {
      message: 'Facebook Login Successfully',
      ...tokens,
    };
  }

  // ─── Private: generate tokens & store session ────────────────────────────────
  private async issueTokens(user: {
    id: string;
    username: string;
    email: string;
    firstName: string;
    lastName: string;
  }) {
    const accessSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    const access_token = this.jwtService.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
      { secret: accessSecret, expiresIn: '1d' },
    );

    const refresh_token = this.jwtService.sign(
      { id: user.id, username: user.username },
      { secret: refreshSecret, expiresIn: '7d' },
    );

    await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshToken: refresh_token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    return { access_token, refresh_token };
  }

  // ─── Private: OTP rate limiting via Redis ────────────────────────────────────
  private async checkOtpRateLimit(
    redisClient: any,
    lockKey: string,
    attemptsKey: string,
  ) {
    const isLocked = await redisClient.get(lockKey);
    if (isLocked) {
      const ttl = await redisClient.ttl(lockKey);
      throw new HttpException(
        `Please wait ${ttl} seconds before requesting a new code`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    const attemptsStr = await redisClient.get(attemptsKey);
    const attempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;
    if (attempts >= 5) {
      throw new HttpException(
        'Daily limit exceeded. You can only request 5 times per day. Please try again after 24 hours.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    return attempts;
  }

  private async applyOtpRateLock(
    redisClient: any,
    lockKey: string,
    attemptsKey: string,
    attempts: number,
  ) {
    const lockDurations = [30, 60, 300, 600, 1800];
    const nextLockSec = lockDurations[attempts] || 1800;
    await redisClient.set(lockKey, 'locked', 'EX', nextLockSec);
    if (attempts === 0) {
      await redisClient.set(attemptsKey, 1, 'EX', 24 * 60 * 60);
    } else {
      await redisClient.incr(attemptsKey);
    }
  }

  // ─── Phone Register: Send OTP ────────────────────────────────────────────────
  async phoneRegister(dto: PhoneRegisterDto) {
    const { fullName, phoneNumber, password } = dto;

    const existingUser = await this.prisma.user.findUnique({
      where: { phoneNumber },
    });
    if (existingUser && existingUser.isPhoneVerified) {
      throw new ConflictException('Phone number is already registered');
    }

    const redisClient = this.redisService.getClient();
    const lockKey = `phone_reg_lock:${phoneNumber}`;
    const attemptsKey = `phone_reg_attempts:${phoneNumber}`;
    const attempts = await this.checkOtpRateLimit(
      redisClient,
      lockKey,
      attemptsKey,
    );

    const nanoId = customAlphabet('0123456789', 6);
    const otp = nanoId();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 min
    const otpHash = await bcrypt.hash(otp, this.saltRounds);

    const sent = await this.infobipService.sendOtp(phoneNumber, otp);
    if (!sent) {
      throw new InternalServerErrorException('Failed to send WhatsApp OTP');
    }

    const passwordHash = await bcrypt.hash(password, this.saltRounds);
    const nameParts = fullName.trim().split(/\s+/);
    const firstName = nameParts[0];
    const lastName =
      nameParts.length > 1 ? nameParts[nameParts.length - 1] : '';

    if (existingUser) {
      // User was created before but never verified – update OTP
      await this.prisma.user.update({
        where: { id: existingUser.id },
        data: {
          firstName,
          lastName,
          passwordHash,
          mfaSecret: `phone_reg|${otpHash}|${otpExpires.getTime()}`,
        },
      });
    } else {
      // Brand new user — create without verified flag
      const baseUsername = fullName.trim().replace(/\s+/g, '');
      const digits = customAlphabet('0123456789', 4);
      let username: string;
      do {
        username = `${baseUsername}${digits()}`;
      } while (await this.prisma.user.findUnique({ where: { username } }));

      await this.prisma.user.create({
        data: {
          firstName,
          lastName,
          username,
          email: `phone_${phoneNumber.replace('+', '')}@placeholder.frc`,
          phoneNumber,
          passwordHash,
          isPhoneVerified: false,
          mfaSecret: `phone_reg|${otpHash}|${otpExpires.getTime()}`,
        },
      });
    }

    await this.applyOtpRateLock(redisClient, lockKey, attemptsKey, attempts);

    return {
      message:
        'OTP sent to your WhatsApp. Please verify to complete registration.',
    };
  }

  // ─── Phone Register: Verify OTP & auto-login ────────────────────────────────
  async verifyPhoneOtp(dto: VerifyPhoneOtpDto) {
    const { phoneNumber, otp } = dto;

    const user = await this.prisma.user.findUnique({ where: { phoneNumber } });
    if (!user) {
      throw new NotFoundException(
        'No registration found for this phone number',
      );
    }
    if (user.isPhoneVerified) {
      return { message: 'Phone already verified' };
    }

    const parts = (user.mfaSecret ?? '').split('|');
    if (parts.length !== 3 || parts[0] !== 'phone_reg') {
      throw new BadRequestException('Invalid OTP');
    }

    const [, storedHash, expiresAt] = parts;
    if (parseInt(expiresAt) < Date.now()) {
      throw new BadRequestException('OTP has expired');
    }

    const isValid = await bcrypt.compare(otp, storedHash);
    if (!isValid) {
      throw new BadRequestException('Invalid OTP');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { isPhoneVerified: true, mfaSecret: null, lastLoginAt: new Date() },
    });

    const tokens = await this.issueTokens(user);

    return {
      message: 'Phone verified and account activated successfully',
      ...tokens,
    };
  }

  // ─── Phone Login: Send OTP ───────────────────────────────────────────────────
  async phoneLogin(dto: PhoneLoginDto) {
    const { phoneNumber } = dto;

    const user = await this.prisma.user.findUnique({ where: { phoneNumber } });
    if (!user) {
      throw new NotFoundException('No account found with this phone number');
    }
    if (!user.isPhoneVerified) {
      throw new BadRequestException('Phone number is not verified yet');
    }

    const redisClient = this.redisService.getClient();
    const lockKey = `phone_login_lock:${phoneNumber}`;
    const attemptsKey = `phone_login_attempts:${phoneNumber}`;
    const attempts = await this.checkOtpRateLimit(
      redisClient,
      lockKey,
      attemptsKey,
    );

    const nanoId = customAlphabet('0123456789', 6);
    const otp = nanoId();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000);
    const otpHash = await bcrypt.hash(otp, this.saltRounds);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { mfaSecret: `phone_login|${otpHash}|${otpExpires.getTime()}` },
    });

    const sent = await this.infobipService.sendOtp(phoneNumber, otp);
    if (!sent) {
      throw new InternalServerErrorException('Failed to send WhatsApp OTP');
    }

    await this.applyOtpRateLock(redisClient, lockKey, attemptsKey, attempts);

    return { message: 'OTP sent to your WhatsApp. Please verify to login.' };
  }

  // ─── Phone Login: Verify OTP ─────────────────────────────────────────────────
  async verifyPhoneLoginOtp(dto: VerifyPhoneOtpDto) {
    const { phoneNumber, otp } = dto;

    const user = await this.prisma.user.findUnique({ where: { phoneNumber } });
    if (!user) {
      throw new NotFoundException('No account found with this phone number');
    }

    const parts = (user.mfaSecret ?? '').split('|');
    if (parts.length !== 3 || parts[0] !== 'phone_login') {
      throw new BadRequestException('Invalid OTP');
    }

    const [, storedHash, expiresAt] = parts;
    if (parseInt(expiresAt) < Date.now()) {
      throw new BadRequestException('OTP has expired');
    }

    const isValid = await bcrypt.compare(otp, storedHash);
    if (!isValid) {
      throw new BadRequestException('Invalid OTP');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { mfaSecret: null, lastLoginAt: new Date() },
    });

    const tokens = await this.issueTokens(user);

    return {
      message: 'Login successful',
      ...tokens,
    };
  }

  // ─── Phone Forgot Password: Send OTP ────────────────────────────────────────
  async phoneForgotPassword(dto: PhoneForgotPasswordDto) {
    const { phoneNumber } = dto;

    const user = await this.prisma.user.findUnique({ where: { phoneNumber } });
    if (!user) {
      throw new NotFoundException('No account found with this phone number');
    }

    const redisClient = this.redisService.getClient();
    const lockKey = `phone_forgot_lock:${phoneNumber}`;
    const attemptsKey = `phone_forgot_attempts:${phoneNumber}`;
    const attempts = await this.checkOtpRateLimit(
      redisClient,
      lockKey,
      attemptsKey,
    );

    const nanoId = customAlphabet('0123456789', 6);
    const otp = nanoId();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000);
    const otpHash = await bcrypt.hash(otp, this.saltRounds);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { mfaSecret: `phone_forgot|${otpHash}|${otpExpires.getTime()}` },
    });

    const sent = await this.infobipService.sendOtp(phoneNumber, otp);
    if (!sent) {
      throw new InternalServerErrorException('Failed to send WhatsApp OTP');
    }

    await this.applyOtpRateLock(redisClient, lockKey, attemptsKey, attempts);

    return {
      message:
        'OTP sent to your WhatsApp. Please verify to reset your password.',
    };
  }

  // ─── Phone Reset Password ────────────────────────────────────────────────────
  async phoneResetPassword(dto: PhoneResetPasswordDto) {
    const { phoneNumber, otp, password, confirmPassword } = dto;

    if (password !== confirmPassword) {
      throw new BadRequestException("Passwords Don't Match");
    }

    const user = await this.prisma.user.findUnique({ where: { phoneNumber } });
    if (!user) {
      throw new NotFoundException('No account found with this phone number');
    }

    const parts = (user.mfaSecret ?? '').split('|');
    if (parts.length !== 3 || parts[0] !== 'phone_forgot') {
      throw new BadRequestException('Invalid OTP');
    }

    const [, storedHash, expiresAt] = parts;
    if (parseInt(expiresAt) < Date.now()) {
      throw new BadRequestException('OTP has expired');
    }

    const isValid = await bcrypt.compare(otp, storedHash);
    if (!isValid) {
      throw new BadRequestException('Invalid OTP');
    }

    if (user.passwordHash) {
      const isSame = await bcrypt.compare(password, user.passwordHash);
      if (isSame) {
        throw new ConflictException(
          'New password cannot be same as old password',
        );
      }
    }

    const newPasswordHash = await bcrypt.hash(password, this.saltRounds);
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: newPasswordHash,
        mfaSecret: null,
        updatedAt: new Date(),
      },
    });

    // Invalidate all sessions
    await this.prisma.session.updateMany({
      where: { userId: user.id },
      data: { isValid: false },
    });

    return { message: 'Password reset successfully' };
  }
}
