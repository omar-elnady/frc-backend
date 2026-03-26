import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Matches } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: 'user@example.com or +201234567890',
    description: 'Email address OR phone number',
  })
  @IsString()
  @IsNotEmpty({ message: 'Email or phone number is required' })
  @Matches(/^(\+[1-9]\d{6,14}|[^\s@]+@[^\s@]+\.[^\s@]+)$/, {
    message: 'Invalid email or phone number format',
  })
  email: string;

  @ApiProperty({ example: 'Password123' })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}
