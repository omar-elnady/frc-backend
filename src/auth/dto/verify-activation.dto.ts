import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Matches } from 'class-validator';

export class VerifyActivationDto {
  @ApiProperty({ example: 'user@example.com', format: 'email' })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @ApiProperty({
    example: '123456',
    description: '6-digit activation code',
    pattern: '^[0-9]{6}$',
  })
  @IsString()
  @Matches(/^[0-9]{6}$/, {
    message: 'Activation code must be a 6-digit number',
  })
  activationCode: string;
}
