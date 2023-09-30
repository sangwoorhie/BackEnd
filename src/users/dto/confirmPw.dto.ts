import { IsString } from 'class-validator';

export class ConfirmPasswordDto {
  @IsString()
  readonly password?: string;
}
