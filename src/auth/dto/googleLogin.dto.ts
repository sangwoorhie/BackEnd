import { IsString, IsEmail, IsOptional } from 'class-validator';

export class GoogleDto {
  @IsOptional()
  @IsString()
  readonly accessToken?: string;
}
