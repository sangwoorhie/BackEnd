import { IsOptional, IsString } from 'class-validator';

export class KakaoDto {
  @IsOptional()
  @IsString()
  readonly accessToken?: string;
}
