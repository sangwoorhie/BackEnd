/* Google Strategy */
type GoogleUser = {
  email: string;
  name: string;
};

export type GoogleRequest = Request & { user: GoogleUser };

/* Kakao Strategy */
type KakaoUser = {
  email: string;
  name: string;
};

export type KakaoRequest = Request & { user: KakaoUser };

// payload
export type Payload = {
  id: number;
  email: string;
};
