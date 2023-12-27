type GoogleUser = {
  email: string;
  name: string;
};

export type GoogleRequest = Request & { user: GoogleUser };
