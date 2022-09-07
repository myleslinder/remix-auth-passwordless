type LinkPayload = {
  email: string;
  form: Record<string, unknown>;
  creationDate: string; // ISO string
};

type LinkErrorType = "expired" | "invalid" | "mismatch";

type CodeErrorType = Exclude<LinkErrorType, "mismatch">;

type AuthErrorTypeMessages = {
  link: Partial<Record<LinkErrorType, string>>;
  code: Partial<Record<CodeErrorType, string>>;
  default: string;
};

type SendEmailOptions<User> = {
  email: string;
  accessLink: string;
  user: User;
  domainUrl: string;
  form: FormData;
  code?: string;
};

type BaseStrategyOptions<User> = {
  /**
   * A secret string used to encrypt and decrypt the token and magic link.
   */
  secret: string;
  /**
   *
   */
  sendEmail: (options: SendEmailOptions<User>) => Promise<void>;
  /**
   * The endpoint the user will go after clicking on the email link.
   * Provide only a pathname as the strategy will
   * detect the host of the request and use it to build the URL.
   * @default "/auth"
   */
  callbackPath?: string;
  /**
   * A function to validate the email address. The message of
   * an error thrown from within this function will be flashed to
   * the session error key
   *
   * By default it only test the email against the RegExp `/.+@.+/`.
   */
  validateEmail?: (email: string) => Promise<void>;
  /**
   * If you want to use the https://verifier.meetchopra.com/ service
   * provide your api key here
   */
  // verifierApiKey?: string;
  /**
   * The name of the form input used to get the email.
   * @default "email"
   */
  emailField?: string;
  /**
   * The key on the session to store the email.
   * @default "auth:email"
   */
  sessionEmailKey?: string;
  /**
   * The param name the strategy will use to read the token from the email link.
   * @default "token"
   */
  linkTokenParam?: string;
  /**
   * The key on the session to store the magic link.
   * @default "auth:accessLink"
   */
  sessionLinkKey?: string;
  /**
   * How long the link and code will be valid. Default to 5 minutes.
   * @default 30_000
   */
  expirationTime?: number;
  /**
   * Should the session be commited before returning
   * the user data if the `successRedirect` is omitted.
   * @default false
   */
  commitOnReturn?: boolean;
  /**
   * Enables sending and accepting a one time code
   * @default false
   */
  useOneTimeCode?: boolean;
};

type LinkStrategyOptions = {
  useOneTimeCode?: false;
  errorMessages?: Omit<Partial<AuthErrorTypeMessages>, "code">;
};

type CodeOptions = {
  size?: number;
  segmentLength?: number;
  lettersOnly?: boolean;
};
type CodeStrategyOptions = {
  useOneTimeCode?: true;
  /**
   * Configuration for the generated one time code
   * @default size=12,segmentLength=4,lettersOnly=false
   */
  codeOptions?: CodeOptions;
  /**
   * The name of the form input used to get the code.
   * @default "code"
   */
  codeField?: string;
  /**
   * The key on the session to store the code.
   * @default "auth:code"
   */
  sessionCodeKey?: string;
  /**
   * The amount of invalid code attempts
   * before they have to generate a new one.
   * This doesn't apply to expired code entry.
   * @default 1
   */
  invalidCodeAttempts?: number;
  errorMessages?: Partial<AuthErrorTypeMessages>;
};

type PasswordlessStrategyOptions<User> = BaseStrategyOptions<User> &
  (LinkStrategyOptions | CodeStrategyOptions);

type PasswordlessStrategyVerifyParams = {
  email: string;
  form: FormData;
};

type ValidateEmailFunction = NonNullable<
  PasswordlessStrategyOptions<unknown>["validateEmail"]
>;

export type {
  CodeOptions,
  PasswordlessStrategyVerifyParams,
  PasswordlessStrategyOptions,
  AuthErrorTypeMessages,
  LinkPayload,
  ValidateEmailFunction,
};
