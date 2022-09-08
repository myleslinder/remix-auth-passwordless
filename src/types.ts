type LinkPayload = {
	email: string;
	form: Record<string, FormDataEntryValue>;
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
	secret: string;
	sendEmail: (options: SendEmailOptions<User>) => Promise<void>;
	/**
	 * Provide only a pathname as the strategy will
	 * detect the host of the request and use it to build the URL.
	 * @default "/auth"
	 */
	callbackPath?: string;
	validateEmail?: (email: string) => Promise<void>;
	emailField?: string;
	/**
	 * The key on the session to store the email.
	 * @default "auth:email"
	 */
	sessionEmailKey?: string;
	linkTokenParam?: string;
	/**
	 * The key on the session to store the magic link.
	 * @default "auth:accessLink"
	 */
	sessionLinkKey?: string;
	/**
	 * @default 300_000
	 */
	expirationTime?: number;
	/**
	 * Should the session be commited before returning
	 * the user data if the `successRedirect` is omitted.
	 * @default false
	 */
	commitOnReturn?: boolean;
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
	codeOptions?: CodeOptions;
	/**
	 * @default "code"
	 */
	codeField?: string;
	/**
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

export type {
	CodeOptions,
	PasswordlessStrategyVerifyParams,
	PasswordlessStrategyOptions,
	AuthErrorTypeMessages,
	LinkPayload,
};
