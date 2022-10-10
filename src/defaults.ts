import type { ValidateEmailFunction } from "~/index";
import type { AuthErrorTypeMessages, CodeOptions } from "~/types";

const FIVE_MINUTES_MS = 1000 * 60 * 5;
const DEFAULT_CODE_OPS: Required<CodeOptions> = {
	size: 12,
	segmentLength: 4,
	lettersOnly: false,
};
const SESSION_CODE_KEY = "auth:code";
const SESSION_LINK_KEY = "auth:accessLink";
const SESSION_EMAIL_KEY = "auth:email";
const CODE_FIELD = "code";
const CODE_ATTEMPT_KEY = "auth:code_attempt_count";
const EMAIL_FIELD = "email";
const CB_URL = "/auth";
const TOKEN_PARAM = "token";

const DEFAULT_ERROR_MESSAGES: Required<AuthErrorTypeMessages> = {
	default: "Something went wrong. Please try again.",
	link: {
		expired: "Access link expired. Please request a new one.",
		invalid: "Access link invalid. Please request a new one.",
		mismatch: `You're trying to log into a browser that was not used to initiate the login`,
	},
	code: {
		expired: "Verification code expired. Please request a new one.",
		invalid: "Invalid verification code. Please try again.",
	},
};

const validateEmail: ValidateEmailFunction = (email: string) => {
	if (!/.+@.+/u.test(email)) {
		throw new Error("A valid email is required.");
	}
	return Promise.resolve();
};

export const DEFAULTS = {
	expiry: FIVE_MINUTES_MS,
	codeOptions: DEFAULT_CODE_OPS,
	validateEmailFn: validateEmail,
	codeField: CODE_FIELD,
	emailField: EMAIL_FIELD,
	sessionCodeKey: SESSION_CODE_KEY,
	errorMessages: DEFAULT_ERROR_MESSAGES,
	callbackPath: CB_URL,
	sessionLinkKey: SESSION_LINK_KEY,
	sessionEmailKey: SESSION_EMAIL_KEY,
	tokenParam: TOKEN_PARAM,
	codeAttemptKey: CODE_ATTEMPT_KEY,
};
