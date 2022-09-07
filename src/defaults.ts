import type {
  AuthErrorTypeMessages,
  CodeOptions,
  ValidateEmailFunction,
} from "~/types";

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
const EMAIL_FIELD = "email";
const CB_URL = "/auth";
const TOKEN_PARAM = "token";

const DEFAULT_ERROR_MESSAGES: Required<AuthErrorTypeMessages> = {
  default: "Something went wrong. Please try again.",
  link: {
    expired: "Magic link expired. Please request a new one.",
    invalid: "Sign in link invalid. Please request a new one.",
    mismatch: `You must open the magic link on the same device it was created from for security reasons. Please request a new link.`,
  },
  code: {
    expired: "Code has expired. Please request a new one.",
    invalid: "Code is invalid. Please try again or request a new one.",
  },
};

const validateEmail: ValidateEmailFunction = async (email: string) => {
  if (!/.+@.+/u.test(email)) {
    throw new Error("A valid email is required.");
  }
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
};
