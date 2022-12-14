import AES from "crypto-js/aes";
import utf8 from "crypto-js/enc-utf8";
import { DEFAULTS } from "./defaults";
import type {
	AuthErrorTypeMessages,
	InternalOptions,
	PasswordlessStrategyOptions,
} from "./types";

function buildFormData(form: Record<string, string | Blob>): FormData {
	return Object.entries(form).reduce((formData, [key, value]) => {
		formData.append(key, value);
		return formData;
	}, new FormData());
}

function encrypt(value: string, secret: string): string {
	return AES.encrypt(value, secret).toString();
}

function decrypt(value: string, secret: string): string {
	const bytes = AES.decrypt(value, secret);
	return bytes.toString(utf8);
}

function mergeErrorMessages(
	errorMessages?: Partial<AuthErrorTypeMessages>,
): Required<AuthErrorTypeMessages> {
	return {
		default: errorMessages?.default ?? DEFAULTS.errorMessages.default,
		code: {
			expired:
				errorMessages?.code?.expired ?? DEFAULTS.errorMessages.code.expired,
			invalid:
				errorMessages?.code?.invalid ?? DEFAULTS.errorMessages.code.invalid,
		},
		link: {
			expired:
				errorMessages?.link?.expired ?? DEFAULTS.errorMessages.link.expired,
			invalid:
				errorMessages?.link?.invalid ?? DEFAULTS.errorMessages.link.invalid,
			mismatch:
				errorMessages?.link?.mismatch ?? DEFAULTS.errorMessages.link.mismatch,
		},
	};
}

function mergeOptions<User>(
	options: PasswordlessStrategyOptions<User>,
): InternalOptions<User> {
	const shouldUseCode = options.useOneTimeCode;

	return {
		callbackPath: options.callbackPath ?? DEFAULTS.callbackPath,
		secret: options.secret,
		sessionLinkKey: options.sessionLinkKey ?? DEFAULTS.sessionLinkKey,
		sessionEmailKey: options.sessionEmailKey ?? DEFAULTS.sessionEmailKey,
		commitOnReturn: options.commitOnReturn ?? false,
		validateEmail: options.validateEmail ?? DEFAULTS.validateEmailFn,
		emailField: options.emailField ?? DEFAULTS.emailField,
		linkTokenParam: options.linkTokenParam ?? DEFAULTS.tokenParam,
		expirationTime: options.expirationTime ?? DEFAULTS.expiry,
		errorMessages: mergeErrorMessages(options.errorMessages),
		sessionCodeKey: shouldUseCode
			? options.sessionCodeKey ?? DEFAULTS.sessionCodeKey
			: DEFAULTS.sessionCodeKey,
		codeField: shouldUseCode
			? options.codeField ?? DEFAULTS.codeField
			: DEFAULTS.codeField,
		useOneTimeCode: shouldUseCode ?? false,
		codeOptions: shouldUseCode
			? {
					size: options.codeOptions?.size ?? DEFAULTS.codeOptions.size,
					segmentLength:
						options.codeOptions?.segmentLength ??
						DEFAULTS.codeOptions.segmentLength,
					lettersOnly:
						options.codeOptions?.lettersOnly ??
						DEFAULTS.codeOptions.lettersOnly,
			  }
			: DEFAULTS.codeOptions,
		sendEmail: shouldUseCode ? options.sendEmail : options.sendEmail,
		invalidCodeAttempts: 1,
		codeCountKey: DEFAULTS.codeAttemptKey,
		// verifierApiKey: options.verifierApiKey ?? "",
	};
}

function getDomainURL(request: Request): string {
	const host =
		request.headers.get("X-Forwarded-Host") ?? request.headers.get("host");

	if (!host) {
		throw new Error("Could not determine domain URL.");
	}

	const protocol =
		host.includes("localhost") || host.includes("127.0.0.1") ? "http" : "https";
	return `${protocol}://${host}`;
}

export {
	getDomainURL,
	mergeErrorMessages,
	buildFormData,
	encrypt,
	decrypt,
	mergeOptions,
};
