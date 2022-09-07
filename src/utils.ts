import { enc } from "crypto-js";
import AES from "crypto-js/aes";

import type {
	AuthTypeErrors,
	MagicLinkPayload,
	VerifyEmailFunction,
} from "./types";

const verifyEmailAddress: VerifyEmailFunction = async (email: string) => {
	if (!/.+@.+/u.test(email)) {
		throw new Error("A valid email is required.");
	}
};

function buildFormData(form: Record<string, unknown>): FormData {
	const formData = new FormData();
	Object.keys(form).forEach((key) => {
		if (Array.isArray(form[key])) {
			(form[key] as unknown[]).forEach((value) => {
				formData.append(key, value as string | Blob);
			});
		} else {
			formData.append(key, form[key] as string | Blob);
		}
	});
	return formData;
}

function getMagicLinkCode(link: string, param: string): string {
	try {
		const url = new URL(link);
		return url.searchParams.get(param) ?? "";
	} catch {
		return "";
	}
}

function encrypt(value: string, secret: string): string {
	return AES.encrypt(value, secret).toString();
}

function decrypt(value: string, secret: string): string {
	const bytes = AES.decrypt(value, secret);
	return bytes.toString(enc.Utf8);
}

function createMagicLinkPayload(
	emailAddress: string,
	form: FormData,
): MagicLinkPayload {
	return {
		emailAddress,
		form: Object.fromEntries(
			[...form.keys()].map((key) => [
				key,
				form.getAll(key).length > 1
					? form.getAll(key).toString()
					: form.get(key)?.toString(),
			]),
		),
		creationDate: new Date().toISOString(),
	};
}

function mergeErrorMessages(
	errorMessages?: Partial<AuthTypeErrors>,
): Required<AuthTypeErrors> {
	const DEFAULT_ERROR_MESSAGES: Required<AuthTypeErrors> = {
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

	return {
		default: errorMessages?.default ?? DEFAULT_ERROR_MESSAGES.default,
		code: {
			expired:
				errorMessages?.code?.expired ?? DEFAULT_ERROR_MESSAGES.code.expired,
			invalid:
				errorMessages?.code?.invalid ?? DEFAULT_ERROR_MESSAGES.code.invalid,
		},
		link: {
			expired:
				errorMessages?.link?.expired ?? DEFAULT_ERROR_MESSAGES.link.expired,
			invalid:
				errorMessages?.link?.invalid ?? DEFAULT_ERROR_MESSAGES.link.invalid,
			mismatch:
				errorMessages?.link?.mismatch ?? DEFAULT_ERROR_MESSAGES.link.mismatch,
		},
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
	getMagicLinkCode,
	encrypt,
	decrypt,
	createMagicLinkPayload,
	verifyEmailAddress,
};
