/// <reference types="@remix-run/node/globals" />
import { createCookieSessionStorage, type Session } from "@remix-run/node";
import { assert, beforeEach, describe, expect, test, vi } from "vitest";
import { DEFAULTS } from "~/defaults";
import { PasswordlessStrategy } from "../src/index";

const sessionStorage = createCookieSessionStorage({
	cookie: { name: "session", secrets: ["s3cr3ts"], path: "/" },
});

async function buildRequest(
	session: Session,
	params?: URLSearchParams,
	method = "GET",
) {
	const url = new URL(`/?${params?.toString() ?? ""}`, "http://localhost:3000");
	return new Request(url, {
		method,
		headers: { Cookie: await sessionStorage.commitSession(session) },
	});
}

describe(PasswordlessStrategy.name, () => {
	beforeEach(() => {
		vi.resetAllMocks();
	});

	type User = {
		id: number;
		token: string;
		email: string;
		role: string;
	};

	const user: User = {
		id: 1,
		token: DEFAULTS.tokenParam,
		email: "test@example.com",
		role: "admin",
	};
	const verify = vi.fn();

	test("POST: should call the verify callback and not set user when producing access link", async () => {
		const session = await sessionStorage.getSession();
		verify.mockReturnValue(user);
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
			},
			verify,
		);

		const formData = new URLSearchParams({
			email: user.email,
		});
		const url = new URL(`/`, "http://localhost:3000");
		const request = new Request(url, {
			method: "POST",
			body: formData,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: "passwordless",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const sessionRes = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(sessionRes.get(DEFAULTS.sessionLinkKey)).toBeDefined();
			expect(sessionRes.get(DEFAULTS.sessionCodeKey)).not.toBeDefined();
			expect(sessionRes.get("user")).not.toBeDefined();
		}
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			}),
		);
	});
	test("POST: should set code when requested producing access link", async () => {
		const session = await sessionStorage.getSession();
		verify.mockReturnValue(user);
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
				useOneTimeCode: true,
			},
			verify,
		);

		const formData = new URLSearchParams({
			email: user.email,
		});
		const url = new URL(`/`, "http://localhost:3000");
		const request = new Request(url, {
			method: "POST",
			body: formData,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: "passwordless",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(session.get(DEFAULTS.sessionLinkKey)).toBeDefined();
			expect(session.get(DEFAULTS.sessionCodeKey)).toBeDefined();
			expect(session.get("user")).not.toBeDefined();
		}
		expect(sendEmail).toHaveBeenCalledOnce();
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			}),
		);
	});

	test("POST: should verify code when requested", async () => {
		const session = await sessionStorage.getSession();
		verify.mockReturnValue(user);
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
				useOneTimeCode: true,
			},
			verify,
		);

		const formData1 = new URLSearchParams({
			email: user.email,
		});
		const url1 = new URL(`/`, "http://localhost:3000");
		const request1 = new Request(url1, {
			method: "POST",
			body: formData1,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});

		let code = "";
		try {
			await strategy.authenticate(request1, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: "passwordless",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const resSession = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(resSession.get(DEFAULTS.sessionLinkKey)).toBeDefined();
			expect(resSession.get(DEFAULTS.sessionCodeKey)).toBeDefined();
			expect(resSession.get(DEFAULTS.sessionEmailKey)).toBe(user.email);
			const _code: unknown = resSession.get(DEFAULTS.sessionCodeKey);
			assert(typeof _code === "string");
			code = _code;
			expect(resSession.get("user")).not.toBeDefined();
		}
		expect(sendEmail).toHaveBeenCalledOnce();

		session.set(DEFAULTS.sessionCodeKey, code);
		session.set(DEFAULTS.sessionEmailKey, user.email);
		const formData = new URLSearchParams({
			// email: user.email,
			code,
		});
		const fd = new FormData();
		fd.set("email", user.email);
		const accessLink = strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			fd,
		);

		session.set(DEFAULTS.sessionLinkKey, accessLink);
		const url = new URL(`/`, "http://localhost:3000");
		const request = new Request(url, {
			method: "POST",
			body: formData,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/inside",
				name: strategy.name,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/inside");
			expect(session.get(DEFAULTS.sessionLinkKey)).not.toBeDefined();
			expect(session.get(DEFAULTS.sessionCodeKey)).not.toBeDefined();
			expect(session.get("user")).toBeDefined();
		}
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			}),
		);
	});
	test("POST: should use invalid code attemps", async () => {
		const session = await sessionStorage.getSession();
		verify.mockReturnValue(user);
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
				useOneTimeCode: true,
				invalidCodeAttempts: 2,
			},
			verify,
		);

		const formData1 = new URLSearchParams({
			email: user.email,
		});
		const url1 = new URL(`/`, "http://localhost:3000");
		const request1 = new Request(url1, {
			method: "POST",
			body: formData1,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});

		let code = "";
		try {
			await strategy.authenticate(request1, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: strategy.name,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const resSession = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(resSession.get(DEFAULTS.sessionLinkKey)).toBeDefined();
			expect(resSession.get(DEFAULTS.sessionCodeKey)).toBeDefined();
			expect(resSession.get(DEFAULTS.sessionEmailKey)).toBe(user.email);
			const _code: unknown = resSession.get(DEFAULTS.sessionCodeKey);
			assert(typeof _code === "string");
			code = _code;
			expect(resSession.get("user")).not.toBeDefined();
		}
		expect(sendEmail).toHaveBeenCalledOnce();

		session.set(DEFAULTS.sessionCodeKey, code);
		session.set(DEFAULTS.sessionEmailKey, user.email);
		const formData = new URLSearchParams({
			// email: user.email,
			code: "wrongcode",
		});
		const fd = new FormData();
		fd.set("email", user.email);
		const accessLink = strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			fd,
		);

		session.set(DEFAULTS.sessionLinkKey, accessLink);
		const url = new URL(`/`, "http://localhost:3000");
		const request = new Request(url, {
			method: "POST",
			body: formData,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/inside",
				failureRedirect: "/outside",
				name: strategy.name,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const sessionRes = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/outside");
			expect(sessionRes.get(DEFAULTS.sessionLinkKey)).toBeDefined();
			expect(sessionRes.get(DEFAULTS.sessionCodeKey)).toBeDefined();
			expect(sessionRes.get("auth:code_count")).toBe(2);
			expect(sessionRes.get("user")).not.toBeDefined();
		}
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			}),
		);
		const formData2 = new URLSearchParams({
			// email: user.email,
			code: "anotherwonrg",
		});
		const fd2 = new FormData();
		fd2.set("email", user.email);
		const accessLink2 = strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			fd2,
		);

		session.set(DEFAULTS.sessionLinkKey, accessLink2);
		session.set("auth:code_count", 2);
		const url2 = new URL(`/`, "http://localhost:3000");
		const request2 = new Request(url2, {
			method: "POST",
			body: formData2,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});

		try {
			await strategy.authenticate(request2, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/inside",
				failureRedirect: "/outside",
				name: strategy.name,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/outside");
			expect(session.get(DEFAULTS.sessionLinkKey)).not.toBeDefined();
			expect(session.get(DEFAULTS.sessionCodeKey)).not.toBeDefined();
			expect(session.get("user")).not.toBeDefined();
		}
	});

	test("GET: should call the verify callback and set user when successfully verify access link", async () => {
		const session = await sessionStorage.getSession();
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
				callbackPath: "/custom",
			},
			verify,
		);

		const formData = new FormData();
		formData.set("email", "somescsc@gmail.com");

		const accessLink = strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			formData,
		);
		expect(new URL(accessLink).pathname).toBe("/custom");

		session.set(DEFAULTS.sessionLinkKey, accessLink);
		const request = await buildRequest(
			session,
			new URLSearchParams({
				token: new URL(accessLink).searchParams.get(DEFAULTS.tokenParam) ?? "",
			}),
		);

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: strategy.name,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			const session = await sessionStorage.getSession(
				redirect.headers.get("Set-Cookie"),
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(headers.get("Set-Cookie")).not.toBeNull();
			expect(session.get("user")).not.toBeDefined();
		}
		expect(sendEmail).not.toHaveBeenCalled();
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: formData,
			}),
		);
	});
	test("GET: should error if no access link token on request url", async () => {
		const session = await sessionStorage.getSession();
		const defaultErr = "error message";
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail: vi.fn(),
				errorMessages: {
					default: defaultErr,
				},
			},
			verify,
		);

		const request = await buildRequest(session);

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				failureRedirect: "/entry",
				name: strategy.name,
			});
		} catch (response) {
			assert(response instanceof Response);
			const headers = response.headers;
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);
			const error = session.get("errorKey") as { message: string };
			assert(typeof error === "object" && error !== null && "message" in error);
			assert("message" in error);
			expect(error.message).to.equal(defaultErr);
		}
		try {
			const newR = await buildRequest(session);
			await strategy.authenticate(newR, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: strategy.name,
			});
		} catch (response) {
			assert(response instanceof Response);
			const json: { message: string } = (await response.json()) as {
				message: string;
			};
			expect(json.message).to.equal(defaultErr);
		}
	});

	test("should prefer context.formData over request.formData()", async () => {
		const body = new FormData();
		body.set("email", "test@example.com");

		const context = { formData: body };
		const session = await sessionStorage.getSession();
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
			},
			verify,
		);

		const url = new URL("/", "http://localhost:3000");
		const formData = new URLSearchParams();
		formData.set("_email", "somescsc@gmail.com");
		const request = new Request(url, {
			method: "POST",
			body: formData,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});
		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: strategy.name,
				context,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			expect(verify).toHaveBeenCalledWith(
				expect.objectContaining({
					email: body.get("email"),
					form: body,
				}),
			);
		}
	});

	test("ignore context.formData if it's not an FormData object", async () => {
		const context = { formData: { email: "fake@example.com" } };
		const session = await sessionStorage.getSession();
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
			},
			verify,
		);

		const url = new URL("/", "http://localhost:3000");
		const formData = new URLSearchParams();
		formData.set("email", "somescsc@gmail.com");
		const request = new Request(url, {
			method: "POST",
			body: formData,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});
		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				name: strategy.name,
				context,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			expect(verify).toHaveBeenCalledWith(
				expect.objectContaining({
					email: "somescsc@gmail.com",
					form: new FormData(),
				}),
			);
		}
	});

	test("it should return the user as result", async () => {
		verify.mockReturnValue(user);
		const session = await sessionStorage.getSession();
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
			},
			verify,
		);
		const formData = new FormData();
		formData.set("email", "somescsc@gmail.com");

		const accessLink = strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			formData,
		);

		session.set(DEFAULTS.sessionLinkKey, accessLink);
		const request = await buildRequest(
			session,
			new URLSearchParams({
				token: new URL(accessLink).searchParams.get(DEFAULTS.tokenParam) ?? "",
			}),
		);

		const verifiedUser = await strategy.authenticate(request, sessionStorage, {
			sessionKey: "user",
			sessionErrorKey: "errorKey",
			sessionStrategyKey: "strategy",
			name: strategy.name,
		});

		expect(sendEmail).not.toHaveBeenCalled();
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: formData,
			}),
		);

		expect(verifiedUser).equals(user);
	});
	test("it should use the provided options over defaults", async () => {
		verify.mockReturnValue(user);
		const session = await sessionStorage.getSession();
		const sendEmail = vi.fn();
		const validateEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				callbackPath: "/custom",
				codeField: "_code",
				codeOptions: {
					lettersOnly: true,
					segmentLength: 4,
					size: 8,
				},
				emailField: "_email",
				expirationTime: 50,
				linkTokenParam: "this_token",
				sessionCodeKey: "sessCode",
				sessionEmailKey: "sessEmail",
				sessionLinkKey: "sessLink",
				validateEmail: validateEmail,
				sendEmail,
				useOneTimeCode: true,
			},
			verify,
		);
		const formData = new URLSearchParams();
		formData.set("_email", "somescsc@gmail.com");

		const url = new URL(`/`, "http://localhost:3000");
		const request1 = new Request(url, {
			method: "POST",
			body: formData,
			headers: {
				Cookie: await sessionStorage.commitSession(session),
				"Content-Type": "application/x-www-form-urlencoded",
				"X-Forwarded-Host": "http://localhost:3000",
			},
		});
		try {
			await strategy.authenticate(request1, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				sessionStrategyKey: "strategy",
				successRedirect: "/entry",
				failureRedirect: "/other",
				name: strategy.name,
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;

			const sessionRes = await sessionStorage.getSession(
				headers.get("Set-Cookie"),
			);

			expect(headers.get("Location")).toBe("/entry");
			expect(headers.get("Set-Cookie")).not.toBeNull();

			expect(sendEmail).toHaveBeenCalled();
			expect(validateEmail).toHaveBeenCalledWith("somescsc@gmail.com");
			expect(verify).toHaveBeenCalledWith(
				expect.objectContaining({
					email: "somescsc@gmail.com",
					form: new FormData(),
				}),
			);

			expect(sessionRes.get("sessLink")).toBeDefined();
			expect(sessionRes.get("sessCode")).toBeDefined();
			expect(sessionRes.get("sessCode").length).toBe(8 + 1);
			expect((sessionRes.get("sessCode") as string).indexOf("-")).toBe(4);
			expect((sessionRes.get("sessCode") as string).lastIndexOf("-")).toBe(4);
			expect(sessionRes.get("user")).not.toBeDefined();
		}

		const nformData = new FormData();
		nformData.set("_email", "somescsc@gmail.com");

		const accessLink = strategy.buildAccessLink(
			"somescsc@gmail.com",
			"http://localhost:3000",
			nformData,
		);

		session.set("sessLink", accessLink);
		const request = await buildRequest(
			session,
			new URLSearchParams({
				this_token: new URL(accessLink).searchParams.get("this_token") ?? "",
			}),
		);

		const verifiedUser = await strategy.authenticate(request, sessionStorage, {
			sessionKey: "user",
			sessionErrorKey: "errorKey",
			sessionStrategyKey: "strategy",
			name: "passwordless",
		});

		expect(sendEmail).toHaveBeenCalledOnce();
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: "somescsc@gmail.com",
				form: nformData,
			}),
		);

		expect(verifiedUser).equals(user);
	});
});

/**
 *  attempty count
 */
