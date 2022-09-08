/// <reference types="@remix-run/node/globals" />
import { createCookieSessionStorage, type Session } from "@remix-run/node";
import { Authenticator } from "remix-auth";
import { assert, beforeEach, describe, expect, test, vi } from "vitest";
import { PasswordlessStrategy } from "../src/index";

const sessionStorage = createCookieSessionStorage({
	cookie: { name: "session", secrets: ["s3cr3ts"], path: "/" },
});

async function buildRequest(
	session: Session,
	params?: URLSearchParams,
	method = "GET"
) {
	const url = new URL(`/?${params?.toString()}`, "http://localhost:3000");
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
		token: "token",
		email: "test@example.com",
		role: "admin",
	};
	const verify = vi.fn();

	const authenticator = new Authenticator<User>(sessionStorage);

	test("POST: should call the verify callback and not set user when producing access link", async () => {
		const session = await sessionStorage.getSession();
		verify.mockReturnValue(user);
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
			},
			verify
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
				successRedirect: "/entry",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie")
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(session.get("auth:accessLink")).toBeDefined();
			expect(session.get("auth:code")).not.toBeDefined();
			expect(session.get("user")).not.toBeDefined();
		}
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			})
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
			verify
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
				successRedirect: "/entry",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie")
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(session.get("auth:accessLink")).toBeDefined();
			expect(session.get("auth:code")).toBeDefined();
			expect(session.get("user")).not.toBeDefined();
		}
		expect(sendEmail).toHaveBeenCalledOnce();
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			})
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
			verify
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
				successRedirect: "/entry",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie")
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(session.get("auth:accessLink")).toBeDefined();
			expect(session.get("auth:code")).toBeDefined();
			code = session.get("auth:code");
			expect(session.get("user")).not.toBeDefined();
		}
		expect(sendEmail).toHaveBeenCalledOnce();

		session.set("auth:code", code);
		const formData = new URLSearchParams({
			email: user.email,
			code,
		});
		const accessLink = await strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			new FormData()
		);
		session.set("auth:accessLink", accessLink);
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
				successRedirect: "/inside",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers;
			expect(headers.get("Set-Cookie")).not.toBeNull();
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie")
			);
			expect(headers.get("Location")).toBe("/inside");
			expect(session.get("auth:accessLink")).not.toBeDefined();
			expect(session.get("auth:code")).not.toBeDefined();
			expect(session.get("user")).toBeDefined();
		}
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			})
		);
	});

	test("GET: should call the verify callback and set user when successfully verify access link", async () => {
		const session = await sessionStorage.getSession();
		const sendEmail = vi.fn();
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail,
			},
			verify
		);

		const accessLink = await strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			new FormData()
		);

		session.set("auth:accessLink", accessLink);
		const request = await buildRequest(
			session,
			new URLSearchParams({
				token: new URL(accessLink).searchParams.get("token") ?? "",
			})
		);

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				successRedirect: "/entry",
			});
		} catch (redirect) {
			assert(redirect instanceof Response);
			const headers = redirect.headers as Headers;
			const session = await sessionStorage.getSession(
				(redirect.headers as Headers).get("Set-Cookie")
			);
			expect(headers.get("Location")).toBe("/entry");
			expect(headers.get("Set-Cookie")).not.toBeNull();
			expect(session.get("user")).not.toBeDefined();
		}
		expect(sendEmail).not.toHaveBeenCalled();
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({
				email: user.email,
				form: new FormData(),
			})
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
			verify
		);

		const accessLink = await strategy.buildAccessLink(
			user.email,
			"http://localhost:3000",
			new FormData()
		);

		session.set("auth:accessLink", accessLink);
		const request = await buildRequest(session);

		try {
			await strategy.authenticate(request, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				successRedirect: "/entry",
				failureRedirect: "/entry",
			});
		} catch (response) {
			assert(response instanceof Response);
			const headers = response.headers;
			const session = await sessionStorage.getSession(
				headers.get("Set-Cookie")
			);
			console.log(session.data);
			expect(session.get("errorKey")?.message).to.equal(defaultErr);
		}
		try {
			const newR = await buildRequest(session);
			await strategy.authenticate(newR, sessionStorage, {
				sessionKey: "user",
				sessionErrorKey: "errorKey",
				successRedirect: "/entry",
			});
		} catch (response) {
			assert(response instanceof Response);
			const json = await response.json();
			expect(json.message).to.equal(defaultErr);
		}
	});

	test.skip("it should return the user as result", async () => {
		verify.mockReturnValue(user);
		const session = await sessionStorage.getSession();
		session.set(authenticator.sessionKey, user);

		const request = await buildRequest(session);
		const strategy = new PasswordlessStrategy(
			{
				secret: "somescsc",
				sendEmail: vi.fn(),
			},
			verify
		);

		const verifiedUser = await strategy.authenticate(request, sessionStorage, {
			sessionKey: "user",
			sessionErrorKey: "errorKey",
		});

		expect(verifiedUser).resolves.toEqual(user);
	});
});

/**
 * get request
 * post request
 *  with no success redirect
 *
 * send email was called (vi.fn())
 * verify was called (vi.fn())
 *
 * expiry
 * same browser check
 *
 * commit on return
 *
 * link only
 * code and link
 *  link verify
 *  code verify
 *  attempty count
 *  otp styles
 */