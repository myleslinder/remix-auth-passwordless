# Remix Auth Passwordless Strategy

> This is sort of a fork of [`remix-auth-email-link`](https://github.com/pbteja1998/remix-auth-email-link) but with changes to suit my preferences and to support one time codes. That repo was based on the [kcd auth flow](https://kentcdodds.com/blog/how-i-built-a-modern-website-in-2021#authentication-with-magic-links).

> > **Warning**
> > You probably want to use [`remix-auth-email-link`](https://github.com/pbteja1998/remix-auth-email-link)

Passwordless strategy for [remix-auth](https://github.com/sergiodxa/remix-auth/). You can use this strategy for email based passwordless authentication with a magic link and optionally a one time access code. It doesn't currently support SMS or sending only one time codes.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |
| Deno       | ✅          |

## Setup

```ts
const authenticator = new Authenticator<YourUserType>(sessionStorage);

authenticator.use(
	new PasswordlessStrategy(
		{
			// The bare minimum configuration
			sendEmail: sendPasswordlessEmail,
			secret: passwordlessLinkSecret,
			// Whether to use one time code in addition to access link
			useOneTimeCode: true,
		},
		async ({ email }) => {
			return getUserSessionByEmail(email);
		}
	)
);
```

### Verify Callback

Your verify function should always try to find and return your full user - or a discriminated shim user if you want to use this flow for sign up as well. When you kick off the access flow by making a post request to `authenticate` without a `codeField` in the form data on the request your `verify` function will be called but the returned value will not be set in the session. It will however be passed to the provided send email function so you have access to whatever info you need to determine if this is a new or returning user, etc.

### Email Validation

If you have an allowlist or only support work emails or something like that this is the function to do that work in. Whatever error you throw from within this function will be flashed to the session error key.

If you provide nothing, the default function used is:

```ts
async (email: string) => {
	if (!/.+@.+/u.test(email)) {
		throw new Error("A valid email is required.");
	}
};
```

<!-- ### Email Verification

If you want to use the [free email verifier service](https://verifier.meetchopra.com/) provide your api key in the `verifierApiKey` option. If you provide an api key the check to the verifier service will be run in parrallel with the validate email function. -->

### Sending Emails

You can send emails however you like, you just need to provide a function with the proper signature:

```ts
type SendEmailOptions<User> = {
  emailAddress: string
  accessLink: string
  user: User
  domainUrl: string
  form: FormData,
  code? string
}

type SendEmailFunction<User> = (options: SendEmailOptions<User>): Promise<void>

```

### Expiry & Same Browser Check

The default expiry is set to 5 minutes and there is no options to disable the same browser check to ensure that the user is using the access link in the same browser they initiated the flow with.

### One Time Code Generation

This strategy uses [`nanoid`](https://github.com/ai/nanoid/) to generate the one time codes.

The generated code is split into segments separated by a `-`, like so: `abc1-2def-x3yz`. In the options you can customize the code length, segment length, and if you want to use only lowercase letters. The shortest one time code that is supported is 4 characters.

By default if the user enters an invalid code then they will have to resend another code, however you can modify this by changing the `invalidCodeAttempts` option.

## A note on `authenticate` without a `successRedirect`

You cannot kick off the access flow without providing the`successRedirect` option. If you omit the value the strategy will throw an error. Additionally, if you provide a `successRedirect` that is a "protected" page in that it requres a user to be authenticated it wont work because there will be no user set in the session.

In every other case (e.g. in the link callback or when providing an entered one time code) you can omit the value and it will behave as documented in the [advanced usage section of the remix auth docs](https://github.com/sergiodxa/remix-auth#advanced-usage). However, if you do not pass the `successRedirect` option to the `authenticate` method it will return the user data and you are responsible for setting the user data in the session, committing the session, and (likely) including the headers in the redirect. With this strategy if you do not provide the `successRedirect` the `sessionLinkKey`, `sessionEmailKey`, and `sessionCodeKey` will not be unset and you likely want to unset them.

Alternatively, **if you don't use cookie session storage** you can use the `commitOnReturn` option to have the changes to the session (setting the user and unsetting the link, email, and code keys) be committed before returning the user data. In this case as the cookie only contains an id if you don't need any other changes to the session you don't need to manually get the session, commit, create headers, or provide them to the redirect.

## Options

All the default options are visible in `/src/defaults.ts`.

```ts
type PasswordlessStrategyOptions<User> = {
	/**
	 * A secret string used to encrypt and decrypt the token and magic link.
	 */
	secret: string;
	/**
	 * The function called to send the email
	 */
	sendEmail: (options: SendEmailOptions<User>) => Promise<void>;
	/**
	 * The endpoint path the user will go after clicking on the email link.
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
	verifyEmail?: (email: string) => Promise<void>;
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
	/**
	 * Configuration for the generated one time code
	 * @default size=12,segmentLength=4,lettersOnly=false
	 */
	codeOptions?: {
		size?: number;
		segmentLength?: number;
		lettersOnly?: boolean;
	};
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
```

### Error Messages

The following error types exist for both code and link access types, except where noted:

- expired
  - Thrown when the magic link has expired.
  - Default - "Access link expired. Please request a new one."
- invalid
  - Thrown when there is an error decrypting the the magic link code, the email address in the payload is not a string, or the link creation date cannot be determined.
  - Default - "Access link invalid. Please request a new one."
- mismatch (link only)
  - This error is thrown if the magic link is valid but it does not match with the existing link in the session (or the existing session has no magic link).
  - Default - "You must open the magic link on the same device it was created from for security reasons. Please request a new link."
- default
  - The default error message when something unknown goes wrong. This is most likely to be used if the token included in the access link is malformed causing a JSON parse error.

You can override any of these messages by setting the relevant key in the `errorMessages` option.

## License

MIT
