import type { Session, SessionStorage } from "@remix-run/server-runtime";
import { json, redirect } from "@remix-run/server-runtime";
import {
  AuthorizationError,
  Strategy,
  type AuthenticateOptions,
  type Authenticator,
  type StrategyVerifyCallback,
} from "remix-auth";

import { generateOtp } from "./otp";
import type {
  AuthTypeErrors,
  EmailLinkStrategyOptions,
  EmailLinkStrategyVerifyParams,
  MagicLinkPayload,
} from "./types";
import {
  buildFormData,
  createMagicLinkPayload,
  decrypt,
  encrypt,
  getDomainURL,
  getMagicLinkCode,
  mergeErrorMessages,
  verifyEmailAddress,
} from "./utils";

const FIVE_MINUTES_MS = 1000 * 60 * 5;

class EmailLinkStrategy<User> extends Strategy<
  User,
  EmailLinkStrategyVerifyParams
> {
  public name = "email-link";

  private readonly internalOptions: Required<EmailLinkStrategyOptions<User>> & {
    errorMessages: Required<AuthTypeErrors>;
  };

  private _session?: Session;

  constructor(
    options: EmailLinkStrategyOptions<User>,
    verify: StrategyVerifyCallback<User, EmailLinkStrategyVerifyParams>
  ) {
    super(verify);
    const shouldUseCode = options.useOneTimeCode;
    const internalCodeOptions = shouldUseCode
      ? {
          sessionCodeKey: options.sessionCodeKey ?? "auth:code",
          codeField: options.codeField ?? "code",
          useOneTimeCode: true as const,
          codeOptions: options.codeOptions ?? {},
          sendEmail: shouldUseCode ? options.sendEmail : options.sendEmail,
        }
      : {
          sessionCodeKey: "auth:code",
          codeField: "code",
          useOneTimeCode: false as const,
          codeOptions: {},
          sendEmail: shouldUseCode ? options.sendEmail : options.sendEmail,
        };
    this.internalOptions = {
      callbackURL: options.callbackURL ?? "/magic",
      secret: options.secret,
      sessionMagicLinkKey: options.sessionMagicLinkKey ?? "auth:magiclink",
      sessionEmailKey: options.sessionEmailKey ?? "auth:email",
      commitOnReturn: options.commitOnReturn ?? false,
      verifyEmailAddress: options.verifyEmailAddress ?? verifyEmailAddress,
      emailField: options.emailField ?? "email",
      magicLinkSearchParam: options.magicLinkSearchParam ?? "token",
      linkExpirationTime: options.linkExpirationTime ?? FIVE_MINUTES_MS,
      errorMessages: mergeErrorMessages(options.errorMessages),
      ...internalCodeOptions,
    };
  }

  public async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions & {
      sessionErrorKey: Authenticator["sessionErrorKey"];
    }
  ): Promise<User> {
    try {
      if (request.method === "GET") {
        const user = await this.handleGet(request, sessionStorage, options);
        return user;
      }
      const user = await this.handlePost(request, sessionStorage, options);
      return user;
    } catch (errorOrRedirect) {
      if (errorOrRedirect instanceof Response) {
        throw errorOrRedirect;
      }

      const message =
        errorOrRedirect instanceof Error
          ? errorOrRedirect.message
          : "An unknown error occured";

      throw await this.failure(message, request, sessionStorage, options);
    }
  }

  public async getMagicLink(
    emailAddress: string,
    domainUrl: string,
    form: FormData
  ): Promise<string> {
    const payload = createMagicLinkPayload(emailAddress, form);
    const stringToEncrypt = JSON.stringify(payload);
    const encryptedString = encrypt(
      stringToEncrypt,
      this.internalOptions.secret
    );
    const url = new URL(domainUrl);
    url.pathname = this.internalOptions.callbackURL;
    url.searchParams.set(
      this.internalOptions.magicLinkSearchParam,
      encryptedString
    );
    return url.toString();
  }

  protected async success(
    user: User,
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    let session = this._session;
    if (!session) {
      session = await sessionStorage.getSession(request.headers.get("Cookie"));
    }

    this.cleanSession(session);
    return this.onSuccess(session, sessionStorage, options, user);
  }

  protected async failure(
    message: string,
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<never> {
    if (!options.failureRedirect) {
      if (options.throwOnError) {
        throw new AuthorizationError(message);
      }
      throw json<{ message: string }>({ message }, 401);
    }

    let session = this._session;
    if (!session) {
      session = await sessionStorage.getSession(request.headers.get("Cookie"));
    }
    this.cleanSession(session);
    session.unset(options.sessionKey);
    session.flash(options.sessionErrorKey, { message });
    throw redirect(options.failureRedirect, {
      headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
    });
  }

  private async onSuccess(
    session: Session,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions,
    user?: User
  ): Promise<User> {
    if (user) {
      session.set(options.sessionKey, user);
      session.set(options.sessionStrategyKey ?? "strategy", this.name);
      if (!options.successRedirect) {
        if (this.internalOptions.commitOnReturn) {
          await sessionStorage.commitSession(session);
        }
        return user;
      }
    } else {
      if (!options.successRedirect) {
        throw new Error(
          "A success callback is required if not checking the code and making a POST request"
        );
      }
    }

    throw redirect(options.successRedirect, {
      headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
    });
  }

  private cleanSession(session: Session) {
    session.unset(this.internalOptions.sessionMagicLinkKey);
    session.unset(this.internalOptions.sessionEmailKey);

    if (this.internalOptions.useOneTimeCode) {
      session.unset(this.internalOptions.sessionCodeKey);
    }
  }

  private async handleGet(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ) {
    const session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );
    this._session = session;

    const magicLink =
      session.get(this.internalOptions.sessionMagicLinkKey) ?? "";
    const decrypted = decrypt(magicLink, this.internalOptions.secret);
    const { emailAddress: email, form } = await this.validateMagicLink(
      request.url,
      decrypted
    );
    const user = await this.verify({ email, form });
    return this.success(user, request, sessionStorage, options);
  }

  private async handlePost(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ) {
    const session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );
    this._session = session;
    const formData = await request.formData();
    const submittedCode = this.internalOptions.useOneTimeCode
      ? formData.get(this.internalOptions.codeField)?.toString()
      : undefined;
    const emailAddress = formData
      .get(this.internalOptions.emailField)
      ?.toString();

    if (!emailAddress || typeof emailAddress !== "string") {
      throw await this.failure(
        "Missing email address.",
        request,
        sessionStorage,
        options
      );
    }

    const domainUrl = getDomainURL(request);
    const isCodeCheck = this.internalOptions.useOneTimeCode && submittedCode;
    if (isCodeCheck) {
      this.validateCode(session, submittedCode);

      const sessionMagicLink =
        session.get(this.internalOptions.sessionMagicLinkKey) ?? "";

      const { emailAddress: email, form: formRecord } = this.parseLinkPayload(
        getMagicLinkCode(
          sessionMagicLink,
          this.internalOptions.magicLinkSearchParam
        ),
        "code"
      );
      const form = buildFormData(formRecord);
      const user = await this.verify({ email, form });
      return this.success(user, request, sessionStorage, options);
    }

    await this.internalOptions.verifyEmailAddress(emailAddress);

    let code: string | undefined;
    if (this.internalOptions.useOneTimeCode) {
      code = await generateOtp({
        size: this.internalOptions.codeOptions.size,
        segmentLength: this.internalOptions.codeOptions.segmentLength,
        lettersOnly: this.internalOptions.codeOptions.lettersOnly,
      });
      session.set(this.internalOptions.sessionCodeKey, code);
    }
    const magicLink = await this.getMagicLink(
      emailAddress,
      domainUrl,
      formData
    );

    const user = await this.verify({
      email: emailAddress,
      form: formData,
    });

    await this.internalOptions.sendEmail({
      emailAddress,
      magicLink,
      user,
      code,
      domainUrl,
      form: formData,
    });

    session.set(this.internalOptions.sessionEmailKey, emailAddress);
    session.set(this.internalOptions.sessionMagicLinkKey, magicLink);

    return this.onSuccess(session, sessionStorage, options, user);
  }

  private validateCode(session: Session, code: string) {
    if (this.internalOptions.useOneTimeCode) {
      const sessionCode = session.get(this.internalOptions.sessionCodeKey);

      if (code !== sessionCode) {
        throw new Error(this.internalOptions.errorMessages.code.invalid);
      }
    } else {
      throw new Error(
        "Attempting to validate code when not configured to do so."
      );
    }
  }

  private parseLinkPayload(linkCode: string, type: "code" | "link") {
    let magicLinkPayload: MagicLinkPayload;
    try {
      const decryptedString = decrypt(linkCode, this.internalOptions.secret);
      magicLinkPayload = JSON.parse(decryptedString) as MagicLinkPayload;
    } catch (error) {
      throw new Error(this.internalOptions.errorMessages.default);
    }
    const { emailAddress, creationDate: linkCreationDateString } =
      magicLinkPayload;
    if (
      typeof emailAddress !== "string" ||
      typeof linkCreationDateString !== "string"
    ) {
      throw new Error(this.internalOptions.errorMessages[type].invalid);
    }
    const linkCreationDate = new Date(linkCreationDateString);
    const expirationTime =
      linkCreationDate.getTime() + this.internalOptions.linkExpirationTime;

    if (Date.now() > expirationTime) {
      throw new Error(this.internalOptions.errorMessages[type].expired);
    }
    return magicLinkPayload;
  }

  private async validateMagicLink(
    requestUrl: string,
    sessionMagicLink?: string
  ) {
    const linkCode = getMagicLinkCode(
      requestUrl,
      this.internalOptions.magicLinkSearchParam
    );
    const sessionLinkCode = sessionMagicLink
      ? getMagicLinkCode(
          sessionMagicLink,
          this.internalOptions.magicLinkSearchParam
        )
      : null;

    const { emailAddress, form } = this.parseLinkPayload(linkCode, "link");

    if (linkCode !== sessionLinkCode) {
      throw new Error(this.internalOptions.errorMessages.link.mismatch);
    }

    const formData = buildFormData(form);
    return { emailAddress, form: formData };
  }
}

export * from "./types";
export { EmailLinkStrategy };
