import type { Session, SessionStorage } from "@remix-run/server-runtime";
import { json, redirect } from "@remix-run/server-runtime";
import type { AuthenticateOptions, StrategyVerifyCallback } from "remix-auth";
import { AuthorizationError, Strategy } from "remix-auth";
import {
  buildFormData,
  createLinkPayload,
  decrypt,
  encrypt,
  getaccessLinkCode,
  getDomainURL,
  mergeOptions,
} from "./helpers";
import { generateOtp } from "./otp";
import type {
  AuthErrorTypeMessages,
  CodeOptions,
  LinkPayload,
  PasswordlessStrategyOptions,
  PasswordlessStrategyVerifyParams,
} from "./types";

class PasswordlessStrategy<User> extends Strategy<
  User,
  PasswordlessStrategyVerifyParams
> {
  public name = "passwordless";
  private _session?: Session;
  private readonly internalOptions: Required<
    PasswordlessStrategyOptions<User>
  > & {
    errorMessages: Required<AuthErrorTypeMessages>;
    codeOptions: Required<CodeOptions>;
  };

  constructor(
    options: PasswordlessStrategyOptions<User>,
    verify: StrategyVerifyCallback<User, PasswordlessStrategyVerifyParams>
  ) {
    super(verify);
    this.internalOptions = mergeOptions(options);
  }

  public async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
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

  public async getaccessLink(
    email: string,
    domainUrl: string,
    form: FormData
  ): Promise<string> {
    const payload = createLinkPayload(email, form);
    const url = new URL(domainUrl);
    url.pathname = this.internalOptions.callbackPath;
    url.searchParams.set(
      this.internalOptions.linkTokenParam,
      encrypt(JSON.stringify(payload), this.internalOptions.secret)
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
    session.unset(this.internalOptions.sessionLinkKey);
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
    console.log({ session });
    const accessLink = session.get(this.internalOptions.sessionLinkKey) ?? "";
    console.log({ accessLink });

    const { email, form } = await this.validateaccessLink(
      request.url,
      accessLink
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
    const email = formData.get(this.internalOptions.emailField)?.toString();

    if (!email || typeof email !== "string") {
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

      const sessionaccessLink =
        session.get(this.internalOptions.sessionLinkKey) ?? "";

      const { email, form: formRecord } = this.parseLinkPayload(
        getaccessLinkCode(
          sessionaccessLink,
          this.internalOptions.linkTokenParam
        ),
        "code"
      );
      const form = buildFormData(formRecord);
      const user = await this.verify({ email, form });
      return this.success(user, request, sessionStorage, options);
    }

    await this.internalOptions.validateEmail(email);
    // await Promise.all([
    //   this.internalOptions.verifierApiKey
    //     ? emailVerifier(email, this.internalOptions.verifierApiKey)
    //     : Promise.resolve(),
    // ]);

    let code: string | undefined;
    if (this.internalOptions.useOneTimeCode) {
      code = await generateOtp({
        size: this.internalOptions.codeOptions.size,
        segmentLength: this.internalOptions.codeOptions.segmentLength,
        lettersOnly: this.internalOptions.codeOptions.lettersOnly,
      });
      session.set(this.internalOptions.sessionCodeKey, code);
    }
    const accessLink = await this.getaccessLink(email, domainUrl, formData);

    const user = await this.verify({
      email: email,
      form: formData,
    });

    await this.internalOptions.sendEmail({
      email,
      accessLink,
      user,
      code,
      domainUrl,
      form: formData,
    });

    session.set(this.internalOptions.sessionEmailKey, email);
    session.set(this.internalOptions.sessionLinkKey, accessLink);

    return this.onSuccess(session, sessionStorage, options);
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
    let LinkPayload: LinkPayload;
    try {
      const decryptedString = decrypt(linkCode, this.internalOptions.secret);
      LinkPayload = JSON.parse(decryptedString) as LinkPayload;
    } catch (error) {
      throw new Error(this.internalOptions.errorMessages.default);
    }
    const { email, creationDate } = LinkPayload;
    if (typeof email !== "string" || typeof creationDate !== "string") {
      throw new Error(this.internalOptions.errorMessages[type].invalid);
    }
    const linkCreationDate = new Date(creationDate);
    const expirationTime =
      linkCreationDate.getTime() + this.internalOptions.expirationTime;

    if (Date.now() > expirationTime) {
      throw new Error(this.internalOptions.errorMessages[type].expired);
    }
    return LinkPayload;
  }

  private async validateaccessLink(
    requestUrl: string,
    sessionaccessLink?: string
  ) {
    const linkCode = getaccessLinkCode(
      requestUrl,
      this.internalOptions.linkTokenParam
    );
    const sessionLinkCode = sessionaccessLink
      ? getaccessLinkCode(
          sessionaccessLink,
          this.internalOptions.linkTokenParam
        )
      : null;

    if (linkCode !== sessionLinkCode) {
      console.log({ linkCode, sessionLinkCode });
      throw new Error(this.internalOptions.errorMessages.link.mismatch);
    }
    const { email, form } = this.parseLinkPayload(linkCode, "link");

    const formData = buildFormData(form);
    return { email, form: formData };
  }
}

export * from "./types";
export { PasswordlessStrategy };
