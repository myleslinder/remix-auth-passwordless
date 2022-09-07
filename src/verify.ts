type VerifierResult =
  | { status: true; email: string; domain: string }
  | {
      status: false;
      error: { code: number; message: string };
    };

async function emailVerifier(emailAddress: string, verifierApiKey: string) {
  const verifierUrl = new URL(
    `https://verifier.meetchopra.com/verify/${emailAddress}`
  );
  verifierUrl.searchParams.append("token", verifierApiKey);
  const response = await fetch(verifierUrl.toString());
  const verifierResult: VerifierResult = await response.json();
  if (!verifierResult.status) {
    const errorMessage = `We tried to verify that email and got this error message: "${verifierResult.error.message}".`;
    throw new Error(errorMessage);
  }
  return verifierResult;
}

export { emailVerifier };
