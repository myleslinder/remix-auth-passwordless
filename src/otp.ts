import { customAlphabet } from "nanoid/async";
import type { CodeOptions } from "./types";

const lowercase = "abcdefghijklmnopqrstuvwxyz";
const numbers = "0123456789";

const generateOtp = async ({
  size = 8,
  segmentLength = 4,
  lettersOnly = false,
}: CodeOptions) => {
  if (size <= 4) {
    throw new Error("The one time code length must be at least 4 characters");
  }
  const alphabet = lowercase + numbers;
  const nanoid = customAlphabet(alphabet, 8);
  const id = await nanoid(8);
  const code = id.split("").reduce((acc, char, i) => {
    const next = i !== 0 && i % 4 === 0 ? `-${char}` : char;
    return `${acc}${next}`;
  }, "");
  return code;
};

export { generateOtp };
