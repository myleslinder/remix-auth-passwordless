import { customAlphabet } from "nanoid";
import type { CodeOptions } from "./types";

const lowercase = "abcdefghijklmnopqrstuvwxyz";
const numbers = "0123456789";

const generateOtp = async ({
	size,
	segmentLength,
	lettersOnly,
}: Required<CodeOptions>): Promise<string> => {
	if (size <= 4) {
		throw new Error("The one time code length must be at least 4 characters");
	}
	const alphabet = `${lowercase}${lettersOnly ? "" : numbers}`;
	const nanoid = customAlphabet(alphabet, size);
	const id = await nanoid(size);
	const code = id.split("").reduce((acc, char, i) => {
		const next = i !== 0 && i % segmentLength === 0 ? `-${char}` : char;
		return `${acc}${next}`;
	}, "");
	return code;
};

export { generateOtp };
