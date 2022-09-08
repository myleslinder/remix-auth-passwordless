/// <reference types="vitest" />
import { resolve } from "path";
import { defineConfig } from "vite";

export default defineConfig({
	resolve: {
		alias: {
			"~": resolve(__dirname, "src"),
		},
	},
	plugins: [],
	build: {
		target: "es2020",
		minify: false,
		// lib: {
		// 	entry: resolve(__dirname, "src", "index.ts"),
		// 	formats: ["es"],
		// },
	},

	test: {
		setupFiles: "./test/setup-test-env.ts",
		// if you have few tests, try commenting one
		// or both out to improve performance:
		threads: false,
		isolate: false,
		include: ["./**/*.test.{ts,tsx}"],
		watchExclude: [".*\\/node_modules\\/.*", ".*\\/dist\\/.*"],
	},
});
