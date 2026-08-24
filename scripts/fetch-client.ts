#!/usr/bin/env bun
/**
 * Builds the collab-web guest client and drops it in `dist/`, ready for
 * `scripts/embed-dist.ts` to compile into the binary.
 *
 * The client is not vendored: it is built from a pinned oh-my-pi commit
 * (`client.json`) so the served UI and the wire contract in `package.json`
 * move together and deliberately, not by accident. The relay works without it
 * — it just stops serving a browser client at `/`.
 */
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { $ } from "bun";

interface ClientPin {
	repo: string;
	/** Full commit sha; a branch name would make builds unreproducible. */
	commit: string;
	/** Package directory inside the monorepo. */
	path: string;
}

const ROOT = join(import.meta.dir, "..");
const CACHE = join(ROOT, ".cache", "oh-my-pi");
const OUT = join(ROOT, "dist");

const pin: ClientPin = await Bun.file(join(ROOT, "client.json")).json();

if (!existsSync(join(CACHE, ".git"))) {
	rmSync(CACHE, { recursive: true, force: true });
	// Blobless clone: the monorepo is ~235 MB with history, ~40 MB without blobs.
	await $`git clone --filter=blob:none --no-checkout ${pin.repo} ${CACHE}`;
}

await $`git -C ${CACHE} fetch --filter=blob:none origin ${pin.commit}`.quiet();
await $`git -C ${CACHE} checkout --force ${pin.commit}`.quiet();

const pkg = join(CACHE, pin.path);
await $`bun install --frozen-lockfile`.cwd(CACHE);
await $`bun run build`.cwd(pkg);

rmSync(OUT, { recursive: true, force: true });
await $`cp -R ${join(pkg, "dist")} ${OUT}`;

const count = [...new Bun.Glob("**/*").scanSync(OUT)].length;
console.log(`client: ${count} files in dist/ from ${pin.commit.slice(0, 12)}`);
