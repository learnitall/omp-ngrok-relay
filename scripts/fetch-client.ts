#!/usr/bin/env bun
/**
 * Builds the collab-web guest client and drops it in `dist/`, ready for
 * `scripts/embed-dist.ts` to compile into the binary.
 *
 * The client is not vendored: it is built from a pinned oh-my-pi commit
 * (`client.json`) so the served UI and the wire contract in `package.json`
 * move together and deliberately, not by accident. The relay works without it
 * — it just stops serving a browser client at `/`.
 *
 * `nix build .#client` does the same fetch and build through
 * `fetchFromGitHub`, off the same pin. Keep the two in step.
 */
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { $ } from "bun";

interface ClientPin {
	owner: string;
	repo: string;
	/** Full commit sha; a branch name would make builds unreproducible. */
	commit: string;
	/** Package directory inside the monorepo. */
	path: string;
	/** Cone-mode sparse paths: the client plus what bun.lock needs to resolve. */
	sparseCheckout: string[];
}

const ROOT = join(import.meta.dir, "..");
const CACHE = join(ROOT, ".cache", "oh-my-pi");
const OUT = join(ROOT, "dist");

const pin: ClientPin = await Bun.file(join(ROOT, "client.json")).json();
const url = `https://github.com/${pin.owner}/${pin.repo}`;

if (!existsSync(join(CACHE, ".git"))) {
	rmSync(CACHE, { recursive: true, force: true });
	// Blobless partial clone, then cone-mode sparse checkout: ~5 MB of working
	// tree out of a 235 MB monorepo. Blobs arrive on demand for the paths below.
	await $`git clone --filter=blob:none --no-checkout --sparse ${url} ${CACHE}`;
}

await $`git -C ${CACHE} sparse-checkout set --cone ${pin.sparseCheckout}`.quiet();
await $`git -C ${CACHE} fetch --filter=blob:none origin ${pin.commit}`.quiet();
await $`git -C ${CACHE} checkout --force ${pin.commit}`.quiet();

// Only the client's own dependency closure: 93 packages against the 394 a
// whole-workspace install pulls. `--frozen-lockfile` is not an option here —
// the absent workspace members read as lockfile drift.
const pkg = join(CACHE, pin.path);
await $`bun install --no-progress --filter ./${pin.path}`.cwd(CACHE);
await $`bun run build`.cwd(pkg);

rmSync(OUT, { recursive: true, force: true });
await $`cp -R ${join(pkg, "dist")} ${OUT}`;

const count = [...new Bun.Glob("**/*").scanSync(OUT)].length;
console.log(`client: ${count} files in dist/ from ${pin.commit.slice(0, 12)}`);
