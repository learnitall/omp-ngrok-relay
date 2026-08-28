#!/usr/bin/env bun
/**
 * Ad-hoc end-to-end check against a real ngrok endpoint. Needs an authtoken, so
 * it is deliberately not part of `bun test` and never runs in CI.
 *
 * It exists because the traffic policy is the endpoint's entire access control
 * and nothing local can exercise it: `bun test` covers the relay's own hosting
 * rule against `startRelay`, but every OAuth and deny rule in `policy.ts` is
 * evaluated by ngrok, on ngrok's side of the tunnel.
 *
 *   bun run e2e                                  # NGROK_AUTHTOKEN from the environment
 *   bun run e2e -- --authtoken-file path/to/token
 *
 * Every argument is forwarded to the relay, so `--ngrok-url` and a real
 * `--oauth-allow` work here too; `--port` and `--oauth-allow` get defaults only
 * when absent. The default allowlist admits nobody, which is what the
 * unauthenticated checks want.
 */
import { parseArgs } from "node:util";

const forwarded = Bun.argv.slice(2);
const { values } = parseArgs({
	args: forwarded,
	options: { "authtoken-file": { type: "string" } },
	allowPositionals: true,
	strict: false,
});

if (!process.env.NGROK_AUTHTOKEN && values["authtoken-file"] === undefined) {
	console.error("e2e needs a real endpoint: set NGROK_AUTHTOKEN or pass --authtoken-file <path>.");
	process.exit(1);
}

const BINARY = "./bin/omp-ngrok-relay";
if (!(await Bun.file(BINARY).exists())) {
	console.error(`${BINARY} not found — run \`bun run build\` first.`);
	process.exit(1);
}

/** A room the relay's path regex accepts; only the local check ever hosts it. */
const ROOM = "E2EPROBEroom";
/** Admits nobody, so every edge check below stays unauthenticated. */
const ALLOW = "e2e-nobody@example.com";
const PORT = "7469";

const has = (flag: string): boolean => forwarded.some((a) => a === flag || a.startsWith(`${flag}=`));
const args = [...forwarded];
if (!has("--port")) args.push("--port", PORT);
if (!has("--oauth-allow")) args.push("--oauth-allow", ALLOW);

const relay = Bun.spawn([BINARY, ...args], { stdout: "pipe", stderr: "inherit" });

/** Reads stdout until the endpoint line appears, echoing it so failures stay legible. */
async function endpoint(): Promise<string> {
	const reader = relay.stdout.getReader();
	const decoder = new TextDecoder();
	let buffered = "";
	while (true) {
		const { value, done } = await reader.read();
		if (done) throw new Error("relay exited before printing an ngrok endpoint");
		const chunk = decoder.decode(value);
		process.stdout.write(chunk);
		buffered += chunk;
		const url = buffered.match(/ngrok endpoint: (https:\/\/\S+)/)?.[1];
		if (url) return url;
	}
}

let failures = 0;

function check(name: string, ok: boolean, detail: string): void {
	console.log(`  ${ok ? "ok  " : "FAIL"}  ${name}${ok ? "" : ` — ${detail}`}`);
	if (!ok) failures++;
}

/** Reports how a handshake ended, without hanging if the edge stalls it. */
function upgrade(url: string): Promise<string> {
	const { promise, resolve } = Promise.withResolvers<string>();
	const socket = new WebSocket(url);
	socket.onopen = () => {
		socket.close();
		resolve("open");
	};
	socket.onerror = () => resolve("refused");
	socket.onclose = (e) => resolve(e.code === 1000 ? "open" : `closed ${e.code}`);
	setTimeout(() => {
		socket.close();
		resolve("timeout");
	}, 10_000);
	return promise;
}

try {
	const publicUrl = await endpoint();
	const wsUrl = publicUrl.replace(/^https/, "wss");
	console.log(`\nedge, unauthenticated (${publicUrl}):`);

	// The policy leaves /healthz open so a probe needs no session.
	const health = await fetch(`${publicUrl}/healthz`, { redirect: "manual" });
	check("/healthz is 200 and unauthenticated", health.status === 200, `got ${health.status}`);

	// Path allowlist, ahead of the oauth rule: a scan must not learn the provider.
	const unknown = await fetch(`${publicUrl}/wp-login.php`, { redirect: "manual" });
	check("an unlisted path is 404, not a redirect", unknown.status === 404, `got ${unknown.status}`);

	// The SPA shell is behind oauth, so an anonymous GET starts the flow.
	const shell = await fetch(`${publicUrl}/`, { redirect: "manual" });
	const location = shell.headers.get("location") ?? "";
	check(
		"/ redirects into the oauth flow",
		shell.status >= 300 && shell.status < 400 && location.length > 0,
		`got ${shell.status} location=${location || "(none)"}`,
	);

	// Hosting never traverses the tunnel, and is denied before the oauth rule
	// runs, so this is a flat 403 rather than a login a terminal cannot complete.
	const host = await fetch(`${publicUrl}/r/${ROOM}?role=host`, { redirect: "manual" });
	check("role=host is 403 at the edge", host.status === 403, `got ${host.status}`);

	// A guest is behind oauth instead, so it gets the redirect the host does not.
	const guest = await fetch(`${publicUrl}/r/${ROOM}?role=guest`, { redirect: "manual" });
	check(
		"role=guest is a redirect, not a 403 or an upgrade",
		guest.status >= 300 && guest.status < 400,
		`got ${guest.status}`,
	);

	// The `omp join` breakage, confirmed rather than assumed: a terminal guest
	// cannot follow the redirect, so the handshake never completes.
	const terminalGuest = await upgrade(`${wsUrl}/r/${ROOM}?role=guest`);
	check("a terminal guest cannot upgrade through the edge", terminalGuest !== "open", `handshake ${terminalGuest}`);

	const tunnelHost = await upgrade(`${wsUrl}/r/${ROOM}?role=host`);
	check("a host cannot upgrade through the edge", tunnelHost !== "open", `handshake ${tunnelHost}`);

	console.log("\nhosting bind, unauthenticated:");
	const port = forwarded.includes("--port") ? forwarded[forwarded.indexOf("--port") + 1] : PORT;
	const localHost = await upgrade(`ws://127.0.0.1:${port}/r/${ROOM}?role=host`);
	check("the hosting bind still accepts role=host", localHost === "open", `handshake ${localHost}`);

	console.log(
		[
			"",
			"Not checkable from a script — an authenticated browser guest. Re-run with your own",
			"--oauth-allow, open the endpoint, sign in, then in the page console:",
			"",
			"  new WebSocket(location.origin.replace('https','wss') + '/r/AAAAAAAAAA?role=guest')",
			"    .onclose = (e) => console.log('handshake reached the relay, close', e.code)",
			"",
			"Close 4004 means the upgrade passed the oauth action and reached the room logic,",
			"which is what makes browser guests viable at all. A redirect or a failed handshake",
			"means OAuth blocks websocket upgrades outright, and browser guests need a different",
			"design.",
		].join("\n"),
	);

	console.log(`\n${failures === 0 ? "all edge checks passed" : `${failures} edge check(s) failed`}`);
} finally {
	relay.kill();
}

process.exit(failures === 0 ? 0 : 1);
