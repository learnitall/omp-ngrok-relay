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
 *
 * An optional observation group fires un-normalized requests at the edge to
 * reveal whether ngrok's target normalisation matches the relay's WHATWG parse.
 * The observation group does not affect the exit code.
 */
import { parseArgs } from "node:util";

const forwarded = Bun.argv.slice(2);
const { values } = parseArgs({
	args: forwarded,
	options: { "authtoken-file": { type: "string" }, port: { type: "string" } },
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

/** Derived from one parse to avoid mismatch between bind and final check. */
const port = (values.port as string | undefined) ?? PORT;
const has = (flag: string): boolean => forwarded.some((a) => a === flag || a.startsWith(`${flag}=`));
const args = [...forwarded];
if (!values.port) args.push("--port", port);

/** Drops a caller-supplied allowlist, so the anonymous pass really is anonymous. */
function withoutAllow(argv: string[]): string[] {
	const out: string[] = [];
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i] as string;
		if (arg === "--oauth-allow") {
			i++;
			continue;
		}
		if (arg.startsWith("--oauth-allow=")) continue;
		out.push(arg);
	}
	return out;
}

interface Relay {
	url: string;
	stop(): Promise<void>;
}

/**
 * Starts the binary and reads back its endpoint, echoing output so failures stay
 * legible. ngrok allows one agent session per account, so the passes below run
 * one at a time and each waits for the previous relay to exit.
 */
async function spawnRelay(argv: string[]): Promise<Relay> {
	const proc = Bun.spawn([BINARY, ...argv], { stdout: "pipe", stderr: "inherit" });
	const reader = proc.stdout.getReader();
	const decoder = new TextDecoder();
	let buffered = "";
	while (true) {
		const { value, done } = await reader.read();
		if (done) throw new Error("relay exited before printing an ngrok endpoint");
		const chunk = decoder.decode(value);
		process.stdout.write(chunk);
		buffered += chunk;
		const url = buffered.match(/ngrok endpoint: (https:\/\/\S+)/)?.[1];
		if (url) {
			return {
				url,
				async stop(): Promise<void> {
					proc.kill();
					await proc.exited;
				},
			};
		}
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

interface Socket {
	ws: WebSocket;
	/** Resolves once the handshake completes, or false if it never does. */
	opened: Promise<boolean>;
	/** First TEXT frame the relay sends, or how the socket ended instead. */
	first: Promise<string>;
}

/** A socket held open, for the one check that needs a live room rather than a probe. */
function hold(url: string): Socket {
	const opened = Promise.withResolvers<boolean>();
	const first = Promise.withResolvers<string>();
	const ws = new WebSocket(url);
	ws.onopen = () => opened.resolve(true);
	ws.onmessage = (e) => first.resolve(typeof e.data === "string" ? e.data : "binary frame");
	ws.onerror = () => {
		opened.resolve(false);
		first.resolve("refused");
	};
	ws.onclose = (e) => {
		opened.resolve(false);
		first.resolve(`closed ${e.code}`);
	};
	setTimeout(() => {
		opened.resolve(false);
		first.resolve("timeout");
	}, 15_000);
	return { ws, opened: opened.promise, first: first.promise };
}

/**
 * Status code for a request target sent verbatim, bypassing the URL
 * canonicalisation `fetch` applies. Only the status line is read; the socket is
 * dropped immediately after.
 */
async function rawStatus(publicUrl: string, target: string): Promise<number> {
	const host = new URL(publicUrl).host;
	const { promise, resolve } = Promise.withResolvers<number>();
	const timer = setTimeout(() => resolve(0), 10_000);
	const done = (status: number): void => {
		clearTimeout(timer);
		resolve(status);
	};
	const socket = await Bun.connect({
		hostname: host,
		port: 443,
		tls: true,
		socket: {
			open(s) {
				s.write(`GET ${target} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
			},
			data(s, chunk) {
				done(Number(new TextDecoder().decode(chunk).match(/^HTTP\/1\.[01] (\d{3})/)?.[1] ?? 0));
				s.end();
			},
			error: () => done(0),
			close: () => done(0),
		},
	});
	const status = await promise;
	socket.end();
	return status;
}

const authed = await spawnRelay(has("--oauth-allow") ? args : [...args, "--oauth-allow", ALLOW]);
try {
	const publicUrl = authed.url;
	const wsUrl = publicUrl.replace(/^https/, "wss");
	console.log(`\nedge with an allowlist, unauthenticated (${publicUrl}):`);

	// The policy leaves /healthz open so a probe needs no session.
	const health = await fetch(`${publicUrl}/healthz`, { redirect: "manual" });
	check("/healthz is 200 and unauthenticated", health.status === 200, `got ${health.status}`);

	// Path allowlist, ahead of the oauth rule: a scan must not learn the provider.
	const unknown = await fetch(`${publicUrl}/wp-login.php`, { redirect: "manual" });
	check("an unlisted path is 404, not a redirect", unknown.status === 404, `got ${unknown.status}`);

	// Undocumented and edge-served, so the only way to know they are still in the
	// allowlist is to ask. A 404 in here does not fail closed, it stalls the
	// visitor mid-flow: the error landing is where a declined consent screen goes,
	// and 404ing it hides ngrok's own "try again" page. Anything but 404 means the
	// request reached the oauth action rather than the deny rule.
	for (const landing of ["/ngrok/callback/error?state=e2e", "/ngrok/callback/authn?state=e2e"]) {
		const res = await fetch(`${publicUrl}${landing}`, { redirect: "manual" });
		check(`${landing.split("?")[0]} is not 404ed by the path allowlist`, res.status !== 404, `got ${res.status}`);
	}

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
	const localHost = await upgrade(`ws://127.0.0.1:${port}/r/${ROOM}?role=host`);
	check("the hosting bind still accepts role=host", localHost === "open", `handshake ${localHost}`);

	console.log("\nedge parser agreement (observation, non-fatal):");

	// Written straight to a TLS socket, because `fetch` resolves dot-segments in
	// the URL before sending: through fetch, `/ngrok/../r/<room>` leaves as
	// `/r/<room>` and ngrok never sees the spelling we are asking about. The
	// question is what *ngrok* normalises, so the request target has to survive
	// verbatim.
	const variants = [
		[`/ngrok/../r/${ROOM}?role=host`, "dot-segment through the allowlisted /ngrok/ prefix"],
		[`/ngrok/callback/../../r/${ROOM}?role=host`, "two-level dot-segment out of /ngrok/callback/"],
		[`/./r/${ROOM}?role=host`, "single dot segment"],
		[`/%2e%2e/r/${ROOM}?role=host`, "percent-encoded dot segments"],
		[`/r/x/../${ROOM}?role=host`, "dot-segment inside /r/"],
		[`/healthz/../r/${ROOM}?role=host`, "dot-segment through /healthz"],
		[`/r/${ROOM}?role=%68ost`, "percent-encoded role value"],
		[`/r/${ROOM}?%72ole=host`, "percent-encoded role key"],
		[`/r/${ROOM}?role=guest&role=host`, "duplicate role, guest first"],
	];

	let caught = 0;
	for (const [target, label] of variants) {
		const status = await rawStatus(publicUrl, target as string);
		// 403 = the policy's host rule matched. 3xx = it did not, and the request
		// went to oauth instead; only the tunnel's listener would stop it.
		const verdict =
			status === 403
				? "caught by the edge"
				: status >= 300 && status < 400
					? "MISSED — reached oauth"
					: status === 404
						? "404 by the path allowlist"
						: `status ${status}`;
		if (status === 403 || status === 404) caught++;
		console.log(`  ${String(label).padEnd(48)} ${verdict}`);
	}
	console.log(
		`  -> the edge rejected ${caught}/${variants.length}; any MISSED line is a spelling only the\n` +
			"     listener split stops, which is why the README calls the edge rule best-effort.",
	);

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
	await authed.stop();
}

// The anonymous mode's whole claim is the inverse of everything above: no oauth
// action, so `omp join` reaches the relay, while the rules that are not oauth
// stay in force. Only a live endpoint can show that, and only with no allowlist.
const anon = await spawnRelay(withoutAllow(args));
try {
	const publicUrl = anon.url;
	const wsUrl = publicUrl.replace(/^https/, "wss");
	console.log(`\nedge with no allowlist, anonymous (${publicUrl}):`);

	const health = await fetch(`${publicUrl}/healthz`, { redirect: "manual" });
	check("/healthz is still 200", health.status === 200, `got ${health.status}`);

	// With the oauth action gone the shell is served outright; a redirect here
	// would mean an allowlist leaked into this pass.
	const shell = await fetch(`${publicUrl}/`, { redirect: "manual" });
	const html = shell.status === 200 ? await shell.text() : "";
	check(
		"/ serves the client instead of an oauth redirect",
		shell.status === 200 && /<html/i.test(html),
		`got ${shell.status}${shell.headers.get("location") ? ` -> ${shell.headers.get("location")}` : ""}`,
	);

	// Dropping oauth must not drop the rules that were never about identity.
	const unknown = await fetch(`${publicUrl}/wp-login.php`, { redirect: "manual" });
	check("an unlisted path is still 404", unknown.status === 404, `got ${unknown.status}`);
	const host = await fetch(`${publicUrl}/r/${ROOM}?role=host`, { redirect: "manual" });
	check("role=host is still 403 at the edge", host.status === 403, `got ${host.status}`);

	// The headline claim: a terminal guest, which oauth makes impossible, joining
	// a real room hosted on the hosting bind. The host being told `peer-joined`
	// is the relay's own room logic answering, through the tunnel, with no login.
	const roomHost = hold(`ws://127.0.0.1:${port}/r/${ROOM}?role=host`);
	check("the hosting bind accepts the host", await roomHost.opened, "host handshake failed");
	const guest = hold(`${wsUrl}/r/${ROOM}?role=guest`);
	check("a terminal guest upgrades through the anonymous edge", await guest.opened, "guest handshake failed");
	const joined = await roomHost.first;
	check("and reaches the room: the host is told it joined", joined === '{"t":"peer-joined","peer":1}', joined);
	guest.ws.close();
	roomHost.ws.close();

	console.log(`\n${failures === 0 ? "all edge checks passed" : `${failures} edge check(s) failed`}`);
} finally {
	await anon.stop();
}

process.exit(failures === 0 ? 0 : 1);
