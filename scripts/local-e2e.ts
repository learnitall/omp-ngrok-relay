#!/usr/bin/env bun
/**
 * End-to-end check against the compiled binary, with no ngrok tunnel and no
 * authtoken. Runs in CI.
 *
 *   bun run e2e:local
 *
 * `bun test` covers the protocol against `startRelay` in-process, and
 * `scripts/e2e.ts` covers the traffic policy against a real endpoint. Neither
 * reaches what only a spawned binary has: flag parsing, the two binds landing
 * where they were told, the client assets compiled in by `--compile`, the guest
 * cap, shutdown, and the refusals that replace a missing authtoken. Those are
 * what this script exercises.
 *
 * Every relay here starts local-only, so the edge bind is the guest door and no
 * check depends on an address outside loopback.
 */

const BINARY = "./bin/omp-ngrok-relay";
if (!(await Bun.file(BINARY).exists())) {
	console.error(`${BINARY} not found — run \`bun run build\` first.`);
	process.exit(1);
}

const ROOM = "LOCALE2Eroom";

let failures = 0;

function check(name: string, ok: boolean, detail = ""): void {
	console.log(`  ${ok ? "ok  " : "FAIL"}  ${name}${ok ? "" : ` — ${detail}`}`);
	if (!ok) failures++;
}

/** An empty authtoken is how the binary is told there is no tunnel; see relay.ts. */
function spawn(args: string[]): Bun.Subprocess<"ignore", "pipe", "inherit"> {
	return Bun.spawn([BINARY, ...args], {
		stdout: "pipe",
		stderr: "inherit",
		env: { ...process.env, NGROK_AUTHTOKEN: "" },
	});
}

interface Relay {
	hostUrl: string;
	guestUrl: string;
	/** Everything the relay has written to stdout so far. */
	output(): string;
	exitCode(): Promise<number>;
	signal(sig: NodeJS.Signals): void;
	kill(): void;
}

/**
 * Starts a relay on ephemeral ports and reads back the binds it actually took,
 * so nothing here collides with a port already in use on the runner.
 */
async function startRelay(extra: string[] = []): Promise<Relay> {
	const proc = spawn(["--port", "0", "--edge-port", "0", ...extra]);
	const reader = proc.stdout.getReader();
	const decoder = new TextDecoder();
	let buffered = "";

	// Keep draining after startup: a full pipe buffer would block the relay.
	const pump = (async () => {
		while (true) {
			const { value, done } = await reader.read();
			if (done) return;
			buffered += decoder.decode(value);
		}
	})();

	const deadline = Date.now() + 15_000;
	let binds: [string, string] | undefined;
	while (Date.now() < deadline) {
		const host = buffered.match(/hosting bind:\s+(ws:\/\/\S+)/)?.[1];
		const guest = buffered.match(/edge bind \(guests only\):\s+(ws:\/\/\S+)/)?.[1];
		if (host && guest) {
			binds = [host, guest];
			break;
		}
		await Bun.sleep(50);
	}
	if (!binds) {
		proc.kill();
		throw new Error(`relay never printed its binds:\n${buffered}`);
	}

	return {
		hostUrl: binds[0],
		guestUrl: binds[1],
		output: () => buffered,
		async exitCode(): Promise<number> {
			const code = await proc.exited;
			await pump;
			return code;
		},
		signal: (sig) => proc.kill(sig),
		kill: () => proc.kill(),
	};
}

type Frame = string | Uint8Array;

interface Peer {
	/** Next frame in arrival order; buffers so nothing is lost between awaits. */
	next(): Promise<Frame>;
	/** Resolves with the close code the relay sent. */
	closed: Promise<number>;
}

async function dial(base: string, role: "host" | "guest", room = ROOM): Promise<Peer> {
	const ws = new WebSocket(`${base}/r/${room}?role=${role}`);
	ws.binaryType = "arraybuffer";

	const queue: Frame[] = [];
	const waiting: ((frame: Frame) => void)[] = [];
	ws.onmessage = (e) => {
		const frame = typeof e.data === "string" ? e.data : new Uint8Array(e.data as ArrayBuffer);
		const waiter = waiting.shift();
		if (waiter) waiter(frame);
		else queue.push(frame);
	};

	const closed = Promise.withResolvers<number>();
	const opened = Promise.withResolvers<void>();
	ws.onopen = () => opened.resolve();
	ws.onclose = (e) => {
		closed.resolve(e.code);
		opened.reject(new Error(`closed ${e.code}`));
	};
	await opened.promise;

	return {
		next(): Promise<Frame> {
			const buffered = queue.shift();
			if (buffered !== undefined) return Promise.resolve(buffered);
			const { promise, resolve } = Promise.withResolvers<Frame>();
			waiting.push(resolve);
			return promise;
		},
		closed: closed.promise,
	};
}

/** Dials without waiting for an open, for handshakes the relay is expected to reject. */
function closeCode(url: string): Promise<number> {
	const { promise, resolve } = Promise.withResolvers<number>();
	const ws = new WebSocket(url);
	ws.onclose = (e) => resolve(e.code);
	return promise;
}

const httpOf = (wsUrl: string): string => wsUrl.replace(/^ws/, "http");

/** Runs the binary to completion and reports how it refused. */
async function refusal(args: string[]): Promise<number> {
	const proc = Bun.spawn([BINARY, ...args], {
		stdout: "pipe",
		stderr: "pipe",
		env: { ...process.env, NGROK_AUTHTOKEN: "" },
	});
	return await proc.exited;
}

// ---------------------------------------------------------------------------

const relay = await startRelay();
try {
	console.log(`\nlocal-only startup (hosting ${relay.hostUrl}, edge ${relay.guestUrl}):`);

	check(
		"announces local-only and prints no ngrok endpoint",
		/local only/.test(relay.output()) && !/ngrok endpoint/.test(relay.output()),
		relay.output().trim().split("\n").pop() ?? "(no output)",
	);
	check(
		"both binds default to loopback",
		new URL(httpOf(relay.hostUrl)).hostname === "127.0.0.1" &&
			new URL(httpOf(relay.guestUrl)).hostname === "127.0.0.1",
		`${relay.hostUrl} / ${relay.guestUrl}`,
	);

	for (const [label, base] of [
		["hosting bind", relay.hostUrl],
		["edge bind", relay.guestUrl],
	] as const) {
		const res = await fetch(`${httpOf(base)}/healthz`);
		check(`/healthz is 200 on the ${label}`, res.status === 200 && (await res.text()) === "ok", `got ${res.status}`);
	}

	console.log("\nclient assets compiled into the binary:");

	const shell = await fetch(`${httpOf(relay.guestUrl)}/`);
	const html = await shell.text();
	check("/ serves the client shell", shell.status === 200 && /<html/i.test(html), `got ${shell.status}`);

	// A deep link (`/#ws://host/r/<id>.<key>`) reaches the server as an unknown
	// path, and a guest following one must get the SPA rather than a 404.
	const deep = await fetch(`${httpOf(relay.guestUrl)}/does-not-exist`);
	check(
		"an unknown path mirrors the shell",
		deep.status === 200 && (await deep.text()) === html,
		`got ${deep.status}`,
	);

	// Asset names are content-hashed by the client build, so they are discovered
	// from the shell rather than hardcoded: the embedding is what is under test,
	// and a stale hardcoded name would make this check vacuously green. The client
	// emits them relative (`./93hhfnct.css`); the relay keys them from the root.
	const assets = [...html.matchAll(/(?:src|href)="\.?\/([A-Za-z0-9_.-]+\.(?:css|js))"/g)].map((m) => `/${m[1]}`);
	if (assets.length === 0) {
		console.log("  --    the shell references no hashed assets (no client embedded); skipped");
	}
	for (const asset of assets.slice(0, 2)) {
		const res = await fetch(`${httpOf(relay.guestUrl)}${asset}`);
		const body = await res.bytes();
		check(`${asset} is served out of the binary`, res.status === 200 && body.length > 0, `got ${res.status}`);
	}

	console.log("\nhosting is the hosting bind only:");

	const edgeHost = await fetch(`${httpOf(relay.guestUrl)}/r/${ROOM}?role=host`);
	check("role=host is refused 403 on the edge bind", edgeHost.status === 403, `got ${edgeHost.status}`);
	const bindHost = await fetch(`${httpOf(relay.hostUrl)}/r/${ROOM}?role=host`);
	check("role=host on the hosting bind wants an upgrade", bindHost.status === 426, `got ${bindHost.status}`);
	const noRole = await fetch(`${httpOf(relay.hostUrl)}/r/${ROOM}`);
	check("a missing role is 404", noRole.status === 404, `got ${noRole.status}`);

	// Only what the process adds: the two binds sharing one room map, which is
	// flag wiring rather than protocol. Frame routing, 4004, 4009 and peer-left
	// are covered against the library in relay.test.ts, so they are not repeated
	// here — this room exists to have something live for SIGTERM to tear down.
	console.log("\na room spanning both binds:");

	const host = await dial(relay.hostUrl, "host");
	const guest = await dial(relay.guestUrl, "guest");
	check(
		"a guest on the edge bind joins a room on the hosting bind",
		(await host.next()) === '{"t":"peer-joined","peer":1}',
	);

	console.log("\nSIGTERM drops the room:");

	relay.signal("SIGTERM");
	const farewell = await guest.next();
	check("guests get room-closed before the socket drops", farewell === '{"t":"room-closed"}', String(farewell));
	check("and are closed 4001", (await guest.closed) === 4001, "wrong close code");
	check("the relay exits 0", (await relay.exitCode()) === 0, "non-zero exit");
} finally {
	relay.kill();
}

const capped = await startRelay(["--max-guests", "1"]);
try {
	console.log("\n--max-guests is enforced:");
	const host = await dial(capped.hostUrl, "host");
	await dial(capped.guestUrl, "guest");
	check("the host sees the one guest the cap allows", (await host.next()) === '{"t":"peer-joined","peer":1}');
	const overflow = await closeCode(`${capped.guestUrl}/r/${ROOM}?role=guest`);
	check("the guest over the cap is closed 4029", overflow === 4029, `got ${overflow}`);
} finally {
	capped.kill();
}

console.log("\nflags that need an edge are refused, not ignored:");
for (const args of [
	["--oauth-allow", "nobody@example.com"],
	["--ngrok-url", "https://collab.example.com"],
]) {
	const code = await refusal(args);
	check(`${args[0]} without an authtoken exits non-zero`, code !== 0, `exited ${code}`);
}
check("a bad --edge-port exits non-zero", (await refusal(["--edge-port", "notaport"])) !== 0);

console.log(`\n${failures === 0 ? "all local checks passed" : `${failures} local check(s) failed`}`);
process.exit(failures === 0 ? 0 : 1);
