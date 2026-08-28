#!/usr/bin/env bun
/**
 * Content-blind relay for `omp` collab sessions.
 *
 * Contract (see docs/collab.md in oh-my-pi):
 *   - GET /r/<roomId>?role=host|guest  -> websocket upgrade
 *   - the host creates the room; a second host is closed with 4009,
 *     a guest for a missing room with 4004, an over-capacity guest with 4029
 *   - host BINARY frame: [4B BE peerId][sealed]; peerId 0 broadcasts to every
 *     guest, peerId N targets guest N. Forwarded byte-for-byte.
 *   - guest BINARY frame: first 4 bytes rewritten to the sender's peerId,
 *     then forwarded to the host.
 *   - TEXT control to the host: {"t":"peer-joined","peer":N} / {"t":"peer-left","peer":N}
 *   - host disconnect: TEXT {"t":"room-closed"} to every guest, close 4001,
 *     room dropped.
 *
 * Payloads are AES-256-GCM sealed by the clients; this process never holds a
 * key and never inspects anything past the 4-byte routing prefix.
 *
 * Two loopback-or-narrower listeners share one room map: the hosting bind, which
 * is the only place a `role=host` upgrade is accepted, and the tunnel's own
 * origin, which refuses hosting. The process always publishes itself through an
 * ngrok endpoint, so an ngrok authtoken is required.
 */
import { parseArgs } from "node:util";
import { forward } from "@ngrok/ngrok";
import { ENVELOPE_HEADER_LENGTH, type RelayControlToGuest, type RelayControlToHost } from "@oh-my-pi/pi-wire";
import { EMBEDDED_FILES } from "./dist-embed.generated";
import { buildTrafficPolicy } from "./policy";

/** Injected by `bun build --define BUILD_VERSION`; absent in a plain `bun relay.ts` run. */
declare const BUILD_VERSION: string | undefined;
const VERSION = typeof BUILD_VERSION === "string" ? BUILD_VERSION : "dev";

const ROOM_PATH = /^\/r\/([A-Za-z0-9_-]{10,64})$/;
/** Frames carry snapshot chunks and inline images; the 16 MiB default is too tight. */
const MAX_PAYLOAD = 32 * 1024 * 1024;
/** A peer this far behind is never catching up; drop it instead of buffering for it. */
const BACKPRESSURE_LIMIT = 8 * 1024 * 1024;
const PING_INTERVAL_MS = 30_000;

/** collab-web, compiled into the binary by `with { type: "file" }` imports. */
const INDEX_HTML = EMBEDDED_FILES["/index.html"];

interface SocketData {
	roomId: string;
	role: "host" | "guest";
	/** Assigned on open for guests; the host stays 0. */
	peerId: number;
}

type RelaySocket = Bun.ServerWebSocket<SocketData>;

interface Room {
	host: RelaySocket;
	guests: Map<number, RelaySocket>;
	nextPeerId: number;
}

const ROOM_CLOSED: RelayControlToGuest = { t: "room-closed" };

export interface RelayOptions {
	/** Port of the hosting bind: `role=host` is accepted here and nowhere else. */
	port?: number;
	/** Address of the hosting bind. Whoever can reach it can host. */
	hostname?: string;
	maxGuests?: number;
	/** Loopback port the tunnel forwards to; 0 picks one. Hosting is refused there. */
	edgePort?: number;
}

export interface RelayHandle {
	/** ws://host:port — the hosting bind; `role=host` is only ever accepted here. */
	url: string;
	port: number;
	/** ws://127.0.0.1:port — the tunnel's origin, guests only. */
	edgeUrl: string;
	edgePort: number;
	/** Closes every room and stops both listeners. */
	stop(): void;
}

export function startRelay(opts: RelayOptions = {}): RelayHandle {
	const rooms = new Map<string, Room>();
	const maxGuests = opts.maxGuests ?? 0;

	const send = (ws: RelaySocket, data: string | Uint8Array): void => {
		if (ws.send(data) === -1 && ws.getBufferedAmount() > BACKPRESSURE_LIMIT) {
			ws.close(1013, "peer too slow");
		}
	};

	const control = (ws: RelaySocket, msg: RelayControlToHost | RelayControlToGuest): void => {
		send(ws, JSON.stringify(msg));
	};

	/**
	 * `hosting` is false on the listener the tunnel forwards to, and the socket a
	 * request arrived on is the whole discriminator. It has to be: the ngrok agent
	 * runs in this process and dials 127.0.0.1, so an edge-forwarded request and a
	 * genuinely local one are indistinguishable by source address.
	 *
	 * Reachability of the hosting bind is therefore the entire hosting rule —
	 * `hostname` decides who may host, and the default keeps that to loopback.
	 */
	const route = (req: Request, srv: Bun.Server<SocketData>, hosting: boolean): Response | undefined => {
		const url = new URL(req.url);
		if (url.pathname === "/healthz") return new Response("ok");

		const match = ROOM_PATH.exec(url.pathname);
		if (match) {
			const role = url.searchParams.get("role");
			if (role !== "host" && role !== "guest") return new Response("not found", { status: 404 });
			if (role === "host" && !hosting) {
				return new Response("hosting is not available through the tunnel", { status: 403 });
			}
			const data: SocketData = { roomId: match[1]!, role, peerId: 0 };
			if (srv.upgrade(req, { data })) return undefined;
			return new Response("websocket upgrade required", { status: 426 });
		}

		return serveStatic(url.pathname);
	};

	const websocket: Bun.WebSocketHandler<SocketData> = {
		maxPayloadLength: MAX_PAYLOAD,
		// Server pings every 30 s; this only has to outlast that round trip.
		idleTimeout: 120,
		open(ws: RelaySocket): void {
			const { roomId, role } = ws.data;
			if (role === "host") {
				if (rooms.has(roomId)) {
					ws.close(4009, "a host is already connected for this room");
					return;
				}
				rooms.set(roomId, { host: ws, guests: new Map(), nextPeerId: 1 });
				console.log(`room ${roomId} opened`);
				return;
			}
			const room = rooms.get(roomId);
			if (!room) {
				ws.close(4004, "no such room");
				return;
			}
			if (maxGuests > 0 && room.guests.size >= maxGuests) {
				ws.close(4029, "room is full");
				return;
			}
			const peerId = room.nextPeerId++;
			ws.data.peerId = peerId;
			room.guests.set(peerId, ws);
			control(room.host, { t: "peer-joined", peer: peerId });
			console.log(`room ${roomId}: peer ${peerId} joined`);
		},
		message(ws: RelaySocket, message: string | Buffer): void {
			if (typeof message === "string") return; // clients never send TEXT
			const room = rooms.get(ws.data.roomId);
			if (!room || message.byteLength < ENVELOPE_HEADER_LENGTH) return;

			if (ws.data.role === "host") {
				const peerId = message.readUInt32BE(0);
				if (peerId === 0) {
					for (const guest of room.guests.values()) send(guest, message);
				} else {
					const guest = room.guests.get(peerId);
					if (guest) send(guest, message);
				}
				return;
			}
			message.writeUInt32BE(ws.data.peerId, 0);
			send(room.host, message);
		},
		close(ws: RelaySocket): void {
			const { roomId, role, peerId } = ws.data;
			const room = rooms.get(roomId);
			if (!room) return;

			if (role === "host") {
				// Rejected second host: the live room is not ours to tear down.
				if (room.host !== ws) return;
				rooms.delete(roomId);
				for (const guest of room.guests.values()) {
					control(guest, ROOM_CLOSED);
					guest.close(4001, "room closed");
				}
				console.log(`room ${roomId} closed (${room.guests.size} guests dropped)`);
				room.guests.clear();
				return;
			}
			if (room.guests.delete(peerId)) {
				control(room.host, { t: "peer-left", peer: peerId });
				console.log(`room ${roomId}: peer ${peerId} left`);
			}
		},
	};

	const local = Bun.serve<SocketData>({
		port: opts.port ?? 7466,
		hostname: opts.hostname ?? "127.0.0.1",
		fetch: (req, srv) => route(req, srv, true),
		websocket,
	});
	// Always loopback: the tunnel's agent runs in this process and dials it locally.
	const edge = Bun.serve<SocketData>({
		port: opts.edgePort ?? 0,
		hostname: "127.0.0.1",
		fetch: (req, srv) => route(req, srv, false),
		websocket,
	});

	const pinger = setInterval(() => {
		for (const room of rooms.values()) {
			room.host.ping();
			for (const guest of room.guests.values()) guest.ping();
		}
	}, PING_INTERVAL_MS);

	const port = local.port ?? 0;
	const edgePort = edge.port ?? 0;
	return {
		// Bun canonicalises the bind address, so an IPv6 literal comes out bracketed
		// and the printed url is one the operator can paste.
		url: `ws://${local.url.host}`,
		port,
		edgeUrl: `ws://${edge.hostname}:${edgePort}`,
		edgePort,
		stop(): void {
			clearInterval(pinger);
			for (const room of rooms.values()) {
				for (const guest of room.guests.values()) {
					control(guest, ROOM_CLOSED);
					guest.close(4001, "room closed");
				}
				room.host.close(1001, "relay shutting down");
			}
			rooms.clear();
			local.stop(true);
			edge.stop(true);
		},
	};
}

/** Exact-match routing, so there is no traversal surface; unknown paths get the SPA shell. */
function serveStatic(pathname: string): Response {
	const file = EMBEDDED_FILES[pathname] ?? INDEX_HTML;
	if (!file) return new Response("not found", { status: 404 });
	return new Response(Bun.file(file));
}

/**
 * The endpoint is the point of this process, so a failure here is fatal rather
 * than degraded: a relay nobody can reach is not a working relay.
 *
 * Takes the handle rather than a port on purpose. Forwarding the tunnel to
 * `relay.port` instead of `relay.edgePort` would hand remote clients the
 * listener that accepts `role=host`, silently undoing the same-host rule, so
 * the choice lives here instead of at the call site.
 */
async function startNgrok(
	relay: RelayHandle,
	url: string | undefined,
	policy: object,
	provider: string,
	authtoken: string,
): Promise<void> {
	const listener = await forward({
		addr: `127.0.0.1:${relay.edgePort}`,
		authtoken,
		domain: url ? new URL(url).hostname : undefined,
		traffic_policy: JSON.stringify(policy),
	});
	const publicUrl = listener.url();
	if (!publicUrl) throw new Error("ngrok returned no url");

	console.log(`ngrok endpoint: ${publicUrl}`);
	console.log(`  browser guests:  ${publicUrl}  (sign in with ${provider})`);
	console.log("  hosting through the tunnel is refused; hosts use the hosting bind.");
	console.log("  terminal guests (`omp join`) cannot authenticate and will be rejected.");
}

/**
 * ngrok's ERR_NGROK_105 quotes the supplied authtoken back verbatim, so printing
 * its message writes the account credential to the log — once per restart under
 * the systemd recipe. The operator still needs the rest of the message to tell a
 * bad token from a bad domain, so redact the value rather than drop the error.
 * Matched on the token itself, never on ngrok's phrasing: a future message could
 * carry it in different words.
 */
export function redactToken(message: string, token: string): string {
	if (token.length === 0) return message;
	// A short token would blank out unrelated words wherever it coincidentally
	// appeared, and an unreadable message is worse than none. A real ngrok token
	// is ~49 characters, so this only fires on a degenerate one.
	if (token.length < 8) {
		return message.includes(token) ? "<redacted: the message contained the authtoken>" : message;
	}
	return message.split(token).join("***");
}

/** How far the hosting bind reaches; see `bindScope`. */
export type BindScope = "loopback" | "any" | "specific";

/**
 * `--hostname` is the hosting ACL, so the startup log has to be honest about how
 * wide it is — and that is a property of the address, not of its spelling: `0`,
 * `0x0`, `::0` and `2130706433` all bind something a literal comparison misses.
 * WHATWG's host parser canonicalises every one of them, so classify the parsed
 * host instead.
 *
 * Anything unrecognised is `specific` rather than `loopback`, which also catches
 * a LAN-only bind: over-warning about a narrow bind is cheap, staying quiet
 * about a wide one is not.
 */
export function bindScope(hostname: string): BindScope {
	const literal = hostname.includes(":") && !hostname.startsWith("[") ? `[${hostname}]` : hostname;
	let host: string;
	try {
		host = new URL(`http://${literal}`).hostname;
	} catch {
		return "specific";
	}
	if (host === "0.0.0.0" || host === "[::]") return "any";
	// Canonical IPv4 is always a dotted quad, so the prefix is the whole of 127/8.
	// IPv4-mapped IPv6 loopback like ::ffff:127.0.0.1 normalises to [::ffff:7f00:1].
	if (
		host === "localhost" ||
		host === "[::1]" ||
		host.startsWith("127.") ||
		(host.startsWith("[::ffff:7f") && host.endsWith(":1]"))
	) {
		return "loopback";
	}
	return "specific";
}

/** `null` for anything that is not a whole number in `0..max`; the caller decides how loudly to die. */
export function parseBoundedInt(raw: string, max: number): number | null {
	// Digits only (no trimming), so "-1", "1.5", "1e3", "", " 8080 " and "zzz" are
	// all rejected rather than silently becoming a negative, truncation, NaN, or valid.
	if (!/^\d+$/.test(raw)) return null;
	const n = Number(raw);
	return Number.isSafeInteger(n) && n <= max ? n : null;
}

const HELP = `omp-ngrok-relay ${VERSION} — content-blind relay for omp collab sessions, published through ngrok

  --port <n>            port of the hosting bind (default 7466)
  --hostname <host>     address of the hosting bind (default 127.0.0.1); whoever can
                        reach it can host, so 0.0.0.0 opens hosting to that network
  --max-guests <n>      per-room guest cap, 0 = unlimited (default 0)
  --ngrok-url <url>     reserved ngrok URL, e.g. https://collab.example.com
  --oauth-provider <p>  ngrok OAuth provider for browser guests (default google)
  --oauth-allow <who>   permitted identity, repeatable or comma-separated:
                        user@example.com for one address, @example.com for a domain
  --authtoken-file <p>  file holding the ngrok authtoken; wins over NGROK_AUTHTOKEN
  --version, --help

An ngrok authtoken (NGROK_AUTHTOKEN or --authtoken-file) and at least one --oauth-allow are
required. --authtoken-file wins over the environment, and keeps the token out of the process
environment and out of the argument list.

Two binds. The hosting bind above accepts role=host and role=guest, unauthenticated — reaching it
*is* the host's credential, so keep it as narrow as the deployment allows. The tunnel gets its own
ephemeral loopback bind and refuses role=host, so hosting never traverses ngrok no matter what the
edge does. Browser guests coming through the tunnel sign in with the provider; terminal guests
(omp join) cannot authenticate and cannot connect. The rules are compiled in and only the allowlist
is a flag; see policy.ts.`;

/** Every flag this binary accepts, as `parseArgs` hands them back. */
interface Flags {
	port: string;
	hostname: string;
	"max-guests": string;
	"ngrok-url"?: string;
	"oauth-provider": string;
	"oauth-allow": string[];
	"authtoken-file"?: string;
	version: boolean;
	help: boolean;
}

/**
 * `parseArgs` throws on a malformed flag, and an uncaught throw here dumps a
 * stack trace through the minified bundle. `--port -1` is the common way in: it
 * reads as a missing argument followed by an unknown short option.
 */
function parseFlags(): Flags {
	try {
		return parseArgs({
			args: Bun.argv.slice(2),
			options: {
				port: { type: "string", default: "7466" },
				hostname: { type: "string", default: "127.0.0.1" },
				"max-guests": { type: "string", default: "0" },
				"ngrok-url": { type: "string" },
				"oauth-provider": { type: "string", default: "google" },
				"oauth-allow": { type: "string", multiple: true, default: [] },
				"authtoken-file": { type: "string" },
				version: { type: "boolean", default: false },
				help: { type: "boolean", default: false },
			},
		}).values as Flags;
	} catch (err) {
		console.error(`${err instanceof Error ? err.message : String(err)}\n\nRun --help for usage.`);
		process.exit(1);
	}
}

if (import.meta.main) {
	const values = parseFlags();

	if (values.help) {
		console.log(HELP);
		process.exit(0);
	}
	if (values.version) {
		console.log(VERSION);
		process.exit(0);
	}
	// `Number("zzz")` is NaN, which Bun.serve reads as "pick any port" and the
	// guest cap reads as "no cap" — both silent, and both leave the operator's
	// relayUrl and firewall rules pointing at nothing. Checked before anything
	// binds, like the token and the allowlist below.
	const port = parseBoundedInt(values.port, 65535);
	if (port === null) {
		console.error(`--port ${values.port}: expected an integer 0-65535`);
		process.exit(1);
	}
	const maxGuests = parseBoundedInt(values["max-guests"], Number.MAX_SAFE_INTEGER);
	if (maxGuests === null) {
		console.error(`--max-guests ${values["max-guests"]}: expected a non-negative integer`);
		process.exit(1);
	}

	// Resolved before the port is bound, so a missing or unreadable token costs
	// nothing. The file wins over the environment: passing it is the deliberate
	// choice, and a stale exported token silently overriding it would be worse.
	let authtoken = process.env.NGROK_AUTHTOKEN ?? "";
	const tokenFile = values["authtoken-file"];
	if (tokenFile !== undefined) {
		try {
			authtoken = (await Bun.file(tokenFile).text()).trim();
		} catch (err) {
			console.error(`--authtoken-file ${tokenFile}: ${err instanceof Error ? err.message : String(err)}`);
			process.exit(1);
		}
		if (authtoken.length === 0) {
			console.error(`--authtoken-file ${tokenFile}: file is empty`);
			process.exit(1);
		}
	}
	if (authtoken.length === 0) {
		console.error(
			"No ngrok authtoken: set NGROK_AUTHTOKEN or pass --authtoken-file. This relay publishes itself " +
				"through ngrok and has no local-only mode.",
		);
		process.exit(1);
	}

	// Built before the port is bound, so a malformed allowlist costs nothing. The
	// policy is the endpoint's only access control, so an invalid one is fatal.
	const provider = values["oauth-provider"];
	let policy: object;
	try {
		policy = buildTrafficPolicy({
			provider,
			// Trimmed because the help text advertises "comma-separated", and the
			// natural spelling of that has a space after the comma.
			allow: values["oauth-allow"]
				.flatMap((v) => v.split(","))
				.map((v) => v.trim())
				.filter((v) => v.length > 0),
		});
	} catch (err) {
		console.error(err instanceof Error ? err.message : String(err));
		process.exit(1);
	}

	const relay = startRelay({ port, hostname: values.hostname, maxGuests });
	const embedded = Object.keys(EMBEDDED_FILES).length;
	console.log(
		`omp-ngrok-relay ${VERSION} listening on ${relay.url}` +
			(embedded > 0 ? ` (${embedded} embedded client files)` : " (no embedded web client)"),
	);
	// `--hostname` is the hosting ACL, so a bind wider than loopback is worth
	// saying out loud. The unspecified address has no address to hand out either:
	// the host reaches it on whatever routes there, which for a published
	// container port is the loopback of the machine outside it.
	const scope = bindScope(values.hostname);
	const reach =
		scope === "any"
			? "  (reachable on every address of this host)"
			: scope === "specific"
				? "  (not loopback: whoever can route to it can host)"
				: "";
	console.log(`  hosting bind:  ${relay.url}${reach}`);
	if (scope !== "any") {
		console.log(`     omp config set collab.relayUrl ${relay.url}`);
		console.log(`     or one-shot, no config:  /collab ${relay.url}`);
	}
	console.log(`  tunnel origin (guests only):  ${relay.edgeUrl}`);

	try {
		await startNgrok(relay, values["ngrok-url"], policy, provider, authtoken);
	} catch (err) {
		console.error(`ngrok: ${redactToken(err instanceof Error ? err.message : String(err), authtoken)}`);
		relay.stop();
		process.exit(1);
	}

	const shutdown = (): void => {
		relay.stop();
		process.exit(0);
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
