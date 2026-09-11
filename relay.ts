#!/usr/bin/env bun
/**
 * Content-blind relay for `omp` collab sessions.
 *
 * Contract (see docs/collab.md in oh-my-pi):
 *   - GET /r/<roomId>?role=host|guest  -> websocket upgrade
 *   - the host creates the room
 *   - a second host is closed with 4009
 *   - a guest for a missing room is closed with 4004
 *   - an over-capacity guest is closed with 4029
 *   - host BINARY frame: [4B BE peerId][sealed]. peerId 0 broadcasts to every
 *     guest, peerId N targets guest N.
 *   - guest BINARY frame: first 4 bytes rewritten to the sender's peerId,
 *     then forwarded to the host.
 *   - TEXT control to the host: {"t":"peer-joined","peer":N} / {"t":"peer-left","peer":N}
 *   - host disconnect: TEXT {"t":"room-closed"} to every guest, close 4001,
 *     room dropped.
 *
 * Payloads are AES-256-GCM sealed by the clients. The relay never holds a
 * key and never inspects anything past the 4-byte routing prefix.
 *
 * Two listeners, loopback by default, share one room map: the hosting bind, which
 * is the only place a `role=host` upgrade is accepted, and the edge bind, which
 * refuses hosting and is what the ngrok tunnel forwards to. The tunnel is started
 * only when an ngrok authtoken is supplied; without one the relay is whatever its
 * two binds are reachable from, and `--edge-hostname` is how you put your own
 * proxy in front of guests.
 */
import { parseArgs } from "node:util";
import { forward } from "@ngrok/ngrok";
import { ENVELOPE_HEADER_LENGTH, type RelayControlToGuest, type RelayControlToHost } from "@oh-my-pi/pi-wire";
import { EMBEDDED_FILES } from "./dist-embed.generated";
import { buildTrafficPolicy } from "./policy";

/** Injected by `bun build --define BUILD_VERSION`. Absent in a plain `bun relay.ts` run. */
declare const BUILD_VERSION: string | undefined;
const VERSION = typeof BUILD_VERSION === "string" ? BUILD_VERSION : "dev";

const ROOM_PATH = /^\/r\/([A-Za-z0-9_-]{10,64})$/;
const MAX_PAYLOAD = 32 * 1024 * 1024;
const BACKPRESSURE_LIMIT = 8 * 1024 * 1024;
const PING_INTERVAL_MS = 30_000;

/** collab-web, compiled into the binary by `with { type: "file" }` imports. */
const INDEX_HTML = EMBEDDED_FILES["/index.html"];

interface SocketData {
	roomId: string;
	role: "host" | "guest";
	/** Assigned on open for guests. The host stays 0. */
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
	/** Port the edge bind listens on, 0 for ephemeral. Hosting is refused there. */
	edgePort?: number;
	/** Address of the edge bind. Loopback keeps it reachable only by this process's tunnel. */
	edgeHostname?: string;
}

export interface RelayHandle {
	/** The hosting bind, `role=host` only. */
	hostUrl: string;
	hostPort: number;
	/** The edge bind, `role=guest` only; the tunnel's origin when one is running. */
	guestUrl: string;
	guestPort: number;
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

	const sendControlMessage = (ws: RelaySocket, msg: RelayControlToHost | RelayControlToGuest): void => {
		send(ws, JSON.stringify(msg));
	};

	/**
	 * `hosting` is false on the listener the tunnel forwards to, and the socket a
	 * request arrived on is the whole discriminator. The ngrok agent runs in this
	 * process and dials 127.0.0.1, so an edge-forwarded request and a genuinely
	 * local one are indistinguishable by source address.
	 *
	 * Reachability of the hosting bind is therefore the entire hosting rule.
	 * The `opts.hostname` decides who may host, and the default keeps that to loopback.
	 */
	const route = (req: Request, srv: Bun.Server<SocketData>, hosting: boolean): Response | undefined => {
		const url = new URL(req.url);
		if (url.pathname === "/healthz") {
			return new Response("ok");
		}

		const match = ROOM_PATH.exec(url.pathname);
		if (match) {
			const role = url.searchParams.get("role");
			if (role !== "host" && role !== "guest") {
				return new Response("not found", { status: 404 });
			}
			// Mirrors the edge's own host rule, so a host attempt gets the same answer
			// whether the policy caught it or it arrived here through a proxy.
			if (role === "host" && !hosting) {
				return new Response("hosting is not available here", { status: 403 });
			}
			const data: SocketData = { roomId: match[1]!, role, peerId: 0 };
			if (srv.upgrade(req, { data })) {
				return undefined;
			}
			return new Response("websocket upgrade required", { status: 426 });
		}

		return serveStatic(url.pathname);
	};

	const websocket: Bun.WebSocketHandler<SocketData> = {
		maxPayloadLength: MAX_PAYLOAD,
		// Server pings every 30 s, so this only has to outlast that round trip.
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
			sendControlMessage(room.host, { t: "peer-joined", peer: peerId });

			console.log(`room ${roomId}: peer ${peerId} joined`);
		},
		message(ws: RelaySocket, message: string | Buffer): void {
			if (typeof message === "string") {
				return; // clients never send TEXT
			}

			const room = rooms.get(ws.data.roomId);
			if (!room || message.byteLength < ENVELOPE_HEADER_LENGTH) {
				return;
			}

			if (ws.data.role === "host") {
				const peerId = message.readUInt32BE(0);
				if (peerId === 0) {
					for (const guest of room.guests.values()) {
						send(guest, message);
					}
				} else {
					const guest = room.guests.get(peerId);
					if (guest) {
						send(guest, message);
					}
				}
				return;
			}

			message.writeUInt32BE(ws.data.peerId, 0);
			send(room.host, message);
		},
		close(ws: RelaySocket): void {
			const { roomId, role, peerId } = ws.data;
			const room = rooms.get(roomId);
			if (!room) {
				return;
			}

			if (role === "host") {
				// Rejected second host: the live room is not ours to tear down.
				if (room.host !== ws) {
					return;
				}
				rooms.delete(roomId);
				for (const guest of room.guests.values()) {
					sendControlMessage(guest, ROOM_CLOSED);
					guest.close(4001, "room closed");
				}
				console.log(`room ${roomId} closed (${room.guests.size} guests dropped)`);
				room.guests.clear();
				return;
			}
			if (room.guests.delete(peerId)) {
				sendControlMessage(room.host, { t: "peer-left", peer: peerId });
				console.log(`room ${roomId}: peer ${peerId} left`);
			}
		},
	};

	const hostSocket = Bun.serve<SocketData>({
		port: opts.port ?? 7466,
		hostname: opts.hostname ?? "127.0.0.1",
		fetch: (req, srv) => route(req, srv, true),
		websocket,
	});
	// Loopback by default: the tunnel's agent runs in this process and dials it
	// locally. Widening it exposes guests to that network without the edge's policy.
	const guestSocket = Bun.serve<SocketData>({
		port: opts.edgePort ?? 0,
		hostname: opts.edgeHostname ?? "127.0.0.1",
		fetch: (req, srv) => route(req, srv, false),
		websocket,
	});

	const pinger = setInterval(() => {
		for (const room of rooms.values()) {
			room.host.ping();
			for (const guest of room.guests.values()) {
				guest.ping();
			}
		}
	}, PING_INTERVAL_MS);

	const hostPort = hostSocket.port ?? 0;
	const guestPort = guestSocket.port ?? 0;
	return {
		// Bun canonicalises the bind address, so an IPv6 literal comes out bracketed
		// and the printed url is one the operator can paste.
		hostUrl: `ws://${hostSocket.url.host}`,
		hostPort: hostPort,
		guestUrl: `ws://${guestSocket.url.host}`,
		guestPort: guestPort,
		stop(): void {
			clearInterval(pinger);
			for (const room of rooms.values()) {
				for (const guest of room.guests.values()) {
					sendControlMessage(guest, ROOM_CLOSED);
					guest.close(4001, "room closed");
				}
				room.host.close(1001, "relay shutting down");
			}
			rooms.clear();
			hostSocket.stop(true);
			guestSocket.stop(true);
		},
	};
}

/** Exact-match routing, so there is no traversal surface. Unknown paths get the SPA shell. */
function serveStatic(pathname: string): Response {
	const file = EMBEDDED_FILES[pathname] ?? INDEX_HTML;
	if (!file) {
		return new Response("not found", { status: 404 });
	}
	return new Response(Bun.file(file));
}

/**
 * The tunnel's agent runs in this process and dials the edge bind directly, so a
 * wildcard bind — which has no address to dial — becomes loopback, which it contains.
 */
export function edgeDialAddress(guestUrl: string): string {
	const { hostname, port } = new URL(guestUrl);
	return `${hostname === "0.0.0.0" || hostname === "[::]" ? "127.0.0.1" : hostname}:${port}`;
}

async function startNgrok(
	relay: RelayHandle,
	url: string | undefined,
	policy: object,
	authtoken: string,
): Promise<void> {
	const listener = await forward({
		addr: edgeDialAddress(relay.guestUrl),
		authtoken,
		domain: url ? new URL(url).hostname : undefined,
		traffic_policy: JSON.stringify(policy),
	});
	const publicUrl = listener.url();
	if (!publicUrl) {
		throw new Error("ngrok returned no url");
	}

	console.log(`ngrok endpoint: ${publicUrl}`);
}

/**
 * ngrok's ERR_NGROK_105 quotes the supplied authtoken back verbatim, so printing
 * its message writes the account credential to the log. We still need the rest of
 * the message to tell a bad token from a bad domain, so redact the value rather than
 * drop the error.
 */
export function redactToken(message: string, token: string): string {
	if (token.length === 0) {
		return message;
	}

	return message.split(token).join("***");
}

/** `null` for anything that is not a whole number in `0..max`. */
export function parseBoundedInt(raw: string, max: number): number | null {
	// Digits only (no trimming), so "-1", "1.5", "1e3", "", " 8080 " and "zzz" are
	// all rejected rather than silently becoming a negative, truncation, NaN, or valid.
	if (!/^\d+$/.test(raw)) {
		return null;
	}
	const n = Number(raw);
	return Number.isSafeInteger(n) && n <= max ? n : null;
}

const HELP = `omp-ngrok-relay ${VERSION} — content-blind relay for omp collab sessions

  --port <n>            port of the hosting bind (default 7466)
  --hostname <host>     address of the hosting bind (default 127.0.0.1); whoever can
                        reach it can host, so 0.0.0.0 opens hosting to that network
  --max-guests <n>      per-room guest cap, 0 = unlimited (default 0)
  --edge-port <n>       port of the guest-only edge bind (default 0, ephemeral)
  --edge-hostname <h>   address of the edge bind (default 127.0.0.1); widen it to put
                        your own proxy, or a LAN, in front of guests
  --ngrok-url <url>     reserved ngrok URL, e.g. https://collab.example.com
  --oauth-allow <who>   permitted google identity, repeatable or comma-separated:
                        user@example.com for one address, @example.com for a domain
  --authtoken-file <p>  file holding the ngrok authtoken; wins over NGROK_AUTHTOKEN
  --version, --help

The ngrok tunnel is optional. Given an authtoken (NGROK_AUTHTOKEN or --authtoken-file) the relay
publishes the edge bind through ngrok; without one it starts local-only, and --ngrok-url and
--oauth-allow are refused because nothing would enforce them. --authtoken-file wins over the
environment, and keeps the token out of the process environment and out of the argument list.

OAuth is optional too, and lives at the ngrok edge. Each --oauth-allow admits one google identity;
with none the endpoint is anonymous — anyone holding the URL and a room token can join, and
terminal guests (omp join) work again, which OAuth otherwise makes impossible.

Two binds. The hosting bind accepts role=host and role=guest, unauthenticated — reaching it *is*
the host's credential, so keep it as narrow as the deployment allows. The edge bind refuses
role=host, so hosting never traverses the tunnel no matter what the edge does. Those rules are
compiled in and only the allowlist is a flag; see policy.ts.`;

/** Every flag this binary accepts, as `parseArgs` hands them back. */
interface Flags {
	port: string;
	hostname: string;
	"max-guests": string;
	"edge-port": string;
	"edge-hostname": string;
	"ngrok-url"?: string;
	"oauth-allow": string[];
	"authtoken-file"?: string;
	version: boolean;
	help: boolean;
}

function parseFlags(): Flags {
	try {
		return parseArgs({
			args: Bun.argv.slice(2),
			options: {
				port: { type: "string", default: "7466" },
				hostname: { type: "string", default: "127.0.0.1" },
				"max-guests": { type: "string", default: "0" },
				"edge-port": { type: "string", default: "0" },
				"edge-hostname": { type: "string", default: "127.0.0.1" },
				"ngrok-url": { type: "string" },
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

	const port = parseBoundedInt(values.port, 65535);
	if (port === null) {
		console.error(`--port ${values.port}: expected an integer 0-65535`);
		process.exit(1);
	}
	const edgePort = parseBoundedInt(values["edge-port"], 65535);
	if (edgePort === null) {
		console.error(`--edge-port ${values["edge-port"]}: expected an integer 0-65535`);
		process.exit(1);
	}
	const maxGuests = parseBoundedInt(values["max-guests"], Number.MAX_SAFE_INTEGER);
	if (maxGuests === null) {
		console.error(`--max-guests ${values["max-guests"]}: expected a non-negative integer`);
		process.exit(1);
	}

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

	const allow = values["oauth-allow"]
		.flatMap((v) => v.split(","))
		.map((v) => v.trim())
		.filter((v) => v.length > 0);

	// The traffic policy is the tunnel's entire access control, so it is built and
	// validated before anything binds. No token means no tunnel and no policy, which
	// leaves the edge-only flags with nothing to enforce them: refuse rather than
	// run on with an allowlist the operator believes is in force.
	let policy: object | undefined;
	if (authtoken.length === 0) {
		const orphaned = [values["ngrok-url"] !== undefined && "--ngrok-url", allow.length > 0 && "--oauth-allow"].filter(
			(f): f is string => f !== false,
		);
		if (orphaned.length > 0) {
			console.error(
				`${orphaned.join(" and ")}: no ngrok tunnel to enforce them. Set NGROK_AUTHTOKEN or pass --authtoken-file.`,
			);
			process.exit(1);
		}
	} else {
		try {
			policy = buildTrafficPolicy(allow);
		} catch (err) {
			console.error(err instanceof Error ? err.message : String(err));
			process.exit(1);
		}
	}

	const relay = startRelay({
		port,
		hostname: values.hostname,
		maxGuests,
		edgePort,
		edgeHostname: values["edge-hostname"],
	});
	console.log(`omp-ngrok-relay ${VERSION} listening on ${relay.hostUrl}`);
	console.log(`  hosting bind:  ${relay.hostUrl}`);
	console.log(`     omp config set collab.relayUrl ${relay.hostUrl}`);
	console.log(`     or one-shot, no config:  /collab ${relay.hostUrl}`);
	console.log(`  edge bind (guests only):  ${relay.guestUrl}`);

	if (policy === undefined) {
		console.log("  no ngrok authtoken: local only, guests reach the binds above or nothing at all.");
	} else {
		try {
			await startNgrok(relay, values["ngrok-url"], policy, authtoken);
		} catch (err) {
			console.error(`ngrok: ${redactToken(err instanceof Error ? err.message : String(err), authtoken)}`);
			relay.stop();
			process.exit(1);
		}
		if (allow.length === 0) {
			console.log("  no --oauth-allow: the endpoint is anonymous, anyone with a room token can join.");
		}
	}

	const shutdown = (): void => {
		relay.stop();
		process.exit(0);
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
