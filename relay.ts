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
 */
import { parseArgs } from "node:util";
import { ENVELOPE_HEADER_LENGTH, type RelayControlToGuest, type RelayControlToHost } from "@oh-my-pi/pi-wire";
import { EMBEDDED_FILES } from "./dist-embed.generated";
import { TRAFFIC_POLICY } from "./policy";

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
	port?: number;
	hostname?: string;
	maxGuests?: number;
}

export interface RelayHandle {
	/** ws://host:port — append `/r/<roomId>?role=…` to connect. */
	url: string;
	port: number;
	/** Closes every room and stops the server. */
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

	const server = Bun.serve<SocketData>({
		port: opts.port ?? 7466,
		hostname: opts.hostname ?? "127.0.0.1",
		fetch(req, srv): Response | undefined {
			const url = new URL(req.url);
			if (url.pathname === "/healthz") return new Response("ok");

			const match = ROOM_PATH.exec(url.pathname);
			if (match) {
				const role = url.searchParams.get("role");
				if (role !== "host" && role !== "guest") return new Response("not found", { status: 404 });
				const data: SocketData = { roomId: match[1]!, role, peerId: 0 };
				if (srv.upgrade(req, { data })) return undefined;
				return new Response("websocket upgrade required", { status: 426 });
			}

			return serveStatic(url.pathname);
		},
		websocket: {
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
		},
	});

	const pinger = setInterval(() => {
		for (const room of rooms.values()) {
			room.host.ping();
			for (const guest of room.guests.values()) guest.ping();
		}
	}, PING_INTERVAL_MS);

	const port = server.port ?? 0;
	return {
		url: `ws://${server.hostname}:${port}`,
		port,
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
			server.stop(true);
		},
	};
}

/** Exact-match routing, so there is no traversal surface; unknown paths get the SPA shell. */
function serveStatic(pathname: string): Response {
	const file = EMBEDDED_FILES[pathname] ?? INDEX_HTML;
	if (!file) return new Response("not found", { status: 404 });
	return new Response(Bun.file(file));
}

async function startNgrok(port: number, url: string | undefined): Promise<void> {
	// Dynamic on purpose: @ngrok/ngrok is a napi native addon with per-platform
	// prebuilds. Loading it statically would make a missing/incompatible binary
	// fatal for every run, including the ones that never asked for a tunnel.
	const ngrok = await import("@ngrok/ngrok");
	const listener = await ngrok.forward({
		addr: `127.0.0.1:${port}`,
		authtoken_from_env: true,
		domain: url ? new URL(url).hostname : undefined,
		traffic_policy: JSON.stringify(TRAFFIC_POLICY),
	});
	const publicUrl = listener.url();
	if (!publicUrl) throw new Error("ngrok returned no url");
	const host = new URL(publicUrl).host;
	console.log(`ngrok endpoint: ${publicUrl}`);
	console.log(`  relay:  omp config set collab.relayUrl wss://${host}`);
	console.log(`  or one-shot, no config:  /collab wss://${host}`);
}

const HELP = `omp-collab-relay ${VERSION} — content-blind relay for omp collab sessions

  --port <n>          local listen port (default 7466)
  --hostname <host>   local bind address (default 127.0.0.1)
  --max-guests <n>    per-room guest cap, 0 = unlimited (default 0)
  --ngrok             publish on a public ngrok endpoint (NGROK_AUTHTOKEN required)
  --ngrok-url <url>   reserved ngrok URL, e.g. https://collab.example.com
  --version, --help

The traffic policy applied to the ngrok endpoint is compiled in; see policy.ts.`;

if (import.meta.main) {
	const { values } = parseArgs({
		args: Bun.argv.slice(2),
		options: {
			port: { type: "string", default: "7466" },
			hostname: { type: "string", default: "127.0.0.1" },
			"max-guests": { type: "string", default: "0" },
			ngrok: { type: "boolean", default: false },
			"ngrok-url": { type: "string" },
			version: { type: "boolean", default: false },
			help: { type: "boolean", default: false },
		},
	});

	if (values.help) {
		console.log(HELP);
		process.exit(0);
	}
	if (values.version) {
		console.log(VERSION);
		process.exit(0);
	}

	const relay = startRelay({
		port: Number(values.port),
		hostname: values.hostname,
		maxGuests: Number(values["max-guests"]),
	});
	const embedded = Object.keys(EMBEDDED_FILES).length;
	console.log(
		`omp-collab-relay ${VERSION} listening on ${relay.url}` +
			(embedded > 0 ? ` (${embedded} embedded client files)` : " (no embedded web client)"),
	);

	if (values.ngrok) {
		await startNgrok(relay.port, values["ngrok-url"]);
	}

	const shutdown = (): void => {
		relay.stop();
		process.exit(0);
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
