import { afterAll, beforeAll, expect, test } from "bun:test";
import { networkInterfaces } from "node:os";
import { ENVELOPE_HEADER_LENGTH } from "@oh-my-pi/pi-wire";
import { type RelayHandle, startRelay } from "./relay";

const ROOM = "TESTROOMabcdef";
let relay: RelayHandle;

beforeAll(() => {
	relay = startRelay({ port: 0 });
});
afterAll(() => relay.stop());

type Frame = string | Uint8Array;

interface Peer {
	ws: WebSocket;
	/** Next frame in arrival order; buffers so nothing is lost between awaits. */
	next(): Promise<Frame>;
}

async function dial(role: "host" | "guest", room = ROOM, base = relay.url): Promise<Peer> {
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

	const opened = Promise.withResolvers<void>();
	ws.onopen = () => opened.resolve();
	ws.onclose = (e) => opened.reject(new Error(`closed ${e.code}`));
	await opened.promise;

	return {
		ws,
		next(): Promise<Frame> {
			const buffered = queue.shift();
			if (buffered !== undefined) return Promise.resolve(buffered);
			const { promise, resolve } = Promise.withResolvers<Frame>();
			waiting.push(resolve);
			return promise;
		},
	};
}

/** Resolves with the close code the relay sends. */
function closeCode(url: string): Promise<number> {
	const { promise, resolve } = Promise.withResolvers<number>();
	const ws = new WebSocket(url);
	ws.onclose = (e) => resolve(e.code);
	return promise;
}

function frame(peer: number, size: number): Uint8Array {
	const msg = new Uint8Array(ENVELOPE_HEADER_LENGTH + size);
	new DataView(msg.buffer).setUint32(0, peer, false);
	for (let i = 0; i < size; i++) msg[ENVELOPE_HEADER_LENGTH + i] = i & 0xff;
	return msg;
}

// A multi-megabyte sealed frame (snapshot chunk, entry with an inline image)
// must survive the relay rather than tripping the default payload cap.
test("relays a 4 MiB frame, stamps the sender's peerId, and keeps targeted frames targeted", async () => {
	const host = await dial("host");
	const guest1 = await dial("guest");
	expect(await host.next()).toBe('{"t":"peer-joined","peer":1}');
	const guest2 = await dial("guest");
	expect(await host.next()).toBe('{"t":"peer-joined","peer":2}');

	const big = frame(0, 4 << 20);
	guest2.ws.send(big);
	const got = (await host.next()) as Uint8Array;
	expect(got.byteLength).toBe(big.byteLength);
	expect(new DataView(got.buffer).getUint32(0, false)).toBe(2);
	expect(Bun.deepEquals(got.subarray(ENVELOPE_HEADER_LENGTH), big.subarray(ENVELOPE_HEADER_LENGTH))).toBe(true);

	// Targeted to peer 2, then a broadcast: guest1's first frame must be the
	// broadcast, so a leaked targeted frame fails here.
	const targeted = frame(2, 1024);
	const broadcast = frame(0, 32);
	host.ws.send(targeted);
	host.ws.send(broadcast);
	expect(((await guest2.next()) as Uint8Array).byteLength).toBe(targeted.byteLength);
	expect(((await guest1.next()) as Uint8Array).byteLength).toBe(broadcast.byteLength);

	// Host gone: guests are told, then closed with 4001.
	host.ws.close();
	expect(await guest1.next()).toBe('{"t":"room-closed"}');
	guest1.ws.close();
	guest2.ws.close();
});

test("a guest for a room with no host is rejected with 4004", async () => {
	expect(await closeCode(`${relay.url}/r/NOSUCHROOMxyz?role=guest`)).toBe(4004);
});

test("a second host for a live room is rejected with 4009", async () => {
	const host = await dial("host", "SECONDHOSTroom");
	expect(await closeCode(`${relay.url}/r/SECONDHOSTroom?role=host`)).toBe(4009);
	host.ws.close();
});

// The CLI cannot be smoke-tested without an ngrok token, so the HTTP surface
// is covered here, against the library.
test("serves /healthz", async () => {
	const res = await fetch(`http://127.0.0.1:${relay.port}/healthz`);
	expect(res.status).toBe(200);
	expect(await res.text()).toBe("ok");
});

// Deep links (`/#ws://host/r/<id>.<key>`) reach the server as unknown paths and
// must render the client shell, not a 404. Holds either way when no client is
// embedded, which is what a bare `bun test` sees.
test("unknown paths mirror the client shell", async () => {
	const base = `http://127.0.0.1:${relay.port}`;
	const [root, deep] = await Promise.all([fetch(`${base}/`), fetch(`${base}/some/deep/link`)]);
	expect(deep.status).toBe(root.status);
	expect(await deep.text()).toBe(await root.text());
});

// The listener a request arrives on is the whole hosting rule, and it has to be:
// the ngrok agent dials 127.0.0.1, so an edge-forwarded request and a genuinely
// local one are indistinguishable by source address.
test("the tunnel's listener refuses role=host but the hosting bind accepts it", async () => {
	const path = "/r/EDGEHOSTroomx?role=host";
	const edge = await fetch(`http://127.0.0.1:${relay.edgePort}${path}`);
	expect(edge.status).toBe(403);

	// 426, not 403: the same request on the hosting bind gets as far as the
	// upgrade, so the 403 above is the host check and not a routing accident.
	const local = await fetch(`http://127.0.0.1:${relay.port}${path}`);
	expect(local.status).toBe(426);
});

test("a browser guest through the tunnel joins a room on the hosting bind", async () => {
	const room = "EDGEGUESTroom";
	const host = await dial("host", room);
	const guest = await dial("guest", room, relay.edgeUrl);
	expect(await host.next()).toBe('{"t":"peer-joined","peer":1}');

	// Both listeners share one room map, or the frame never arrives.
	const payload = frame(0, 64);
	guest.ws.send(payload);
	expect(new DataView(((await host.next()) as Uint8Array).buffer).getUint32(0, false)).toBe(1);

	guest.ws.close();
	host.ws.close();
});

// Browser guests arrive through the tunnel, so its listener must serve the
// client shell and the probe the traffic policy leaves unauthenticated.
test("the tunnel's listener still serves the client and /healthz", async () => {
	const base = `http://127.0.0.1:${relay.edgePort}`;
	const [health, shell] = await Promise.all([fetch(`${base}/healthz`), fetch(`${base}/some/deep/link`)]);
	expect(await health.text()).toBe("ok");
	expect(shell.status).toBe(200);
});

const lan = Object.values(networkInterfaces())
	.flat()
	.find((i) => i && i.family === "IPv4" && !i.internal)?.address;

// Reaching the hosting bind *is* the host's credential, so widening the bind
// widens hosting on purpose — that is what makes hosting from outside a
// container possible. The tunnel's listener still refuses, whatever the bind.
test.skipIf(!lan)("a wide bind lets a remote peer host, but never through the tunnel", async () => {
	const wide = startRelay({ port: 0, hostname: "0.0.0.0" });
	try {
		const path = "/r/WIDEBINDroomx?role=host";
		const remote = await fetch(`http://${lan}:${wide.port}${path}`);
		expect(remote.status).toBe(426);

		const tunnel = await fetch(`http://127.0.0.1:${wide.edgePort}${path}`);
		expect(tunnel.status).toBe(403);
	} finally {
		wide.stop();
	}
});

// A guest reaching a wide hosting bind directly has bypassed the edge, so it has
// bypassed OAuth too. That is inherent to exposing the bind, and the reason the
// default is loopback.
test.skipIf(!lan)("a wide bind serves guests without oauth, since oauth lives at the edge", async () => {
	const wide = startRelay({ port: 0, hostname: "0.0.0.0" });
	try {
		const res = await fetch(`http://${lan}:${wide.port}/r/WIDEGUESTroom?role=guest`);
		expect(res.status).toBe(426);
	} finally {
		wide.stop();
	}
});
