import { afterAll, beforeAll, expect, test } from "bun:test";
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

async function dial(role: "host" | "guest", room = ROOM): Promise<Peer> {
	const ws = new WebSocket(`${relay.url}/r/${room}?role=${role}`);
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
