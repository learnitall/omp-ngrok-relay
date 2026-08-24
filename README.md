# omp-ngrok-relay

Self-hostable relay for [omp](https://github.com/can1357/oh-my-pi) `/collab` sessions, with the
browser guest client compiled into the binary and published on an [ngrok](https://ngrok.com)
endpoint.

`/collab` shares a live omp session with other terminals and browsers. By default that traffic goes
through `wss://my.omp.sh`. This is a drop-in replacement you run yourself.

```sh
omp config set collab.relayUrl wss://collab.example.com
```

## What it does, and what it can't

The relay is a **content-blind switchboard**. Every session payload is sealed with AES-256-GCM by
the clients before it reaches the socket, so the relay only ever sees:

- room ids and connection counts,
- opaque ciphertext frames and their sizes,
- a 4-byte routing prefix naming the target peer.

It cannot read a session, and a bug in it cannot corrupt one — the worst it can do is misroute or
drop frames.

## Quick start

```sh
export NGROK_AUTHTOKEN=...      # https://dashboard.ngrok.com/get-started/your-authtoken
bun install
bun run client                  # build the pinned collab-web guest client into dist/
bun run build                   # compile bin/omp-ngrok-relay with the client embedded
./bin/omp-ngrok-relay
```

Or without cloning anything:

```sh
NGROK_AUTHTOKEN=... nix run github:learnitall/omp-ngrok-relay
```

Either way it prints the endpoint and how to point omp at it:

```
omp-ngrok-relay 0.1.0 listening on ws://127.0.0.1:7466 (22 embedded client files)
ngrok endpoint: https://swift-mouse-42.ngrok-free.app
  relay:  omp config set collab.relayUrl wss://swift-mouse-42.ngrok-free.app
  or one-shot, no config:  /collab wss://swift-mouse-42.ngrok-free.app
```

Guests join from a terminal (`omp join`) or from that URL in a browser.

## Why the tunnel is not optional

Plain `ws://` is only accepted for localhost — omp's link parser rejects it for any other host — so
a relay other people can reach needs TLS, which means a certificate, a DNS record and a reverse
proxy in front. ngrok collapses all three into the process itself, so there is one thing to run and
one thing to trust.

A local-only mode would be a relay nobody can join, so there isn't one: with no `NGROK_AUTHTOKEN`
the binary exits before it binds a port. The local listener is still there as the tunnel's origin,
and guests on the same machine can use `ws://127.0.0.1:7466` directly.

For a stable address, reserve a domain on your ngrok account and name it:

```sh
./bin/omp-ngrok-relay --ngrok-url https://collab.example.com
```

Its DNS must point at ngrok (`ERR_NGROK_319` otherwise). Without the flag you get whatever URL your
account defaults to, which changes between runs on the free plan.

## Security model

**There is no authentication, by design.** The collab link *is* the credential:

- the link carries `base64url(32-byte AES-256-GCM room key ‖ 16-byte write token)`,
- the **host** — not the relay — verifies that write token with a timing-safe compare and gates
  every mutating frame (prompt, abort, agent control) on it,
- a view-only link is the bare key: it decrypts the session but cannot steer it.

Adding endpoint auth would break every client. `parseCollabLink` normalises links through
`url.origin`, which drops userinfo, so `wss://user:pass@host/...` silently loses the credentials;
neither `omp join` nor the browser client can set headers on a WebSocket upgrade; and OAuth needs a
redirect a WebSocket client cannot perform.

What an open relay actually risks is **abuse** — anyone who learns the hostname can open rooms and
push bytes through it. That is a rate-limiting problem, so the ngrok endpoint ships with a compiled-in
traffic policy ([`policy.ts`](./policy.ts)) that caps handshakes per client IP and 404s any path
outside `/`, `/healthz`, `/r/*`, and the client's static assets. It is deliberately not a CLI flag:
rules that protect the endpoint should not be swappable out of band.

If you want real access control, put an `oauth` action on `/` only — the browser UI sits behind a
login while `/r/*` stays open to terminal guests, still protected by the link secret.

## The browser client

`bun run client` builds [`packages/collab-web`](https://github.com/can1357/oh-my-pi/tree/main/packages/collab-web)
from the oh-my-pi commit pinned in [`client.json`](./client.json) and drops it in `dist/`, where
`scripts/embed-dist.ts` turns it into `with { type: "file" }` imports that Bun compiles into the
binary. One artifact, no asset directory to deploy, no path-traversal surface (routing is an
exact-match map).

The client is not vendored so that the served UI and the wire contract move together and
deliberately. Skip the step and the relay still works — it just serves nothing at `/`.

`nix build .#relay` embeds the same client, off the same pin: `fetchFromGitHub` does a blobless
partial clone (`--filter=blob:none`) with a cone-mode sparse checkout of six directories, which
turns a 235 MB monorepo into ~10 MB of source, and `nix build .#client` builds just the `dist/`.
Both are fixed-output derivations, so `client.json` carries their hashes next to the commit:

| field | covers | bump it when |
|---|---|---|
| `srcHash` | the sparse checkout | `commit` or `sparseCheckout` changes |
| `distHash` | the built `dist/` | the pin moves, or nixpkgs' bun bundles differently |

Nix reports the correct hash on mismatch. The sparse list is the client plus the workspace members
`bun.lock` resolves its dependencies to — leave one out and bun silently falls back to the registry
or refuses to resolve at all.

## Protocol

Implements the relay half of [omp's collab contract](https://github.com/can1357/oh-my-pi/blob/main/docs/collab.md).

| | |
|---|---|
| `GET /r/<roomId>?role=host\|guest` | WebSocket upgrade; `roomId` is `[A-Za-z0-9_-]{10,64}` |
| `GET /healthz` | liveness |
| `GET /` | embedded guest client (SPA fallback for unknown paths) |
| host → relay | `[4B BE peerId][sealed]`; `0` broadcasts, `N` targets guest N; forwarded byte-for-byte |
| guest → relay | first 4 bytes rewritten to the sender's peerId, forwarded to the host |
| control → host | `{"t":"peer-joined","peer":N}`, `{"t":"peer-left","peer":N}` |
| host disconnect | `{"t":"room-closed"}` to every guest, then close `4001` |
| close codes | `4001` room closed · `4004` no such room · `4009` host already connected · `4029` room full |

Frame shapes and the envelope header come from [`@oh-my-pi/pi-wire`](https://www.npmjs.com/package/@oh-my-pi/pi-wire),
the same package the clients compile against, so the contract cannot drift silently.

## Options

```
--port <n>          local origin port the tunnel forwards to (default 7466)
--hostname <host>   local bind address (default 127.0.0.1)
--max-guests <n>    per-room guest cap, 0 = unlimited (default 0)
--ngrok-url <url>   reserved ngrok URL, e.g. https://collab.example.com
--version, --help
```

`NGROK_AUTHTOKEN` is required; there is no flag for it, since ngrok's own SDK reads it.

## Deployment

**systemd:**

```ini
[Service]
Environment=NGROK_AUTHTOKEN=...
ExecStart=/usr/local/bin/omp-ngrok-relay --ngrok-url https://collab.example.com
Restart=always
DynamicUser=yes

[Install]
WantedBy=multi-user.target
```

**Container** (Linux hosts; `dockerTools` would otherwise package the host's Mach-O binary):

```sh
nix build .#container && docker load < result
docker run -p 7466:7466 -e NGROK_AUTHTOKEN omp-ngrok-relay:0.1.0
```

**Releases.** Tagging `v*` cross-compiles binaries for linux and darwin on x64/arm64 (glibc and
musl), publishes them with checksums, and pushes the container image to ghcr.io.

## Development

```sh
nix develop     # bun, typos, git, plus `dev`, `client`, and `check` commands
check           # typecheck, lint, spellcheck, test
nix fmt         # treefmt: biome, nixfmt, typos
nix flake check
nix build .#client   # just the guest client, into result/
```

Tests cover the parts that are easy to get quietly wrong: a 4 MiB frame surviving the payload cap
with its peerId stamped and bytes intact, targeted frames not leaking to other guests, and the
`4004`/`4009`/`room-closed` paths.

### Nix hashes

`nodeModulesHash` in [`flake.nix`](./flake.nix) is per system, because `bun install` resolves
`@ngrok/ngrok`'s napi prebuild for the host platform only. `aarch64-darwin`, `aarch64-linux` and
`x86_64-linux` are recorded; `x86_64-darwin` is not. Anything else fails at eval with instructions.

A machine of that architecture is not required. The hash is a NAR hash of what `bun install`
produces, so a container of that platform can produce the tree and nix can hash it anywhere:

```sh
tar -cf - package.json bun.lock |
  podman run --rm -i --platform linux/amd64 docker.io/oven/bun:1.3.13 \
    sh -c 'mkdir /w && tar xf - -C /w && cd /w &&
           bun install --frozen-lockfile 1>&2 && tar -cf - node_modules' |
  tar -x -C /tmp/nm
nix hash path --mode nar --type sha256 --sri /tmp/nm/node_modules
```

Use the bun release nixpkgs pins, or the tree can differ. Running nix in the container works too —
set the entry to `lib.fakeHash`, `nix build path:/src#relay`, and read the hash it reports — but
only if the VM backend can emulate that architecture. On macOS an `applehv` podman machine (Rosetta)
runs nix; a `libkrun` machine falls back to qemu user-mode, where nix segfaults on startup and only
plain binaries such as bun still run. Under emulation nix also needs `--option filter-syscalls
false`, since it cannot load its seccomp filter there.

**A stale entry is invisible locally.** A fixed-output derivation is addressed by the hash you
declare: once a path with that hash is in the store, nix reuses it and never re-runs `bun install`.
A dependency bump can sit unnoticed for as long as that path survives, and surface only on a fresh
store — CI, or a rename that changes the derivation name. To force the check, set the entry to
`lib.fakeHash` or recompute it with the recipe above.

## Credits

The protocol, the reference implementation this follows
([`scripts/local-relay.ts`](https://github.com/can1357/oh-my-pi/blob/main/packages/collab-web/scripts/local-relay.ts)),
and the web client are all from [can1357/oh-my-pi](https://github.com/can1357/oh-my-pi).

MIT.
