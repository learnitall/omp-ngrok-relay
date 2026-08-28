# omp-ngrok-relay

Self-hostable relay for [omp](https://github.com/can1357/oh-my-pi) `/collab` sessions, with the
browser guest client compiled into the binary and published on an [ngrok](https://ngrok.com)
endpoint.

`/collab` shares a live omp session with other terminals and browsers. By default that traffic goes
through `wss://my.omp.sh`. This is a replacement you run yourself, with two behavioural differences:
**hosting is restricted to whoever can reach the hosting bind** (loopback by default), and **browser
guests must sign in through OAuth** while terminal guests (`omp join`) cannot connect at all. See
[Security model](#security-model).

So the host points omp at the hosting bind, not at the public endpoint:

```sh
omp config set collab.relayUrl ws://127.0.0.1:7466
```

## What it does, and what it can't

The relay is a **content-blind switchboard**. Every session payload is sealed with AES-256-GCM by
the clients before it reaches the socket, so the relay only ever sees:

- room ids and connection counts,
- opaque ciphertext frames and their sizes,
- a 4-byte routing prefix naming the target peer.

It cannot read a session, and a bug in it cannot corrupt one — the worst it can do is misroute or
drop frames.

It also cannot authenticate a browser guest — that is enforced one layer out, at the ngrok edge.
What it *does* enforce itself is who may host: the tunnel gets its own listener that never accepts a
host upgrade, so `role=host` is reachable only on the hosting bind.

## Quick start

```sh
export NGROK_AUTHTOKEN=...      # or --authtoken-file; see Options
bun install
bun run client                  # build the pinned collab-web guest client into dist/
bun run build                   # compile bin/omp-ngrok-relay with the client embedded
./bin/omp-ngrok-relay --oauth-allow you@gmail.com
```

Or without cloning anything:

```sh
NGROK_AUTHTOKEN=... nix run github:learnitall/omp-ngrok-relay -- --oauth-allow you@gmail.com
```

Either way it prints both doors:

```
omp-ngrok-relay 0.1.0 listening on ws://127.0.0.1:7466 (22 embedded client files)
  hosting bind:  ws://127.0.0.1:7466
     omp config set collab.relayUrl ws://127.0.0.1:7466
     or one-shot, no config:  /collab ws://127.0.0.1:7466
  tunnel origin (guests only):  ws://127.0.0.1:59663
ngrok endpoint: https://swift-mouse-42.ngrok-free.app
  browser guests:  https://swift-mouse-42.ngrok-free.app  (sign in with google)
  hosting through the tunnel is refused; hosts use the hosting bind.
  terminal guests (`omp join`) cannot authenticate and will be rejected.
```

So: **omp hosts through the hosting bind**, and browser guests join from the ngrok URL after signing
in as an identity you allowed. **Terminal guests cannot join at all**, and **hosting never traverses
the tunnel.** See [Security model](#security-model) for both trades.

## Why the tunnel is not optional

Plain `ws://` is only accepted for localhost — omp's link parser rejects it for any other host — so
a relay other people can reach needs TLS, which means a certificate, a DNS record and a reverse
proxy in front. ngrok collapses all three into the process itself, so there is one thing to run and
one thing to trust.

A local-only mode would be a relay nobody can join, so there isn't one: with no authtoken the binary
exits before it binds a port. The tunnel gets its own ephemeral loopback listener as its origin,
while `--port`/`--hostname` are the bind omp hosts through.

For a stable address, reserve a domain on your ngrok account and name it:

```sh
./bin/omp-ngrok-relay --ngrok-url https://collab.example.com
```

Its DNS must point at ngrok (`ERR_NGROK_319` otherwise). Without the flag you get whatever URL your
account defaults to, which changes between runs on the free plan.

## Security model

Three separate questions, three separate answers: who may **open** a room, who may **join** one, and
who may **steer** the session inside it.

**Steering is gated by the link secret, inside the session.** The collab link carries
`base64url(32-byte AES-256-GCM room key ‖ 16-byte write token)`; the **host** — not the relay —
verifies that write token with a timing-safe compare and gates every mutating frame (prompt, abort,
agent control) on it. A view-only link is the bare key: it decrypts the session but cannot steer it.
This part is unchanged, and the relay is not involved in it.

**Opening a room is gated by reachability** — see [below](#hosting-is-gated-by-the-bind).

**Joining a room is gated by OAuth.** The compiled-in traffic policy
([`policy.ts`](./policy.ts)) puts an ngrok `oauth` action in front of `/`, the client's static
assets, and the `role=guest` WebSocket upgrade, then denies any identity outside `--oauth-allow`
with a 403. OAuth on its own only proves the visitor has an account with the provider, so the
allowlist is required and the relay refuses to start without one.

### Hosting is gated by the bind

`role=host` is accepted **only on the hosting bind**, and there is no credential for it beyond
reaching it. The relay binds two listeners over one room map:

| listener | address | accepts |
|---|---|---|
| hosting bind | `--hostname:--port`, default `127.0.0.1:7466` | `role=host`, `role=guest`, client, `/healthz` |
| tunnel origin | ephemeral loopback, not configurable | everything except `role=host` |

The split is the mechanism, and it exists because no address check could do the job. The ngrok agent
runs inside this process and dials `127.0.0.1`, so a request forwarded from the edge and a request
from a genuinely local client arrive from the *same source address* — the listener a request landed
on is the only thing that tells them apart.

So **`--hostname` is the hosting ACL.** The default keeps hosting to the relay's own machine.
Widening it deliberately widens hosting, which is how you host from outside a container:

```sh
# in the container: accept hosts from the container network
docker run -p 127.0.0.1:7466:7466 -e NGROK_AUTHTOKEN \
  omp-ngrok-relay:0.1.0 --hostname 0.0.0.0 --oauth-allow you@gmail.com

# on the docker host: omp hosts through the published port
omp config set collab.relayUrl ws://127.0.0.1:7466
```

Note the `127.0.0.1:` on the published port. Plain `-p 7466:7466` publishes on every interface,
which hands hosting to the whole network — the bind inside the container is wide *on purpose*, so
the narrowing has to happen at the publish.

Two layers enforce the rule, and they cover each other:

| layer | mechanism | catches |
|---|---|---|
| relay | the tunnel's listener refuses `role=host` | everything, including a tunnel pointed at the wrong listener |
| edge | traffic policy denies `role=host` with a 403 before the `oauth` action runs | remote host attempts, one hop earlier and cheaper |

**A guest that reaches the hosting bind directly has bypassed OAuth**, because OAuth lives at the
edge. That is inherent to exposing the bind and is the reason the default is loopback: widen it only
to a network you would let host anyway.

### What this costs: `omp join`

**Terminal guests no longer work.** `omp join` speaks WebSocket, not OAuth: it cannot follow the
redirect that starts the flow, and `parseCollabLink` normalises links through `url.origin`, which
drops userinfo, so it cannot carry a credential to be checked either. Its `role=guest` upgrade gets
a redirect it will not follow. That is the deliberate trade — authenticated browser guests instead
of anonymous terminal ones.

Note that `omp join` and a remote host are refused by *different* rules. A terminal guest through
the tunnel is refused because it cannot do OAuth; a host through the tunnel is refused because
hosting never traverses the tunnel at all. A terminal guest that can reach the hosting bind still
works, and is not asked to authenticate.

Gating `/` alone would also have been theater. The browser's data path is the `/r/*` WebSocket,
which anyone holding the link can open from any origin — putting a login in front of the SPA shell
while leaving `/r/*` open buys nothing. Authenticating browser guests and rejecting terminal ones
are the same lever, not two.

### The rest of the policy

An open relay also risks plain **abuse** — anyone who learns the hostname can open rooms and push
bytes through it — so the policy caps handshakes per client IP and 404s any path outside `/`,
`/healthz`, `/r/*`, `/ngrok/*`, and the client's static assets. The 404 rule runs *before* the
`oauth` action, so scanning for unrelated paths gets a flat 404 rather than a redirect naming your
identity provider.

Only the allowlist and the provider are flags. *Who* may enter is deployment data; the shape of the
gate is not, and there is no way to start the relay without a gate.

`--oauth-provider` defaults to `google` and uses ngrok's managed OAuth app, which needs no client
id or secret. `github`, `gitlab`, `microsoft`, `linkedin` and `twitch` also have managed apps. For
a production deployment you would normally register your own app with the provider; that needs
`client_id`/`client_secret` on the `oauth` action, which this relay does not expose as flags —
secrets on a command line are worse than a managed app.

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

The relay binds **two** listeners sharing one room map, differing in exactly one rule: the hosting
bind that `--hostname`/`--port` name, and an ephemeral loopback one that is the ngrok tunnel's
origin.

| | hosting bind | tunnel listener |
|---|---|---|
| `GET /r/<roomId>?role=host` | upgrade; `roomId` is `[A-Za-z0-9_-]{10,64}` | **403** |
| `GET /r/<roomId>?role=guest` | upgrade | upgrade, behind OAuth at the edge |
| `GET /healthz` | `ok` | `ok`, left unauthenticated by the policy |
| `GET /` | client (SPA fallback for unknown paths) | same, behind OAuth |

| | |
|---|---|
| host → relay | `[4B BE peerId][sealed]`; `0` broadcasts, `N` targets guest N; forwarded byte-for-byte |
| guest → relay | first 4 bytes rewritten to the sender's peerId, forwarded to the host |
| control → host | `{"t":"peer-joined","peer":N}`, `{"t":"peer-left","peer":N}` |
| host disconnect | `{"t":"room-closed"}` to every guest, then close `4001` |
| close codes | `4001` room closed · `4004` no such room · `4009` host already connected · `4029` room full |

Frame shapes and the envelope header come from [`@oh-my-pi/pi-wire`](https://www.npmjs.com/package/@oh-my-pi/pi-wire),
the same package the clients compile against, so the contract cannot drift silently.

The relay process does not authenticate anyone: OAuth is enforced by the ngrok edge. What the relay
*does* enforce is which listener may host, since that is the one thing the edge cannot see.

## Options

```
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
```

An ngrok authtoken is required, from `NGROK_AUTHTOKEN` or `--authtoken-file`. The file wins when
both are set: passing it is the deliberate choice, and a stale exported token silently overriding it
would be the worse failure. A file also keeps the token out of the process environment (readable via
`/proc/<pid>/environ` on Linux) and out of the argument list. It is read and trimmed at startup, so
a trailing newline is fine, and an unreadable or empty file is fatal.

At least one `--oauth-allow` is required too. Token, allowlist and policy are all resolved before
the port is bound, so a misconfiguration costs nothing.

The `@` on a domain entry is not decoration: `@example.com` compiles to
`endsWith('@example.com')`, which `someone@evil-example.com` cannot satisfy. Entries are validated
rather than escaped — anything that is not an address or an `@domain` is a startup failure, so a
crafted entry cannot inject into the policy's CEL.

There is no flag for the tunnel's port — it is an internal loopback detail, and making it
configurable would only create a way to point the tunnel at the wrong listener.

## Deployment

**systemd:**

```ini
[Service]
# LoadCredential keeps the token out of the unit file and the environment.
LoadCredential=ngrok:/etc/omp-ngrok-relay/authtoken
ExecStart=/usr/local/bin/omp-ngrok-relay --ngrok-url https://collab.example.com \
  --oauth-allow @example.com --authtoken-file %d/ngrok
Restart=always
DynamicUser=yes

[Install]
WantedBy=multi-user.target
```

**Container** (Linux hosts; `dockerTools` would otherwise package the host's Mach-O binary):

```sh
nix build .#container && docker load < result

# relay only, nothing published: the container's own omp session hosts
docker run -e NGROK_AUTHTOKEN omp-ngrok-relay:0.1.0 --oauth-allow you@gmail.com

# to host from the docker host, widen the bind and narrow the publish
docker run -p 127.0.0.1:7466:7466 -e NGROK_AUTHTOKEN \
  omp-ngrok-relay:0.1.0 --hostname 0.0.0.0 --oauth-allow you@gmail.com
```

The relay dials out, so nothing has to be published for the tunnel to work. Publishing is only for
reaching the **hosting bind** from outside the container, and then the bind has to be wide — traffic
through a bridge arrives from the gateway address, not loopback. Bind wide *inside*, publish narrow
*outside*: `-p 127.0.0.1:7466:7466`, not `-p 7466:7466`. Mount a token file with
`-v /path/token:/token:ro --authtoken-file /token` instead of `-e` if you would rather not put it in
the container's environment.

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

Tests cover the parts that are easy to get quietly wrong.

*Relay:* a 4 MiB frame surviving the payload cap with its peerId stamped and bytes intact, targeted
frames not leaking to other guests, the `4004`/`4009`/`room-closed` paths, and the hosting boundary
— `role=host` refused on the tunnel's listener but accepted on the hosting bind, a guest arriving
through the tunnel joining a room on the hosting bind, and a wide bind letting a remote peer host
while the tunnel still refuses.

*Policy:* the `@` anchor on domain entries, the `role=host` denial ordering ahead of the `oauth`
action, `/healthz` being the only exemption left, allowlist entries being rejected rather than
escaped, and the 404 rule preceding `oauth`.

Each of those was checked by mutating the source and confirming the suite goes red. One line is not
covered that way: pointing the tunnel at the hosting listener needs a live endpoint to observe, so
`startNgrok` takes the relay handle instead of a port — there is no port argument to get wrong — and
the edge's own `role=host` denial backstops it.

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
