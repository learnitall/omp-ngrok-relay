/**
 * Edge traffic policy, compiled into the binary rather than passed at runtime:
 * the rules are part of what this service *is*, and an operator who can swap
 * them out of band can silently unprotect the endpoint. Only the identity
 * allowlist is a parameter — *who* may enter is deployment data, the shape of
 * the gate is not — and there is no way to start without one.
 *
 * Two different doors, because the two roles have different credentials:
 *
 *   - `role=host` is refused here outright. Hosting is same-host only, and the
 *     relay enforces that structurally by giving the tunnel its own loopback
 *     listener that never accepts a host upgrade (see `startRelay`). This rule
 *     is the earlier, cheaper rejection, not the boundary.
 *   - everything else — `/`, the client's static assets, and the `role=guest`
 *     upgrade — sits behind OAuth plus an identity allowlist. OAuth alone only
 *     proves the visitor has an account with the provider, so the allowlist is
 *     required and the relay refuses to start without one.
 *
 * The cost is terminal guests. `omp join` speaks WebSocket, not OAuth: it
 * cannot follow the redirect that starts the flow, and `parseCollabLink`
 * normalises links through `url.origin`, which drops userinfo, so it cannot
 * carry a credential to be checked either. That is the accepted trade —
 * authenticated browser guests instead of anonymous terminal ones.
 */

/**
 * `role` is absent on asset requests, and indexing a missing key is a CEL
 * error, so the key is tested before it is read.
 *
 * Best-effort, and deliberately not the boundary. ngrok documents `req.url.path`
 * as normalised — there is a separate `req.url.raw_path` — without saying what
 * that normalises, and says nothing about percent-decoding query keys or values.
 * So spellings the relay's WHATWG parse resolves to a host upgrade, such as
 * `/./r/<room>?role=host` or `?role=%68ost`, may reach the `oauth` action
 * instead of this 403. Harmless, because the tunnel's listener refuses
 * `role=host` however it was spelled; `scripts/e2e.ts` observes which spellings
 * the edge actually catches.
 */
const HOST_UPGRADE =
	"req.url.path.startsWith('/r/') && 'role' in req.url.query_params && 'host' in req.url.query_params['role']";

/**
 * ngrok's `oauth` action reserves exactly two endpoint-local paths, `/ngrok/login`
 * and `/ngrok/logout`. Matched exactly rather than by `/ngrok/` prefix, which also
 * admitted `/ngrok/../r/<room>?role=host` — a path the relay resolves to a genuine
 * host upgrade. `req.url.path` excludes the query string, so the documented
 * `?auth_id=` and `?redirect_path=` forms still match.
 */
const NGROK_AUTH_PATHS = "req.url.path == '/ngrok/login' || req.url.path == '/ngrok/logout'";

/** The liveness probe is the one thing the edge serves unauthenticated. */
const NOT_HEALTHZ = "req.url.path != '/healthz'";

/**
 * A positive class, not a negated one: `[^\s@'"\\]` admitted `U+0000` and
 * `U+200B`, which no provider ever asserts, so such an entry was a permanently
 * dead allowlist line accepted without complaint. Naming what may appear cannot
 * be surprised by the next Unicode category, and it still excludes `'`, `"` and
 * `\` — that exclusion is what stops a validated entry terminating the CEL
 * string literal it is interpolated into. ASCII-only also keeps `toLowerCase()`
 * below in exact agreement with CEL's `lowerAscii()`.
 */
const ALLOW_EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const ALLOW_DOMAIN = /^@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const PROVIDER = /^[a-z0-9-]{1,32}$/;

export interface OAuthConfig {
	/** ngrok provider id; without a client id only providers with a managed app work. */
	provider: string;
	/** `user@example.com` for one address, `@example.com` for a whole domain; matched case-insensitively. */
	allow: string[];
}

/**
 * Operator data reaching a CEL expression is validated, not escaped: an entry
 * that is not exactly an address or an `@domain` is a startup failure.
 *
 * The `@` in a domain entry is load-bearing. `endsWith('@example.com')` cannot
 * be satisfied by `someone@evil-example.com`, `endsWith('example.com')` can.
 *
 * Both sides are lowercased, because CEL `in` and `endsWith` are case-sensitive
 * while only some providers normalise the address they assert. Without it,
 * `--oauth-allow You@Example.COM` starts, publishes an endpoint, and admits
 * nobody.
 */
function identityTest(allow: string[]): string {
	const emails: string[] = [];
	const domains: string[] = [];
	for (const entry of allow) {
		if (ALLOW_DOMAIN.test(entry)) domains.push(entry.toLowerCase());
		else if (ALLOW_EMAIL.test(entry)) emails.push(entry.toLowerCase());
		else throw new Error(`--oauth-allow ${entry}: expected user@example.com or @example.com`);
	}
	const email = "actions.ngrok.oauth.identity.email.lowerAscii()";
	const tests = domains.map((d) => `${email}.endsWith('${d}')`);
	if (emails.length > 0) tests.unshift(`${email} in [${emails.map((e) => `'${e}'`).join(", ")}]`);
	return tests.join(" || ");
}

export function buildTrafficPolicy(oauth: OAuthConfig): object {
	if (!PROVIDER.test(oauth.provider)) {
		throw new Error(`--oauth-provider ${oauth.provider}: expected an ngrok provider id such as google or github`);
	}
	if (oauth.allow.length === 0) throw new Error("--oauth-allow is required: OAuth with no allowlist admits everyone");
	const allowed = identityTest(oauth.allow);

	return {
		on_http_request: [
			{
				name: "rate limit handshakes per client ip",
				actions: [
					{
						type: "rate-limit",
						config: {
							name: "collab-relay",
							algorithm: "sliding_window",
							capacity: 120,
							rate: "60s",
							bucket_key: ["conn.client_ip"],
						},
					},
				],
			},
			// Ahead of the OAuth rule, so a scan for unrelated paths gets a flat 404
			// instead of a redirect that advertises the identity provider.
			{
				name: "allow only the relay, health, the static client, and ngrok's auth paths",
				expressions: [
					"!(req.url.path == '/' || req.url.path == '/healthz' || req.url.path.startsWith('/r/') " +
						"|| (" +
						NGROK_AUTH_PATHS +
						") " +
						"|| req.url.path.matches('^/[A-Za-z0-9_.-]+[.](css|js|map|png|svg|ico|webmanifest|txt|xml|woff2?)$'))",
				],
				actions: [{ type: "deny", config: { status_code: 404 } }],
			},
			// Before the OAuth rule and terminating, so a remote host attempt gets a
			// flat 403 rather than being walked through a login it can never use.
			{
				name: "hosting is same-host only, never through the tunnel",
				expressions: [HOST_UPGRADE],
				actions: [{ type: "deny", config: { status_code: 403 } }],
			},
			{
				name: "require oauth on everything the browser touches",
				expressions: [NOT_HEALTHZ],
				actions: [{ type: "oauth", config: { provider: oauth.provider } }],
			},
			// OAuth only proves the visitor has an account with the provider; without
			// this rule "authenticated" means "has a Google account", which is not
			// access control.
			{
				name: "allow only the configured identities",
				expressions: [NOT_HEALTHZ, `!(${allowed})`],
				actions: [{ type: "deny", config: { status_code: 403 } }],
			},
		],
	};
}
