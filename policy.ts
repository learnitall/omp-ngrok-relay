/**
 * ngrok traffic policy for protecting the public-side of the relay for guest
 * connections:
 *
 *   - Allow-list connections to a preset list of expected paths.
 *   - Deny all connections that contain `role=host`, since we are limiting
 *     hosting to same-host only.
 *   - Require OAuth, when an allowlist is configured.
 *
 * OAuth costs terminal guests: `omp join` speaks WebSocket, not OAuth, so it
 * can't follow the redirect that starts the flow. An empty allowlist is the
 * deliberate other side of that trade — an anonymous endpoint that terminal
 * guests can reach, protected by the path and hosting rules alone.
 *
 * TODO:add another operating mode for the relay that allows terminal guests to
 * join by proxying WebSocket connections through an OAuth-authenticated ngrok
 * tunnel.
 */

/**
 * Regex strings to match against different --oauth-allow options.
 */
const ALLOW_EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const ALLOW_DOMAIN = /^@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

/** ngrok provider id. Fixed: the relay configures Google and nothing else. */
const PROVIDER = "google";

/**
 * Return a CEL expression that matches against the set of emails and domains
 * provided.
 *
 * The strings provided are matched as either a single-email or a domain based on the
 * `ALLOW_EMAIL` and `ALLOW_DOMAIN` regex strings. An error is thrown if a string matches neither.
 */
function getAllowedOAuthIdentities(allow: string[]): string {
	// Callers gate on this, but an empty list here would compile to `!()` — invalid
	// CEL that ngrok rejects at best and admits everyone at worst.
	if (allow.length === 0) throw new Error("--oauth-allow: allowlist is empty");

	const emails: string[] = [];
	const domains: string[] = [];
	for (const entry of allow) {
		if (ALLOW_DOMAIN.test(entry)) {
			domains.push(entry.toLowerCase());
		} else if (ALLOW_EMAIL.test(entry)) {
			emails.push(entry.toLowerCase());
		} else {
			throw new Error(`--oauth-allow '${entry}': expected user@example.com or @example.com`);
		}
	}
	const tests = domains.map((d) => `actions.ngrok.oauth.identity.email.lowerAscii().endsWith('${d}')`);
	if (emails.length > 0) {
		tests.unshift(`actions.ngrok.oauth.identity.email.lowerAscii() in [${emails.map((e) => `'${e}'`).join(", ")}]`);
	}

	return tests.join(" || ");
}

/** An empty `allow` publishes an anonymous endpoint: no oauth action, no identity rule. */
export function buildTrafficPolicy(allow: string[]): object {
	const oauth =
		allow.length === 0
			? []
			: [
					{
						name: "require oauth on everything the browser touches",
						// The probe has to answer an unauthenticated GET or it stops being a
						// liveness check; every other path goes through the provider.
						expressions: ["req.url.path != '/healthz'"],
						actions: [{ type: "oauth", config: { provider: PROVIDER } }],
					},
					// OAuth only proves the visitor has an account with the provider; without
					// this rule "authenticated" means "has a Google account", which is not
					// access control.
					{
						name: "allow only the configured identities",
						// Both must hold to deny: expressions are ANDed, so exempting the probe
						// here too keeps it reachable without an identity claim to test.
						expressions: ["req.url.path != '/healthz'", `!(${getAllowedOAuthIdentities(allow)})`],
						actions: [{ type: "deny", config: { status_code: 403 } }],
					},
				];

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
			{
				name: "allow only the relay, health, the static client, and ngrok's auth paths",
				expressions: [
					"!(" +
						"req.url.path == '/' || " +
						"req.url.path == '/healthz' || " +
						"req.url.path.startsWith('/r/') || " +
						"req.url.path.startsWith('/ngrok/') || " +
						"req.url.path.matches('^/[A-Za-z0-9_.-]+[.](css|js|map|png|svg|ico|webmanifest|txt|xml|woff2?)$')" +
						")",
				],
				actions: [{ type: "deny", config: { status_code: 404 } }],
			},
			{
				name: "hosting is same-host only, never through the tunnel",
				expressions: [
					"req.url.path.startsWith('/r/') && 'role' in req.url.query_params && 'host' in req.url.query_params['role']",
				],
				// 403, not 404: a host that reaches the edge asked for something the edge
				// will never do, and saying so beats a terminal walking into an oauth
				// redirect it cannot complete.
				actions: [{ type: "deny", config: { status_code: 403 } }],
			},
			...oauth,
		],
	};
}
