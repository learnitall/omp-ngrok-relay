import { expect, test } from "bun:test";
import { buildTrafficPolicy } from "./policy";

interface Action {
	type: string;
	config: Record<string, unknown>;
}

interface Rule {
	name: string;
	expressions?: string[];
	actions: Action[];
}

function rules(allow: string[], provider = "google"): Rule[] {
	const policy = buildTrafficPolicy({ provider, allow }) as { on_http_request: Rule[] };
	return policy.on_http_request;
}

function rule(name: string, allow = ["@example.com"]): Rule {
	const found = rules(allow).find((r) => r.name.includes(name));
	if (!found) throw new Error(`no rule matching ${name}`);
	return found;
}

/**
 * The `@` is what makes a domain entry a domain rather than a suffix:
 * `endsWith('example.com')` also admits `someone@evil-example.com`.
 */
test("a domain entry anchors on the @", () => {
	expect(rule("configured identities").expressions?.at(-1)).toContain("endsWith('@example.com')");
});

test("addresses become a set membership test, domains a suffix test", () => {
	const expr = rule("configured identities", ["alice@a.com", "@b.com", "bob@a.com"]).expressions?.at(-1);
	expect(expr).toContain("lowerAscii() in ['alice@a.com', 'bob@a.com']");
	expect(expr).toContain("lowerAscii().endsWith('@b.com')");
});

/**
 * Hosting is same-host only, so the edge refuses it outright rather than walking
 * a terminal `omp` process through a login it cannot complete. The rule must
 * come *before* the oauth rule, or a remote host attempt gets a redirect
 * instead of a flat 403.
 */
test("the host upgrade is denied at the edge, before oauth runs", () => {
	const names = rules(["@example.com"]).map((r) => r.name);
	expect(names.indexOf("hosting is same-host only, never through the tunnel")).toBeLessThan(
		names.indexOf("require oauth on everything the browser touches"),
	);
	expect(rule("hosting is same-host only").expressions).toEqual([
		"req.url.path.startsWith('/r/') && 'role' in req.url.query_params && 'host' in req.url.query_params['role']",
	]);
});

/**
 * With the host upgrade already denied, oauth covers everything but the probe.
 * A stray exemption here would be a hole, not a convenience.
 */
test("oauth and the authorization rule exempt only the liveness probe", () => {
	expect(rule("require oauth").expressions).toEqual(["req.url.path != '/healthz'"]);
	expect(rule("configured identities").expressions?.[0]).toBe("req.url.path != '/healthz'");
});

/** A redirect to the identity provider is a disclosure; unknown paths 404 first. */
test("the path allowlist is evaluated before oauth", () => {
	const names = rules(["@example.com"]).map((r) => r.name);
	expect(names.indexOf("allow only the relay, health, the static client, and ngrok's auth paths")).toBeLessThan(
		names.indexOf("require oauth on everything the browser touches"),
	);
});

/** `/ngrok/login` and `/ngrok/logout` are the only endpoint-local paths served by the edge. */
test("ngrok's auth paths are exactly /ngrok/login and /ngrok/logout", () => {
	const expr = rule("allow only the relay").expressions?.[0] ?? "";
	expect(expr).toContain("req.url.path == '/ngrok/login'");
	expect(expr).toContain("req.url.path == '/ngrok/logout'");
	expect(expr).not.toContain("req.url.path.startsWith('/ngrok/')");
});

test("an empty allowlist is refused", () => {
	expect(() => rules([])).toThrow(/--oauth-allow is required/);
});

/**
 * Entries are validated, not escaped, so a crafted address cannot close the CEL
 * string literal and append a disjunct that admits everyone.
 */
test.each([
	"'",
	"a'@x.com",
	"x@y.com'] || true || ['",
	'x@y."com',
	"x@y.com\\",
	"x y@z.com",
	"@example",
	"example.com",
	"@",
	"",
	// `\s` does not cover these, so a negated character class admitted them and
	// produced an allowlist entry no provider claim can ever equal.
	"a\u0000b@example.com",
	"a\u200bb@example.com",
	"a\tb@example.com",
	"a\u007fb@example.com",
])("rejects %p", (entry) => {
	expect(() => rules([entry])).toThrow(/--oauth-allow/);
});

test("rejects a provider that is not a bare identifier", () => {
	expect(() => rules(["@example.com"], "google'} , {'x")).toThrow(/--oauth-provider/);
});

test("the provider reaches the oauth action", () => {
	const policy = buildTrafficPolicy({ provider: "github", allow: ["@example.com"] });
	expect(JSON.stringify(policy)).toContain('"provider":"github"');
});

/**
 * Pins the generated expression, not ngrok's evaluation of it: whether ngrok
 * resolves `/ngrok/../r/<room>` before matching is undocumented, which is why
 * the prefix went away. `scripts/e2e.ts` observes the real answer live.
 */
test("ngrok's auth paths are matched exactly, never by prefix", () => {
	const expr = rule("allow only the relay").expressions?.[0] ?? "";
	expect(expr).toContain("req.url.path == '/ngrok/login'");
	expect(expr).toContain("req.url.path == '/ngrok/logout'");
	// A prefix also admitted `/ngrok/../r/<room>?role=host`, which the relay
	// resolves to a genuine host upgrade.
	expect(expr).not.toContain("startsWith('/ngrok/')");
});

/**
 * The expressions decide who is caught; the actions decide what happens to them.
 * Asserting only expressions let the identity deny become a 200 — admitting every
 * authenticated provider account — with the suite still green.
 */
test.each([
	["allow only the relay", 404],
	["hosting is same-host only", 403],
	["allow only the configured identities", 403],
])("%s denies with %i", (name, status) => {
	expect(rule(name).actions).toEqual([{ type: "deny", config: { status_code: status } }]);
});

test("the oauth action carries the provider and nothing else", () => {
	expect(rule("require oauth").actions).toEqual([{ type: "oauth", config: { provider: "google" } }]);
});

test("the rate limit is a per-client-ip sliding window", () => {
	expect(rule("rate limit").actions).toEqual([
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
	]);
});
