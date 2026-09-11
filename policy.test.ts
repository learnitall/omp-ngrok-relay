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

function rules(allow: string[]): Rule[] {
	const policy = buildTrafficPolicy(allow) as { on_http_request: Rule[] };
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

/**
 * The edge serves this subtree itself and does not document all of it, so an
 * enumerated set is a list that ngrok can silently outgrow — it already did,
 * twice, missing `/ngrok/callback/error` and `/ngrok/callback/authn`. A 404 in
 * here does not fail closed, it strands the visitor mid-flow with ngrok's own
 * diagnostic suppressed.
 */
test("the whole /ngrok/ prefix is admitted, not an enumerated set", () => {
	const expr = rule("allow only the relay").expressions?.[0] ?? "";
	expect(expr).toContain("req.url.path.startsWith('/ngrok/')");
	expect(expr).not.toContain("req.url.path == '/ngrok/");
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
