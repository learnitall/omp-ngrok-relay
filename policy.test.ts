import { expect, test } from "bun:test";
import { buildTrafficPolicy } from "./policy";

interface Rule {
	name: string;
	expressions?: string[];
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
	expect(expr).toContain("email in ['alice@a.com', 'bob@a.com']");
	expect(expr).toContain("email.endsWith('@b.com')");
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

/** `/ngrok/login` and `/ngrok/logout` are served by the edge and must survive the 404 rule. */
test("ngrok's own auth paths are not 404'd", () => {
	expect(rule("static client").expressions?.[0]).toContain("req.url.path.startsWith('/ngrok/')");
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
