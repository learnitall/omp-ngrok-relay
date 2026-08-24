/**
 * Edge traffic policy, compiled into the binary rather than passed at runtime:
 * the rules are part of what this service *is*, and an operator who can swap
 * them out of band can silently unprotect the endpoint.
 *
 * Deliberately no auth. The collab link is the capability (AES-256-GCM room key
 * plus write token), and neither `omp join` nor the browser client can present
 * credentials on a WebSocket upgrade — `parseCollabLink` normalises through
 * `url.origin`, which drops userinfo. basic-auth or oauth here locks out every
 * terminal guest. What an open relay actually risks is abuse, so: rate limit.
 */
export const TRAFFIC_POLICY = {
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
			name: "allow only the relay, health, and the static client",
			expressions: [
				"!(req.url.path == '/' || req.url.path == '/healthz' || req.url.path.startsWith('/r/') " +
					"|| req.url.path.matches('^/[A-Za-z0-9_.-]+[.](css|js|map|png|svg|ico|webmanifest|txt|xml|woff2?)$'))",
			],
			actions: [{ type: "deny", config: { status_code: 404 } }],
		},
	],
};
