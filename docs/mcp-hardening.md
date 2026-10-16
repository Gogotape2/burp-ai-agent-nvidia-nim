# MCP Hardening Runbook

Use this checklist before exposing MCP beyond loopback.

## Baseline

1. Keep bind host at `127.0.0.1` unless external access is required.
2. Keep **Unsafe mode** disabled by default. This applies to the GitHub full build; the BApp Store build has no unsafe tools, so its Unsafe mode switch is shown disabled with "No unsafe tools in this build".
3. Enable only the minimum MCP tools needed for current workflow.

## External Access

1. Enable TLS.
2. Use strong bearer token and rotate it.
3. Restrict allowed origins/hosts to trusted clients.
4. Validate `Authorization: Bearer <token>` is required on every request except `GET /__mcp/health`. That one route is deliberately exempt so the extension's own bind-conflict liveness probe can tell whether something is already holding the MCP port without putting the bearer token on the wire against a listener whose identity has not been established.
5. Do not rely on the identifying response header `X-Burp-AI-Agent: mcp` for health checks outside loopback: it is emitted only while external access is disabled, so an unauthenticated scan of an externally exposed port cannot confirm which extension is listening.
6. Use an MCP client that sends ordinary HTTP request headers, such as Claude Desktop or Codex CLI, because a browser-based client is unsupported in external mode: `EventSource` cannot set request headers and therefore cannot present the bearer token on the initial `GET /sse`.
7. Restrict allowed origins explicitly if your threat model cares about origin disclosure, because CORS preflight (`OPTIONS`) is answered before authentication and, when no allowed origins are configured, the server permits any origin, so an unauthenticated peer can learn which origins are allow-listed. This behaviour is deliberately unchanged.

## Operational Controls

1. Set conservative MCP request concurrency.
2. Set **Max body size (KB)** to avoid oversized payload exfiltration.
3. Keep privacy mode at `STRICT` or `BALANCED` for cloud clients.
4. Keep audit logging enabled for traceability.

## Takeover on a Bind Conflict

1. When the MCP server cannot bind its port, the extension probes the port and, if something MCP-shaped answers, asks it to shut down and retries. Expect these Output lines: `MCP bind conflict detected on <host>:<port>. Shutdown requested from existing MCP server; retrying in ...` on success, `Port appears busy and no compatible MCP server was detected for takeover.` when the probe found nothing usable, and `Existing MCP server did not accept shutdown request.` when the holder refused. Repeated conflicts end at `MCP bind conflict persists after N takeover attempts.`
2. No credential is sent to the port holder. The takeover presents a keyed proof over the target host, port and a short time window, not the bearer token, so a process squatting the MCP port learns nothing it can reuse against you. `GET /__mcp/health` is the only route the probe touches and it carries no credential either. If you drive `POST /__mcp/shutdown` by hand, `Authorization: Bearer <token>` still works unchanged.
3. Under TLS on a **loopback** bind the takeover requires a readable keystore at the configured path and will refuse rather than downgrade. The client trusts only the certificate in that keystore, so if the keystore has moved or been deleted you will see `MCP takeover was not attempted under TLS: no pinned certificate could be read from <path>.` and the MCP server will stay down until you fix the path or free the port. Treat that line as an action item, not a warning: check that `<path>` exists and is readable, then restart MCP. The certificate pin is scoped to loopback hosts, so a **non-loopback** bind — only possible in external mode — never produces that line however readable the keystore is. It gets `MCP takeover was not attempted under TLS: certificate pinning is applied to loopback hosts only and this server is bound to <host>.` instead, and the action item is different: no takeover is attempted at all, so free the port yourself and then restart MCP.
4. To confirm the behaviour, with TLS enabled and MCP running: `curl -sk -o /dev/null -w '%{http_code}\n' -X POST https://127.0.0.1:<port>/__mcp/shutdown` returns `401` with no credential, and the same request with `-H "Authorization: Bearer <token>"` returns `200` and stops the server. Then rename the keystore file, provoke a bind conflict by starting anything else on that port, and confirm the Output line above appears instead of a takeover.

Why the takeover works this way, and which residual risks are accepted, is recorded in `DECISIONS.md` ADR-16.

## Credential Storage

1. The TLS keystore password is persisted in Burp's preferences (`mcp.tls.keystore.password`) as plaintext. Burp preferences are stored in the user's project file and are only as protected as that file.
2. If the project file or preferences export could leak (shared backups, multi-user hosts), treat the MCP bearer token and TLS keystore as compromised and rotate both.
3. For high-assurance setups, generate the keystore offline with your own `keytool` invocation and point the extension at it via settings, so the password never touches Burp preferences.
4. The MCP bearer token is generated with `SecureRandom` (32 bytes base64). Rotate it if any external client is decommissioned.

## Verification

1. Test local health endpoint: `GET /__mcp/health`.
2. Test denied requests return the expected bare status: in external mode `POST /message` and `GET /sse` without `Authorization` return `401` with an empty body while `GET /__mcp/health` returns `200`, and in local mode a request carrying a foreign `Origin`, a foreign `Host`, a foreign `Referer`, or a browser `User-Agent` with no `Origin` returns `403` with an empty body. The responses are bare statuses with no diagnostic body by design. Where the denial reason shows up depends on the vector, so check the right evidence for the case you are testing:
   - For the external-mode `401`s, and for the local-mode foreign `Host`, foreign `Referer` and browser `User-Agent`-with-no-`Origin` cases, the reason is recorded in Burp's Output tab and, when audit logging is enabled, in the audit log.
   - A foreign `Origin` is the exception: that denial is **not recorded** in the Output tab or in the audit log, and its absence there is expected. Ktor's own CORS plugin answers a disallowed origin with `403` and commits the response before the extension's access-control gate evaluates the request, so the gate never sees the request and emits nothing for it. The `403` status is therefore the only observable for this vector — a missing Output-tab line or audit entry here is not evidence of a broken audit trail. To confirm the recording path itself is healthy, exercise one of the other three local-mode vectors instead.
3. Confirm unsafe tools are blocked when the **Unsafe mode** switch is off (full build). In the BApp Store build, confirm the switch is shown disabled with "No unsafe tools in this build".
4. Confirm responses from routes the server resolves — not only its `404` responses — carry `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and `Content-Security-Policy: default-src 'none'`.

## Incident Response

1. Disable MCP toggle immediately.
2. Rotate token.
3. Review audit logs and extension output.
4. Re-enable with reduced scope.
