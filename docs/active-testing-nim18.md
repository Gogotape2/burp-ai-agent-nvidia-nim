# AI payload attacks and WebSocket sessions (nim.18)

The full build adds nine tools. They use the normal chat tool protocol and the embedded MCP server. They are enabled by default, while tools that send traffic or mutate state still require the existing unsafe permission. The existing automatic approval checkbox controls confirmation cards. No new bypass of these settings is introduced.

## Payload runner

Montoya's public [Intruder interface](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/intruder/Intruder.html) does not expose attack start/results. `intruder` and `intruder_prepare` continue to stage native Intruder tabs. The new runner uses Burp's HTTP API and returns its own attack handles; it cannot attach to native GUI attacks, export native Intruder result tables or run native payload-generator plugins.

| Tool | Operation |
|---|---|
| `intruder_attack_start` | Validate the complete plan and scope, start the job, return `attackId` immediately |
| `intruder_attack_status` | Read progress, completed/failed counts and lifecycle state |
| `intruder_attack_results` | Read request-index pages; optionally include bounded request/response captures |
| `intruder_attack_cancel` | Stop scheduling work and interrupt local workers; already-sent HTTP requests may finish |

Example start arguments for an isolated local test service:

```json
{
  "content": "GET /case?value={{value}} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
  "targetHostname": "127.0.0.1",
  "targetPort": 18080,
  "usesHttps": false,
  "positions": [
    {"marker": "{{value}}", "baseValue": "baseline", "payloads": ["alpha", "beta"]}
  ],
  "mode": "SNIPER",
  "maxRequests": 3,
  "concurrency": 1,
  "intervalMs": 200,
  "timeoutMs": 30000,
  "durationMs": 120000,
  "includeBaseline": true
}
```

Markers are literal strings in `content`. They must be unique, non-overlapping and present in the template. Replacement is non-recursive: a marker-looking payload remains payload data. Payloads are inserted exactly as supplied, with no implicit URL/JSON encoding. Header line endings and Content-Length are repaired using UTF-8 byte lengths. The template must contain real line breaks. An omitted final empty line is repaired only for an unambiguous header-only request; a body still requires a header separator. Double-escaped line breaks are rejected before any traffic so the model can repair the arguments instead of waiting for a Burp transport timeout.

`SNIPER` varies each position independently and restores other positions to `baseValue`. `BATTERING_RAM` uses identical payload lists at all positions. `PITCHFORK` requires equally sized lists and advances them together. `CLUSTER_BOMB` uses their Cartesian product. The optional baseline counts toward `maxRequests`; excessive plans are rejected before any request, rather than silently truncated.

Limits: 1-16 positions, 1-1000 total requests, up to 5 workers per attack and 5 HTTP sends globally, 2 running attacks, 8 retained jobs, 16 KiB per payload, 1 MiB combined payloads/template, and 4 MiB of captured messages per job. Defaults are 1 worker, 200 ms spacing, 30-second response timeout and 120-second total duration. Maximum response timeout is 120 seconds; maximum duration is 900 seconds. Deterministic mode uses one worker. Captures are at most 32 KiB per request/response; full response byte counts and SHA-256 hashes support comparison. Captures marked truncated are incomplete evidence. Completed jobs expire after 15 minutes and may be evicted earlier when the registry is full.

Results use stable **request indices**, not completion order. `pendingIndices` may include slow requests from an earlier page: revisit them after completion. Terminal `notExecutedIndices` were not completed before cancellation/deadline; do not poll them indefinitely. Polling a completed job or receiving HTTP 200 does not establish a vulnerability. Stopping a job does not undo requests already sent. Scope is checked before all variants are scheduled, before each send and again when results are read. Cancellation remains possible after a scope change.

Suggested chat request: "Use the payload runner with these explicit values, compare each result with the baseline, read the actual results and report only observed differences. Do not infer a vulnerability from status code alone."

## WebSocket sessions

The [WebSockets API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/websocket/WebSockets.html) creates extension-owned connections. These tools do not seize or modify browser sockets from Proxy history.

| Tool | Operation |
|---|---|
| `websocket_open` | Open a connection using service/path or a captured GET upgrade request in `content` |
| `websocket_send` | Send exactly one `text` or `base64` binary message |
| `websocket_receive` | Read inbound/outbound messages after a sequence cursor, with an optional bounded wait |
| `websocket_close` | Close a connection; retained messages remain readable temporarily |
| `websocket_connections` | List bounded connection metadata |

```json
{"targetHostname":"127.0.0.1","targetPort":18080,"usesHttps":false,"path":"/ws","timeoutMs":15000}
```

Use the returned `connectionId` in subsequent calls:

```json
{"connectionId":"<returned connectionId>","text":"hello"}
```

```json
{"connectionId":"<returned connectionId>","afterSequence":0,"count":20,"waitMs":1000}
```

Read `nextSequence` and use it as `afterSequence` next time. `gap` and `droppedMessages` indicate buffer loss. Incoming frames may arrive after a send returns; use a bounded receive wait instead of resending. Outgoing frames describe sends, not confirmed application processing.

Limits: 8 open connections, 16 retained connections, 64 KiB per outgoing message/captured frame, 256 retained frames and 1 MiB buffer per connection. Pages contain at most 100 messages; waits are at most 30 seconds. Connections without tool activity close after five minutes. Closed sessions expire after 15 minutes and may be evicted under pressure. A timed-out handshake is closed if it completes late. A send timeout has an **unknown delivery outcome**; inspect messages before retrying. The transport cannot undo a send already executed by Burp.

Text frames use an explicit UTF-8 bridge over the byte-oriented Montoya String boundary verified in Burp 2026.9.1, preserving Cyrillic, CJK and supplementary characters. Custom handshakes preserve explicitly supplied headers. Request/response text follows the current privacy policy before being returned to the model. Binary frame bodies are withheld while privacy mode is enabled; OFF mode allows bounded base64 captures. Scope restrictions apply to open/send/read/list. Close remains available for cleanup after a scope change. Extension unload cancels jobs and closes its owned connections.

## Verification

See the versioned verification report for selected automated test counts and the separate installed-Burp, isolated-local-service checks. Synthetic Montoya tests, local HTTP/WebSocket traffic and live model calls are recorded separately. No successful test implies compatibility with every target, server, authentication scheme or third-party MCP service.


To reproduce installed-Burp loopback checks, enable local-mode MCP and the relevant tools, install Python 3.11+ with `websockets==16.0`, then run `python scripts/verify-active-tools.py --report local-active-tools.json`. The script creates ephemeral loopback-only fixtures, checks all four payload modes and all nine tool operations, and shuts its fixtures down. It does not contact a remote target or change tool permissions. `--serve-only --manifest fixture.json` leaves the isolated fixtures running until interrupted for manual demonstrations.
