# Tool runtime audit: local 1.0.0-nim.17

This is the historical nim.17 audit snapshot. Its changes are included in nim.18, which also adds [active payload and WebSocket tools](active-testing-nim18.md). Installation and publication statements below describe the original audit, not the later nim.18 release.

This update covers all 62 existing catalog tools. It does not turn every Burp GUI action into an API.
The running Burp project was not reloaded or modified, and this update was not pushed or published.

## Changes

- Correct function schemas: optional constructor defaults remain optional, defensive required URLs stay required, nullable values and nested insertion-point objects have complete schemas. Native and textual schemas carry execution bounds, including the configured proxy-history page limit.
- Native tool discovery and the embedded MCP server now advertise enabled, permitted, edition-compatible runtime tools. `/tools` includes an explanation for disabled/uninitialized entries and uses the same privacy-restricted history schema as execution.
- HTTP/1 and HTTP/2 select the intended protocol and accept `timeoutMs` (30,000 by default; 1,000-600,000). Missing responses become errors. All text message factories use explicit UTF-8 bytes, independent of Burp's configured string encoding. Header normalization preserves body newlines and calculates Content-Length from those same bytes. Repeater replacements and issue evidence use the same normalization.
- Audit inputs and scope are checked before creating a task. Partial audit submission failures delete the new task. Empty audits report zero queued requests; use `scan_audit_start_requests` to test traffic. Crawl seeds must be nonempty absolute HTTP(S) URLs and respect scope.
- Scanner findings/reports and cookies respect the global scope setting. Scope URL construction supports IPv6 and OPTIONS `*`, and uses the actual connection destination for absolute request-targets. Missing scan tasks and unavailable runtimes return errors.
- `editor_get` and `editor_set` use an explicit Montoya message-editor binding, selected by opening an HTTP message context menu. Editor access runs on the EDT; parsing/factories run off it. Read-only viewers, stale selections and out-of-scope reads/edits are rejected. Chat focus cannot become an editor target.
- Collaborator is correctly marked Professional-only. Generation returns a local `client_id=collab_...`, passed back as `clientId`; actual restoration secrets are kept out of generated output. Existing `secretKey` input remains supported for restoration. Handles expire with the configured collaborator TTL.
- Invalid pagination, ports, random-string lengths, scan sizes and configuration JSON fail before side effects. Explicit error/refusal responses are marked as errors. Output limits include their truncation notice, preserve UTF-8 code points and retain external result boundaries.
- AI passive scans honor explicit zero-based proxy-history indices instead of ignoring them. SSE and stdio MCP contexts now receive the same AI dependencies as chat. MCP logs use argument hashes rather than raw argument previews.

## External MCP

Saved enabled servers are reconciled by a shared background runtime. Saving unrelated settings does not reconnect unchanged servers. Chat obtains the current connected tools on each turn; external tool IDs remain `ext:<server>:<tool>`. NIM uses deterministic protocol-safe wire names and restores the original tool name and call ID before approval and execution.

Discovery follows cursors with page/count limits, preserves input schemas, rejects duplicate tool names, and reports connection state in Settings. External stdio selection is independent of the embedded server's stdio setting. Local process arguments are passed as a list, without shell expansion, with only explicitly configured environment variables. On Windows, use an absolute executable path and provide any environment variables the server needs.

Stdio diagnostics are drained from stderr separately from JSON-RPC stdout. Initialization/discovery have a 30-second upper deadline and calls have a 120-second upper deadline; transport-level limits may expire earlier. Failed connections are cleaned up before bounded reconnect attempts. Remote `isError` is preserved, nested JSON argument types are retained, output is redacted and wrapped as untrusted external data, and unknown/disconnected tools cannot execute. No failed tool call is automatically replayed. Removal/unload cancels connections and terminates child processes.

External tools are available to the extension's chat executor. This update does not expose an external-tool relay through the embedded Burp MCP server. Its tool discovery covers the built-in catalog. Text results are supported; image-only results produce an explicit unsupported-content error.

## Verification scope

`McpAllToolsSmokeTest` executes the production dispatcher for each of the 62 tools, with deterministic Montoya API/factory fixtures, in OFF and BALANCED privacy modes. It checks the complete catalog-to-fixture mapping and selected HTTP, Repeater, editor, issue and scanner effects. It does not send traffic to a pentest target or simulate a real Burp license/server implementation.

`McpCatalogContractTest` checks disabled tools, unsafe permission, Community/Professional restrictions and malformed input across the catalog. Dedicated regressions cover native external-name/call-ID round trips, schemas, scope, audit setup, missing tasks/editor, body-byte preservation, nested arguments and UTF-8 bounds. `ExternalMcpProtocolTest` compiles and launches an isolated Java MCP server and checks actual stdio initialization, paginated discovery, schemas, successful/error results and shutdown, including stderr noise.

Aggregate test counts and build checks are recorded in `verification/nim.17/verification.json`. No real-provider inference or GUI installation is claimed by these tests. Existing endpoint tests remain opt-in. Successful client dispatch does not guarantee provider acceptance, target reachability, a completed scan or a confirmed vulnerability.

## API boundaries and use

Repeater tools create tabs; `http1_request` / `http2_request` send requests and return evidence. Intruder tools prepare tabs and insertion points. The [Montoya Intruder API](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/intruder/Intruder.html) does not provide an attack-start/results interface. WebSocket tools read captured history; they do not create active WebSocket sessions. Professional scanner and Collaborator tools need their corresponding Burp services. Free public web research remains optional and subject to public endpoint availability.

To use editor tools, open a message context menu in Burp, enable the editor tool(s), then return to the chat. Before an active tool call, configure the intended target scope and existing tool permissions. The existing auto-approval checkbox and tool-call budget retain their behavior and saved values.

## Catalog coverage

All entries below participate in the synthetic execution test. Readiness in a user's Burp session also depends on its settings and services.

| Tool | Group | Additional runtime condition |
|---|---|---|
| `web_search` | Web research | Existing tool toggle and approval policy |
| `web_fetch` | Web research | Existing tool toggle and approval policy |
| `context_read` | Context | Current chat snapshot |
| `status` | Extension | Existing tool toggle and approval policy |
| `url_encode` | Utilities | Existing tool toggle and approval policy |
| `url_decode` | Utilities | Existing tool toggle and approval policy |
| `base64_encode` | Utilities | Existing tool toggle and approval policy |
| `base64_decode` | Utilities | Existing tool toggle and approval policy |
| `random_string` | Utilities | Existing tool toggle and approval policy |
| `hash_compute` | Utilities | Existing tool toggle and approval policy |
| `jwt_decode` | Utilities | Existing tool toggle and approval policy |
| `decode_as` | Utilities | Existing tool toggle and approval policy |
| `cookie_jar_get` | Utilities | Existing tool toggle and approval policy |
| `proxy_http_history` | History | Existing tool toggle and approval policy |
| `proxy_http_history_regex` | History | Existing tool toggle and approval policy |
| `proxy_history_annotate` | History | Explicit unsafe permission |
| `response_body_search` | History | Existing tool toggle and approval policy |
| `proxy_ws_history` | History | Existing tool toggle and approval policy |
| `proxy_ws_history_regex` | History | Existing tool toggle and approval policy |
| `site_map` | Site Map | Existing tool toggle and approval policy |
| `site_map_regex` | Site Map | Existing tool toggle and approval policy |
| `scope_check` | Scope | Existing tool toggle and approval policy |
| `scope_include` | Scope | Explicit unsafe permission |
| `scope_exclude` | Scope | Explicit unsafe permission |
| `scanner_issues` | Scanner | Professional |
| `http1_request` | Requests | Explicit unsafe permission |
| `http2_request` | Requests | Explicit unsafe permission |
| `repeater_tab` | Requests | Explicit unsafe permission |
| `repeater_tab_with_payload` | Requests | Explicit unsafe permission |
| `intruder` | Requests | Explicit unsafe permission |
| `intruder_prepare` | Requests | Explicit unsafe permission |
| `insertion_points` | Requests | Existing tool toggle and approval policy |
| `params_extract` | Requests | Existing tool toggle and approval policy |
| `diff_requests` | Requests | Existing tool toggle and approval policy |
| `request_parse` | Requests | Existing tool toggle and approval policy |
| `response_parse` | Requests | Existing tool toggle and approval policy |
| `find_reflected` | Requests | Existing tool toggle and approval policy |
| `comparer_send` | Requests | Explicit unsafe permission |
| `task_engine_state` | Burp Control | Explicit unsafe permission |
| `proxy_intercept` | Burp Control | Explicit unsafe permission |
| `editor_get` | Editor | Select an HTTP message using its Burp context menu |
| `editor_set` | Editor | Explicit unsafe permission; Select an HTTP message using its Burp context menu |
| `project_options_get` | Config | Existing tool toggle and approval policy |
| `user_options_get` | Config | Existing tool toggle and approval policy |
| `project_options_set` | Config | Explicit unsafe permission |
| `user_options_set` | Config | Explicit unsafe permission |
| `collaborator_generate` | Collaborator | Professional; Configured Burp Collaborator service |
| `collaborator_poll` | Collaborator | Professional; Configured Burp Collaborator service |
| `scan_audit_start` | Scanner | Professional; Explicit unsafe permission |
| `scan_audit_start_mode` | Scanner | Professional; Explicit unsafe permission |
| `scan_audit_start_requests` | Scanner | Professional; Explicit unsafe permission |
| `scan_crawl_start` | Scanner | Professional; Explicit unsafe permission |
| `scan_task_status` | Scanner | Professional |
| `scan_task_delete` | Scanner | Professional; Explicit unsafe permission |
| `scan_report` | Scanner | Professional; Explicit unsafe permission |
| `issue_create` | Issues | Existing tool toggle and approval policy |
| `ai_analyze` | AI | Configured AI/scanner/logger runtime |
| `ai_passive_scan` | AI | Configured AI/scanner/logger runtime |
| `ai_findings_recent` | AI | Configured AI/scanner/logger runtime |
| `redact_preview` | AI | Existing tool toggle and approval policy |
| `ai_audit_query` | AI | Configured AI/scanner/logger runtime |
| `ai_backends_list` | AI | Configured AI/scanner/logger runtime |
