# Burp AI Agent - NVIDIA NIM fork

Unofficial NVIDIA NIM compatibility fork of [Custom AI Agent by six2dez](https://github.com/six2dez/burp-ai-agent).
Based on upstream **v1.0.0**, commit `e7d3fc47d224d661e990c28da82dfa3bac50fa6b`.
Fork release: **1.0.0-nim.18**. The extension appears in Burp as **Custom AI Agent**.

**[Download nim.18](https://github.com/Gogotape2/burp-ai-agent-nvidia-nim/releases/tag/v1.0.0-nim.18)** | [Technical notes](docs/nvidia-nim-patch.md) | [Web research](docs/web-research.md) | [Validation](verification/nim.18/verification.json) | [Upstream README](README.upstream.md)

## Latest release: 1.0.0-nim.18

The full build now exposes **71 built-in tools**. Nine new tools let the model run bounded HTTP payload attacks and manage extension-owned WebSockets. Payload attacks support Sniper, Battering Ram, Pitchfork and Cluster Bomb, asynchronous progress, paginated results, response hashes and cancellation. WebSockets support custom upgrade requests, text/binary sends, cursor-based reads and explicit close.

The payload runner uses Burp's HTTP API. It is separate from the native Intruder GUI, whose public API still only stages requests. WebSocket tools create their own connections; captured browser sockets remain read-only history. Existing permissions, automatic-approval preference, scope and privacy controls apply. See [usage and limits](docs/active-testing-nim18.md).

This release also includes the nim.17 tool-runtime and external-MCP repairs; see [technical details](docs/tool-runtime-nim17.md).

## Previous release: 1.0.0-nim.16

Interactive chat replies default to Russian; explicit user requests for another language still apply. Scanner prompts and structured scanner output are unchanged. Tool arguments/results and internal result-followup wrappers are not rendered as large chat bubbles: the model retains its existing history/context, and the chat shows compact tool status rows. Restored transcripts use the same presentation rules. Sanitized diagnostic details remain in Execution log.

An explicit practical-testing request that ends without a successful HTTP/active-testing tool receives a separate incomplete-execution notice. Its **Выполнить проверку** button starts a new model request only when clicked, through the current tool catalog and existing approval/scope gates. This is conservative Russian/English intent detection and actual tool bookkeeping, not proof that a vulnerability was confirmed. Unavailable tools disable the button; stale cards cannot start work in another task.

NIM waiting messages distinguish request preparation, the extension's queue, provider waiting, response processing, retry/backoff, tool execution and the final answer. A task clock survives transitions and retries; a separate phase clock identifies the current wait. Buffered NIM output is classified before rendering, so raw function JSON does not flash into the transcript.

Selected compatible upstream fixes add an explicit UTF-8 JSON content type and classify HTTP 429 health results as reachable/degraded. See [upstream review](docs/upstream-review-nim16.md) for adopted and deferred changes. Artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.16.jar`. This release uses the exact previously tested local JAR; publication metadata is attached separately from the original verification snapshot.

## Previous release: 1.0.0-nim.15

NVIDIA NIM settings now include **Tool calls per analysis**, with a default of 24 and a range of 1-128. Save applies to the next user request, including requests in an existing chat. Each chain retains its starting limit, counts individual batch members and denied attempts, and requests a final evidence-based answer when exhausted. Existing saved NIM options without this field receive 24; model presets restore the default. Other backends retain their existing limit. Cancellation, request timeouts, scope and approval checks are unchanged.

This release cumulatively includes the native function calling, context management, free web research, execution journal and cancellation fixes developed in nim.8-nim.14. The version-specific notes below retain the original scope of each development snapshot; those snapshots were not published as separate releases.

Artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.15.jar`. Exact nim.15 validation is recorded in [verification](verification/nim.15/verification.json).

## Local update: 1.0.0-nim.14 (unpublished)

After eight automatic tool calls, the chat now explicitly requests a final verdict from the collected evidence and records `tool_limit` in the execution journal. If the provider ignores `tool_choice=none`, one bounded final-answer repair removes function definitions and renders prior tool exchanges as evidence text. No additional tool is executed. A provider that continues returning calls stops explicitly after that one repair; both inference usages are counted when available. The original deadline, cancellation, approval and tool-count limits remain in force.

Development artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.14.jar`. Verification is recorded in `verification/nim.14/`; included cumulatively in nim.15.

## Local update: 1.0.0-nim.13 (unpublished)

Cancel now closes the abandoned NIM conversation turn before the next user request. This prevents an unfinished tool-result instruction from merging into the new question. Both initial-generation and tool-followup cancellation have deterministic UI-to-wire regression tests. The backend-list tool distinguishes the selected chat backend from the separate background worker, whose Idle state does not imply NIM failure.

Web research is under **Settings > Burp Integration > Web research**. The nim.12 transport and protocol remain unchanged. The AI health badge caches an explicit Test connection result for five minutes; background polling does not generate requests.

Development artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.13.jar`. Verification is recorded in `verification/nim.13/`; included cumulatively in nim.15.

## Local update: 1.0.0-nim.12 (unpublished)

Free web research is built into the full JAR: no search API key, FCC, Python or browser installation is needed. In **Settings > Burp Integration > Web research**, enable **Free web search and page reading**, save, then start a new chat. The switch controls the existing `web_search` and `web_fetch` tool toggles. Existing automatic-approval settings apply. New tools are off by default so an upgrade does not silently enable new outbound requests.

`web_search` reads DuckDuckGo Lite results. `web_fetch` reads a public text/HTML source with timestamps, bounded fragments, literal `query` search, and `nextOffset` pagination. Model instructions distinguish current external facts from target evidence: vendor advisories should be read before being cited, routine summaries should not browse, and a matching CVE does not confirm exploitability on the target. Public web text is explicitly untrusted source data.

Requests use a dedicated anonymous HTTP client with a 20-second total deadline, bounded DNS, manual redirect validation, a 1 MiB response limit and small TTL/LRU caches. Cancellation retires only the originating chat's request. Private/reserved addresses and unsupported ports, credentials, downloads and JavaScript execution are rejected. The client uses a direct public Internet connection, separate from Burp's target request tools; corporate environments requiring an explicit proxy are not supported by this initial web transport. Search challenges and unexpected layouts are reported as errors, without retry loops or invented results. Protected search arguments are rejected before outbound traffic.

Local artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.12.jar`. See [web research notes](docs/web-research.md) and `verification/nim.12/` for validation scope. This version has not been published.

## Local update: 1.0.0-nim.11 (unpublished)

NIM now accepts a complete tool-only text turn containing adjacent JSON objects or a JSON array, including a sole JSON/tool fence. Every member is decoded and checked against the enabled function catalog before the first is exposed. Batches are bounded to 16 and run sequentially through the existing approval, scope and iteration gates. Results retain call IDs in both native and text protocols. JSON examples inside prose and mixed report/call payloads remain data.

An explicit unsupported-native-tools response during a followup can switch the conversation to text without losing or duplicating previous results. No API inference is needed between queued batch members. Disabling tools supplies skipped results for remaining members before the final completion.

HTTP 451 now has a specific refusal/access-policy diagnostic rather than a server-error retry hint. The existing no-retry behavior for 451 remains; metadata includes model, actual protocol and statuses from earlier attempts. A 451 after two attempts can follow an earlier transient failure. Error-body text is never copied into diagnostics. The patch does not remove a provider restriction; its exact cause requires the provider response. See [RFC 7725](https://www.rfc-editor.org/rfc/rfc7725.html) for the standard status meaning.

Local artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.11.jar`. Validation and the separate benign API control result are recorded in `verification/nim.11/`. That control contains no target traffic and is not a live Burp test. This version has not been published.

## Local update: 1.0.0-nim.10 (unpublished)

**Settings > NVIDIA NIM > Use GLM 5.3 defaults** fills the model `z-ai/glm-5.3`, NVIDIA endpoint, a 900-second timeout and the standard generation/limit profile. Reasoning and tool calling are Auto, the completion limit is 16,384, and context compaction is enabled. API credentials and extra headers are retained. Click Save and start a new chat to apply the new connection settings.

This is a preset UI update. The nim.9 runtime and GLM verification below remain the baseline; no new live API requests are needed for this button. Local artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.10.jar`.

## Local update: 1.0.0-nim.9 (unpublished)

NIM chat now supports native OpenAI-compatible function calls. **Tool calling = auto** uses native functions and switches to the text protocol only if the endpoint explicitly rejects them. **native** reports that rejection; **text** forces the legacy protocol. Returned batches pass through the existing tool gates in order, and results retain their provider call IDs.

Large approved context and tool results can be stored in a bounded per-chat memory and replaced with concise references. The enabled `context_read` tool retrieves exact ranges or a literal search match. Its snapshot contains only what Burp captured under the configured privacy and capture limits. References expire when a chat is cleared or entries are evicted; they do not restore previously truncated bodies. Disable compaction to keep inline context.

The input footer estimates prompt size, separate from the answer/thinking reserve. **Input token budget** defaults to 64,000 estimated tokens and trims complete older turns; it is a character-based estimate, not the provider tokenizer or a new model context limit. Oversized current requests fail before sending.

**Execution log** in the chat footer shows chain steps, HTTP status, retries, native calls and tool outcomes. Selecting an event shows sanitized arguments/results. Export first opens a redacted preview and writes a new JSON file only after Save. The journal is bounded and held in memory until explicitly exported.

After loading the local JAR, start a new chat. Saved model/connection options apply to new connections; an existing chat can retain its previous connection settings. The automatic-approval checkbox remains independent of native function calling.

Local artifact: `build/libs/Custom-AI-Agent-full-1.0.0-nim.9.jar`. The focused Windows/JDK 21 task ran **833 tests: 831 passed, 2 skipped, zero failures/errors**; ktlintCheck, detekt and shadowJar passed. It includes live GLM checks through the compiled adapter, while its HTTP bridge remains outside Burp's runtime.

GLM 5.3 passed short-response, native-function/result and 43,145-character synthetic-context requests. The real-catalog check accepted 35 enabled schemas with the stock 16,384-token completion limit. Provider latency varied; these checks do not guarantee future availability. See [local verification](verification/nim.9/verification.json), [direct GLM checks](verification/nim.9/glm53-direct.json), [adapter roundtrip](verification/nim.9/glm53-adapter.json) and [catalog check](verification/nim.9/glm53-catalog.json). No private target traffic was submitted. This version has not been published.

## Local update: 1.0.0-nim.8 (unpublished)

The local build fixes report JSON being mistaken for a tool invocation, which could produce `Unknown tool: <issue title>` followed by another model request.
Only a standalone tool payload is executable; code examples embedded in an answer remain data.
An explicit unknown tool receives one final completion with tools disabled, rather than repeated execution attempts.

NIM receives the enabled tool catalog and execution instructions in the system role on every step.
The stock issue-analysis prompt now asks for evidence gathering with enabled tools; unchanged legacy defaults migrate while custom prompts are preserved.
The pending label shows the step number and total elapsed time across the chain.
These instructions improve the tool workflow but do not guarantee a model will follow every instruction.
Start a new chat after updating to avoid older catalogs and generated instructions in retained history.
This development snapshot is included cumulatively in nim.15.

Local validation: **796 tests, 794 passed, 2 skipped, 0 failures/errors**; `ktlintCheck`, `detekt` and `shadowJar` passed.
The initial run exposed an existing test waiting on another chat's global completion event; that wait now matches its own request trace without weakening assertions.
See [nim.8 validation](verification/nim.8/verification.json). No live Burp reload or NVIDIA inference was performed for this build.

## What this fork changes

- A dedicated NVIDIA NIM adapter explicitly requests buffered JSON with `stream=false`, avoiding the original SSE/JSON mismatch behind `Streaming response received`.
- Configurable total timeout, bounded retries, shared concurrency and request-rate limits. Chats, scanners and connection tests use the same NIM request coordinator.
- Model-aware reasoning settings, configurable completion and conversation-history budgets, UTF-8 requests, and clearer provider errors.
- Background status reads the last explicit health result instead of submitting a paid or quota-consuming inference every five seconds.
- Chat retains attached context and tool results without recursively embedding earlier tool followups.
- Passive scanner batch flushing, manual scan delivery and status labels work without relying on Swing HTML rendering.
- An optional **Automatically approve tool calls** checkbox, disabled by default.
- AI tools called from chat receive the actual runtime dependencies. `ai_analyze` uses an independent backend connection with JSON/token options and a bounded wait. `ai_passive_scan` converts proxy history using Montoya's request/response factory.

## Install

Requires Java 21 or newer. Burp Community supports the chat workflow; automatic Burp passive-check integration requires Burp Professional.

1. Download `Custom-AI-Agent-full-1.0.0-nim.18.jar` from this fork's [release](https://github.com/Gogotape2/burp-ai-agent-nvidia-nim/releases/tag/v1.0.0-nim.18).
2. Disable the previous Custom AI Agent extension under **Extensions > Installed**.
3. Add the downloaded file as a **Java** extension. Load one version at a time.
4. Open **Custom AI Agent > Settings** and select **NVIDIA NIM**.
5. Enter your NVIDIA API key and a complete model ID, then save settings.
6. Run **Test connection**, then start a new chat.

The built-in Burp **Use AI** permission is required only for the `burp-ai` backend; NVIDIA NIM uses the external provider configuration.
Existing settings share the upstream configuration location. Starting a new chat avoids reusing transcripts generated by older builds.

## NVIDIA NIM settings

| Setting | Default |
| --- | --- |
| Base URL | `https://integrate.api.nvidia.com` |
| Model preset | `nvidia/nemotron-3-ultra-550b-a55b` |
| Total timeout | 900 seconds |
| Max tokens, answer plus thinking | 16,384; configurable up to 32,768 in this adapter |
| Reasoning effort | Auto |
| Concurrent requests | 5, shared across the extension |
| Requests per window | 30 |
| Window | 60 seconds |
| Additional retries | 2 |
| Tool calling | auto |
| Tool calls per analysis | 24; configurable from 1 to 128 |
| Input token budget | 64,000 estimated tokens |
| Compact large context | Enabled, when context_read is available |
| Retained history | 1,000,000 characters, up to 200 previous messages |

These are client settings, not guarantees of model availability, provider quota, or the model's context window.
The base host, a `/v1` base and a full chat-completions URL are normalized by the adapter.
The adapter's Auto profile requests no reasoning for Nemotron Ultra and low reasoning for its GLM 5.3 profiles; other models retain provider defaults.

## Tool confirmations and scanning

Open **Settings > MCP Server > Tool confirmations**, enable **Automatically approve tool calls**, then save settings to run available model-emitted tools without individual approval cards.
With this option off, the existing confirmation tiers apply, including **Approve for session** and per-call confirmation.
In that default mode, bounded tools can run automatically, the middle tier supports session approval, and the strict tier confirms every call.
Unrecognised names and external `ext:` tool names use the strict tier. Decisions are recorded in the audit/activity output.
**Unsafe Mode** controls capability availability independently of these confirmation tiers.
Per-chat denials remain effective, and already pending cards are not accepted retroactively.
Tool enablement, the unsafe-tool allowlist, MCP Scope and request limits apply independently.

Use `/tools` to inspect the current tool catalog. Custom HTTP tools are named `http1_request` and `http2_request`; this extension does not expose `repeater_send`.
Automatic passive input requires Burp Pro's live passive audit, enabled extension checks, and matching scope.
Existing proxy history is processed through a manual scan action or `ai_passive_scan`; changing scope does not replay old traffic automatically.

## Validation and known limits

The nim.18 selected regression run on Windows/JDK 21 completed **769 tests: 760 passed, 9 skipped, 0 failures/errors**. `ktlintCheck`, `detekt` and `shadowJar` passed. The installed build was checked against isolated HTTP and WebSocket services through its real local MCP server, covering all nine new tools, all four payload modes, cancellation, invalid plans, Unicode and binary frames, custom upgrade headers and connection cleanup. See [nim.18 verification](verification/nim.18/verification.json) and [active-testing documentation](docs/active-testing-nim18.md).

In a live NVIDIA NIM chat, the model executed seven tools over eight model steps in about 23 seconds: three payload requests returned HTTP 200, Cyrillic WebSocket echo matched, the connection closed and the model produced a Russian summary. Results were checked against the installed extension's execution journal. This local fixture measurement is not a provider latency guarantee.

A broader earlier candidate run executed 1,518 tests and failed one existing redaction time-budget stress case (`RedactionTest.windowedScanRedactsJsonPairAcrossEveryBoundaryAlignment`). Its original test and production redaction limits were preserved. The complete suite was not rerun on the final artifact; the selected passing run and installed-Burp checks are separate evidence, not a claim that the full suite is green.

Earlier results retain their version-specific scope:

The nim.16 selected regression task ran **607 tests: 598 passed, 9 skipped, 0 failures/errors** on Windows/JDK 21. `ktlintCheck`, `detekt` and `shadowJar` passed. Tests cover hidden native arguments/results, preserved model evidence, fresh-panel session restoration, execution notices and guarded retry buttons, continuous clocks and cancellation after switching sessions. See [nim.16 verification](verification/nim.16/verification.json). The complete suite and separate live endpoint suite were not repeated. This JAR has not been installed or GUI-tested in the user's running Burp project; publication does not replace that check. The original `published=false` verification field records the local pre-publication snapshot.

Earlier results retain their version-specific scope:

The nim.15 selected regression task ran **589 tests: 580 passed, 9 skipped, 0 failures/errors** on Windows/JDK 21. One additional legacy-options persistence and validation test passed separately.
`ktlintCheck`, `detekt` and `shadowJar` passed.
The tests include the real Swing ChatPanel tool-call/result continuation with a synthetic backend, timeout cleanup, scope filtering and scanner-session isolation.
The exact nim.15 JAR was loaded into Burp Pro. A saved limit of 3 ran three of four synthetic `url_encode` calls and reported the fourth as skipped. After saving 24, the next request in the same chat ran all nine calls. Both chains produced final answers without model errors; no target HTTP requests were sent. See [the validation record](verification/nim.15/verification.json), [sanitized journal](verification/nim.15/burp-ui-execution.json) and [technical notes](docs/nvidia-nim-patch.md).

- The complete suite and separate live endpoint suite were not rerun for nim.15. Earlier version-labelled reports remain under `verification/`, including the [nim.6 baseline](verification/nim.7/nim6-baseline-full-suite.json) with two redaction time-budget failures. Earlier results do not substitute for testing every workflow on this exact build.
- HTTP 429 quota/capacity errors and HTTP 500 provider errors remain possible. Client retries and timeouts cannot increase provider capacity.
- Responses are displayed after generation; this buffered transport does not provide live token streaming. Async HTTP 202 polling is not implemented.
- Stop discards late results locally. Montoya does not expose an HTTP cancellation handle in the transport path used here, so a submitted inference can continue at the provider.
- `ai_analyze` performs model inference. Current-source retrieval uses the separately enabled `web_search` and `web_fetch` tools. Free search relies on public HTML and may encounter challenges or markup changes; the web client does not provide a configured corporate proxy, login, JavaScript rendering or PDF downloads. See [web research](docs/web-research.md). External MCP routing and its limits are described in [the tool runtime notes](docs/tool-runtime-nim17.md).

## Build

Use JDK 21 and the included Gradle wrapper:

```powershell
.\gradlew.bat shadowJar
```

On macOS/Linux use `./gradlew shadowJar`. The output is `build/libs/Custom-AI-Agent-full-1.0.0-nim.18.jar`.
The complete test task remains available as `./gradlew test`; known baseline failures are documented above and are not silently excluded from that task.

## Privacy and security notes

The upstream privacy and [security policy](SECURITY.md) remain relevant to this fork.
Stored API keys and tokens use AES-256-GCM, but the master key is itself stored in **Burp Preferences**, Base64-encoded alongside the ciphertext, under `secret.master.key.v1`.
This addresses casual inspection of preferences or an export; it does not protect against someone who can read those preferences and recover the master key.
Tool confirmation controls and the opt-in automatic mode are described above. See [the UI safety guide](docs/ui-safety-guide.md) for the upstream confirmation design; the checkbox in this fork is an explicit override of per-call approval.

## Credits and license

Original project: [six2dez/burp-ai-agent](https://github.com/six2dez/burp-ai-agent), published as Custom AI Agent.
This is an independent fork and is not an official release by six2dez, NVIDIA or PortSwigger.
The original MIT [LICENSE](LICENSE) and copyright notice are preserved.
