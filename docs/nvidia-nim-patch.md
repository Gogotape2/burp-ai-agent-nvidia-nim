# NVIDIA NIM patch notes - 1.0.0-nim.16

Upstream base: [v1.0.0](https://github.com/six2dez/burp-ai-agent/releases/tag/v1.0.0), commit `e7d3fc47d224d661e990c28da82dfa3bac50fa6b`.
This document describes the cumulative unofficial patch. It contains no runtime credentials or captured target traffic.

Release: [1.0.0-nim.16](https://github.com/Gogotape2/burp-ai-agent-nvidia-nim/releases/tag/v1.0.0-nim.16). Current regression results are recorded in [nim.16 verification](../verification/nim.16/verification.json); its pre-publication snapshot is preserved. This JAR was not installed or GUI-tested in the running Burp project. Earlier Burp UI results belong to [nim.15](../verification/nim.15/verification.json). The older sections below retain their original version-specific scope; statements about loading and testing a development snapshot refer to that snapshot.

## nim.16 chat workflow and upstream review

Chat presentation now keeps native call JSON, raw tool-result rows and internal tool-result followups out of the visible transcript. The existing model history and context snapshots retain the data. The same presentation filter applies to restored sessions; ordinary explanations and code examples remain visible. Model instructions request concise evidence summaries rather than full tool dumps.

The interactive system instruction defaults replies to Russian, preserving code/schema/evidence literals and allowing an explicit user language override. Scanner prompts are not modified. An explicit practical-testing request receives an incomplete-execution notice when tool bookkeeping does not show a successful HTTP/active-testing call. The optional action button sends a new request under current permissions and scope; it does not invent a request or bypass a refusal. Read-only history lookup, denied calls, failures and successful HTTP execution are distinguished; completed execution is not a confirmed vulnerability verdict.

Progress displays the local request queue, provider waiting, retries, tool execution and finalization with separate total/phase clocks. The total clock is fixed at the root request; cancelling a tool stops its local activity row and continuation, including after switching sessions. A superseded worker can close its original activity row without showing its result or restarting a model followup.

The upstream review and limited compatible backports are recorded in [upstream review](upstream-review-nim16.md). Publication uses the exact tested local nim.16 JAR with updated release documentation.

## Local nim.15 configurable tool limit

Under Settings > AI Backend > NVIDIA NIM, **Tool calls per analysis** accepts 1-128, default 24. The value persists in the existing NIM options object, with missing legacy fields receiving the default. Save affects the next user request; an active chain keeps its original budget and step numbering. Each individual tool attempt, including a batch member or denial, consumes the same monotone budget as before. Exhaustion still disables tools and requests a final verdict; the nim.14 bounded repair remains available. Other backends retain their existing eight-call budget. This setting does not increase HTTP timeouts, rate limits or permissions.

## Local nim.14 final answer after the tool limit

An actual Burp issue-analysis trace reached its eight-call limit. Step 9 correctly had zero enabled tools and received HTTP 200, but the provider still emitted a native function call. The adapter previously failed with `Provider returned tool calls while tools were disabled`, losing the final verdict.

The UI now identifies exhaustion explicitly in its system instruction and execution journal. If an endpoint ignores disabled tools, the adapter makes one final-answer repair under the same deadline and coordinator. It removes function definitions and converts prior native metadata into plain evidence, preserving observed results and skipped batch members. Returned native or standalone textual calls cannot execute or become the repaired final answer. Repeated noncompliance stops without another inference repair. Token usage includes both responses when both are available. No target traffic or provider response bodies are included in the release diagnostics.

## Local nim.13 cancellation regression

Burp UI checks reproduced a fresh request receiving an answer to the cancelled tool task. Conversation normalization had merged the unfinished user/tool-result text with the next user request. An explicit client-side cancellation boundary now ends the abandoned turn, retaining its earlier evidence while keeping the next question in its own user turn. Two regression tests fail on the previous implementation and pass with the boundary. The backend-list tool now reports selected backend and worker state separately. The settings documentation uses the actual Burp Integration tab.


## Local nim.12 free web research

The full JAR adds optional `web_search` and `web_fetch` tools backed by DuckDuckGo Lite and an anonymous public HTTP client. A synchronized master checkbox in MCP Tools controls the existing persisted tool toggles. Research remains behind the existing approval mode, and tools default to off on upgrade. The NIM inference protocol and model profiles are unchanged from nim.11.

See [web research](web-research.md) for the exact reading, pagination, privacy, cancellation, network and cache limits. Opt-in compiled workflow checks and deterministic regression results are recorded separately in `verification/nim.12/`. These development snapshots are included in the cumulative nim.15 release.

## Local nim.11 tool-only text batches and HTTP 451

The NIM adapter decodes complete adjacent tool JSON objects, arrays and sole fences as an ordered bounded batch. It validates all members and enabled names before exposing any call. Native mode normalizes recovered calls into assistant/tool protocol records; forced/fallback text mode carries the same call IDs in text history and merges consecutive result turns. Existing confirmation, allowlist, scope, audit and iteration limits remain in force. JSON inside prose and reports is not executed. Incomplete/mixed batches never expose a partial call.

A native capability fallback during a result followup converts the prepared conversation once and preserves each result. Remaining queued calls are skipped when tools are disabled. Tests exercise the exact reported history/search payload, escaped braces, malformed later members, ID correlation in both protocols, mid-chain fallback and denial cleanup.

HTTP 451 is not a 5xx failure and remains non-retryable. The diagnostic classifies explicit terms/content-policy, account-entitlement and regional phrases into controlled categories, otherwise states that the exact reason is unknown. Raw provider bodies can echo prompts or credentials and remain excluded. Request metadata now includes a bounded model ID, actual native/text protocol and attempt-status sequence. This separates an earlier transient error from the final refusal. The patch cannot change provider access decisions. Standard status semantics: [RFC 7725](https://www.rfc-editor.org/rfc/rfc7725.html).

The separate access probe sends only a short synthetic marker request to GLM and does not replay target traffic. Its result is recorded separately from synthetic regression success; a timeout is not proof of access or of the cause of the user's 451. The new JAR is not automatically loaded into Burp.

## Local nim.10 GLM preset button

The NVIDIA NIM settings card adds Use GLM 5.3 defaults beside the existing Nemotron preset. Both use one shared field-update action; GLM selects z-ai/glm-5.3 and its Auto reasoning profile. The preset applies the NVIDIA base URL, 900-second total timeout and standard NIM options (including 16,384 completion tokens and Auto tool calling). It retains the API key and extra headers. Changes are saved through the existing Save action and apply to a new chat connection.

The existing settings-panel and model-profile tests are used for this UI update. Native runtime validation remains the nim.9 baseline; it is not reported as a new live inference run. The delivery includes the rendered settings card and a separate nim.10 verification report.

## Local nim.9 native functions, context and execution journal

Native NIM turns now carry enabled function schemas in `tools`, assistant `tool_calls` and correlated `tool` results. The adapter validates the whole batch before exposing any call and drains it sequentially through the existing UI gate without additional model inference between queued calls. Scope, allowlists, approval settings and chain limits still apply. Stopping tools supplies skipped results for remaining batch calls before a final `tool_choice=none` completion.

Auto fallback is restricted to explicit unsupported-tools HTTP 400/422 errors. Ordinary failures and missing function calls do not silently select another protocol. Text mode preserves the nim.8 standalone-payload parser. Duplicate IDs, malformed or oversized arguments, incomplete streams and calls returned with tools disabled fail explicitly.

Approved capture snapshots and large results can be compacted into bounded summaries with per-chat references. `context_read` pages exact captured data or searches a literal substring and reapplies the current privacy policy. Storage is in memory, limited to 48 entries and two million characters per chat, and cleared with the chat. Snapshot collection still has request/response body limits; retrieval cannot recover data absent from the capture. Scanner issue captures now include bounded associated HTTP evidence and redact issue descriptions.

A separate estimated input budget includes system instructions, schemas and serialized protocol overhead. Older history is removed in complete turns; current input is rejected if it cannot fit. Character-based estimates are not exact tokenizer counts. Answer/thinking tokens remain a separate provider parameter.

The per-chat execution journal records preparation, queueing, HTTP outcomes, retries, provider usage, tool decisions/results and cancellation. It retains at most 250 events and one million characters, with bounded per-field detail. The dialog sanitizes displayed details; export generates a sanitized preview off the EDT, then writes a new file on explicit Save. Header, structured-key, query/form and provider-token masking applies regardless of chat privacy. Incomplete structured records fail closed during export.

Start a new chat after changing model or protocol options: existing supervisor connections retain their launch configuration. Native reasoning text is excluded from visible answers and the journal. Buffered SSE decoding remains a compatibility path; live SSE transport is not implemented.

## Local nim.9 validation

The final focused Windows/JDK 21 task ran 833 tests: 831 passed, 2 skipped, zero failures/errors. ktlintCheck, detekt and shadowJar passed. It covers UI, MCP, configuration, supervisor, scanner, context, journal and NIM behavior, including invalid argument types and trailing JSON tokens. This is a selected regression set; the full-suite caveat below remains in force.

Live GLM 5.3 checks passed a short answer, a native function/result exchange and 43,145 characters of synthetic context. The compiled adapter also completed a correlated roundtrip and selected scope_check from 35 actual enabled Burp schemas using the stock max_tokens=16384 limit. Test functions use synthetic markers or example.test metadata; they do not send target traffic. The compiled tests use an OkHttp bridge and do not establish live Montoya/Burp UI behavior. The new JAR was not automatically loaded into Burp.

GLM's Auto profile follows the documented low reasoning and clear_thinking=true chat settings; the provider documents OpenAI-compatible tool calls. See the [NVIDIA GLM 5.3 reference](https://docs.api.nvidia.com/nim/reference/z-ai-glm-5-3).

The initial regression reports are retained with their final corrections. Deterministic capture ordering is computed before host anonymization, catalog/EDT ledgers account for the added tool and journal callbacks, URL query metadata follows the current privacy policy, and the legacy HTTP fixture now contains real CRLF delimiters. See [local verification](../verification/nim.9/verification.json) and the separately included intermediate reports. Provider-side delays, quotas and capacity remain outside the patch's control.

## Local nim.8 issue-analysis and tool-chain correction

The parser previously scanned JSON fragments anywhere in an assistant response and accepted an arbitrary `name` field as a tool name.
An issue report such as `{"name":"Authentication Bypass: Login Accepts Arbitrary Credentials"}` could therefore run an unknown tool and trigger another inference after the answer appeared complete.
The whole assistant turn must now be a standalone call, optionally inside a sole `json` or `tool` fence.
Legacy name-plus-arguments and OpenAI-style wrappers remain supported. Report objects with domain fields, name-only objects and examples inside prose are not calls.

Explicit unknown tool calls are recorded with error status and receive one final completion with tools disabled.
Known tools retain bounded recovery for errors such as an excessive history count.
Disabled-tool completions no longer advertise executable tools. Existing approval settings, scope, allowlists and the chain iteration cap remain in force.

NIM receives the current enabled schemas and protocol in the system role on every request, outside retained user history.
Issue analysis requests relevant captured evidence through enabled tools and separates observations from suspected causes and unverified impact.
The unchanged upstream issue-analysis default migrates to this workflow; custom prompts are preserved verbatim.
Model compliance is not guaranteed, and a tool cannot run if it is unavailable or disabled.

The spinner previously restarted for each new assistant bubble rather than wrapping at 60 seconds.
NIM bubbles now share the root request's monotonic start time and show the current chain step.
No provider retry or timeout setting is changed in nim.8.
Validation for this local build is recorded separately from nim.7. No live Burp reload or NVIDIA inference is implied.

The final focused regression task ran 796 tests: 794 passed, two skipped, zero failures/errors; ktlintCheck, detekt and shadowJar passed.
The first run exposed a pre-existing asynchronous test race: a global settle event from another panel could release a failure-path assertion too early.
The harness now supports trace-filtered waits; that assertion and the new NIM chain tests await their own trace. Production assertions were retained.
Report JSON checks also assert that no tool worker was dispatched, so a delayed false invocation cannot pass unnoticed.
See [nim.8 verification](../verification/nim.8/verification.json) and the separately retained [initial run](../verification/nim.8/initial-focused-suite.json).

## Transport, retries and settings

The original NIM configuration enabled streaming while the shared connection expected a complete JSON response.
The dedicated adapter sends `stream=false` with `Accept: application/json`, parses complete JSON replies and can decode a complete buffered SSE body from a compatible gateway.
It preserves UTF-8 and token usage, excludes `reasoning_content` from the visible answer, and reports malformed, truncated, reasoning-only and token-exhausted responses explicitly.

Requests continue through Montoya with upstream TLS verification, Burp's certificate store and configured upstream proxy settings.
The timeout covers queueing, HTTP attempts and retry backoff as one deadline. The Montoya API used here does not expose separate connect/read/write timers.
The default total timeout is 900 seconds. Chat/scanner/AI-tool wait budgets honor this timeout plus the existing 5-second completion margin.
Legacy stock NIM timeouts of 60/120 seconds are raised on the first patched load; explicitly saved later values are retained.

The shared request coordinator enforces extension-wide concurrency and sliding-window limits across chat, scanners, retries and explicit connection tests.
Every attempt counts. Retryable failures share a cooldown so separate sessions do not immediately repeat a failed request.
Retry-After accepts delta seconds and HTTP dates; otherwise bounded backoff applies. Authentication and configuration errors fail immediately.
Retries reuse the same serialized messages, and do not append another copy of the user turn.
Default values and supported ranges are in [NvidiaNimOptions.kt](../src/main/kotlin/com/six2dez/burp/aiagent/config/NvidiaNimOptions.kt).

An explicit Test connection submits a short inference with a maximum 120-second test budget.
Background status only reads the cached explicit health result, scoped to the endpoint/model/credential/header configuration; it does not make periodic NIM inferences.

## Conversation and reasoning

The adapter normalizes adjacent conversation roles, drops orphan assistant turns created by history trimming, and rejects unsupported role placement locally.
NIM chat honors the configured completion limit instead of an unconditional 4,096-token cap.
The history setting is a character-retention budget with a 200-message limit, not the model's token context window.
The first sent context-bearing prompt is retained so captured context and the tool catalog survive later turns.
Tool followups carry the original user request and only the new tool result; preceding followups are not recursively embedded in each other.

The Auto model profile uses none for Nemotron Ultra and low with clear_thinking for the adapter's GLM 5.3 profiles.
Explicit settings are validated against the known profile. Unknown models receive no invented model-specific reasoning parameters.
Provider-side availability and support can change independently of these client profiles.

## Scanner and UI

The passive batch queue has a guarded timer for partial batches, while manual scans bypass batching.
Disabling passive analysis discards buffered automatic work; shutdown does not flush a buffer to the provider.
The worker respects token-budget and native Burp AI gates. Header rows distinguish passive input, scope skips, queued work and budget pauses.
The header uses plain labels so disabled Swing HTML rendering does not expose literal markup.
Worker On demand is separate from provider health and from an independently working chat session.

Automatic passive input still requires Burp Professional's live passive audit, extension checks and matching scope.
Active confirmation continues to depend on eligible passive findings and its configured scope, confidence and risk settings.

## Tool runtime and confirmations

Chat MCP contexts carry the supervisor, passive scanner, backend registry, activity logger, actual chat backend, response preprocessing and configured history/scope settings.
The missing supervisor previously produced `AI tools not initialized` even when the surrounding NIM chat worked.
Native Use AI permission is checked for burp-ai rather than imposed on external NIM.

Each ai_analyze call opens an independent connection using the normal launch configuration and shared NIM coordinator.
JSON mode and the requested output limit are forwarded. Completion, backend error, timeout and thread interruption close the tool-owned connection.
This does not replace the running chat or background scanner connection.
Proxy history entries for ai_passive_scan are filtered by MCP Scope and converted with Montoya's HttpRequestResponse factory, replacing an unsafe cast between unrelated interfaces.

Automatically approve tool calls defaults to false and persists as `mcp.tools.auto.approve`.
When enabled, calls use the audit decision `auto_approved`; disabling restores normal confirmation tiers.
Capability permissions, unsafe allowlists, scope, request limits and explicit per-chat denials remain effective.
An already pending approval card is not automatically accepted when the checkbox changes.

The catalog refreshes when enabled tools change and advertises the configured history page limit.
Actual request tool IDs are http1_request/http2_request; repeater_send is not present.
Web search is not implemented. ai_analyze is inference rather than retrieval, and external MCP production wiring remains incomplete upstream.

## Validation

The nim.7 focused regression ran 789 cases: 787 passed, 2 skipped, zero failures/errors.
It covered UI, MCP, configuration, supervisor, scanner and NIM tests; ktlintCheck, detekt and shadowJar passed with exit code zero.
The real ChatPanel fixture verifies model-tool-result continuation. Other new checks cover external NIM with native AI disabled, JSON/token forwarding, timeout/error cleanup, standalone backend resolution, passive history conversion, scope and scanner-session isolation.
The opt-in live endpoint test was not enabled. No live NVIDIA request or Burp runtime reload was performed for nim.7.

The complete suite was not rerun for nim.7. The included nim.6 baseline report records 1,193 cases with two redaction time-budget failures and two skipped.
An earlier isolated redactor run also reproduced budget failures without coverage instrumentation.
Secrets were hidden by the fail-closed dropped-body behavior while those tests expected in-place redaction within the budget.
Redaction.class is byte-identical between the nim.6 and nim.7 JARs; neither the redactor implementation nor its limits were changed by this patch.
The baseline is disclosed as failing, not reported as a successful full-suite run.

See [verification.json](../verification/nim.7/verification.json), [focused-suite.json](../verification/nim.7/focused-suite.json) and [nim6 baseline](../verification/nim.7/nim6-baseline-full-suite.json).

## Runtime limits

- Provider 429/500 failures can remain after a valid request; the client cannot alter remote quota or capacity.
- Buffered responses appear after generation. A gateway requiring live SSE despite stream=false remains incompatible with this path.
- Async HTTP 202 polling is not implemented.
- Stop resolves local callbacks and drops late results. An already submitted provider inference may still finish because this Montoya path has no HTTP cancellation handle.
- The shared NIM gate spans the extension, including separate custom endpoints and keys.
- Current input and system prompts are outside the retained-history character budget; provider context limits still apply.

## Build

Use JDK 21 and the included Gradle wrapper. Run `./gradlew shadowJar` or `.\gradlew.bat shadowJar` on Windows.
Output for the current local build: `build/libs/Custom-AI-Agent-full-1.0.0-nim.11.jar`.
