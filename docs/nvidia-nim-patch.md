# NVIDIA NIM patch notes - 1.0.0-nim.7

Upstream base: [v1.0.0](https://github.com/six2dez/burp-ai-agent/releases/tag/v1.0.0), commit `e7d3fc47d224d661e990c28da82dfa3bac50fa6b`.
This document describes the cumulative unofficial patch. It contains no runtime credentials or captured target traffic.

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
Output: `build/libs/Custom-AI-Agent-full-1.0.0-nim.7.jar`.
