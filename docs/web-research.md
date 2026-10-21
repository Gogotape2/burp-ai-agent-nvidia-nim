# Built-in free web research (nim.15)

Enable **Settings > Burp Integration > Web research > Enable free web search and page reading**, save and start a new chat. The existing optional automatic-approval switch controls confirmation cards. The two tool toggles are persisted in the existing MCP settings map; there is no second permission database. They default to off for existing and new installations.

## What the tools do

- `web_search`: a short product/version/CVE query to DuckDuckGo Lite; 1-10 deduplicated results (default 5), titles and public URLs, observation timestamp and cache status. Search results are leads rather than verified claims.
- `web_fetch`: anonymous public HTTP(S) GET of readable text/HTML/JSON/XML. It returns the final URL, title, timestamp, text range, total character count, `truncated`, and `nextOffset`. `maxChars` defaults to 12000 and cannot exceed 24000. An optional literal `query` locates a relevant passage at or after `offset`; `queryFound=false` is explicit when no match exists. This is not regex search.

Example research sequence:

```json
{"tool":"web_search","args":{"query":"Apache HTTP Server CVE-2024-38475 official advisory","count":5}}
```

Then read the actual vendor source from the returned results:

```json
{"tool":"web_fetch","args":{"url":"https://httpd.apache.org/security/vulnerabilities_24.html","query":"CVE-2024-38475","maxChars":6000}}
```

The chat model receives enabled native functions or the existing text-tool protocol. It is instructed to browse for current external facts, inspect captured evidence before target verification, avoid browsing for ordinary summaries/decoding, read the primary source before citing, and separate an affected-version claim from a confirmed target vulnerability. These are model instructions tested with opt-in live workflows, not a guarantee against every possible model error or adversarial page.

## Limits and privacy

The dedicated client has no Burp cookies, authorization headers, NVIDIA key, browser profile or inherited proxy credentials. Search arguments pass the current privacy policy plus token/cookie protection and are rejected if redaction changes them. In Strict mode, use generic product/version/CVE terms rather than target domains. Public source URLs anonymized in a tool result can be resolved through the existing session host mapping for a later page read. Source text is redacted again before reaching the model. MCP request logs omit raw web arguments while retaining hashes and outcomes.

The client uses a direct public connection and verifies TLS with the JVM trust store. It accepts only ports 80/443 and follows up to four validated redirects. Resolved private, loopback, link-local, reserved and IPv4 transition destinations are rejected, including mixed public/private DNS answers. The addresses supplied to the HTTP connection come from that validated lookup; DNS workers and caller waits are bounded. Public documentation research does not inherit Burp target-scope restrictions; target HTTP, scanning and approval gates remain in effect for the existing tools.

Each operation has a 20-second deadline; at most two web HTTP requests run concurrently. Search starts are spaced by at least 1.5 seconds; failures are never cached or automatically retried. Responses are capped at 1 MiB after HTTP decompression, and the LRU cache holds at most 12 public resources for five minutes. Pagination/search reads cached source text rather than downloading a long advisory repeatedly. Source timestamps reflect the original retrieval and the result indicates cache use.

Cancellation uses a per-worker signal and cancels the matching HTTP call. Clearing/deleting a chat or unloading the extension also supersedes its continuation. No late web result should start another model turn. Unload closes web HTTP and DNS resources after the application stops dispatching work.

HTML scripts, forms, navigation and style content are removed. The tool does not run JavaScript, solve CAPTCHAs, log in, fetch private services, download binaries, render PDFs or execute instructions from pages. A CAPTCHA, HTTP challenge, unexpected search layout, unsupported content type or oversized body returns an explicit tool error. An empty search result is returned only when the provider's response identifies a no-results case.

## Validation

Deterministic tests cover catalog/approval settings, query redaction, strict-mode URL continuation, search parsing, cache TTL/eviction, malformed/challenged search pages, long-page pagination/query, redirect/address validation, body/type limits, cancellation isolation, bounded DNS and UI switch synchronization. Existing NIM protocol and chat approval/EDT tests are retained.

Opt-in endpoint checks use synthetic questions and public vendor documentation with the configured local NVIDIA key held only in process memory/environment. They check a real search/read, model-initiated research for current facts, no browsing for supplied evidence, and a hostile-page fixture. These exercise the compiled adapter with an OkHttp bridge and do not claim that a new JAR was loaded into a running Burp instance. Results and any limitations are recorded in `verification/nim.12/`.

DuckDuckGo HTML is a public web interface, not a contracted search API. Availability, rate limits and markup can change. This release reports failures explicitly; it does not rotate identities, evade challenges or silently switch to a paid service. A self-hosted SearXNG adapter is not included in this version.

The web tools first appeared in the nim.12 development snapshot and are included in the [nim.15 release](https://github.com/Gogotape2/burp-ai-agent-nvidia-nim/releases/tag/v1.0.0-nim.15). Exact nim.15 Burp checks and their limits are recorded in [verification](../verification/nim.15/verification.json).

## Local nim.13 regression fix

An explicit local cancellation boundary separates an abandoned NIM request (including a tool-result followup) from the next user message. Without that boundary, conversation normalization merged both messages into one user turn, allowing the old tool-result instructions to take precedence. Regression tests reproduce both initial-generation and tool-followup cancellation. The backend-list tool now distinguishes the selected chat backend from the separate background worker.
