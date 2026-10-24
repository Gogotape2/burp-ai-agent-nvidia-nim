# Upstream review for nim.16

Reviewed on 2026-10-22. The fork baseline remains upstream v1.0.0 (`e7d3fc47d224d661e990c28da82dfa3bac50fa6b`). This review fetched upstream refs without merging, committing or pushing changes.

The public release list was rechecked on 2026-10-24; v1.1.0 remains the latest listed release.

## Sources inspected

- [v1.0.1 release](https://github.com/six2dez/burp-ai-agent/releases/tag/v1.0.1) and its [hotfix commit b1226a8](https://github.com/six2dez/burp-ai-agent/commit/b1226a8): transport encoding, privacy/redaction, scanner safety, history and health changes.
- [v1.1.0 release](https://github.com/six2dez/burp-ai-agent/releases/tag/v1.1.0), commit `1718308d8d864b94c8347ec537e301a9cbb5d5ac`: separate core/full builds, provider egress rules, scanner suggestions and on-demand status reporting.
- Upstream main at `b1738c0`: Windows source-reading test normalization after v1.1.0.

## Adopted in this local update

Two isolated changes from the v1.0.1 transport hotfix fit the current fork without replacing its NIM protocol: JSON posts explicitly declare `application/json; charset=utf-8`, and HTTP 429 during a connection-health GET means reachable/degraded rather than offline. Request bodies already used explicit UTF-8 bytes in this fork; that behavior is retained and tested. No dependency or scanner-format change is needed.

## Already addressed separately in this fork

The fork already requests buffered NIM JSON, handles native/text tool results, preserves UTF-8 bytes, bounds retries and does not perform idle NIM inference polls. Its AI tool/runtime and proxy-history conversion changes were tested independently. Upstream fixes in these areas are not applied a second time over the custom implementation.

## Deferred after comparison

The v1.1.0 core/full source split, new build tasks and provider egress contracts span backend, supervisor, settings, scanner and MCP boundaries. A direct merge would replace assumptions behind this fork's native tool runtime and requires a dedicated migration. The current full JAR is not converted to the BApp Store provider-permission policy.

The v1.0.1 deterministic redaction/URL handling and active-scanner request-safety changes are significant candidates for a separate port. They span multiple production components and dedicated fixtures; this chat-focused update does not claim to inherit those fixes. Scanner suggestions and auto-queue changes likewise require scanner/UI validation and are not imported here.

These changes are included in fork release nim.16. The earlier nim.15 tag and release retain their original source and artifacts.
