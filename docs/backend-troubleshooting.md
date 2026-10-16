# Backend Troubleshooting Runbook

## Fast Triage

1. Check the status pill. It shows one of:
   * `AI: OK` — the last check or chat reply reached the backend.
   * `AI: Degraded` — the endpoint is reachable but the check failed, for example authentication or a rate limit; the tooltip says why.
   * `AI: Offline` — the backend did not answer or returned an error; the tooltip carries the error.
   * `AI: ?` — full build, before the first check (the startup check replaces it).
   * `Not checked · click to test` — BApp Store build: no check has run yet. Click the pill or use **Test connection**.
   * `AI disabled in Burp` — Burp's "Use AI" is off and the selected backend was refused. In the BApp Store build that refuses every backend; in the full build, only Burp AI. See the [README Requirements section](../README.md#requirements) for what each Burp edition supports.
2. Run **Test connection** for selected backend.
3. Check Burp extension output/errors tab.

## CLI Backends

> **Full build only.** The CLI backends (Gemini CLI, Claude Code, Codex CLI, OpenCode CLI, Copilot CLI) and the Ollama CLI command are part of the GitHub full build (`./gradlew fullJar`, `Custom-AI-Agent-full-<version>.jar`). The BApp Store build (`./gradlew bappJar`) has no CLI backend. See [the README build section](../README.md#1-install).

1. Run configured command in terminal exactly as in settings.
2. Use full path if GUI-launched Burp misses PATH entries.
3. Re-check auth env vars in Burp runtime context.

## HTTP Backends

1. Verify service is listening on configured URL.
2. Verify model exists and is loadable.
3. Confirm API key/header settings.
4. Increase timeout for large models or long prompts.

## Long Session/Prompt Issues

1. Start a fresh chat session.
2. Reduce manual context body caps.
3. Verify history trimming settings and runtime defaults.

## Escalation Data

When reporting an issue, include:

* backend type and command/URL,
* status pill text,
* extension output error snippet,
* minimal reproducible prompt/action.
