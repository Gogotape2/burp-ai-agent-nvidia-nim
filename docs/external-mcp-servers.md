# External MCP Servers

Custom AI Agent can connect to external or custom MCP servers over SSE (HTTP-based) or stdio (local process) transports, so AI agents can call tools from those servers alongside Burp's built-in MCP tools in the same session.

> **Full build only.** External MCP servers, the **Settings > MCP Server > External MCP Servers** section and the `ext:` tools are part of the GitHub full build (`./gradlew fullJar`, `Custom-AI-Agent-full-<version>.jar`). The BApp Store build (`./gradlew bappJar`) has neither the external MCP client nor that settings section. See [the README build section](../README.md#1-install).

## Setup

1. Open **Settings > MCP Server** and expand **External MCP Servers**.
2. Click **Add Server**, enter a **Display name** and choose the **Transport**:
   - **SSE**: enter the full SSE URL in **Server URL** (e.g. `http://localhost:3000/sse`).
   - **stdio**: enter the executable in **Command** (e.g. `/usr/local/bin/my-mcp-server`). The **Transport** list offers stdio only while **Enable stdio bridge** is on in the same tab.
3. For SSE servers that require authentication, enter the **Bearer token**. The token is stored encrypted at rest (AES-256-GCM) — see [Security Notes](#security-notes) for what that does and does not protect against.
4. Click **Save Server**, then **Save settings**. Once connected, the server's tools appear in the agent's tool list alongside the built-in Burp tools.

## Transport Types

| Transport | Use When | Example |
|-----------|----------|---------|
| SSE | HTTP-based remote or local server | `http://localhost:3000/sse` |
| stdio | Local process (launched by the extension) | `/usr/local/bin/my-mcp-server` |

## Security Notes

1. Auth tokens for external servers are stored encrypted at rest (AES-256-GCM), the same as Anthropic and other API keys. **The AES master key is itself stored in Burp Preferences, Base64-encoded, beside the ciphertext** (preference `secret.master.key.v1`), so this protects against casual inspection of a preferences file or an export, not against a local attacker who can read those preferences. Full statement: [`README.md`](../README.md#privacy-and-security-notes) and [`SECURITY.md`](../SECURITY.md#security-model).
2. Configuring a non-loopback SSE URL (any host other than `127.0.0.1` or `localhost`) triggers an SSRF warning — confirm intent before proceeding.
3. All output from external servers is wrapped in a trust-boundary marker before it enters the AI prompt, preventing prompt-injection attacks from untrusted or compromised server responses.
4. Every external tool invocation is recorded in the audit log (when audit logging is enabled) with the server name, tool name and status; an error adds its exception class and a SHA-256 and length of the message (the message itself only with Verbose audit on).
5. When the extension's own AI emits a call to an `ext:`-namespaced tool, it always asks you first — every single call, with no "approve for session" option. External tools never inherit a built-in tool's automatic tier. See [Tool-Call Confirmation](ui-safety-guide.md#tool-call-confirmation).
