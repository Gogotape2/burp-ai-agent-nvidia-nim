package com.six2dez.burp.aiagent.mcp

internal object ActiveToolCatalog {
    val tools =
        listOf(
            tool(
                "intruder_attack_start",
                "Start AI payload attack",
                "Runs an extension-owned HTTP payload attack, not the native Intruder GUI. Supply explicit positions with literal markers (for example {{id}}), payloads and baseValue. " +
                    "Modes: SNIPER, BATTERING_RAM, PITCHFORK, CLUSTER_BOMB. Returns attackId immediately. Poll status/results and cancel when done. No automatic encoding; Content-Length is " +
                    "repaired. maxRequests 1-1000 includes optional baseline; concurrency 1-5; intervalMs 0-60000; timeoutMs 1000-120000; durationMs 1000-900000. Do not call legacy " +
                    "intruder/intruder_prepare to execute attacks.",
                true,
                SecTier.CONFIRM_EACH,
            ),
            tool(
                "intruder_attack_status",
                "Payload attack status",
                "Reads progress/state for an attackId returned by intruder_attack_start. Creating a job is not proof a request succeeded; inspect completed/failed and results.",
                false,
                SecTier.AUTO,
            ),
            tool(
                "intruder_attack_results",
                "Payload attack results",
                "Reads payload attack results by request-index offset/count (1-100). Includes status codes, sizes, durations and response hashes. includeMessages returns bounded " +
                    "request/response captures. Revisit pendingIndices after completion; nextOffset paginates. Truncated messages are incomplete evidence.",
                false,
                SecTier.CONFIRM,
            ),
            tool(
                "intruder_attack_cancel",
                "Cancel payload attack",
                "Stops scheduling new requests for an attackId. In-flight HTTP requests may finish before state becomes CANCELLED; inspect status. Results remain available temporarily.",
                true,
                SecTier.CONFIRM,
            ),
            tool(
                "websocket_open",
                "Open WebSocket",
                "Opens an extension-owned WebSocket using targetHostname/targetPort/usesHttps and path. For authenticated handshakes supply a complete GET upgrade request in content. " +
                    "Returns connectionId. timeoutMs 1000-120000. Does not reuse or modify a browser socket; idle connections expire after five minutes.",
                true,
                SecTier.CONFIRM_EACH,
            ),
            tool(
                "websocket_send",
                "Send WebSocket message",
                "Sends exactly one text or base64 binary message on connectionId from websocket_open. Maximum decoded size 64 KiB. Sending is real target traffic. A timeout can mean delivery is unknown: read messages before retrying.",
                true,
                SecTier.CONFIRM_EACH,
            ),
            tool(
                "websocket_receive",
                "Read WebSocket messages",
                "Reads bounded inbound/outbound messages on an extension-owned connection. afterSequence is a stable cursor; count 1-100; waitMs 0-30000. Pass nextSequence on the next " +
                    "call. gap/droppedMessages indicate buffer loss. Binary bodies are withheld when privacy mode is enabled.",
                false,
                SecTier.CONFIRM,
            ),
            tool("websocket_close", "Close WebSocket", "Closes an extension-owned connectionId. Buffered messages remain readable temporarily. Does not affect captured browser WebSockets.", true, SecTier.CONFIRM),
            tool("websocket_connections", "List AI WebSocket connections", "Lists bounded metadata for extension-owned connections: connectionId, URL, state and message counts. Does not expose browser socket handles.", false, SecTier.AUTO),
        )

    private fun tool(
        id: String,
        title: String,
        description: String,
        unsafe: Boolean,
        tier: SecTier,
    ) = McpToolDescriptor(
        id = id,
        title = title,
        description = description,
        category = if (id.startsWith("websocket_")) "WebSocket testing" else "Payload attacks",
        defaultEnabled = true,
        unsafeOnly = unsafe,
        secTier = tier,
    )
}
