package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RequestOptions
import java.security.MessageDigest
import java.util.HexFormat

/** Shared by chat, SSE and stdio; owned and shut down with the extension supervisor. */
class McpActiveRuntime(
    api: MontoyaApi,
) : AutoCloseable {
    internal val attacks =
        IntruderAttackRuntime { raw, input, timeout ->
            val request = McpTextMessages.request(input.toMontoyaService(), raw)
            val result =
                api.http().sendRequest(
                    request,
                    RequestOptions
                        .requestOptions()
                        .withHttpMode(HttpMode.HTTP_1)
                        .withUpstreamTLSVerification()
                        .withResponseTimeout(timeout),
                )
            val response = checkNotNull(result?.response()) { "HTTP request completed without a response" }
            val bytes = response.toByteArray()
            val capture = bytes.subArray(0, minOf(bytes.length(), ActiveToolLimits.MAX_CAPTURE_BYTES)).bytes
            AttackHttpResult(response.statusCode().toInt(), bytes.length(), String(capture, Charsets.UTF_8), digest(bytes))
        }
    internal val websockets = WebSocketRuntime(api)

    override fun close() {
        attacks.close()
        websockets.close()
    }

    private fun digest(bytes: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-256")
        var offset = 0
        while (offset < bytes.length()) {
            val end = minOf(offset + ActiveToolLimits.MAX_FRAME_BYTES, bytes.length())
            hash.update(bytes.subArray(offset, end).bytes)
            offset = end
        }
        return HexFormat.of().formatHex(hash.digest())
    }
}
