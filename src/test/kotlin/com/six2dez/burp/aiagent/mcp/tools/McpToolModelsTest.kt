package com.six2dez.burp.aiagent.mcp.tools

import kotlinx.serialization.MissingFieldException
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Core CreateAuditIssue guards; generic model tests are in FullMcpToolModelsTest. */
class McpToolModelsTest {
    @Test
    fun createAuditIssueOverridesTheGuardToCheckOnlyTheHostname() {
        // Documented divergence: CreateAuditIssue's override drops the port check, so a
        // non-blank host with port 0 is ACCEPTED here where SendHttp1Request rejects it.
        val blankHost = decode<CreateAuditIssue>(auditIssueJson(hostname = "", port = 443))
        assertNull(blankHost.toMontoyaServiceOrNull { it })

        val resolver = RecordingResolver()
        val zeroPort = decode<CreateAuditIssue>(auditIssueJson(hostname = "example.com", port = 0))
        runCatching { zeroPort.toMontoyaServiceOrNull(resolver) }

        assertEquals(listOf("example.com"), resolver.seen, "the override checks the hostname only")
    }

    @Test
    fun createAuditIssueDefaultsEveryOptionalNarrativeFieldToNull() {
        val parsed =
            decode<CreateAuditIssue>(
                """
                {"name":"SQL injection","detail":"Detail","baseUrl":"https://example.com/",
                 "severity":"HIGH","confidence":"CERTAIN"}
                """.trimIndent(),
            )

        assertNull(parsed.remediation)
        assertNull(parsed.background)
        assertNull(parsed.remediationBackground)
        assertNull(parsed.typicalSeverity)
        assertNull(parsed.httpRequest)
        assertNull(parsed.httpResponseContent)
        assertEquals("", parsed.targetHostname)
        assertEquals(443, parsed.targetPort)
        assertTrue(parsed.usesHttps)
    }

    @Test
    fun aPayloadMissingSeveralRequiredFieldsFailsDeserialisation() {
        assertThrows(MissingFieldException::class.java) {
            decode<CreateAuditIssue>("""{"name":"issue"}""")
        }
    }

    private class RecordingResolver : (String) -> String {
        val seen = mutableListOf<String>()

        override fun invoke(host: String): String {
            seen += host
            return "resolved-$host"
        }
    }

    private inline fun <reified T> decode(json: String): T = Json.decodeFromString<T>(json)

    private fun auditIssueJson(
        hostname: String,
        port: Int,
    ): String =
        """
        {"name":"SQL injection","detail":"Detail","baseUrl":"https://example.com/","severity":"HIGH",
         "confidence":"CERTAIN","targetHostname":"$hostname","targetPort":$port,"usesHttps":true}
        """.trimIndent()
}
