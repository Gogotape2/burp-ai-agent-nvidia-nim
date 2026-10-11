package com.six2dez.burp.aiagent.mcp.schema

import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.InteractionId
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.websocket.Direction
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.mcp.tools.toolJson
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.ZonedDateTime
import burp.api.montoya.http.HttpService as MontoyaHttpService
import burp.api.montoya.http.message.HttpRequestResponse as MontoyaHttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence as MontoyaConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity as MontoyaSeverity

/**
 * Tests for the MCP wire schema in `Serialization.kt` — the mapping layer between Montoya
 * objects and the JSON an MCP client receives.
 *
 * Phase 26 plan 26-02 (QUAL-06 / SC2).
 *
 * Two things are asserted that a bulk "construct every data class" test would miss:
 *
 *  - The severity and confidence enums are mapped by NAME (`valueOf(severity().name)`), so a
 *    Montoya enum rename fails loudly here instead of silently mapping into the wrong bucket.
 *  - Every null-tolerance branch (`?: "<no response>"`, `?: "<no request>"`, `?: "<no url>"`,
 *    `?: "<no payload>"`) is exercised, because those are the branches that keep a partially
 *    populated Burp object from throwing into a tool result.
 *
 * Montoya values whose mapping goes through `toString()` are named mocks — mockito returns the
 * mock name from `toString()`, so the fixture text is deterministic without stubbing
 * `toString()` itself. The Montoya static factories cannot be used: they dereference
 * `burp.api.montoya.internal.ObjectFactoryLocator.FACTORY`, which is null outside Burp.
 */
class SerializationTest {
    // ── AuditIssue.toSerializableForm ────────────────────────────────────────────────────

    @Nested
    inner class AuditIssueMapping {
        @Test
        fun mapsEveryFieldItReads() {
            val issue = auditIssue()

            val details = issue.toSerializableForm()

            assertEquals("SQL injection", details.name)
            assertEquals("Detail text", details.detail)
            assertEquals("Remediation text", details.remediation)
            assertEquals(HttpService("example.com", 443, true), details.httpService)
            assertEquals("https://example.com/login", details.baseUrl)
            assertEquals(AuditIssueSeverity.HIGH, details.severity)
            assertEquals(AuditIssueConfidence.CERTAIN, details.confidence)
            assertEquals(
                AuditIssueDefinition("Definition name", "Background", "Definition remediation", 7),
                details.definition,
            )
        }

        @Test
        fun mapsTheRequestResponseList() {
            val issue = auditIssue()

            val details = issue.toSerializableForm()

            assertEquals(1, details.requestResponses.size)
            assertEquals("GET /login HTTP/1.1", details.requestResponses[0].request)
            assertEquals("HTTP/1.1 200 OK", details.requestResponses[0].response)
        }

        @Test
        fun mapsTheCollaboratorInteractions() {
            val issue = auditIssue()

            val details = issue.toSerializableForm()

            assertEquals(1, details.collaboratorInteractions.size)
            assertEquals("interaction-1", details.collaboratorInteractions[0].interactionId)
            assertEquals(interactionTime.toString(), details.collaboratorInteractions[0].timestamp)
        }

        @Test
        fun mapsAnIssueWithNoRequestResponsesAndNoInteractions() {
            val issue = auditIssue(requestResponses = emptyList(), interactions = emptyList())

            val details = issue.toSerializableForm()

            assertTrue(details.requestResponses.isEmpty())
            assertTrue(details.collaboratorInteractions.isEmpty())
        }

        @Test
        fun everyMontoyaSeverityIsMappedByNameNotByOrdinal() {
            // A Montoya enum rename must fail here rather than silently land in the wrong bucket.
            MontoyaSeverity.entries.forEach { montoya ->
                val details = auditIssue(severity = montoya).toSerializableForm()

                assertEquals(montoya.name, details.severity.name, "severity=$montoya")
            }
        }

        @Test
        fun everyMontoyaConfidenceIsMappedByNameNotByOrdinal() {
            MontoyaConfidence.entries.forEach { montoya ->
                val details = auditIssue(confidence = montoya).toSerializableForm()

                assertEquals(montoya.name, details.confidence.name, "confidence=$montoya")
            }
        }
    }

    // ── HttpRequestResponse.toSerializableForm ───────────────────────────────────────────

    @Nested
    inner class HttpRequestResponseMapping {
        @Test
        fun mapsRequestResponseAndNotes() {
            val rr = requestResponse(notes = "analyst note")

            val serialized = rr.toSerializableForm()

            assertEquals("GET /login HTTP/1.1", serialized.request)
            assertEquals("HTTP/1.1 200 OK", serialized.response)
            assertEquals("analyst note", serialized.notes)
        }

        @Test
        fun toleratesANullResponse() {
            val rr = requestResponse(response = null)

            val serialized = rr.toSerializableForm()

            assertEquals("<no response>", serialized.response)
        }

        @Test
        fun toleratesANullRequest() {
            val rr = requestResponse(request = null)

            val serialized = rr.toSerializableForm()

            assertEquals("<no request>", serialized.request)
        }

        @Test
        fun toleratesNullNotes() {
            val rr = requestResponse(notes = null)

            assertNull(rr.toSerializableForm().notes)
        }
    }

    // ── ProxyHttpRequestResponse.toSerializableForm ──────────────────────────────────────

    @Nested
    inner class ProxyHttpRequestResponseMapping {
        @Test
        fun withoutPreprocessorSettingsTheRawResponseIsPassedThrough() {
            val proxy = proxyRequestResponse(RAW_HTML_RESPONSE)

            val serialized = proxy.toSerializableForm()

            assertEquals(RAW_HTML_RESPONSE, serialized.response)
            assertEquals("GET /login HTTP/1.1", serialized.request)
            assertEquals("proxy note", serialized.notes)
        }

        @Test
        fun withPreprocessorSettingsABinaryResponseIsFiltered() {
            val proxy = proxyRequestResponse(BINARY_RESPONSE)

            val serialized = proxy.toSerializableForm(ResponsePreprocessorSettings())

            assertTrue(
                serialized.response!!.contains("Binary content filtered out"),
                "expected the preprocessor to run; got: ${serialized.response}",
            )
        }

        @Test
        fun aMissingResponseSkipsThePreprocessorAndYieldsThePlaceholder() {
            val proxy = proxyRequestResponse(null)

            val serialized = proxy.toSerializableForm(ResponsePreprocessorSettings())

            assertEquals("<no response>", serialized.response)
        }

        @Test
        fun aMissingRequestYieldsThePlaceholder() {
            val proxy = proxyRequestResponse(RAW_HTML_RESPONSE, request = null)

            assertEquals("<no request>", proxy.toSerializableForm().request)
        }
    }

    // ── ProxyWebSocketMessage.toSerializableForm ─────────────────────────────────────────

    @Nested
    inner class ProxyWebSocketMessageMapping {
        @Test
        fun mapsTheClientToServerDirection() {
            val message = webSocketMessage(Direction.CLIENT_TO_SERVER)

            val serialized = message.toSerializableForm()

            assertEquals(WebSocketMessageDirection.CLIENT_TO_SERVER, serialized.direction)
            assertEquals("ws payload", serialized.payload)
            assertEquals("ws note", serialized.notes)
        }

        @Test
        fun mapsTheServerToClientDirection() {
            val message = webSocketMessage(Direction.SERVER_TO_CLIENT)

            assertEquals(WebSocketMessageDirection.SERVER_TO_CLIENT, message.toSerializableForm().direction)
        }

        @Test
        fun toleratesANullPayload() {
            val message = webSocketMessage(Direction.CLIENT_TO_SERVER, payload = null)

            assertEquals("<no payload>", message.toSerializableForm().payload)
        }
    }

    // ── toSiteMapEntry ───────────────────────────────────────────────────────────────────

    @Nested
    inner class SiteMapEntryMapping {
        @Test
        fun producesTheEntryShapeForARequestResponsePair() {
            val rr = requestResponse()

            val entry = rr.toSiteMapEntry()

            assertEquals("https://example.com/login", entry.url)
            assertEquals("GET /login HTTP/1.1", entry.request)
            assertEquals("HTTP/1.1 200 OK", entry.response)
        }

        @Test
        fun aMissingRequestYieldsTheUrlAndRequestPlaceholders() {
            val rr = requestResponse(request = null)

            val entry = rr.toSiteMapEntry()

            assertEquals("<no url>", entry.url)
            assertEquals("<no request>", entry.request)
        }

        @Test
        fun aMissingResponseYieldsTheResponsePlaceholder() {
            val rr = requestResponse(response = null)

            assertEquals("<no response>", rr.toSiteMapEntry().response)
        }
    }

    // ── Wire round-trips through the production Json instance ────────────────────────────

    @Nested
    inner class WireRoundTrip {
        @Test
        fun issueDetailsRoundTripsThroughToolJson() {
            assertRoundTrips(sampleIssueDetails())
        }

        @Test
        fun httpRequestResponseRoundTripsIncludingItsNullFields() {
            assertRoundTrips(HttpRequestResponse(request = null, response = null, notes = null))
            assertRoundTrips(HttpRequestResponse("req", "res", "notes"))
        }

        @Test
        fun webSocketMessageRoundTripsForBothDirections() {
            WebSocketMessageDirection.entries.forEach { direction ->
                assertRoundTrips(WebSocketMessage("payload", direction, "notes"))
            }
        }

        @Test
        fun siteMapEntryHttpServiceAndInteractionRoundTrip() {
            assertRoundTrips(SiteMapEntry("https://example.com/", "req", "res"))
            assertRoundTrips(HttpService("example.com", 8443, false))
            assertRoundTrips(Interaction("id-1", "2026-01-01T00:00Z"))
        }

        @Test
        fun auditIssueDefinitionRoundTripsIncludingItsNullFields() {
            assertRoundTrips(AuditIssueDefinition("id", null, null, 0))
            assertRoundTrips(AuditIssueDefinition("id", "background", "remediation", 3))
        }

        @Test
        fun encodedIssueDetailsCarriesTheEnumNamesOnTheWire() {
            // `toolJson` sets encodeDefaults = true; the enums must serialise as their NAMES so an
            // MCP client reads HIGH/CERTAIN rather than an ordinal that shifts on an enum edit.
            val json = toolJson.encodeToString(sampleIssueDetails())

            assertTrue(json.contains("\"severity\":\"HIGH\""), "got: $json")
            assertTrue(json.contains("\"confidence\":\"CERTAIN\""), "got: $json")
        }

        private inline fun <reified T> assertRoundTrips(value: T) {
            val encoded = toolJson.encodeToString(value)

            assertEquals(value, toolJson.decodeFromString<T>(encoded), "round-trip of $encoded")
        }

        private fun sampleIssueDetails(): IssueDetails =
            IssueDetails(
                name = "SQL injection",
                detail = "Detail",
                remediation = "Remediation",
                httpService = HttpService("example.com", 443, true),
                baseUrl = "https://example.com/login",
                severity = AuditIssueSeverity.HIGH,
                confidence = AuditIssueConfidence.CERTAIN,
                requestResponses = listOf(HttpRequestResponse("req", "res", null)),
                collaboratorInteractions = listOf(Interaction("id-1", "2026-01-01T00:00Z")),
                definition = AuditIssueDefinition("def", "background", "remediation", 1),
            )
    }

    // ── Fixtures ─────────────────────────────────────────────────────────────────────────

    private val interactionTime: ZonedDateTime = ZonedDateTime.parse("2026-01-02T03:04:05Z")

    private fun auditIssue(
        severity: MontoyaSeverity = MontoyaSeverity.HIGH,
        confidence: MontoyaConfidence = MontoyaConfidence.CERTAIN,
        requestResponses: List<MontoyaHttpRequestResponse> = listOf(requestResponse()),
        interactions: List<Interaction> = listOf(interaction()),
    ): AuditIssue {
        val service = mock<MontoyaHttpService>()
        whenever(service.host()).thenReturn("example.com")
        whenever(service.port()).thenReturn(443)
        whenever(service.secure()).thenReturn(true)

        val definition = mock<AuditIssueDefinition>()
        whenever(definition.name()).thenReturn("Definition name")
        whenever(definition.background()).thenReturn("Background")
        whenever(definition.remediation()).thenReturn("Definition remediation")
        whenever(definition.typeIndex()).thenReturn(7)

        // Built before the `whenever` chain below for the same UnfinishedStubbing reason.
        val issue = mock<AuditIssue>()
        whenever(issue.name()).thenReturn("SQL injection")
        whenever(issue.detail()).thenReturn("Detail text")
        whenever(issue.remediation()).thenReturn("Remediation text")
        whenever(issue.httpService()).thenReturn(service)
        whenever(issue.baseUrl()).thenReturn("https://example.com/login")
        whenever(issue.severity()).thenReturn(severity)
        whenever(issue.confidence()).thenReturn(confidence)
        whenever(issue.requestResponses()).thenReturn(requestResponses)
        whenever(issue.collaboratorInteractions()).thenReturn(interactions)
        whenever(issue.definition()).thenReturn(definition)
        return issue
    }

    private fun interaction(): Interaction {
        val id = mock<InteractionId>(name = "interaction-1")
        val interaction = mock<Interaction>()
        whenever(interaction.id()).thenReturn(id)
        whenever(interaction.timeStamp()).thenReturn(interactionTime)
        return interaction
    }

    private fun annotations(notes: String?): Annotations {
        val annotations = mock<Annotations>()
        whenever(annotations.notes()).thenReturn(notes)
        return annotations
    }

    private fun requestResponse(
        request: HttpRequest? = requestMock(),
        response: HttpResponse? = mock(name = "HTTP/1.1 200 OK"),
        notes: String? = "note",
    ): MontoyaHttpRequestResponse {
        // Every collaborating mock is fully built BEFORE the enclosing `whenever` chain starts:
        // creating one inside a `thenReturn(...)` argument trips mockito's UnfinishedStubbing check.
        val annotationsMock = annotations(notes)
        val rr = mock<MontoyaHttpRequestResponse>()
        whenever(rr.request()).thenReturn(request)
        whenever(rr.response()).thenReturn(response)
        whenever(rr.annotations()).thenReturn(annotationsMock)
        return rr
    }

    private fun proxyRequestResponse(
        responseText: String?,
        request: HttpRequest? = requestMock(),
    ): ProxyHttpRequestResponse {
        val responseMock = responseText?.let { mock<HttpResponse>(name = it) }
        val annotationsMock = annotations("proxy note")
        val proxy = mock<ProxyHttpRequestResponse>()
        whenever(proxy.request()).thenReturn(request)
        whenever(proxy.response()).thenReturn(responseMock)
        whenever(proxy.annotations()).thenReturn(annotationsMock)
        return proxy
    }

    private fun webSocketMessage(
        direction: Direction,
        payload: String? = "ws payload",
    ): ProxyWebSocketMessage {
        val payloadMock = payload?.let { mock<ByteArray>(name = it) }
        val annotationsMock = annotations("ws note")
        val message = mock<ProxyWebSocketMessage>()
        whenever(message.direction()).thenReturn(direction)
        whenever(message.payload()).thenReturn(payloadMock)
        whenever(message.annotations()).thenReturn(annotationsMock)
        return message
    }

    private fun requestMock(): HttpRequest {
        val request = mock<HttpRequest>(name = "GET /login HTTP/1.1")
        whenever(request.url()).thenReturn("https://example.com/login")
        return request
    }

    private companion object {
        const val RAW_HTML_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        const val BINARY_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\nPNGDATA"
    }
}
