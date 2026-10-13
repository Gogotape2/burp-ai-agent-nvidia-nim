package com.six2dez.burp.aiagent.mcp.tools

import kotlinx.serialization.MissingFieldException
import kotlinx.serialization.SerializationException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/**
 * Tests for the MCP tool-input models in `McpToolModels.kt`.
 *
 * Phase 26 plan 26-02 (QUAL-06 / SC2). The production path for these models is
 * `model-supplied JSON -> kotlinx.serialization -> tool-input data class`, so every model here is
 * built by DESERIALISING a payload through the production `toolJson` instance rather than by
 * calling its Kotlin constructor. Constructor calls appear only as the EXPECTED value of an
 * equality assertion.
 *
 * Three trust boundaries are asserted:
 *
 *  - T-26-02-04: `toMontoyaServiceOrNull` rejects a blank hostname and a non-positive port, so a
 *    partially specified model-supplied target cannot become an outbound request destination.
 *  - T-26-02-05: a payload missing a REQUIRED field FAILS rather than silently defaulting, so a
 *    model-emitted call cannot acquire a parameter value the model never wrote.
 *  - The `require(...)` init guards on `ScopeCheck` / `ScopeUpdate` reject a blank URL.
 *
 * `HttpService.httpService(...)` cannot be called in a unit test — it dereferences
 * `burp.api.montoya.internal.ObjectFactoryLocator.FACTORY`, which is null outside the Burp
 * runtime. The guard is therefore asserted through a recording `resolveHost` transform: the
 * transform is only invoked once the guard has been passed, so "the resolver saw the hostname"
 * and "the resolver saw nothing" are exactly the accept and reject outcomes.
 */
class FullMcpToolModelsTest {
    // ── toMontoyaServiceOrNull / toMontoyaService (T-26-02-04) ───────────────────────────

    @Nested
    inner class HttpServiceGuard {
        @Test
        fun aBlankHostnameIsRejected() {
            listOf("", "   ").forEach { hostname ->
                val resolver = RecordingResolver()
                val params = decode<SendHttp1Request>(http1Json(hostname, 443))

                assertNull(params.toMontoyaServiceOrNull(resolver), "hostname=[$hostname]")
                assertTrue(resolver.seen.isEmpty(), "a rejected target must never reach resolveHost")
            }
        }

        @Test
        fun aZeroOrNegativePortIsRejected() {
            listOf(0, -1, -443).forEach { port ->
                val resolver = RecordingResolver()
                val params = decode<SendHttp1Request>(http1Json("example.com", port))

                assertNull(params.toMontoyaServiceOrNull(resolver), "port=$port")
                assertTrue(resolver.seen.isEmpty(), "a rejected target must never reach resolveHost")
            }
        }

        @Test
        fun aValidHostAndPortPassTheGuardAndReachTheMontoyaFactory() {
            val resolver = RecordingResolver()
            val params = decode<SendHttp1Request>(http1Json("example.com", 443))

            val outcome = runCatching { params.toMontoyaServiceOrNull(resolver) }

            assertEquals(listOf("example.com"), resolver.seen, "a valid pair must pass the guard")
            assertFalse(
                outcome.isSuccess && outcome.getOrNull() == null,
                "a valid host/port pair must never yield a silent null",
            )
        }

        @Test
        fun toMontoyaServiceAppliesTheResolveHostTransformItIsGiven() {
            val resolver = RecordingResolver()
            val params = decode<SendHttp1Request>(http1Json("host-abcdef012345.local", 8443))

            runCatching { params.toMontoyaService(resolver) }

            assertEquals(
                listOf("host-abcdef012345.local"),
                resolver.seen,
                "toMontoyaService must route the hostname through the supplied transform",
            )
        }

        @Test
        fun everyHttpServiceParamsModelSharesTheSameDefaultGuard() {
            val blankTargets =
                listOf(
                    decode<SendHttp2Request>(http2Json("")),
                    decode<CreateRepeaterTab>(repeaterJson("")),
                    decode<RepeaterTabWithPayload>(repeaterWithPayloadJson("")),
                    decode<SendToIntruder>(intruderJson("")),
                    decode<IntruderPrepare>(intruderPrepareJson("")),
                    decode<StartAuditWithRequests>(startAuditWithRequestsJson("")),
                )

            blankTargets.forEach { params ->
                assertNull(params.toMontoyaServiceOrNull { it }, "blank host on ${params::class.simpleName}")
            }
        }
    }

    // ── Required fields must FAIL, never silently default (T-26-02-05) ───────────────────

    @Nested
    inner class RequiredFields {
        @Test
        fun aPayloadMissingARequiredFieldFailsDeserialisation() {
            val missingHostname =
                """{"content":"GET / HTTP/1.1","targetPort":443,"usesHttps":true}"""

            assertThrows(MissingFieldException::class.java) {
                decode<SendHttp1Request>(missingHostname)
            }
        }

        @Test
        fun aPayloadMissingSeveralRequiredFieldsFailsDeserialisation() {
            assertThrows(MissingFieldException::class.java) {
                decode<StartAuditWithRequests>("""{"builtInConfiguration":"legacy_active"}""")
            }
        }

        @Test
        fun aRequiredFieldOfTheWrongShapeFailsDeserialisation() {
            val portAsArray =
                """{"content":"GET / HTTP/1.1","targetHostname":"example.com","targetPort":[443],"usesHttps":true}"""

            assertThrows(SerializationException::class.java) {
                decode<SendHttp1Request>(portAsArray)
            }
        }

        @Test
        fun aQuotedIntegerIsAcceptedForAnIntFieldByTheProductionJsonConfiguration() {
            // Observed behaviour, pinned rather than assumed: `toolJson` accepts `"443"` where the
            // model declares an Int. Recorded here so a future change to the Json configuration
            // (isLenient / strict number parsing) surfaces as a failing test rather than as a
            // silent change to what a model-supplied payload is allowed to say.
            val portAsString =
                """{"content":"GET / HTTP/1.1","targetHostname":"example.com","targetPort":"443","usesHttps":true}"""

            assertEquals(443, decode<SendHttp1Request>(portAsString).targetPort)
        }

        @Test
        fun anUnknownFieldFailsDeserialisationUnderTheProductionJsonConfiguration() {
            val extraField =
                """{"token":"a.b.c","injectedField":"surprise"}"""

            assertThrows(SerializationException::class.java) {
                decode<JwtDecode>(extraField)
            }
        }
    }

    // ── require(...) init guards ─────────────────────────────────────────────────────────

    @Nested
    inner class ScopeGuards {
        @Test
        fun scopeCheckRejectsAnAbsentOrBlankUrl() {
            listOf("{}", """{"url":""}""", """{"url":"   "}""").forEach { payload ->
                val error =
                    assertThrows(IllegalArgumentException::class.java) {
                        decode<ScopeCheck>(payload)
                    }
                assertTrue(error.message!!.contains("scope_check"), "payload=$payload got: ${error.message}")
            }
        }

        @Test
        fun scopeUpdateRejectsAnAbsentOrBlankUrl() {
            listOf("{}", """{"url":"  "}""").forEach { payload ->
                val error =
                    assertThrows(IllegalArgumentException::class.java) {
                        decode<ScopeUpdate>(payload)
                    }
                assertTrue(error.message!!.contains("scope_include"), "payload=$payload got: ${error.message}")
            }
        }

        @Test
        fun aNonBlankUrlIsAccepted() {
            assertEquals(
                ScopeCheck("https://example.com/"),
                decode<ScopeCheck>("""{"url":"https://example.com/"}"""),
            )
            assertEquals(
                ScopeUpdate("https://example.com/"),
                decode<ScopeUpdate>("""{"url":"https://example.com/"}"""),
            )
        }
    }

    // ── Documented defaults when every optional field is omitted ─────────────────────────

    @Nested
    inner class OmittedOptionalFieldsYieldDocumentedDefaults {
        @Test
        fun intruderPrepareDefaultsToNoInsertionPointsAndTheOffsetsMode() {
            val parsed = decode<IntruderPrepare>(intruderPrepareJson("example.com"))

            assertEquals(emptyList<InsertionPointRange>(), parsed.insertionPoints)
            assertEquals("REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS", parsed.mode)
            assertNull(parsed.tabName)
        }

        @Test
        fun insertionPointsAndParseModelsCarryTheirDefaults() {
            assertEquals(
                InsertionPoints("GET / HTTP/1.1", "REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS"),
                decode<InsertionPoints>("""{"content":"GET / HTTP/1.1"}"""),
            )
            assertEquals(
                RequestParse("GET / HTTP/1.1", includeBody = false),
                decode<RequestParse>("""{"content":"GET / HTTP/1.1"}"""),
            )
            assertEquals(
                ResponseParse("HTTP/1.1 200 OK", includeBody = false),
                decode<ResponseParse>("""{"content":"HTTP/1.1 200 OK"}"""),
            )
        }

        @Test
        fun proxyHistoryAnnotateDefaultsToNoHighlightScopeOnlyAndALimitOfTwenty() {
            val parsed = decode<ProxyHistoryAnnotate>("""{"regex":"admin","note":"check"}""")

            assertEquals(ProxyHistoryAnnotate("admin", "check", null, scopeOnly = true, limit = 20), parsed)
        }

        @Test
        fun cookieJarGetDefaultsToSubdomainsScopeOnlyAndValuesWithheld() {
            val parsed = decode<CookieJarGet>("{}")

            assertEquals(
                CookieJarGet(domain = null, includeSubdomains = true, scopeOnly = true, includeValues = false),
                parsed,
            )
            assertFalse(parsed.includeValues, "cookie VALUES must stay withheld unless explicitly requested")
        }

        @Test
        fun everyPaginatedModelDefaultsToFiveItemsFromOffsetZero() {
            val paginated =
                listOf<Paginated>(
                    decode<GetScannerIssues>("{}"),
                    decode<GetProxyHttpHistory>("{}"),
                    decode<GetProxyHttpHistoryRestricted>("{}"),
                    decode<GetSiteMap>("{}"),
                    decode<GetProxyWebsocketHistory>("{}"),
                    decode<ResponseBodySearch>("""{"regex":"secret"}"""),
                    decode<GetProxyHttpHistoryRegex>("""{"regex":"secret"}"""),
                    decode<GetProxyHttpHistoryRegexRestricted>("""{"regex":"secret"}"""),
                    decode<GetProxyWebsocketHistoryRegex>("""{"regex":"secret"}"""),
                    decode<GetSiteMapRegex>("""{"regex":"secret"}"""),
                )

            paginated.forEach { page ->
                assertEquals(5, page.count, "count default on ${page::class.simpleName}")
                assertEquals(0, page.offset, "offset default on ${page::class.simpleName}")
            }
        }

        @Test
        fun theHistoryModelsWithholdUnpreprocessedResponsesAndSpanAllListenerPortsByDefault() {
            assertEquals(
                GetProxyHttpHistory(5, 0, includeUnpreprocessedResponse = false, listenerPort = null),
                decode<GetProxyHttpHistory>("{}"),
            )
            assertEquals(
                GetProxyHttpHistoryRestricted(5, 0, listenerPort = null),
                decode<GetProxyHttpHistoryRestricted>("{}"),
            )
            assertEquals(
                GetProxyHttpHistoryRegex("secret", 5, 0, includeUnpreprocessedResponse = false),
                decode<GetProxyHttpHistoryRegex>("""{"regex":"secret"}"""),
            )
        }

        @Test
        fun responseBodySearchAndCollaboratorModelsDefaultToTheirNarrowSetting() {
            assertTrue(
                decode<ResponseBodySearch>("""{"regex":"secret"}""").scopeOnly,
                "a body search must default to in-scope traffic only",
            )
            assertEquals(
                CollaboratorGenerate(customData = null, options = emptyList()),
                decode<CollaboratorGenerate>("{}"),
            )
            assertEquals(
                CollaboratorPoll("secret-key", includeHttp = false),
                decode<CollaboratorPoll>("""{"secretKey":"secret-key"}"""),
            )
        }

        @Test
        fun startAuditModeDefaultsToNoTargetAndHttps() {
            val parsed = decode<StartAuditMode>("""{"mode":"active"}""")

            assertEquals(StartAuditMode("active", emptyList(), "", 0, usesHttps = true), parsed)
            assertNull(
                parsed.toMontoyaServiceOrNull { it },
                "the default StartAuditMode target must be rejected by the guard, not silently used",
            )
        }
    }

    // ── Realistic payloads map field for field ───────────────────────────────────────────

    @Nested
    inner class RealisticPayloads {
        @Test
        fun theRequestSendingModelsMapFieldForField() {
            assertEquals(
                SendHttp1Request("GET /a HTTP/1.1", "example.com", 443, true),
                decode<SendHttp1Request>(http1Json("example.com", 443)),
            )
            assertEquals(
                SendHttp2Request(
                    mapOf(":method" to "GET", ":path" to "/a"),
                    mapOf("accept" to "application/json"),
                    "body",
                    "example.com",
                    443,
                    true,
                ),
                decode<SendHttp2Request>(http2Json("example.com")),
            )
        }

        @Test
        fun theRepeaterAndIntruderModelsMapFieldForField() {
            assertEquals(
                CreateRepeaterTab("tab", "GET /a HTTP/1.1", "example.com", 443, true),
                decode<CreateRepeaterTab>(repeaterJson("example.com")),
            )
            assertEquals(
                RepeaterTabWithPayload(
                    "tab",
                    "GET /§X§ HTTP/1.1",
                    mapOf("§X§" to "admin"),
                    "example.com",
                    443,
                    true,
                ),
                decode<RepeaterTabWithPayload>(repeaterWithPayloadJson("example.com")),
            )
            assertEquals(
                SendToIntruder("tab", "GET /a HTTP/1.1", "example.com", 443, true),
                decode<SendToIntruder>(intruderJson("example.com")),
            )
        }

        @Test
        fun intruderInsertionPointsAreMappedAsRanges() {
            val parsed =
                decode<IntruderPrepare>(
                    """
                    {"tabName":"tab","content":"GET /a HTTP/1.1",
                     "insertionPoints":[{"start":5,"end":7},{"start":9,"end":11}],
                     "mode":"REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS",
                     "targetHostname":"example.com","targetPort":443,"usesHttps":true}
                    """.trimIndent(),
                )

            assertEquals(listOf(InsertionPointRange(5, 7), InsertionPointRange(9, 11)), parsed.insertionPoints)
        }

        @Test
        fun theScannerModelsMapFieldForField() {
            assertEquals(StartAudit("legacy_active"), decode<StartAudit>("""{"builtInConfiguration":"legacy_active"}"""))
            assertEquals(
                StartAuditWithRequests("legacy_active", listOf("GET /a HTTP/1.1"), "example.com", 443, true),
                decode<StartAuditWithRequests>(startAuditWithRequestsJson("example.com")),
            )
            assertEquals(
                StartCrawl(listOf("https://example.com/")),
                decode<StartCrawl>("""{"seedUrls":["https://example.com/"]}"""),
            )
            assertEquals(GetScanTaskStatus("task-1"), decode<GetScanTaskStatus>("""{"taskId":"task-1"}"""))
            assertEquals(DeleteScanTask("task-1"), decode<DeleteScanTask>("""{"taskId":"task-1"}"""))
        }

        @Test
        fun theScannerReportModelCarriesTheModelSuppliedPath() {
            // The `path` here is what `resolveReportPath` later has to contain (T-26-02-03).
            val parsed =
                decode<GenerateScannerReport>(
                    """{"taskId":null,"allIssues":true,"format":"HTML","path":"../../etc/passwd"}""",
                )

            assertEquals(GenerateScannerReport(null, true, "HTML", "../../etc/passwd"), parsed)
            assertThrows(IllegalArgumentException::class.java) { resolveReportPath(parsed.path) }
        }

        @Test
        fun theEncodingAndUtilityModelsMapFieldForField() {
            assertEquals(UrlEncode("a b"), decode<UrlEncode>("""{"content":"a b"}"""))
            assertEquals(UrlDecode("a%20b"), decode<UrlDecode>("""{"content":"a%20b"}"""))
            assertEquals(Base64Encode("plain"), decode<Base64Encode>("""{"content":"plain"}"""))
            assertEquals(Base64Decode("cGxhaW4="), decode<Base64Decode>("""{"content":"cGxhaW4="}"""))
            assertEquals(DecodeAs("cGxhaW4=", "utf-8"), decode<DecodeAs>("""{"base64":"cGxhaW4=","encoding":"utf-8"}"""))
            assertEquals(JwtDecode("a.b.c"), decode<JwtDecode>("""{"token":"a.b.c"}"""))
            assertEquals(HashCompute("plain", "sha256"), decode<HashCompute>("""{"content":"plain","algorithm":"sha256"}"""))
            assertEquals(
                GenerateRandomString(16, "alphanumeric"),
                decode<GenerateRandomString>("""{"length":16,"characterSet":"alphanumeric"}"""),
            )
        }

        @Test
        fun theAnalysisModelsMapFieldForField() {
            assertEquals(ExtractParams("GET /a?x=1 HTTP/1.1"), decode<ExtractParams>("""{"content":"GET /a?x=1 HTTP/1.1"}"""))
            assertEquals(DiffRequests("a", "b"), decode<DiffRequests>("""{"requestA":"a","requestB":"b"}"""))
            assertEquals(FindReflected("req", "res"), decode<FindReflected>("""{"request":"req","response":"res"}"""))
            assertEquals(ComparerSend(listOf("a", "b")), decode<ComparerSend>("""{"items":["a","b"]}"""))
        }

        @Test
        fun theBurpStateModelsMapFieldForField() {
            assertEquals(SetProjectOptions("""{"a":1}"""), decode<SetProjectOptions>("""{"json":"{\"a\":1}"}"""))
            assertEquals(SetUserOptions("""{"a":1}"""), decode<SetUserOptions>("""{"json":"{\"a\":1}"}"""))
            assertEquals(SetTaskExecutionEngineState(true), decode<SetTaskExecutionEngineState>("""{"running":true}"""))
            assertEquals(SetProxyInterceptState(false), decode<SetProxyInterceptState>("""{"intercepting":false}"""))
            assertEquals(SetActiveEditorContents("text"), decode<SetActiveEditorContents>("""{"text":"text"}"""))
        }

        @Test
        fun theParsedResultModelsMapFieldForField() {
            assertEquals(
                ParsedParam("query", "x", "1"),
                decode<ParsedParam>("""{"type":"query","name":"x","value":"1"}"""),
            )
            assertEquals(
                ParsedRequest(
                    "GET",
                    "/a",
                    "https://example.com/a",
                    mapOf("Accept" to "*/*"),
                    listOf(ParsedParam("query", "x", "1")),
                    null,
                    0,
                ),
                decode<ParsedRequest>(
                    """
                    {"method":"GET","path":"/a","url":"https://example.com/a","headers":{"Accept":"*/*"},
                     "parameters":[{"type":"query","name":"x","value":"1"}],"bodyLength":0}
                    """.trimIndent(),
                ),
            )
            assertEquals(
                ParsedResponse(200, mapOf("Content-Type" to "text/html"), null, 0),
                decode<ParsedResponse>("""{"statusCode":200,"headers":{"Content-Type":"text/html"},"bodyLength":0}"""),
            )
            assertEquals(
                CookieEntry("sid", "abc", "example.com", "/", null),
                decode<CookieEntry>("""{"name":"sid","value":"abc","domain":"example.com","path":"/"}"""),
            )
        }
    }

    // ── Fixtures ─────────────────────────────────────────────────────────────────────────

    /** Records the hostnames the guard forwards, which is only ever after the guard has passed. */
    private class RecordingResolver : (String) -> String {
        val seen = mutableListOf<String>()

        override fun invoke(host: String): String {
            seen += host
            return "resolved-$host"
        }
    }

    private inline fun <reified T> decode(json: String): T = toolJson.decodeFromString<T>(json)

    private fun http1Json(
        hostname: String,
        port: Int,
    ): String = """{"content":"GET /a HTTP/1.1","targetHostname":"$hostname","targetPort":$port,"usesHttps":true}"""

    private fun http2Json(hostname: String): String =
        """
        {"pseudoHeaders":{":method":"GET",":path":"/a"},"headers":{"accept":"application/json"},
         "requestBody":"body","targetHostname":"$hostname","targetPort":443,"usesHttps":true}
        """.trimIndent()

    private fun repeaterJson(hostname: String): String = """{"tabName":"tab","content":"GET /a HTTP/1.1","targetHostname":"$hostname","targetPort":443,"usesHttps":true}"""

    private fun repeaterWithPayloadJson(hostname: String): String =
        """
        {"tabName":"tab","content":"GET /§X§ HTTP/1.1","replacements":{"§X§":"admin"},
         "targetHostname":"$hostname","targetPort":443,"usesHttps":true}
        """.trimIndent()

    private fun intruderJson(hostname: String): String = """{"tabName":"tab","content":"GET /a HTTP/1.1","targetHostname":"$hostname","targetPort":443,"usesHttps":true}"""

    private fun intruderPrepareJson(hostname: String): String = """{"tabName":null,"content":"GET /a HTTP/1.1","targetHostname":"$hostname","targetPort":443,"usesHttps":true}"""

    private fun startAuditWithRequestsJson(hostname: String): String =
        """
        {"builtInConfiguration":"legacy_active","requests":["GET /a HTTP/1.1"],
         "targetHostname":"$hostname","targetPort":443,"usesHttps":true}
        """.trimIndent()
}
