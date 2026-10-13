package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.core.Range
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.intruder.HttpRequestTemplate
import burp.api.montoya.intruder.HttpRequestTemplateGenerationOptions
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.spi.ToolHandler
import kotlinx.serialization.encodeToString

// Phase 29 / D-13 / D-14 — the generic request tools: raw HTTP/1.1 and HTTP/2 sends, Repeater, Intruder,
// Comparer and the request/response parsers. Each descriptor sits next to its handler and was moved
// verbatim from the catalog; each body was moved verbatim from the executor's residual dispatch `when`
// (its early `return`s became `return@toolHandler`). None redacts anything itself:
// McpToolExecutor.executeToolResult wraps every handler result in context.redactIfNeeded. The two
// target sends below are pinned by TargetTrafficTlsTest, and the parameter/cookie carriers by
// ParameterCarrierRedactionTest and CookieCarrierInventoryTest. Contributed by GenericToolProvider.

private val http1RequestHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "http1_request",
                title = "Send HTTP/1.1 request",
                description = "Issues an HTTP/1.1 request and returns the response.",
                category = "Requests",
                defaultEnabled = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { SendHttp1Request::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SendHttp1Request>(args)
        api.logging().logToOutput(
            "MCP HTTP/1.1 request: ${context.resolveHost(input.targetHostname)}:${input.targetPort}",
        )
        val fixedContent = normalizeHttpRequest(input.content)
        // 07-03 D-03: derive the URL from the parameters and reject BEFORE
        // constructing the HttpRequest, so out-of-scope calls never produce
        // outbound traffic. URL derivation is equivalent to request.url() for
        // scope-check purposes.
        val scopeUrl =
            McpScopeFilter.deriveScopeUrl(
                context.resolveHost(input.targetHostname),
                input.targetPort,
                input.usesHttps,
                fixedContent,
            )
        McpScopeFilter.rejectIfOutOfScope(scopeUrl, context)?.let { return@toolHandler it }
        val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), fixedContent)
        // Target traffic follows Burp's own TLS settings so self-signed targets work; only the AI-provider transport requires verification.
        val response = api.http().sendRequest(request, RequestOptions.requestOptions())
        response?.toString() ?: "<no response>"
    }

private val http2RequestHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "http2_request",
                title = "Send HTTP/2 request",
                description = "Issues an HTTP/2 request and returns the response.",
                category = "Requests",
                defaultEnabled = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { SendHttp2Request::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SendHttp2Request>(args)
        api.logging().logToOutput(
            "MCP HTTP/2 request: ${context.resolveHost(input.targetHostname)}:${input.targetPort}",
        )

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")
        val fixedPseudoHeaders =
            LinkedHashMap<String, String>().apply {
                orderedPseudoHeaderNames.forEach { pname ->
                    val value = input.pseudoHeaders[pname.removePrefix(":")] ?: input.pseudoHeaders[pname]
                    if (value != null) put(pname, value)
                }
                input.pseudoHeaders.forEach { (key, value) ->
                    val properKey = if (key.startsWith(":")) key else ":$key"
                    if (!containsKey(properKey)) put(properKey, value)
                }
            }

        // 07-03 D-03: derive the URL from pseudo-headers + target tuple BEFORE
        // constructing any Montoya factory objects, so the scope check runs
        // even when downstream factories are unavailable (and out-of-scope
        // calls never trigger header construction).
        val h2Path = fixedPseudoHeaders[":path"] ?: input.pseudoHeaders["path"] ?: "/"
        val scopeUrl =
            McpScopeFilter.deriveScopeUrl(
                context.resolveHost(input.targetHostname),
                input.targetPort,
                input.usesHttps,
                "GET $h2Path HTTP/2",
            )
        McpScopeFilter.rejectIfOutOfScope(scopeUrl, context)?.let { return@toolHandler it }
        val headerList =
            (fixedPseudoHeaders + input.headers).map {
                HttpHeader.httpHeader(it.key.lowercase(), it.value)
            }
        val request =
            HttpRequest.http2Request(
                input.toMontoyaService(context::resolveHost),
                headerList,
                input.requestBody,
            )
        // Target traffic follows Burp's own TLS settings so self-signed targets work; only the AI-provider transport requires verification.
        val response =
            api.http().sendRequest(
                request,
                RequestOptions.requestOptions().withHttpMode(HttpMode.HTTP_2),
            )
        response?.toString() ?: "<no response>"
    }

private val repeaterTabHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "repeater_tab",
                title = "Create repeater tab",
                description = "Creates a new Repeater tab with the specified HTTP request.",
                category = "Requests",
                defaultEnabled = false,
                unsafeOnly = true,
                // CONFIRM_EACH under ADR-15's "or stage it for one click" clause — the same clause that tiers intruder / intruder_prepare.
                // The handler below builds an HttpRequest from model-supplied `content` and hands it to sendToRepeater, so the
                // request sits one Send click from the wire. It shipped as CONFIRM, which let one approve-for-session click cover every later
                // call with DIFFERENT request content in that chat; the content is the whole attack surface, so per-call is the only defensible tier.
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { CreateRepeaterTab::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<CreateRepeaterTab>(args)
        // 07-03 D-03: reject BEFORE constructing the HttpRequest so out-of-scope
        // URLs never produce any api.repeater() interaction.
        val scopeUrl =
            McpScopeFilter.deriveScopeUrl(
                context.resolveHost(input.targetHostname),
                input.targetPort,
                input.usesHttps,
                input.content,
            )
        McpScopeFilter.rejectIfOutOfScope(scopeUrl, context)?.let { return@toolHandler it }
        val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), input.content)
        api.repeater().sendToRepeater(request, input.tabName)
        "Repeater tab created"
    }

private val repeaterTabWithPayloadHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "repeater_tab_with_payload",
                title = "Create repeater tab with payload",
                description = "Creates a Repeater tab after applying placeholder replacements.",
                category = "Requests",
                defaultEnabled = false,
                unsafeOnly = true,
                // CONFIRM_EACH for the same ADR-15 clause as `repeater_tab` above, and with slightly more reason: the handler below
                // runs applyReplacements(input.content, input.replacements) BEFORE staging, so the request content and the substituted
                // payloads are both model-supplied. Placeholder substitution running first does not make the staged request any less
                // model-authored — it widens what one approve-for-session click would have covered.
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { RepeaterTabWithPayload::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<RepeaterTabWithPayload>(args)
        val rendered = applyReplacements(input.content, input.replacements)
        // 07-03 D-03: reject AFTER replacements (so the final URL is checked)
        // but BEFORE constructing the HttpRequest.
        val scopeUrl =
            McpScopeFilter.deriveScopeUrl(
                context.resolveHost(input.targetHostname),
                input.targetPort,
                input.usesHttps,
                rendered,
            )
        McpScopeFilter.rejectIfOutOfScope(scopeUrl, context)?.let { return@toolHandler it }
        val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), rendered)
        api.repeater().sendToRepeater(request, input.tabName)
        "Repeater tab created"
    }

private val intruderHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "intruder",
                title = "Send to Intruder",
                description = "Sends a request to Intruder.",
                category = "Requests",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { SendToIntruder::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SendToIntruder>(args)
        // 07-03 D-03: reject BEFORE constructing the HttpRequest.
        val scopeUrl =
            McpScopeFilter.deriveScopeUrl(
                context.resolveHost(input.targetHostname),
                input.targetPort,
                input.usesHttps,
                input.content,
            )
        McpScopeFilter.rejectIfOutOfScope(scopeUrl, context)?.let { return@toolHandler it }
        val request = HttpRequest.httpRequest(input.toMontoyaService(context::resolveHost), input.content)
        api.intruder().sendToIntruder(request, input.tabName)
        "Sent to Intruder"
    }

private val intruderPrepareHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "intruder_prepare",
                title = "Prepare Intruder tab",
                description = "Creates an Intruder tab with explicit insertion points.",
                category = "Requests",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { IntruderPrepare::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<IntruderPrepare>(args)
        val fixed = input.content.replace("\r", "").replace("\n", "\r\n")
        // 07-03 D-03: derive scope URL from the target tuple + raw content,
        // reject BEFORE constructing the byte template or calling api.intruder().
        val scopeUrl =
            McpScopeFilter.deriveScopeUrl(
                context.resolveHost(input.targetHostname),
                input.targetPort,
                input.usesHttps,
                fixed,
            )
        McpScopeFilter.rejectIfOutOfScope(scopeUrl, context)?.let { return@toolHandler it }
        val byteArray =
            burp.api.montoya.core.ByteArray
                .byteArray(fixed)
        val template =
            if (input.insertionPoints.isNotEmpty()) {
                val ranges = input.insertionPoints.map { Range.range(it.start, it.end) }
                HttpRequestTemplate.httpRequestTemplate(byteArray, ranges)
            } else {
                val option = HttpRequestTemplateGenerationOptions.valueOf(input.mode.trim().uppercase())
                HttpRequestTemplate.httpRequestTemplate(byteArray, option)
            }
        api.intruder().sendToIntruder(input.toMontoyaService(context::resolveHost), template, input.tabName)
        "Intruder tab created"
    }

private val insertionPointsHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "insertion_points",
                title = "List insertion points",
                description = "Lists insertion point offsets for a request.",
                category = "Requests",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { InsertionPoints::class.asInputSchema() },
    ) { args, _ ->
        val input = decodeToolArgs<InsertionPoints>(args)
        val request = HttpRequest.httpRequest(input.content)
        val option = HttpRequestTemplateGenerationOptions.valueOf(input.mode.trim().uppercase())
        val template = HttpRequestTemplate.httpRequestTemplate(request, option)
        template.insertionPointOffsets().joinToString(separator = "\n") { range ->
            "start=${range.startIndexInclusive()} end=${range.endIndexExclusive()}"
        }
    }

private val paramsExtractHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "params_extract",
                title = "Extract parameters",
                description = "Extracts parameters from a request.",
                category = "Requests",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { ExtractParams::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<ExtractParams>(args)
        val request = HttpRequest.httpRequest(input.content)
        // (PRIV-05) D-27-17: the line shape reads its three fields off the
        // SANITIZED ParsedParam rather than off the Montoya parameter, so the
        // cookie control cannot be bypassed by the formatter. `type` is
        // HttpParameterType.name where it used to be the enum's toString();
        // ParameterCarrierRedactionTest's enum-parity fixture is what proves
        // those are the same token for every constant, so the rendered line is
        // byte-identical for a non-cookie type.
        sanitizeParameters(request.parameters(), context).joinToString(separator = "\n") { param ->
            "type=${param.type} name=${param.name} value=${param.value}"
        }
    }

private val diffRequestsHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "diff_requests",
                title = "Diff requests",
                description = "Produces a line diff between two requests.",
                category = "Requests",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { DiffRequests::class.asInputSchema() },
    ) { args, _ ->
        val input = decodeToolArgs<DiffRequests>(args)
        diffLines(input.requestA, input.requestB)
    }

private val requestParseHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "request_parse",
                title = "Parse request",
                description = "Parses a raw HTTP request into method, path, headers, parameters, and body.",
                category = "Requests",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { RequestParse::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<RequestParse>(args)
        val request = HttpRequest.httpRequest(input.content)
        val parsed =
            ParsedRequest(
                method = request.method(),
                path = request.path(),
                url = maybeAnonymizeUrl(request.url(), context),
                headers = sanitizeHeaders(request.headers(), context),
                // (PRIV-05) D-27-17: this field and the `headers` field one line
                // above carry the SAME cookie bytes — Burp parses `Cookie:` into
                // COOKIE-typed parameters — and they were controlled three rounds
                // apart. Deleting either call re-opens the leak on the sibling.
                parameters = sanitizeParameters(request.parameters(), context),
                body = if (input.includeBody) request.bodyToString() else null,
                bodyLength = request.body().length(),
            )
        toolJson.encodeToString(parsed)
    }

private val responseParseHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "response_parse",
                title = "Parse response",
                description = "Parses a raw HTTP response into status, headers, and body.",
                category = "Requests",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { ResponseParse::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<ResponseParse>(args)
        val response =
            burp.api.montoya.http.message.responses.HttpResponse
                .httpResponse(input.content)
        val parsed =
            ParsedResponse(
                statusCode = response.statusCode().toInt(),
                headers = sanitizeHeaders(response.headers(), context),
                body = if (input.includeBody) response.bodyToString() else null,
                bodyLength = response.body().length(),
            )
        toolJson.encodeToString(parsed)
    }

private val findReflectedHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "find_reflected",
                title = "Find reflected values",
                description = "Finds reflected parameter values in a response.",
                category = "Requests",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { FindReflected::class.asInputSchema() },
    ) { args, _ ->
        val input = decodeToolArgs<FindReflected>(args)
        val request = HttpRequest.httpRequest(input.request)
        val responseText = input.response
        val hits =
            request.parameters().mapNotNull { param ->
                val value = param.value()
                if (value.isBlank()) return@mapNotNull null
                val count = countOccurrences(responseText, value)
                if (count > 0) "name=${param.name()} type=${param.type()} count=$count" else null
            }
        if (hits.isEmpty()) "No reflections found" else hits.joinToString(separator = "\n")
    }

// Montoya's sendToComparer takes a vararg; the spread is the only way to hand it a list.
@Suppress("SpreadOperator")
private val comparerSendHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "comparer_send",
                title = "Send to Comparer",
                description = "Sends one or more items to Burp Comparer.",
                category = "Requests",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { ComparerSend::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<ComparerSend>(args)
        val byteArrays =
            input.items.map {
                burp.api.montoya.core.ByteArray
                    .byteArray(it)
            }
        api.comparer().sendToComparer(*byteArrays.toTypedArray())
        "Sent ${input.items.size} item(s) to Comparer"
    }

/** The request handlers, in declared order. Declared last: top-level properties initialize in file order. */
internal val genericRequestHandlers: List<ToolHandler> =
    listOf(
        http1RequestHandler,
        http2RequestHandler,
        repeaterTabHandler,
        repeaterTabWithPayloadHandler,
        intruderHandler,
        intruderPrepareHandler,
        insertionPointsHandler,
        paramsExtractHandler,
        diffRequestsHandler,
        requestParseHandler,
        responseParseHandler,
        findReflectedHandler,
        comparerSendHandler,
    )
