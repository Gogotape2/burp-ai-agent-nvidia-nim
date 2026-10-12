package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.utilities.CompressionType
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.spi.ToolHandler
import kotlinx.serialization.encodeToString
import java.security.MessageDigest

// Phase 29 / D-13 / D-14 — the generic utility tools: encoders, decoders, hashing, JWT and the cookie
// jar. Each descriptor sits next to its handler and was moved verbatim from the catalog; each body was
// moved verbatim from the executor's dispatch `when`. Contributed by GenericToolProvider.

private val urlEncodeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "url_encode",
                title = "URL encode",
                description = "URL encodes the input string.",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { UrlEncode::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<UrlEncode>(args)
        api.utilities().urlUtils().encode(input.content)
    }

private val urlDecodeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "url_decode",
                title = "URL decode",
                description = "URL decodes the input string.",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { UrlDecode::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<UrlDecode>(args)
        api.utilities().urlUtils().decode(input.content)
    }

private val base64EncodeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "base64_encode",
                title = "Base64 encode",
                description = "Base64 encodes the input string.",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { Base64Encode::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<Base64Encode>(args)
        api.utilities().base64Utils().encodeToString(input.content)
    }

private val base64DecodeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "base64_decode",
                title = "Base64 decode",
                description = "Base64 decodes the input string.",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { Base64Decode::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<Base64Decode>(args)
        api
            .utilities()
            .base64Utils()
            .decode(input.content)
            .toString()
    }

private val randomStringHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "random_string",
                title = "Generate random string",
                description = "Generates a random string of specified length and character set.",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { GenerateRandomString::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<GenerateRandomString>(args)
        api.utilities().randomUtils().randomString(input.length, input.characterSet)
    }

private val hashComputeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "hash_compute",
                title = "Compute hash",
                description = "Computes a hash for input text (MD5/SHA1/SHA256/SHA512).",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { HashCompute::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<HashCompute>(args)
        val algo = normalizeHashAlgorithm(input.algorithm)
        val digest = MessageDigest.getInstance(algo)
        val bytes = digest.digest(input.content.toByteArray(Charsets.UTF_8))
        bytes.joinToString("") { "%02x".format(it) }
    }

private val jwtDecodeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "jwt_decode",
                title = "Decode JWT",
                description = "Decodes JWT header/payload without verifying the signature.",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { JwtDecode::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<JwtDecode>(args)
        decodeJwt(input.token)
    }

private val decodeAsHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "decode_as",
                title = "Decode content",
                description = "Decodes base64 content using compression codecs (gzip/deflate/brotli).",
                category = "Utilities",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { DecodeAs::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<DecodeAs>(args)
        val decoded = api.utilities().base64Utils().decode(input.base64)
        val codec = input.encoding.trim().uppercase()
        if (codec == "IDENTITY" || codec == "RAW") {
            decoded.toString()
        } else {
            val type = CompressionType.valueOf(codec)
            api
                .utilities()
                .compressionUtils()
                .decompress(decoded, type)
                .toString()
        }
    }

private val cookieJarGetHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "cookie_jar_get",
                title = "Cookie jar",
                description = "Returns cookies from Burp's cookie jar (values redacted unless privacy is OFF).",
                category = "Utilities",
                defaultEnabled = true,
                // CONFIRM, tiered for its worst case (PrivacyMode.OFF with includeValues): the tier must not depend on privacy mode — a mode-dependent trust boundary is the same defect D-01 rejects for unsafeOnly.
                secTier = SecTier.CONFIRM,
            ),
        schema = { CookieJarGet::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<CookieJarGet>(args)
        val cookies = api.http().cookieJar().cookies()
        val domainFilter =
            input.domain
                ?.trim()
                .orEmpty()
                .removePrefix(".")
                .lowercase()
                .ifBlank { null }
        val results =
            cookies
                .asSequence()
                .filter { cookie ->
                    if (domainFilter == null) return@filter true
                    val cookieDomain = cookie.domain().removePrefix(".").lowercase()
                    if (input.includeSubdomains) {
                        cookieDomain == domainFilter || cookieDomain.endsWith(".$domainFilter")
                    } else {
                        cookieDomain == domainFilter
                    }
                }.filter { cookie ->
                    if (!input.scopeOnly) return@filter true
                    val cookieDomain = cookie.domain().removePrefix(".")
                    val httpUrl = "http://$cookieDomain/"
                    val httpsUrl = "https://$cookieDomain/"
                    api.scope().isInScope(httpUrl) || api.scope().isInScope(httpsUrl)
                }.map { cookie ->
                    val rawDomain = cookie.domain()
                    val safeDomain =
                        if (context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.STRICT) {
                            Redaction.anonymizeHost(rawDomain.removePrefix("."), context.hostSalt)
                        } else {
                            rawDomain
                        }
                    val value =
                        if (input.includeValues &&
                            context.privacyMode == com.six2dez.burp.aiagent.redact.PrivacyMode.OFF
                        ) {
                            cookie.value()
                        } else {
                            "[REDACTED]"
                        }
                    CookieEntry(
                        name = cookie.name(),
                        value = value,
                        domain = safeDomain,
                        path = cookie.path(),
                        expiresAt = cookie.expiration().map { it.toString() }.orElse(null),
                    )
                }.toList()
        toolJson.encodeToString(results)
    }

/** The utility handlers, in declared order. Declared last: top-level properties initialize in file order. */
internal val genericUtilityHandlers: List<ToolHandler> =
    listOf(
        urlEncodeHandler,
        urlDecodeHandler,
        base64EncodeHandler,
        base64DecodeHandler,
        randomStringHandler,
        hashComputeHandler,
        jwtDecodeHandler,
        decodeAsHandler,
        cookieJarGetHandler,
    )
