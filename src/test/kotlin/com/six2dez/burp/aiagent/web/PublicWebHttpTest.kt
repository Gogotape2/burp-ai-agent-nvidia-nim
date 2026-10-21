package com.six2dez.burp.aiagent.web

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList

class PublicWebHttpTest {
    @Test
    fun anonymousGetAndCharsetDecodeWorkWithMissingCharset() {
        val requests = CopyOnWriteArrayList<okhttp3.Request>()
        val http =
            http { request ->
                requests.add(request)
                response(request, 200, "<p>Русский</p>")
            }
        try {
            assertTrue(http.get("https://example.org/doc").body.contains("Русский"))
            assertEquals("GET", requests.single().method)
            assertEquals(setOf("Accept", "User-Agent"), requests.single().headers.names())
        } finally {
            http.close()
        }
    }

    @Test
    fun everyRedirectIsRevalidatedBeforeAnotherRequest() {
        var calls = 0
        val http =
            http { request ->
                calls++
                response(request, 302, "", "http://169.254.169.254/latest/meta-data/")
            }
        try {
            assertThrows(IllegalArgumentException::class.java) { http.get("https://example.org/doc") }
            assertEquals(1, calls)
        } finally {
            http.close()
        }
    }

    @Test
    fun redirectsAreBoundedAndFinalUrlIsReported() {
        var calls = 0
        val http =
            http { request ->
                calls++
                response(request, 302, "", "/loop")
            }
        try {
            assertThrows(IllegalStateException::class.java) { http.get("https://example.org/doc") }
            assertEquals(WebLimits.MAX_REDIRECTS + 1, calls)
        } finally {
            http.close()
        }
        val success = http { request -> if (request.url.encodedPath == "/doc") response(request, 302, "", "/final") else response(request, 200, "ok") }
        try {
            assertEquals("https://example.org/final", success.get("https://example.org/doc").url)
        } finally {
            success.close()
        }
    }

    @Test
    fun downloadsOversizedBodiesAndChallengesReturnErrors() {
        val pdf =
            http { request ->
                Response
                    .Builder()
                    .request(request)
                    .protocol(Protocol.HTTP_1_1)
                    .code(200)
                    .message("ok")
                    .body("binary".toResponseBody("application/pdf".toMediaType()))
                    .build()
            }
        try {
            assertThrows(IllegalArgumentException::class.java) { pdf.get("https://example.org/doc") }
        } finally {
            pdf.close()
        }
        val large = http { request -> response(request, 200, "x".repeat(WebLimits.MAX_BYTES + 1)) }
        try {
            assertThrows(IllegalArgumentException::class.java) { large.get("https://example.org/doc") }
        } finally {
            large.close()
        }
        listOf(202, 403, 429, 500).forEach { status ->
            var count = 0
            val http =
                http { request ->
                    count++
                    response(request, status, "challenge")
                }
            try {
                assertThrows(IllegalStateException::class.java) { http.get("https://example.org/doc") }
                assertEquals(1, count)
            } finally {
                http.close()
            }
        }
    }

    private fun http(answer: (okhttp3.Request) -> Response) = PublicWebHttp(OkHttpClient.Builder().addInterceptor { answer(it.request()) }.build())

    private fun response(
        request: okhttp3.Request,
        code: Int,
        text: String,
        location: String? = null,
    ): Response =
        Response
            .Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message("fixture")
            .body(text.toResponseBody("text/html".toMediaType()))
            .apply { location?.let { header("Location", it) } }
            .build()
}
