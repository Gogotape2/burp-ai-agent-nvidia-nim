package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.invocation.InvocationOnMock
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/** One request that reached the mocked `Http.sendRequest`. */
internal data class RecordedRequest(
    val url: String,
    val body: String,
)

/**
 * Phase 31 / GATE-01 — a mocked Burp whose HTTP stack records every provider request, so a test can
 * count what really left the extension (`Http.sendRequest` calls), and whose "Use AI" setting is a
 * switch ([aiEnabled], initially off).
 *
 * Construction installs a mocked [MontoyaObjectFactory] into [ObjectFactoryLocator.FACTORY] (the
 * static Montoya factory that `HttpRequest.httpRequestFromUrl` and `RequestOptions.requestOptions`
 * use) and [close] restores the previous one, the TargetTrafficTlsTest pattern. Use it with `use {}`
 * or close it in an `@AfterEach`.
 *
 * The request and response mocks answer through default answers instead of stubbing, so they can be
 * created safely on the backend worker threads that send the requests. Test code only.
 */
internal class RecordingMontoya : AutoCloseable {
    private val savedFactory: MontoyaObjectFactory? = ObjectFactoryLocator.FACTORY
    private val recorded = CopyOnWriteArrayList<RecordedRequest>()

    /** The one RETURNS_SELF [RequestOptions] every provider request is given. */
    val options: RequestOptions = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)

    /** Burp's "Use AI" setting, as `api.ai().isEnabled()` reports it. */
    val aiEnabled = AtomicBoolean(false)

    /** Answers each recorded request with a status code and a body; defaults to 200 and `{}`. */
    @Volatile
    var responder: (RecordedRequest) -> Pair<Int, String> = { 200 to "{}" }

    /** Every request that reached `Http.sendRequest`, in order. */
    val requests: List<RecordedRequest> get() = recorded.toList()

    val http: Http = Mockito.mock(Http::class.java, Answer { inv -> answerHttp(inv) })

    val api: MontoyaApi = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    init {
        whenever(api.http()).thenReturn(http)
        whenever(api.ai().isEnabled()).thenAnswer { aiEnabled.get() }
        ObjectFactoryLocator.FACTORY = Mockito.mock(MontoyaObjectFactory::class.java, Answer { inv -> answerFactory(inv) })
    }

    fun sendCount(): Int = recorded.size

    override fun close() {
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    private fun answerHttp(inv: InvocationOnMock): Any? {
        if (inv.method.name != "sendRequest") return Answers.RETURNS_DEFAULTS.answer(inv)
        val request = inv.arguments[0] as HttpRequest
        val entry = RecordedRequest(request.url(), request.bodyToString())
        recorded += entry
        val (status, body) = responder(entry)
        val response = responseMock(status, body)
        return Mockito.mock(
            HttpRequestResponse::class.java,
            Answer { call -> if (call.method.name == "response") response else Answers.RETURNS_DEFAULTS.answer(call) },
        )
    }

    private fun answerFactory(inv: InvocationOnMock): Any? =
        when (inv.method.name) {
            "requestOptions" -> options
            "httpRequestFromUrl" -> requestMock(inv.arguments[0] as String)
            "byteArray" ->
                if (inv.method.parameterTypes.singleOrNull() == ByteArray::class.java) {
                    byteArrayMock(rawBytes(inv))
                } else {
                    Answers.RETURNS_MOCKS.answer(inv)
                }
            else -> Answers.RETURNS_MOCKS.answer(inv)
        }

    // Mockito may expand a vararg call into one argument per element; accept both shapes.
    private fun rawBytes(inv: InvocationOnMock): ByteArray {
        val args = inv.arguments
        val single = args.singleOrNull()
        if (single is ByteArray) return single.copyOf()
        return ByteArray(args.size) { (args[it] as Byte) }
    }

    private fun requestMock(url: String): HttpRequest {
        val body = AtomicReference("")
        return Mockito.mock(
            HttpRequest::class.java,
            Answer { inv ->
                when (inv.method.name) {
                    "url" -> url
                    "bodyToString" -> body.get()
                    "withBody" -> {
                        val arg = inv.arguments[0]
                        body.set(if (arg is MontoyaByteArray) String(arg.bytes, Charsets.UTF_8) else arg.toString())
                        inv.mock
                    }
                    else ->
                        if (inv.method.returnType == HttpRequest::class.java) inv.mock else Answers.RETURNS_DEFAULTS.answer(inv)
                }
            },
        )
    }

    private fun responseMock(
        status: Int,
        body: String,
    ): HttpResponse {
        val bytes = byteArrayMock(body.toByteArray(Charsets.UTF_8))
        return Mockito.mock(
            HttpResponse::class.java,
            Answer { inv ->
                when (inv.method.name) {
                    "statusCode" -> status.toShort()
                    "body" -> bytes
                    "bodyToString" -> body
                    else -> Answers.RETURNS_DEFAULTS.answer(inv)
                }
            },
        )
    }

    private fun byteArrayMock(bytes: ByteArray): MontoyaByteArray =
        Mockito.mock(
            MontoyaByteArray::class.java,
            Answer { inv ->
                when (inv.method.name) {
                    "getBytes" -> bytes.copyOf()
                    "length" -> bytes.size
                    else -> Answers.RETURNS_DEFAULTS.answer(inv)
                }
            },
        )
}
