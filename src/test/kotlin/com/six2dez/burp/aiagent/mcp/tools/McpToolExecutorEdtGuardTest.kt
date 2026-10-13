package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.lang.reflect.InvocationTargetException
import javax.swing.SwingUtilities

/**
 * REL-05 / SC1 · SC2 — scenario S-10: the executor's door refuses the AWT Event Dispatch Thread.
 *
 * **What is under test is a control that fires in shipped Burp, and that is the whole point.**
 * `ChatPanel`'s existing private EDT assertion uses the JVM's debug-time assertion facility, which is
 * disabled without `-ea` — i.e. in every Burp a user actually runs. SC1 names that gap explicitly, so
 * the guard at `McpToolExecutor.executeToolResult` throws instead. The `edtGuardWithoutAssertionsTest`
 * Gradle task (`build.gradle.kts`) runs THIS class with `-da`, which is what turns "it throws" from a
 * claim into a demonstration; `tasks.test` runs it again with the project's usual `-ea`.
 *
 * **Naming constraint (hard).** `.github/workflows/build.yml:47` runs
 * `./gradlew test -PexcludeHeavyTests=true` and `build.gradle.kts` excludes `*IntegrationTest`,
 * `*ConcurrencyTest`, `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under that flag.
 * Any of those suffixes here would make this suite nightly-only — never running on the cross-platform
 * matrix, which is the one place a platform EDT difference would surface. Do not rename this class.
 */
class McpToolExecutorEdtGuardTest {
    private fun context(): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 8192,
            // The store registry has no dynamic namespace: no provider claims an `ext:` name, so off the
            // EDT the call returns a typed "Unknown tool" result instead of throwing. It is the absence of
            // that result on the EDT that proves the guard ran first (see
            // [theGuardPrecedesTheExternalToolEarlyReturn]). The full build's half is FullExternalEdtGuardTest.
        )
    }

    /**
     * Runs [body] on the EDT and returns whatever it threw there, unwrapped.
     *
     * `invokeAndWait` re-throws a runnable's failure wrapped in an [InvocationTargetException], so the
     * cause has to be unwrapped before its type means anything — the same JDK behaviour
     * `MontoyaHttpTransport.kt` handles with `throw e.cause ?: e`.
     */
    private fun throwableFromEdt(body: () -> Unit): Throwable? {
        var thrown: Throwable? = null
        try {
            SwingUtilities.invokeAndWait { body() }
        } catch (e: InvocationTargetException) {
            thrown = e.cause ?: e
        }
        return thrown
    }

    @Test
    fun executingABuiltInToolOnTheEdtIsRefused() {
        val context = context()

        val thrown =
            throwableFromEdt {
                McpToolExecutor.executeToolResult("proxy_http_history", """{"count":5}""", context)
            }

        assertInstanceOf(
            IllegalStateException::class.java,
            thrown,
            "REL-05 / SC1: entering the executor from the EDT must fail loudly. Thrown was: $thrown.",
        )
        assertTrue(
            thrown?.message.orEmpty().contains("REL-05"),
            "The failure must name the requirement it enforces and point the caller at the dispatch " +
                "helper, or whoever meets it has to guess. Message was: ${thrown?.message}.",
        )
        assertTrue(
            thrown?.message.orEmpty().contains("OffEdtDispatch"),
            "The message must say what to do instead. Message was: ${thrown?.message}.",
        )
    }

    /**
     * F-4 — the guard precedes the `ext:` early return, so a provider's dynamic namespace is covered too.
     *
     * **This test distinguishes the two candidate placements rather than passing under either.** The full
     * build's external branch blocks its own thread waiting on a coroutine, so a guard placed one line
     * lower — after the early return — would leave that path as the single place the EDT could still
     * freeze. It would also leave THIS call returning the typed "Unknown tool" result instead of throwing,
     * which is exactly what the assertions below reject.
     */
    @Test
    fun theGuardPrecedesTheExternalToolEarlyReturn() {
        val context = context()

        val thrown =
            throwableFromEdt {
                McpToolExecutor.executeToolResult("ext:demo:search", """{"q":"x"}""", context)
            }

        assertInstanceOf(
            IllegalStateException::class.java,
            thrown,
            "F-4: an ext:-prefixed call from the EDT must be refused BEFORE the external early return. " +
                "A null result here means the call returned a value, i.e. the guard sits after the " +
                "early return and the external path is unguarded. Thrown was: $thrown.",
        )
        assertTrue(
            thrown?.message.orEmpty().contains("REL-05"),
            "Message was: ${thrown?.message}.",
        )
    }

    /**
     * The negative half, without which a guard that threw unconditionally would satisfy both tests above.
     *
     * The `ext:` branch is used because its outcome is fully determined by the store classpath: no
     * provider claims the name, so the executor produces a typed "Unknown tool" RESULT. Getting that
     * result back is proof the call travelled past the guard and through the dynamic-namespace branch, on
     * a thread that is not the EDT.
     */
    @Test
    fun theSameCallOffTheEdtReachesPastTheGuard() {
        val context = context()

        val result = McpToolExecutor.executeToolResult("ext:demo:search", """{"q":"x"}""", context)

        val text = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text?.toString().orEmpty() }
        assertTrue(result.isError == true, "An unclaimed ext: name is an error result. Got: $text.")
        assertEquals(
            "Unknown tool: ext:demo:search",
            text,
            "Off the EDT the call must reach past the guard; on the store classpath no provider claims " +
                "the name. Got: $text.",
        )
        assertFalse(
            text.contains("REL-05"),
            "The guard must not fire off the EDT — it would refuse the MCP-server path, which already " +
                "runs on Ktor coroutines. Got: $text.",
        )
    }
}
