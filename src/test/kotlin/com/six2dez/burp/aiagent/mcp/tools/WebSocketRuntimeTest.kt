package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class WebSocketRuntimeTest {
    private val api = mock<MontoyaApi>()
    private val socket = mock<ExtensionWebSocket>()
    private val registration = mock<Registration>()
    private val creation = mock<ExtensionWebSocketCreation>()
    private lateinit var handler: ExtensionWebSocketMessageHandler
    private val input = WebSocketOpen("fixture.test", 443, true)

    private fun runtime(create: () -> ExtensionWebSocketCreation = { creation }): WebSocketRuntime {
        whenever(creation.status()).thenReturn(ExtensionWebSocketCreationStatus.SUCCESS)
        whenever(creation.webSocket()).thenReturn(Optional.of(socket))
        whenever(socket.registerMessageHandler(any())).thenAnswer { call ->
            handler = call.getArgument(0)
            registration
        }
        return WebSocketRuntime(api) { create() }
    }

    private fun open(runtime: WebSocketRuntime) =
        runtime
            .open(input, "https://fixture.test/")
            .getValue("connectionId")
            .jsonPrimitive.content

    private fun incoming(text: String) {
        val message = mock<TextMessage>()
        whenever(message.payload()).thenReturn(text)
        handler.textMessageReceived(message)
    }

    @Test
    fun openSendReadAndCloseUseStableConnectionAndMessageHandles() {
        runtime().use { runtime ->
            val id = open(runtime)
            runtime.send(WebSocketSend(id, text = "hello")) { }
            incoming("world")
            val read = runtime.receive(WebSocketReceive(id), true) { }
            assertEquals(
                listOf("OUTBOUND", "INBOUND"),
                read.getValue("messages").jsonArray.map {
                    it.jsonObject
                        .getValue("direction")
                        .jsonPrimitive.content
                },
            )
            val cursor =
                read
                    .getValue("nextSequence")
                    .jsonPrimitive.content
                    .toLong()
            assertTrue(
                runtime
                    .receive(WebSocketReceive(id, afterSequence = cursor), true) { }
                    .getValue("messages")
                    .jsonArray
                    .isEmpty(),
            )
            runtime.disconnect(id) { }
            runtime.disconnect(id) { }
            verify(socket).sendTextMessage("hello")
            verify(socket, times(1)).close()
            verify(registration, times(1)).deregister()
        }
    }

    @Test
    fun privacyModeWithholdsBinaryBodies() {
        runtime().use { runtime ->
            val id = open(runtime)
            val message = mock<BinaryMessage>()
            val bytes = mock<burp.api.montoya.core.ByteArray>()
            whenever(bytes.length()).thenReturn(3)
            whenever(bytes.subArray(0, 3)).thenReturn(bytes)
            whenever(bytes.bytes).thenReturn(byteArrayOf(1, 2, 3))
            whenever(message.payload()).thenReturn(bytes)
            handler.binaryMessageReceived(message)
            val off = runtime.receive(WebSocketReceive(id), true) { }.toString()
            val balanced = runtime.receive(WebSocketReceive(id), false) { }.toString()
            assertTrue(off.contains("AQID"))
            assertFalse(balanced.contains("AQID"))
            assertTrue(balanced.contains("withheld"))
        }
    }

    @Test
    fun overflowIsBoundedAndReportsCursorGaps() {
        runtime().use { runtime ->
            val id = open(runtime)
            repeat(300) { incoming("message $it") }
            val read = runtime.receive(WebSocketReceive(id, count = 100), true) { }
            assertEquals("true", read.getValue("gap").jsonPrimitive.content)
            assertEquals(100, read.getValue("messages").jsonArray.size)
            assertEquals(
                "44",
                read
                    .getValue("connection")
                    .jsonObject
                    .getValue("droppedMessages")
                    .jsonPrimitive.content,
            )
        }
    }

    @Test
    fun invalidMessagesAndScopeChecksPreventSending() {
        runtime().use { runtime ->
            val id = open(runtime)
            assertThrows(IllegalArgumentException::class.java) { runtime.send(WebSocketSend(id, text = "x", base64 = "eA==")) { } }
            assertThrows(IllegalArgumentException::class.java) { runtime.send(WebSocketSend(id, base64 = "!!!")) { } }
            assertThrows(IllegalStateException::class.java) { runtime.send(WebSocketSend(id, text = "x")) { error("out of scope") } }
            verify(socket, never()).sendTextMessage(any())
            assertTrue(runtime.connections { false }.isEmpty())
        }
    }

    @Test
    fun lateSuccessfulHandshakeIsClosedAfterCallerTimeout() {
        val closed = CountDownLatch(1)
        doAnswer {
            closed.countDown()
            null
        }.whenever(socket).close()
        runtime {
            Thread.sleep(1200)
            creation
        }.use { runtime ->
            assertThrows(IllegalStateException::class.java) { runtime.open(input.copy(timeoutMs = 1000), "https://fixture.test/") }
            assertTrue(closed.await(3, TimeUnit.SECONDS))
            assertTrue(runtime.connections { true }.isEmpty())
        }
    }

    @Test
    fun remoteCloseWakesWaitingReaders() {
        runtime().use { runtime ->
            val id = open(runtime)
            handler.onClose()
            val read = runtime.receive(WebSocketReceive(id, waitMs = 1000), true) { }
            assertEquals(
                "CLOSED",
                read
                    .getValue("connection")
                    .jsonObject
                    .getValue("state")
                    .jsonPrimitive.content,
            )
            assertThrows(IllegalStateException::class.java) { runtime.send(WebSocketSend(id, text = "later")) { } }
        }
    }
}
