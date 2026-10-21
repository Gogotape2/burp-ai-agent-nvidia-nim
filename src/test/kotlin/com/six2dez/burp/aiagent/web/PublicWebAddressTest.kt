package com.six2dez.burp.aiagent.web

import okhttp3.Dns
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.UnknownHostException

class PublicWebAddressTest {
    @Test
    fun privateReservedAndMappedAddressesAreRejected() {
        listOf(
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "172.20.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.1.1",
            "198.18.1.1",
            "192.0.2.1",
            "198.51.100.2",
            "203.0.113.4",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ).forEach {
            assertFalse(PublicWebAddress.isPublic(InetAddress.getByName(it)), it)
        }
        listOf("1.1.1.1", "8.8.8.8", "151.101.2.132", "2606:4700:4700::1111").forEach {
            assertTrue(PublicWebAddress.isPublic(InetAddress.getByName(it)), it)
        }
    }

    @Test
    fun credentialsPortsSchemesAndLocalAliasesFailBeforeHttp() {
        listOf(
            "file:///etc/passwd",
            "ftp://example.org/test",
            "http://user:password@example.org/",
            "http://example.org:8080/",
            "http://localhost/",
            "http://local.localhost/",
            "http://router.local/",
            "http://127.1/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
        ).forEach {
            assertThrows(IllegalArgumentException::class.java, { PublicWebAddress.parse(it) }, it)
        }
        assertEquals("https://example.org/path", PublicWebAddress.parse("https://example.org/path#part").toString())
    }

    @Test
    fun dnsRejectsMixedAnswersAndNeverReturnsPrivateFallback() {
        val publicAddress = InetAddress.getByName("1.1.1.1")
        val mixed = PublicWebDns(Dns { listOf(publicAddress, InetAddress.getLoopbackAddress()) })
        assertThrows(UnknownHostException::class.java) { mixed.lookup("fixture.example") }
        assertEquals(listOf(publicAddress), PublicWebDns(Dns { listOf(publicAddress) }).lookup("fixture.example"))
        assertThrows(UnknownHostException::class.java) { PublicWebDns(Dns { emptyList() }).lookup("fixture.example") }
    }

    @Test
    fun slowDnsHasABoundedCallerWait() {
        val start = System.nanoTime()
        assertThrows(UnknownHostException::class.java) {
            PublicWebDns(
                Dns {
                    Thread.sleep(5000)
                    listOf(InetAddress.getByName("1.1.1.1"))
                },
                timeoutMs = 30,
            ).lookup("fixture.example")
        }
        assertTrue(
            java.util.concurrent.TimeUnit.NANOSECONDS
                .toMillis(System.nanoTime() - start) < 1000,
        )
    }
}
