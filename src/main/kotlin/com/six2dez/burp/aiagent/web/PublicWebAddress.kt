package com.six2dez.burp.aiagent.web

import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.math.BigInteger
import java.net.InetAddress
import java.net.UnknownHostException

/** CIDRs also exclude transition mechanisms that can tunnel a private IPv4 destination. */
internal object PublicWebAddress {
    private const val BITS_PER_BYTE = 8
    private const val IPV6_BYTES = 16
    private val ports = setOf(WebLimits.HTTP_PORT, WebLimits.HTTPS_PORT)
    private val denied =
        listOf(
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/3",
            "2001::/23",
            "2001:db8::/32",
            "2002::/16",
            "3fff::/20",
        ).map(::Cidr)
    private val globalV6 = Cidr("2000::/3")

    fun parse(raw: String): HttpUrl {
        require(raw.length <= WebLimits.MAX_URL_CHARS && raw.none { it.isISOControl() }) { "Invalid public web URL" }
        val url = requireNotNull(raw.toHttpUrlOrNull()) { "Web research requires an HTTP(S) URL" }
        require(url.username.isEmpty() && url.password.isEmpty() && url.port in ports) { "Web research accepts public HTTP(S) pages on ports 80/443 without credentials" }
        require(url.host != "localhost" && !url.host.endsWith(".localhost") && !url.host.endsWith(".local")) { "Web research cannot access local hosts" }
        if (url.host.contains(':') || url.host.all { it.isDigit() || it == '.' }) {
            require(isPublic(InetAddress.getByName(url.host))) { "Web research cannot access private or reserved addresses" }
        }
        return url.newBuilder().fragment(null).build()
    }

    fun isPublic(address: InetAddress): Boolean {
        val local = address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress
        if (local || address.isSiteLocalAddress || address.isMulticastAddress) return false
        return denied.none { it.contains(address) } && (address.address.size != IPV6_BYTES || globalV6.contains(address))
    }

    private class Cidr(
        value: String,
    ) {
        private val host = InetAddress.getByName(value.substringBefore('/')).address
        private val width = host.size * BITS_PER_BYTE
        private val mask =
            BigInteger.ONE
                .shiftLeft(width)
                .subtract(BigInteger.ONE)
                .xor(BigInteger.ONE.shiftLeft(width - value.substringAfter('/').toInt()).subtract(BigInteger.ONE))
        private val network = BigInteger(1, host).and(mask)

        fun contains(address: InetAddress): Boolean = address.address.size == host.size && BigInteger(1, address.address).and(mask) == network
    }
}

internal class PublicWebDns(
    private val resolver: Dns = Dns.SYSTEM,
    private val timeoutMs: Long = 3000L,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val addresses = WebDnsResolver.lookup(resolver, hostname, timeoutMs)
        if (addresses.isEmpty() || addresses.any { !PublicWebAddress.isPublic(it) }) throw UnknownHostException("Web research rejected a non-public DNS answer")
        return addresses
    }
}
