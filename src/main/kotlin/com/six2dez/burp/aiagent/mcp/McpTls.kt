package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.config.McpSettings
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class McpTlsMaterial(
    val keyStore: KeyStore,
    val password: CharArray,
    val keyAlias: String,
)

object McpTls {
    /**
     * Phase 34 / D-07: how long MCP TLS setup waits for keytool. RSA-2048 key generation takes
     * seconds; a keytool still running after this is treated as hung.
     */
    private const val KEYTOOL_TIMEOUT_SECONDS = 60L

    fun resolve(settings: McpSettings): McpTlsMaterial? {
        val keystorePath = settings.tlsKeystorePath.trim()
        if (keystorePath.isBlank()) return null

        val password = settings.tlsKeystorePassword.toCharArray()
        val keystoreFile = File(keystorePath)

        if (!keystoreFile.exists()) {
            if (!settings.tlsAutoGenerate) return null
            generateSelfSigned(keystoreFile, password)
        }

        val keyStore = KeyStore.getInstance("PKCS12")
        keystoreFile.inputStream().use { input ->
            keyStore.load(input, password)
        }

        val alias = keyStore.aliases().toList().firstOrNull() ?: "mcp"
        return McpTlsMaterial(keyStore = keyStore, password = password, keyAlias = alias)
    }

    /**
     * SEC-07 / SC5 — the SHA-256 digest of the leaf certificate stored at
     * [McpSettings.tlsKeystorePath], or null when no certificate can be read there.
     *
     * This is the value the bind-conflict takeover client pins the loopback TLS handshake to, so that
     * it trusts exactly the certificate this extension serves and not whatever certificate a local
     * process squatting the MCP port chooses to present.
     *
     * READS ONLY. It never generates, never writes and never creates a directory, and it is
     * deliberately NOT implemented in terms of [resolve] even though the two read the same keystore.
     * [resolve] mints a self-signed keystore when `tlsAutoGenerate` is on and none exists, which is
     * correct for the server that is about to serve it and wrong for a client that is about to
     * identify one: a client-side probe generating key material would create a file the user never
     * asked for AND mint a fresh certificate that by construction cannot match the certificate the
     * already-running server is presenting, producing a pin that is guaranteed wrong exactly when it
     * matters. If a future refactor collapses these two functions into one, TLS takeover breaks in
     * precisely the configuration it exists to serve.
     */
    fun pinnedLeafSha256(settings: McpSettings): ByteArray? {
        val keystorePath = settings.tlsKeystorePath.trim()
        val keystoreFile = File(keystorePath)
        if (keystorePath.isBlank() || !keystoreFile.exists()) return null
        // runCatching rather than a catch clause on purpose: a corrupt keystore, a wrong password or
        // an aliasless store must all yield null (fail closed) rather than throw, and runCatching has
        // no catch clause, so it adds neither a TooGenericExceptionCaught nor a SwallowedException
        // finding to the frozen detekt baseline.
        return runCatching {
            val password = settings.tlsKeystorePassword.toCharArray()
            val keyStore = KeyStore.getInstance("PKCS12")
            keystoreFile.inputStream().use { input ->
                keyStore.load(input, password)
            }
            val alias = keyStore.aliases().toList().firstOrNull() ?: "mcp"
            MessageDigest.getInstance("SHA-256").digest(keyStore.getCertificate(alias).encoded)
        }.getOrNull()
    }

    private fun generateSelfSigned(
        keystoreFile: File,
        password: CharArray,
    ) {
        keystoreFile.parentFile?.mkdirs()
        // IN-01: keep a local copy of the password array and zero it in a finally block.
        // Do NOT zero the caller's array — resolve() still needs it to load the keystore after
        // this function returns. The String materialisation (passStr) is unavoidable for
        // ProcessBuilder.environment(), but its lifetime is bounded to this call frame.
        val localPassword = password.copyOf()
        val passStr = String(localPassword)
        try {
            // Use keytool from the running JDK - available in all JDK versions.
            // SEC-02 / A3: pass the keystore password via the child-process environment (KS_PASS)
            // using -storepass:env / -keypass:env instead of a literal argv token, so the password
            // is never visible in a `ps aux` process listing.
            val keytoolPath = findKeytool()
            val process =
                ProcessBuilder(
                    keytoolPath,
                    "-genkeypair",
                    "-alias",
                    "mcp",
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "2048",
                    "-validity",
                    "365",
                    "-storetype",
                    "PKCS12",
                    "-keystore",
                    keystoreFile.absolutePath,
                    "-storepass:env",
                    "KS_PASS",
                    "-keypass:env",
                    "KS_PASS",
                    "-dname",
                    "CN=burp-mcp",
                    "-sigalg",
                    "SHA256withRSA",
                ).redirectErrorStream(true)
                    .also { it.environment()["KS_PASS"] = passStr }
                    .start()

            // Phase 34 / D-07: wait with a deadline BEFORE reading. readText() blocks until keytool
            // exits, so reading first would defeat the deadline. keytool prints a few lines, far
            // below a pipe buffer, so waiting first cannot fill the pipe and stall the child.
            val exitCode = awaitKeytoolExit(process, KEYTOOL_TIMEOUT_SECONDS)
            val output = process.inputStream.bufferedReader().readText()
            if (exitCode != 0) {
                throw RuntimeException("keytool failed (exit $exitCode): $output")
            }
        } finally {
            // Defense-in-depth: zero the local copy so it does not linger on the heap. The String
            // copy (passStr) is immutable and cannot be zeroed, but its lifetime is bounded to
            // this call frame and it will be eligible for GC as soon as this method returns.
            localPassword.fill(' ')
        }
    }

    /**
     * Phase 34 / D-07: waits up to [timeoutSeconds] for the keytool [process] and returns its exit
     * code. On expiry the process is destroyed and setup fails closed with an IllegalStateException.
     *
     * Visibility: `internal` so McpTlsKeytoolWaitTest can drive it with a stand-in child process.
     */
    internal fun awaitKeytoolExit(
        process: Process,
        timeoutSeconds: Long,
    ): Int {
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            // error() throws IllegalStateException, the fail-closed setup error.
            error("keytool did not finish within ${timeoutSeconds}s")
        }
        return process.exitValue()
    }

    private fun findKeytool(): String {
        val javaHome = System.getProperty("java.home")
        val keytool = File(javaHome, "bin/keytool")
        if (keytool.exists()) return keytool.absolutePath
        // Windows
        val keytoolExe = File(javaHome, "bin/keytool.exe")
        if (keytoolExe.exists()) return keytoolExe.absolutePath
        // Fallback to PATH
        return "keytool"
    }
}
