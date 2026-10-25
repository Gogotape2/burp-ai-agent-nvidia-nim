package com.six2dez.burp.aiagent.mcp.tools

/** Expand explicit literal markers without recursive replacement or implicit encoding. */
internal class PayloadAttackPlan(
    val input: IntruderAttackStart,
) {
    val total: Int
    private val template: String

    init {
        validateService(input)
        require(input.content.toByteArray().size <= ActiveToolLimits.MAX_TEMPLATE_BYTES) { "Request template exceeds 1 MiB" }
        template = prepareTemplate(input.content)
        require(input.positions.size in 1..ActiveToolLimits.MAX_POSITIONS) { "Provide 1-16 payload positions" }
        require(input.maxRequests in 1..ActiveToolLimits.MAX_REQUESTS) { "maxRequests must be 1-1000" }
        require(input.concurrency in 1..ActiveToolLimits.MAX_CONCURRENCY) { "concurrency must be 1-5" }
        require(input.intervalMs in 0..ActiveToolLimits.MAX_INTERVAL_MS) { "intervalMs must be 0-60000" }
        require(input.timeoutMs in ActiveToolLimits.MIN_TIMEOUT_MS..ActiveToolLimits.MAX_TIMEOUT_MS) { "timeoutMs must be 1000-120000" }
        require(input.durationMs in ActiveToolLimits.MIN_TIMEOUT_MS..ActiveToolLimits.MAX_DURATION_MS) { "durationMs must be 1000-900000" }
        validatePositions()
        val variants = variantCount()
        val requested = variants + if (input.includeBaseline) 1 else 0
        require(requested <= input.maxRequests) { "Attack needs $requested requests; maxRequests=${input.maxRequests}. Reduce payload sets or explicitly raise maxRequests (at most 1000)." }
        total = requested.toInt()
    }

    private fun validatePositions() {
        val markers = input.positions.map { it.marker }
        require(markers.distinct().size == markers.size) { "Payload markers must be unique" }
        input.positions.forEach { position ->
            require(position.marker.isNotEmpty() && position.marker.length <= ActiveToolLimits.MAX_MARKER_CHARS && input.content.contains(position.marker)) { "Each marker must occur in the request template and have 1-128 characters" }
            require(markers.none { it != position.marker && (it.contains(position.marker) || position.marker.contains(it)) }) { "Payload markers must not overlap" }
            require(position.payloads.size in 1..ActiveToolLimits.MAX_REQUESTS) { "Each position needs 1-1000 explicit payloads" }
            require((position.payloads + position.baseValue).all { it.toByteArray().size <= ActiveToolLimits.MAX_PAYLOAD_BYTES }) { "A payload or baseValue exceeds 16 KiB" }
        }
        require(input.positions.sumOf { it.payloads.sumOf { item -> item.toByteArray().size.toLong() } } <= ActiveToolLimits.MAX_TEMPLATE_BYTES) { "Combined payloads exceed 1 MiB" }
        if (input.mode == PayloadAttackMode.BATTERING_RAM) require(input.positions.all { it.payloads == input.positions.first().payloads }) { "BATTERING_RAM requires identical payload lists at every position" }
        if (input.mode == PayloadAttackMode.PITCHFORK) {
            require(
                input.positions
                    .map { it.payloads.size }
                    .distinct()
                    .size == 1,
            ) { "PITCHFORK requires equally sized payload lists" }
        }
    }

    private fun variantCount(): Long =
        when (input.mode) {
            PayloadAttackMode.SNIPER -> input.positions.sumOf { it.payloads.size.toLong() }
            PayloadAttackMode.BATTERING_RAM, PayloadAttackMode.PITCHFORK ->
                input.positions
                    .first()
                    .payloads.size
                    .toLong()
            PayloadAttackMode.CLUSTER_BOMB -> input.positions.fold(1L) { n, p -> (n * p.payloads.size).coerceAtMost(ActiveToolLimits.MAX_REQUESTS + 1L) }
        }

    fun values(index: Int): List<String> {
        require(index in 0 until total)
        val variant = index - if (input.includeBaseline) 1 else 0
        if (variant < 0) return input.positions.map { it.baseValue }
        return when (input.mode) {
            PayloadAttackMode.SNIPER -> {
                var remaining = variant
                input.positions.map { position ->
                    val value = if (remaining in position.payloads.indices) position.payloads[remaining] else position.baseValue
                    remaining -= position.payloads.size
                    value
                }
            }
            PayloadAttackMode.BATTERING_RAM, PayloadAttackMode.PITCHFORK -> input.positions.map { it.payloads[variant] }
            PayloadAttackMode.CLUSTER_BOMB -> {
                var remaining = variant
                input.positions
                    .asReversed()
                    .map { p -> p.payloads[remaining % p.payloads.size].also { remaining /= p.payloads.size } }
                    .asReversed()
            }
        }
    }

    fun render(index: Int): String {
        val replacements = input.positions.mapIndexed { i, p -> p.marker to values(index)[i] }.toMap()
        val pattern = Regex(replacements.keys.joinToString("|") { Regex.escape(it) })
        val rendered = pattern.replace(template) { replacements.getValue(it.value) }
        require(rendered.toByteArray().size <= ActiveToolLimits.MAX_TEMPLATE_BYTES) { "Rendered request exceeds 1 MiB" }
        return normalizeHttpRequest(rendered)
    }

    private fun prepareTemplate(raw: String): String {
        val lines = raw.replace("\r\n", "\n").replace('\r', '\n')
        require('\n' in lines) { "Request template must contain real line breaks. Decode JSON line escapes once; do not supply literal backslash-r/backslash-n sequences." }
        if ("\n\n" in lines) return raw
        val headers = lines.substringAfter('\n').trimEnd('\n').split('\n')
        require(headers.isNotEmpty() && headers.all { HEADER_LINE.matches(it) }) { "Request template needs an empty line between headers and body. Only a header-only request can omit its final empty line." }
        // Models often omit trailing blank lines; repair only unambiguous header-only templates.
        return raw.trimEnd('\r', '\n') + "\r\n\r\n"
    }

    private companion object {
        val HEADER_LINE = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\\r\\n]*")
    }
}
