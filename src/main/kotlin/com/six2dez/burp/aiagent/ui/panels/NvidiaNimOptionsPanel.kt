package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.formGrid
import java.awt.BorderLayout
import javax.swing.JComboBox
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.SpinnerNumberModel

internal class NvidiaNimOptionsPanel(
    initial: NvidiaNimOptions,
) : JPanel(BorderLayout()) {
    private val maxTokens = spinner(initial.validated().maxTokens, 1, NvidiaNimOptions.MAX_COMPLETION_TOKENS, NvidiaNimOptions.TOKEN_SPINNER_STEP)
    private val effort = JComboBox(NvidiaNimOptions.REASONING_MODES.toTypedArray())
    private val budget = spinner(initial.validated().reasoningBudget, 0, NvidiaNimOptions.MAX_COMPLETION_TOKENS, NvidiaNimOptions.TOKEN_SPINNER_STEP)
    private val concurrency = spinner(initial.validated().maxConcurrency, 1, NvidiaNimOptions.MAX_CONCURRENCY)
    private val rate = spinner(initial.validated().rateLimit, 1, NvidiaNimOptions.MAX_RATE_LIMIT)
    private val window = spinner(initial.validated().rateWindowSeconds, 1, NvidiaNimOptions.MAX_RATE_WINDOW_SECONDS)
    private val retries = spinner(initial.validated().maxRetries, 0, NvidiaNimOptions.MAX_RETRIES)
    private val historyChars = spinner(initial.validated().historyMaxChars, NvidiaNimOptions.MIN_HISTORY_CHARS, NvidiaNimOptions.MAX_HISTORY_CHARS, NvidiaNimOptions.HISTORY_SPINNER_STEP)

    init {
        isOpaque = false
        val form = formGrid()
        addRowFull(form, "Max tokens (answer + thinking)", maxTokens)
        addRowFull(form, "Reasoning effort", effort)
        addRowFull(form, "Reasoning budget (high only)", budget)
        addRowFull(form, "History budget (characters)", historyChars)
        addRowFull(form, "Concurrent requests", concurrency)
        addRowFull(form, "Requests per window", rate)
        addRowFull(form, "Window (seconds)", window)
        addRowFull(form, "Retries (429 / 5xx / network)", retries)
        add(form, BorderLayout.CENTER)
        effort.toolTipText = "Auto: Ultra none (fast); GLM 5.3 low with clear_thinking. Ultra supports none/medium/high; GLM low/high/max. Other models keep provider defaults."
        budget.toolTipText = "High reasoning only; capped below Max tokens so the model can still answer."
        concurrency.toolTipText = "Shared across NIM chat, scanners and connection tests in this extension."
        rate.toolTipText = "All NIM attempts, including retries and connection tests, count toward the shared sliding window."
        retries.toolTipText = "All attempts and backoff share Total timeout. Authentication and configuration errors are not retried."
        historyChars.toolTipText = "Retain up to 200 previous messages within this character budget; older turns are removed first. This is not the model's token context window."
        effort.addActionListener { budget.isEnabled = effort.selectedItem == "high" }
        applyOptions(initial)
    }

    fun currentOptions(): NvidiaNimOptions {
        // Commit typed spinner edits before collecting; invalid edits keep the previous valid value.
        listOf(maxTokens, budget, concurrency, rate, window, retries, historyChars).forEach { runCatching { it.commitEdit() } }
        return NvidiaNimOptions(
            maxTokens = maxTokens.value as Int,
            reasoningEffort = effort.selectedItem as String,
            reasoningBudget = budget.value as Int,
            maxConcurrency = concurrency.value as Int,
            rateLimit = rate.value as Int,
            rateWindowSeconds = window.value as Int,
            maxRetries = retries.value as Int,
            historyMaxChars = historyChars.value as Int,
        ).validated()
    }

    fun applyOptions(options: NvidiaNimOptions) {
        val safe = options.validated()
        maxTokens.value = safe.maxTokens
        effort.selectedItem = safe.reasoningEffort
        budget.value = safe.reasoningBudget
        concurrency.value = safe.maxConcurrency
        rate.value = safe.rateLimit
        window.value = safe.rateWindowSeconds
        retries.value = safe.maxRetries
        historyChars.value = safe.historyMaxChars
        budget.isEnabled = safe.reasoningEffort == "high"
    }

    private fun spinner(
        value: Int,
        min: Int,
        max: Int,
        step: Int = 1,
    ): JSpinner =
        JSpinner(SpinnerNumberModel(value, min, max, step)).apply {
            editor = JSpinner.NumberEditor(this, "#")
        }
}
