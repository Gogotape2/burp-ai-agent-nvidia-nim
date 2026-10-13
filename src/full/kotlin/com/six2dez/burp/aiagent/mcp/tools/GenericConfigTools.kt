package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.spi.ToolHandler
import io.modelcontextprotocol.kotlin.sdk.Tool

// Phase 29 / D-13 / D-14 — the generic Burp configuration, Burp control and message-editor tools. Each
// descriptor sits next to its handler and was moved verbatim from the catalog; each body was moved
// verbatim from the executor's dispatch `when`. Contributed by GenericToolProvider.

private val projectOptionsGetHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "project_options_get",
                title = "Output project options",
                description = "Outputs project-level configuration as JSON.",
                category = "Config",
                defaultEnabled = false,
                // CONFIRM despite being read-only — the data is not attacker-controlled, but it is the user's own credential material (ADR-15, Pitfall 1).
                secTier = SecTier.CONFIRM,
            ),
        schema = { Tool.Input() },
    ) { _, context ->
        val api = context.api
        api.burpSuite().exportProjectOptionsAsJson()
    }

private val userOptionsGetHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "user_options_get",
                title = "Output user options",
                description = "Outputs user-level configuration as JSON.",
                category = "Config",
                defaultEnabled = false,
                // CONFIRM despite being read-only — the data is not attacker-controlled, but it is the user's own credential material (ADR-15, Pitfall 1).
                secTier = SecTier.CONFIRM,
            ),
        schema = { Tool.Input() },
    ) { _, context ->
        val api = context.api
        api.burpSuite().exportUserOptionsAsJson()
    }

private val projectOptionsSetHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "project_options_set",
                title = "Set project options",
                description = "Sets project-level configuration from JSON.",
                category = "Config",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { SetProjectOptions::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SetProjectOptions>(args)
        api.logging().logToOutput("Setting project-level configuration via MCP.")
        api.burpSuite().importProjectOptionsFromJson(input.json)
        "Project configuration has been applied"
    }

private val userOptionsSetHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "user_options_set",
                title = "Set user options",
                description = "Sets user-level configuration from JSON.",
                category = "Config",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { SetUserOptions::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SetUserOptions>(args)
        api.logging().logToOutput("Setting user-level configuration via MCP.")
        api.burpSuite().importUserOptionsFromJson(input.json)
        "User configuration has been applied"
    }

private val taskEngineStateHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "task_engine_state",
                title = "Set task execution engine state",
                description = "Sets Burp's task execution engine to paused or running.",
                category = "Burp Control",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { SetTaskExecutionEngineState::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SetTaskExecutionEngineState>(args)
        api.burpSuite().taskExecutionEngine().state = if (input.running) RUNNING else PAUSED
        "Task execution engine is now ${if (input.running) "running" else "paused"}"
    }

private val proxyInterceptHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "proxy_intercept",
                title = "Set proxy intercept state",
                description = "Enables or disables Proxy intercept.",
                category = "Burp Control",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { SetProxyInterceptState::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SetProxyInterceptState>(args)
        if (input.intercepting) api.proxy().enableIntercept() else api.proxy().disableIntercept()
        "Intercept has been ${if (input.intercepting) "enabled" else "disabled"}"
    }

private val editorGetHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "editor_get",
                title = "Get active editor contents",
                description = "Outputs the contents of the active message editor.",
                category = "Editor",
                defaultEnabled = false,
                secTier = SecTier.CONFIRM,
            ),
        schema = { Tool.Input() },
    ) { _, context ->
        val api = context.api
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

private val editorSetHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "editor_set",
                title = "Set active editor contents",
                description = "Sets the content of the active message editor.",
                category = "Editor",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { SetActiveEditorContents::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<SetActiveEditorContents>(args)
        val editor = getActiveEditor(api) ?: return@toolHandler "<No active editor>"
        if (!editor.isEditable) return@toolHandler "<Current editor is not editable>"
        editor.text = input.text
        "Editor text has been set"
    }

/** The config handlers, in declared order. Declared last: top-level properties initialize in file order. */
internal val genericConfigHandlers: List<ToolHandler> =
    listOf(
        projectOptionsGetHandler,
        userOptionsGetHandler,
        projectOptionsSetHandler,
        userOptionsSetHandler,
        taskEngineStateHandler,
        proxyInterceptHandler,
        editorGetHandler,
        editorSetHandler,
    )
