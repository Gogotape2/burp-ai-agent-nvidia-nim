package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.scanner.audit.Audit
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.mcp.schema.toSerializableForm
import com.six2dez.burp.aiagent.spi.ToolHandler
import kotlinx.serialization.encodeToString

// Phase 29 / D-13 / D-14 — the generic Burp Scanner and Collaborator tools. Each descriptor sits next to
// its handler and was moved verbatim from the catalog; each body was moved verbatim from the executor's
// residual dispatch `when` (its early `return`s became `return@toolHandler`, and the tool id it passed to
// ensureProEdition is now the literal id). Tasks started here are tracked in ScannerTaskRegistry and
// Collaborator clients in CollaboratorRegistry (D-15). `scanner_issues` serializes raw traffic
// (SerializedEmissionSiteInventoryTest pins it); none redacts anything itself —
// McpToolExecutor.executeToolResult wraps every handler result in context.redactIfNeeded. Contributed by
// GenericToolProvider.

private val scannerIssuesHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scanner_issues",
                title = "Scanner issues",
                description = "Displays scanner issues (Burp Pro only).",
                category = "Scanner",
                defaultEnabled = true,
                proOnly = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { GetScannerIssues::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        ensureProEdition(context, "scanner_issues")
        val input = decodeToolArgs<GetScannerIssues>(args)
        val issues = api.siteMap().issues()
        val seq =
            if (context.determinismMode) {
                issues.sortedBy { it.name() }.asSequence()
            } else {
                issues.asSequence()
            }
        context.limitedJoin(
            seq
                .drop(input.offset)
                .take(input.count)
                .map { toolJson.encodeToString(it.toSerializableForm()) },
        )
    }

private val scanAuditStartHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scan_audit_start",
                title = "Start scanner audit",
                description = "Starts a Burp Scanner audit.",
                category = "Scanner",
                defaultEnabled = false,
                proOnly = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { StartAudit::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        ensureProEdition(context, "scan_audit_start")
        val input = decodeToolArgs<StartAudit>(args)
        val cfg =
            AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.valueOf(input.builtInConfiguration),
            )
        val audit = api.scanner().startAudit(cfg)
        val id = ScannerTaskRegistry.put(audit)
        "Started audit: id=$id status=${audit.statusMessage()}"
    }

private val scanAuditStartModeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scan_audit_start_mode",
                title = "Start scanner audit (mode)",
                description = "Starts a scanner audit using active or passive mode.",
                category = "Scanner",
                defaultEnabled = false,
                proOnly = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { StartAuditMode::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        ensureProEdition(context, "scan_audit_start_mode")
        val input = decodeToolArgs<StartAuditMode>(args)
        val cfg = AuditConfiguration.auditConfiguration(resolveAuditConfig(input.mode))
        val audit = api.scanner().startAudit(cfg)
        val service = input.toMontoyaServiceOrNull(context::resolveHost)
        if (input.requests.isNotEmpty() && service == null) {
            return@toolHandler "Error: targetHostname/targetPort required when providing requests"
        }
        for (raw in input.requests) {
            val fixed = raw.replace("\r", "").replace("\n", "\r\n")
            val req = HttpRequest.httpRequest(service ?: input.toMontoyaService(context::resolveHost), fixed)
            audit.addRequest(req)
        }
        val id = ScannerTaskRegistry.put(audit)
        if (input.requests.isEmpty()) {
            "Started audit: id=$id status=${audit.statusMessage()}"
        } else {
            "Started audit with requests: id=$id status=${audit.statusMessage()}"
        }
    }

private val scanAuditStartRequestsHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scan_audit_start_requests",
                title = "Start audit with requests",
                description = "Starts an audit and adds HTTP requests.",
                category = "Scanner",
                defaultEnabled = false,
                proOnly = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { StartAuditWithRequests::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        ensureProEdition(context, "scan_audit_start_requests")
        val input = decodeToolArgs<StartAuditWithRequests>(args)
        val cfg =
            AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.valueOf(input.builtInConfiguration),
            )
        val audit = api.scanner().startAudit(cfg)
        val service = input.toMontoyaService(context::resolveHost)
        for (raw in input.requests) {
            val fixed = raw.replace("\r", "").replace("\n", "\r\n")
            val req = HttpRequest.httpRequest(service, fixed)
            audit.addRequest(req)
        }
        val id = ScannerTaskRegistry.put(audit)
        "Started audit with requests: id=$id status=${audit.statusMessage()}"
    }

// Montoya's crawlConfiguration takes the seed URLs as a vararg; the spread is the only way to hand it a list.
@Suppress("SpreadOperator")
private val scanCrawlStartHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scan_crawl_start",
                title = "Start crawl",
                description = "Starts a Burp Scanner crawl.",
                category = "Scanner",
                defaultEnabled = false,
                proOnly = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { StartCrawl::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        ensureProEdition(context, "scan_crawl_start")
        val input = decodeToolArgs<StartCrawl>(args)
        val crawl =
            api.scanner().startCrawl(
                burp.api.montoya.scanner.CrawlConfiguration
                    .crawlConfiguration(*input.seedUrls.toTypedArray()),
            )
        val id = ScannerTaskRegistry.put(crawl)
        "Started crawl: id=$id status=${crawl.statusMessage()}"
    }

private val scanTaskStatusHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scan_task_status",
                title = "Get scan task status",
                description = "Gets status for a crawl/audit task.",
                category = "Scanner",
                defaultEnabled = false,
                proOnly = true,
                secTier = SecTier.AUTO,
            ),
        schema = { GetScanTaskStatus::class.asInputSchema() },
    ) { args, context ->
        ensureProEdition(context, "scan_task_status")
        val input = decodeToolArgs<GetScanTaskStatus>(args)
        val task = ScannerTaskRegistry.get(input.taskId) ?: return@toolHandler "Task not found: ${input.taskId}"
        val base = "status=${task.statusMessage()} requests=${task.requestCount()} errors=${task.errorCount()}"
        val audit = task as? Audit
        if (audit != null) {
            val count = audit.issues().size
            "$base issues=$count"
        } else {
            base
        }
    }

private val scanTaskDeleteHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scan_task_delete",
                title = "Delete scan task",
                description = "Deletes a crawl/audit task started via MCP.",
                category = "Scanner",
                defaultEnabled = false,
                proOnly = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { DeleteScanTask::class.asInputSchema() },
    ) { args, context ->
        ensureProEdition(context, "scan_task_delete")
        val input = decodeToolArgs<DeleteScanTask>(args)
        val task = ScannerTaskRegistry.remove(input.taskId) ?: return@toolHandler "Task not found: ${input.taskId}"
        task.delete()
        "Deleted task: ${input.taskId}"
    }

private val scanReportHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scan_report",
                title = "Generate scanner report",
                description = "Generates a scanner report to a path.",
                category = "Scanner",
                defaultEnabled = false,
                proOnly = true,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { GenerateScannerReport::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        ensureProEdition(context, "scan_report")
        val input = decodeToolArgs<GenerateScannerReport>(args)
        val formatEnum = ReportFormat.valueOf(input.format)
        val pathObj =
            try {
                resolveReportPath(input.path)
            } catch (e: IllegalArgumentException) {
                return@toolHandler "Error: ${e.message}"
            }
        val issues =
            when {
                input.taskId != null -> {
                    val task = ScannerTaskRegistry.get(input.taskId)
                    val audit = task as? Audit ?: return@toolHandler "Task not found or not an audit: ${input.taskId}"
                    audit.issues()
                }
                input.allIssues -> api.siteMap().issues()
                else -> return@toolHandler "Provide taskId or set allIssues=true"
            }
        api.scanner().generateReport(issues, formatEnum, pathObj)
        "Report generated: ${input.path}"
    }

// Montoya's generatePayload takes the payload options as a vararg; the spread is the only way to hand it a list.
@Suppress("SpreadOperator")
private val collaboratorGenerateHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "collaborator_generate",
                title = "Generate Collaborator payload",
                description = "Generates a Burp Collaborator payload.",
                category = "Collaborator",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { CollaboratorGenerate::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<CollaboratorGenerate>(args)
        val client = api.collaborator().createClient()
        val opts =
            input.options
                .mapNotNull { opt ->
                    runCatching {
                        burp.api.montoya.collaborator.PayloadOption
                            .valueOf(opt.trim().uppercase())
                    }.getOrNull()
                }.toTypedArray()
        val payload =
            if (input.customData.isNullOrBlank()) {
                client.generatePayload(*opts)
            } else {
                client.generatePayload(input.customData.trim(), *opts)
            }
        val secretKey = client.getSecretKey().toString()
        CollaboratorRegistry.put(secretKey, client)
        buildString {
            appendLine("payload=$payload")
            appendLine("interaction_id=${payload.id()}")
            appendLine("secret_key=$secretKey")
        }.trim()
    }

private val collaboratorPollHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "collaborator_poll",
                title = "Poll Collaborator interactions",
                description = "Fetches interactions for a Collaborator secret key.",
                category = "Collaborator",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { CollaboratorPoll::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<CollaboratorPoll>(args)
        val key = input.secretKey.trim()
        val client =
            CollaboratorRegistry.get(key)
                ?: api.collaborator().restoreClient(
                    burp.api.montoya.collaborator.SecretKey
                        .secretKey(key),
                )
        val interactions = client.getAllInteractions()
        if (interactions.isEmpty()) return@toolHandler "No interactions"
        interactions.joinToString(separator = "\n\n") { interaction ->
            buildString {
                appendLine("id=${interaction.id()}")
                appendLine("type=${interaction.type()}")
                appendLine("time=${interaction.timeStamp()}")
                appendLine("client_ip=${interaction.clientIp().hostAddress}")
                appendLine("client_port=${interaction.clientPort()}")
                interaction.customData().ifPresent { appendLine("custom_data=$it") }
                interaction.dnsDetails().ifPresent { dns ->
                    appendLine("dns_type=${dns.queryType()}")
                    appendLine("dns_query=${dns.query()}")
                }
                if (input.includeHttp) {
                    interaction.httpDetails().ifPresent { http ->
                        val rr = http.requestResponse()
                        appendLine("http_request=${rr.request()?.toString().orEmpty()}")
                        appendLine("http_response=${rr.response()?.toString().orEmpty()}")
                    }
                }
                interaction.smtpDetails().ifPresent { smtp ->
                    appendLine("smtp=$smtp")
                }
            }.trim()
        }
    }

/** The scanner and Collaborator handlers, in declared order. Declared last: top-level properties initialize in file order. */
internal val genericScannerHandlers: List<ToolHandler> =
    listOf(
        scannerIssuesHandler,
        scanAuditStartHandler,
        scanAuditStartModeHandler,
        scanAuditStartRequestsHandler,
        scanCrawlStartHandler,
        scanTaskStatusHandler,
        scanTaskDeleteHandler,
        scanReportHandler,
        collaboratorGenerateHandler,
        collaboratorPollHandler,
    )
