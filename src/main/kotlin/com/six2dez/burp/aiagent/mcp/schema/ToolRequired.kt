package com.six2dez.burp.aiagent.mcp.schema

/** Required despite a defensive decoder default (for example, a blank URL rejected by init). */
@Target(AnnotationTarget.PROPERTY)
@Retention(AnnotationRetention.RUNTIME)
annotation class ToolRequired
