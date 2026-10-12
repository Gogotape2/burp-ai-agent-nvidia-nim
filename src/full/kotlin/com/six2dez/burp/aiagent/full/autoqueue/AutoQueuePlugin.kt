package com.six2dez.burp.aiagent.full.autoqueue

import com.six2dez.burp.aiagent.spi.ExtensionPlugin
import com.six2dez.burp.aiagent.spi.PluginHost

// RED skeleton (29-16 Task 2): replaced by the real plug-in in the GREEN commit.
class AutoQueuePlugin : ExtensionPlugin {
    override fun install(host: PluginHost) {}

    companion object {
        const val KEY = "full.active.autoqueue.enabled"
    }
}
