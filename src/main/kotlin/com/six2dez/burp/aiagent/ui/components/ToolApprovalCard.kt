package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.mcp.ImplicitDenyReason
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.ToolDecision
import com.six2dez.burp.aiagent.mcp.sanitizeBlock
import com.six2dez.burp.aiagent.mcp.sanitizeInline
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.applyAreaStyle
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.helpLabel
import java.awt.Color
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.KeyboardFocusManager
import java.awt.RenderingHints
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.border.CompoundBorder
import javax.swing.border.EmptyBorder
import javax.swing.border.LineBorder
import javax.swing.border.MatteBorder

// -------------------------------------------------------------------------------------------------
// Numeric constants. Named rather than inline because MagicNumber is active and QUAL-07 forbids
// growing detekt-baseline.xml.
// -------------------------------------------------------------------------------------------------

/** 3 px left accent strip, matching the compound-border idiom in SubtleNotice.kt:117. */
private const val ACCENT_STRIP_WIDTH = 3

/** Corner arc of the tier badge's rounded rect — the same 6 px `toolBadge` uses (Components.kt:452). */
private const val BADGE_ARC = 6

/** Tier-badge internal padding, adopted transitively from `toolBadge` (Components.kt:470). */
private const val BADGE_PAD_VERTICAL = 2

/** Tier-badge internal padding, adopted transitively from `toolBadge` (Components.kt:470). */
private const val BADGE_PAD_HORIZONTAL = 6

/**
 * Inline cap for the model-supplied tool ID. Long enough for any legitimate `ext:<server>:<tool>`
 * triple, short enough that a model cannot use the ID as a canvas.
 */
private const val TOOL_ID_MAX_LENGTH = 120

/** Preview character cap — roughly 40 rows x 80 columns, so it bites at about the same height as the line cap. */
private const val ARGS_PREVIEW_MAX_CHARS = 3200

/** Preview source-line cap, tightening ActionCard.limitLines(raw, 50). */
private const val ARGS_PREVIEW_MAX_LINES = 40

// Ordinal suffix arithmetic for the repeat counter (Mechanism B).
private const val ORDINAL_CENTURY = 100
private const val ORDINAL_DECADE = 10
private const val ORDINAL_TEEN_FIRST = 11
private const val ORDINAL_TEEN_LAST = 13
private const val ORDINAL_THIRD = 3

// -------------------------------------------------------------------------------------------------
// Copy. Every string here is EXTENSION-DERIVED and appears OUTSIDE every model region. Verbatim from
// 22-UI-SPEC.md "Copywriting Contract", which is normative. English only (CLAUDE.md, AGENTS.md).
// -------------------------------------------------------------------------------------------------

private const val HEADING = "The AI asked to run a tool"
private const val UNKNOWN_TOOL_TITLE = "Not a known tool — this call will fail if you approve it."

// A separate string on purpose: row 1's pending wording ends "…if you approve it", which names a button
// that does not exist on a compact row, and it is tense-wrong in both compact states — a session-approved
// call already ran, a session-denied one was never run at all.
//
// An unknown tool resolves to CONFIRM_EACH (22-03's fail-closed fallback) and CONFIRM_EACH never
// populates either session set (22-04), so no unknown tool can occupy a compact row. ADR-15 records this
// under "claim only what ships": implemented for title exhaustiveness, unreachable in this phase.
private const val UNKNOWN_TOOL_TITLE_COMPACT = "Not a known tool — no catalog entry matches this name."

private const val TRUST_LABEL = "AI-supplied — this extension did not write the text below:"
private const val TIER_REASON_CONFIRM = "Approving for the session applies to this tool until this chat is deleted."
private const val TIER_REASON_CONFIRM_EACH =
    "This tool is approved one call at a time. A session-wide approval is not offered for it."
private const val SESSION_SCOPE_FOOTER =
    "\"Session\" means this chat. Approvals are forgotten when the chat is deleted, and are not restored when Burp restarts."

/**
 * Applies the UI-SPEC §Typography overflow contract: an `<html>` prefix at offset 0, which is what makes
 * `BasicHTML` install a wrapping View on a row that would otherwise clip.
 *
 * A plain `JLabel` does not wrap, and `BasicLabelUI.getMinimumSize` returns its PREFERRED size for one,
 * so an unwrapped caption row sets a hard floor under the whole card. Measured on Temurin 21 headless
 * at Dialog-12: row 10 drops from a 625 px minimum to 55 px with the prefix, and row 2's CONFIRM_EACH
 * reason from 450 px to 71 px. Without them the card could not shrink below 644 px inside a transcript
 * that sets `HORIZONTAL_SCROLLBAR_NEVER` (`ChatPanel.SessionPanel`), so dragging the sessions divider
 * right pushed `Approve for session` off the viewport edge with no scrollbar, no wrap and no
 * affordance — a security control the user could not reach (22-UI-REVIEW.md S-1). The other half of
 * that fix is the `minimumSize` floor `MainTab` puts on `ChatPanel.root`.
 *
 * Applied ONLY to extension-authored copy with no interpolation of any kind, which is why it takes an
 * already-composed string rather than a template: no model byte can reach offset 0, or any other
 * offset, in what is passed here. That is the same exemption [footerTextFor] documents, and
 * `ToolApprovalCardTest` enumerates every row allowed to carry the renderer and re-asserts the
 * no-model-byte property on each rather than exempting `JLabel` as a class.
 *
 * **Residual, recorded rather than discovered later.** An HTML `JLabel` reports the preferred height of
 * its UNCONSTRAINED layout, so between the card's new floor and its ~625 px preferred width these two
 * captions wrap to a second line while `SessionPanel.addComponent`'s height-capping wrapper still
 * allocates one, and the second line is clipped. That is a strictly better failure than the one it
 * replaces — the four decision buttons stay reachable at every reachable width, and the spec's
 * safe-action-first ordering keeps `Deny` the last control to be lost — but it is a trade, not a free
 * win. Fixing it properly needs a width-aware `getPreferredSize` override, which was judged too much
 * new layout machinery to add on a review fix.
 */
private fun wrapped(text: String): String = "<html>$text"

/**
 * The load-bearing last sentence of both truncation footers: the display cap is a DISPLAY limit, not
 * an execution limit. `McpToolExecutor.executeTool` receives the whole args string regardless of what
 * this card renders, and a user authorising a call must know that.
 */
private const val ARGS_SENT_IN_FULL = "The full arguments are sent to the tool if you approve."

private const val LABEL_DENY = "Deny"
private const val LABEL_DENY_SESSION = "Deny for session"
private const val LABEL_APPROVE_ONCE = "Approve once"
private const val LABEL_APPROVE_SESSION = "Approve for session"

private const val TIP_DENY = "Do not run this call. The AI is told the call was not authorised and continues without it."
private const val TIP_APPROVE_ONCE = "Run this tool call now. The AI must ask again next time."

/**
 * The disclosure clause that makes the accessible description safe.
 *
 * Note the trailing space and the fact that the model's tool ID is appended straight after it with
 * NOTHING following. Rule T-2 forbids concatenating a model string into extension text, and the obvious
 * justification for this one exception — "it is not a rendered surface" — is **wrong**: for a blind user
 * the accessible description IS the rendered surface. What makes concatenation survivable in a `JLabel`
 * is that `BasicHTML.isHTMLString` fires only at offset 0, and that rule has no screen-reader analogue —
 * a screen reader has no notion of position, it simply reads on, so a model string placed mid-sentence
 * would be followed by extension-authored audio and `scope_check. Press Approve once to continue` would
 * be indistinguishable from narration this extension wrote. The mitigation is positional in a different
 * way: put the model string LAST and let nothing follow it.
 */
private const val DISCLOSURE_CLAUSE = "The following tool name was written by the AI, not by this extension: "

/** U+25B6 / U+25BC, matching AccordionPanel.kt:103 so the affordance reads the same everywhere. */
private const val GLYPH_COLLAPSED = "▶"
private const val GLYPH_EXPANDED = "▼"

/** U+2714 / U+2716. An approve/deny pair needs both poles; a checkmark alone with colour-only negation would rely on colour. */
private const val GLYPH_APPROVED = "✔"
private const val GLYPH_DENIED = "✖"

/** Reuses the format `ChatPanel.ChatMessagePanel` already renders rather than inventing a second one. */
private const val TIMESTAMP_PATTERN = "h:mm a"

/** Which of the three args disclosure stages the card is showing. */
private enum class ArgsStage { PREVIEW, FULL }

/**
 * One resolved outcome, split the way the outcome row renders it: the glyph label carries the leading
 * glyph and nothing else, the timestamp label carries the trailing time token including its separator or
 * parentheses exactly as the copy line writes them, and the verb label carries everything between.
 */
private data class Outcome(
    val glyph: String,
    val verb: String,
    val timePart: String,
    val approved: Boolean,
)

/**
 * The SEC-06 decision surface: an inline card in the chat transcript that shows one model-emitted tool
 * call and offers the user an explicit decision about it (D-06, D-07, D-11).
 *
 * **The hard problem this component solves is not layout — it is that two classes of text share one
 * card.** The heading, the catalog title, the tier badge and the button labels are extension-derived
 * and trustworthy. The tool ID and the args JSON are model-supplied and an injected prompt can write
 * "safe routine read" into either. A user must tell them apart WITHOUT reading carefully, so:
 *
 * - **Containment (primary).** Every model-supplied string is rendered inside a bordered, input-styled
 *   region, and nothing extension-derived is ever rendered inside one.
 * - **Widget class (anti-spoofing).** Model text goes ONLY into [JTextField] / [JTextArea]. It is
 *   forbidden in [JLabel], any `AbstractButton`, any `JEditorPane`, and any tooltip: all of those route
 *   their text through `BasicHTML.updateRenderer`, so `"<html><b>Approved</b>"` in a tool ID would
 *   render as extension-looking chrome. `ToolApprovalCardTest` asserts this mechanically through
 *   `getClientProperty("html")`.
 * - **Font family (theme-independent).** Extension text is proportional; model text is monospace.
 * - **An explicit label.** A caption above the first model region says this extension did not write
 *   what follows. It sits outside every box, so model text physically cannot escape into it.
 *
 * The card is also a **record**, not just a prompt: it stays in the transcript after the decision and
 * must read unambiguously months later.
 *
 * Deliberately NOT an `ActionCard` subclass. `ActionCard` renders all four of its text fields into
 * `JLabel`s, which is the one thing this card may never do; it also uses the legacy theme shim, a
 * nested scroll pane, off-grid insets, and has no `updateUI()` override.
 *
 * Contract: `.planning/phases/22-agent-tool-call-trust-boundary/22-UI-SPEC.md` (approved, binding).
 */
internal class ToolApprovalCard private constructor(
    private val tier: SecTier,
    private val catalogTitle: String?,
    // Named so its trust class is obvious at every call site: this is `ParsedToolCall.tool`, i.e.
    // whatever string the model wrote. Attacker-influenceable.
    modelSuppliedToolId: String,
    // Also attacker-influenceable.
    modelSuppliedArgsJson: String?,
    // Computed by the gate, never re-derived from the tier here: whether the two session-wide actions
    // are offered is the gate's call, and duplicating the rule would let the two disagree.
    // Deliberately has NO default value (the ContextPreviewDialog.kt:21-23 convention).
    private val offersSessionActions: Boolean,
    private val repeatCount: Int,
    // Deliberately has NO default value: a default onDecision is how a future caller ships a card
    // whose buttons do nothing.
    private val onDecision: (ToolDecision) -> Unit,
    private val onRequestFocusRestore: (() -> Unit)?,
    // Non-null puts the card in resolved-only "compact row" mode. Private, and set only by [compact],
    // so no caller can build a hybrid that offers buttons AND claims a decision was already applied.
    private val compactDecision: ToolDecision?,
) : JPanel(GridBagLayout()) {
    /**
     * The pending card: the only constructor a caller can reach.
     *
     * [onRequestFocusRestore] is invoked by [resolve] when the button row being removed owns focus;
     * `ChatPanel.askForToolApproval` wires it to the same `inputArea.requestFocusInWindow()` call the
     * panel already makes elsewhere.
     */
    internal constructor(
        tier: SecTier,
        catalogTitle: String?,
        modelSuppliedToolId: String,
        modelSuppliedArgsJson: String?,
        offersSessionActions: Boolean,
        repeatCount: Int,
        onDecision: (ToolDecision) -> Unit,
        onRequestFocusRestore: (() -> Unit)? = null,
    ) : this(
        tier = tier,
        catalogTitle = catalogTitle,
        modelSuppliedToolId = modelSuppliedToolId,
        modelSuppliedArgsJson = modelSuppliedArgsJson,
        offersSessionActions = offersSessionActions,
        repeatCount = repeatCount,
        onDecision = onDecision,
        onRequestFocusRestore = onRequestFocusRestore,
        compactDecision = null,
    )

    // `JPanel.<init>` invokes updateUI() BEFORE the Kotlin field initialisers below run, so an
    // unguarded re-apply would NPE on every child field. The flag is zero-initialised to false by the
    // JVM, so the guard short-circuits during super-construction, and is flipped at the end of init {}.
    // Same hazard and same fix as SafetyIndicator.kt:23-27. ActionCard has no such override; that is a
    // gap, not a precedent.
    private var initialized = false

    /** Rule T-6 inline form: control characters REMOVED (never replaced), whitespace collapsed, capped. */
    private val sanitizedToolId = sanitizeInline(modelSuppliedToolId, TOOL_ID_MAX_LENGTH).orEmpty()

    /** Rule T-6 block form: `\n` and `\t` preserved, uncapped — the honest denominator for every count below. */
    private val sanitizedArgs = sanitizeBlock(modelSuppliedArgsJson, maxChars = Int.MAX_VALUE, maxLines = Int.MAX_VALUE)

    private val previewArgs =
        sanitizeBlock(modelSuppliedArgsJson, maxChars = ARGS_PREVIEW_MAX_CHARS, maxLines = ARGS_PREVIEW_MAX_LINES)

    private val totalChars = sanitizedArgs.length

    private val previewTruncated = previewArgs != sanitizedArgs

    // sanitizeBlock appends exactly one ellipsis character when it truncates, so subtracting it gives
    // the exact number of ARGUMENT characters on screen. The footer states that number, and a count
    // that was one too high would be a false statement on a card whose whole job is authorisation.
    private val previewShownChars = if (previewTruncated) previewArgs.length - 1 else previewArgs.length

    // Defensive only: args come from model output requested at CHAT_MAX_OUTPUT_TOKENS, so in practice
    // this cannot bite — but a local backend may ignore the output cap. When it does bite the Full
    // stage says so, and "Showing all N characters." is never generated.
    private val ceilingEngaged = totalChars > Defaults.MAX_CONTEXT_TOTAL_CHARS

    private val fullArgs =
        if (ceilingEngaged) {
            sanitizeBlock(modelSuppliedArgsJson, maxChars = Defaults.MAX_CONTEXT_TOTAL_CHARS, maxLines = Int.MAX_VALUE)
        } else {
            sanitizedArgs
        }

    // Anti-habituation Mechanism A / threat T-22-29. Derived from the tier INSIDE this file rather
    // than exposed as a constructor parameter, so no call site can defeat the rule. D-02/D-04's whole
    // argument for CONFIRM_EACH is "constant tool name and hostile args" — for that tier the args ARE
    // the decision, so showing them is not friction, it is showing the thing that must be read.
    // Intended side effect: the two tiers become physically different sizes, so a CONFIRM_EACH card
    // visually interrupts a run of CONFIRM cards.
    private val initiallyExpanded = tier == SecTier.CONFIRM_EACH

    /** True for a compact resolved row — a receipt for a decision the user made earlier, not a prompt. */
    private val isCompact = compactDecision != null

    private var resolved = isCompact

    private var outcome: Outcome? = null

    // Mechanism A expands args to interrupt a run of prompts; a compact row interrupts nothing, and it
    // was never pending so there is no prior user expand state to preserve.
    private var expanded = !isCompact && initiallyExpanded

    private var argsStage = ArgsStage.PREVIEW

    private val headingLabel = JLabel(HEADING)

    // Rule T-7: an unrecognised tool is LABELLED, never shown bare, and no catalog title is fabricated
    // for it. The model's own string still appears — sanitized, inside its box — because the user must
    // see what was asked for.
    private val titleLabel = JLabel(catalogTitle ?: if (isCompact) UNKNOWN_TOOL_TITLE_COMPACT else UNKNOWN_TOOL_TITLE)

    private val tierReasonLabel = helpLabel(wrapped(tierReasonFor(tier)))

    private val repeatLabel =
        JLabel(if (repeatCount > 1) "${ordinalFor(repeatCount)} request for this tool in this chat" else "")

    private val trustLabel = helpLabel(TRUST_LABEL)

    private val toolIdField = JTextField(sanitizedToolId)

    private val argsToggle = JButton()

    private val argsArea = JTextArea()

    private val truncationFooter = helpLabel("")

    private val showAllButton = JButton()

    /** Holds the truncation footer and, when more is available on this card, the show-all button. */
    private val overflowRow = JPanel()

    private val buttonRow = JPanel()

    private val decisionButtons = mutableListOf<JButton>()

    private val sessionScopeLabel = helpLabel(wrapped(SESSION_SCOPE_FOOTER))

    private val badge = tierBadge(tier)

    private var outcomeRow: JPanel? = null

    private var outcomeGlyphLabel: JLabel? = null

    private var outcomeVerbLabel: JLabel? = null

    private var outcomeTimeLabel: JLabel? = null

    init {
        isOpaque = true

        // Set isEditable BEFORE the design-system builder runs: several L&Fs paint a non-editable text
        // component with the disabled background and would overwrite the token value if reversed.
        toolIdField.isEditable = false
        toolIdField.caretPosition = 0
        argsArea.isEditable = false

        argsToggle.horizontalAlignment = SwingConstants.LEFT
        argsToggle.isFocusPainted = false
        argsToggle.addActionListener {
            expanded = !expanded
            updateArgsView()
        }

        showAllButton.horizontalAlignment = SwingConstants.LEFT
        showAllButton.isFocusPainted = false
        showAllButton.addActionListener {
            argsStage = ArgsStage.FULL
            updateArgsView()
        }

        if (compactDecision != null) {
            outcome = outcomeFor(compactDecision, null, nowTimestamp())
            buildOutcomeRow()
        } else {
            buildButtonRow()
        }
        buildRows()

        initialized = true
        applyTheme()
        updateArgsView()
        updateAccessibleDescription()
    }

    /**
     * Resolves a pending card in place: the buttons are **removed** and replaced by an outcome row that
     * names the clicked action verbatim, the accent strip drops to `borderSubtle`, and everything else
     * stays.
     *
     * Buttons are removed rather than disabled. A disabled `JButton` renders as grey text on the same
     * chrome — months later it is indistinguishable from "unavailable", and four dead buttons occupy
     * permanent noise in a scrolling record. What was *offered* is still recorded, by the tier badge
     * (which is what determined whether four or two buttons existed) and by the outcome line itself.
     *
     * The args expand state is preserved exactly as the user left it: not auto-collapsed on approve, not
     * auto-expanded on deny. The args are the record, and collapsing them would hide the thing the user
     * just authorised. The card also does not scroll itself — the user is where they are.
     */
    internal fun resolve(
        decision: ToolDecision,
        implicitReason: ImplicitDenyReason? = null,
    ) {
        if (resolved) {
            return
        }
        // Removing the button row while it owns focus lets Swing move focus somewhere arbitrary — often
        // another card, or the sessions list. Guarded on ownership so a mouse click does not yank focus
        // from wherever the user put it. Precedent: `ChatPanel.showToolsMenu`, which returns focus to the
        // input area only on the branch that just wrote into it.
        val focusOwner = KeyboardFocusManager.getCurrentKeyboardFocusManager().focusOwner
        if (focusOwner != null && SwingUtilities.isDescendingFrom(focusOwner, this)) {
            onRequestFocusRestore?.invoke()
        }

        outcome = outcomeFor(decision, implicitReason, nowTimestamp())
        resolved = true
        buildOutcomeRow()

        // Replace IN THE SAME GRID CELL so no other row reflows. getConstraints returns a copy of the
        // constraints the button row was added with, which is exactly the cell to reuse. The
        // height-capping wrapper in `ChatPanel.SessionPanel.addComponent` recomputes from the layout on
        // every pass, so the
        // card shrinking needs no extra work.
        val cell = (layout as GridBagLayout).getConstraints(buttonRow)
        remove(buttonRow)
        decisionButtons.clear()
        outcomeRow?.let { add(it, cell) }

        applyTheme()
        // A resolved card that still announces "The AI asked to run a tool" is a false statement made to
        // the one user who cannot see that the buttons are gone, so accessibleDescription is rewritten
        // here as well as at construction.
        updateAccessibleDescription()
        revalidate()
        repaint()
    }

    override fun updateUI() {
        super.updateUI()
        // Re-apply every token-derived colour, font and border after a Burp theme switch. Guarded
        // against the super-construction callback (see [initialized]).
        if (initialized) {
            applyTheme()
        }
    }

    /**
     * Single-column [GridBagLayout], eleven rows, `gridwidth = REMAINDER` throughout.
     *
     * Horizontal insets are 0 on every row: horizontal padding is declared once, by the card's own
     * `EmptyBorder`. All vertical insets are on the 4 px grid.
     */
    private fun buildRows() {
        val constraints =
            GridBagConstraints().apply {
                gridx = 0
                gridy = 0
                gridwidth = GridBagConstraints.REMAINDER
                fill = GridBagConstraints.HORIZONTAL
                weightx = 1.0
                anchor = GridBagConstraints.WEST
            }
        val tight = Insets(0, 0, DesignTokens.Spacing.xs, 0)
        val roomy = Insets(0, 0, DesignTokens.Spacing.sm, 0)

        overflowRow.layout = BoxLayout(overflowRow, BoxLayout.Y_AXIS)
        overflowRow.isOpaque = false
        truncationFooter.alignmentX = LEFT_ALIGNMENT
        val showAllRow = JPanel()
        showAllRow.layout = BoxLayout(showAllRow, BoxLayout.X_AXIS)
        showAllRow.isOpaque = false
        showAllRow.alignmentX = LEFT_ALIGNMENT
        showAllRow.add(showAllButton)
        showAllRow.add(Box.createHorizontalGlue())
        overflowRow.add(truncationFooter)
        overflowRow.add(showAllRow)

        if (isCompact) {
            // Five visible rows against a resolved full card's eight or nine — the whole point of the
            // word "compact". The heading is dropped because the next line already answers it, and the
            // tier badge because nothing was ever offered here, so it has no record to carry and would
            // read the same on every compact row. The tier reason, the repeat counter, the buttons and
            // the session-scope footer go for the reasons in UI-SPEC §"The compact resolved row".
            outcomeRow?.let { addRow(it, constraints, tight) }
            addRow(titleLabel, constraints, tight)
            addRow(trustLabel, constraints, tight)
            addRow(toolIdField, constraints, roomy)
            addRow(argsToggle, constraints, tight)
            addRow(argsArea, constraints, roomy)
            addRow(overflowRow, constraints, tight)
            return
        }

        // Row 0 — heading + tier badge, kept adjacent rather than pinning the badge to a far-right
        // edge that moves when the user drags the Burp tab divider.
        val header = JPanel()
        header.layout = BoxLayout(header, BoxLayout.X_AXIS)
        header.isOpaque = false
        header.add(headingLabel)
        header.add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
        header.add(badge)
        header.add(Box.createHorizontalGlue())
        addRow(header, constraints, tight)

        addRow(titleLabel, constraints, tight)
        addRow(tierReasonLabel, constraints, tight)
        // Row 3 — Mechanism B. The one signal that actually breaks autopilot: it says the model is
        // INSISTING. Rendered only when there is something to say.
        if (repeatCount > 1) {
            addRow(repeatLabel, constraints, tight)
        }
        addRow(trustLabel, constraints, tight)
        addRow(toolIdField, constraints, roomy)
        addRow(argsToggle, constraints, tight)
        addRow(argsArea, constraints, roomy)
        addRow(overflowRow, constraints, tight)
        addRow(buttonRow, constraints, Insets(DesignTokens.Spacing.sm, 0, 0, 0))
        addRow(sessionScopeLabel, constraints, tight)
    }

    /**
     * Row 9. Left-aligned, because the card is a record and not a dialog footer.
     *
     * Scope escalates left to right within each group, so the two narrowest actions flank the 16 px
     * gap and the two session-wide ones sit at the outer edges. Visual order equals focus order, so Tab
     * from the input area reaches `Deny` first — the fail-closed reflex target.
     */
    private fun buildButtonRow() {
        buttonRow.layout = BoxLayout(buttonRow, BoxLayout.X_AXIS)
        buttonRow.isOpaque = false
        // Tooltips interpolate the CATALOG title and never the model's string — a tooltip renders HTML,
        // so a model-authored one would be styled, floating, extension-looking text (Rule T-2). When the
        // tool is unrecognised there is no title to interpolate and the two session tooltips are simply
        // omitted rather than filled with invented copy.
        val denySessionTip =
            catalogTitle?.let { "Do not run this call, and refuse any later $it call in this chat without asking again." }
        val approveSessionTip = catalogTitle?.let { "Run this and any later $it call in this chat without asking." }

        buttonRow.add(decisionButton(LABEL_DENY, TIP_DENY, ToolDecision.DENY))
        if (offersSessionActions) {
            buttonRow.add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
            buttonRow.add(decisionButton(LABEL_DENY_SESSION, denySessionTip, ToolDecision.DENY_SESSION))
        }
        // The 16 px gap between the deny and approve poles is the cheapest mis-click mitigation
        // available: a mis-aimed click near the boundary lands in dead space, not on the wrong pole.
        buttonRow.add(Box.createRigidArea(Dimension(DesignTokens.Spacing.lg, 0)))
        buttonRow.add(decisionButton(LABEL_APPROVE_ONCE, TIP_APPROVE_ONCE, ToolDecision.APPROVE_ONCE))
        if (offersSessionActions) {
            buttonRow.add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
            buttonRow.add(decisionButton(LABEL_APPROVE_SESSION, approveSessionTip, ToolDecision.APPROVE_SESSION))
        }
        buttonRow.add(Box.createHorizontalGlue())
    }

    /**
     * The outcome row. Colour appears on the **glyph only** — no filled background on a resolved card,
     * because a denied card that shouts red forever is itself a habituation trainer.
     *
     * On a mutated full card this row lands last, in the button row's cell, which is a mechanical
     * consequence of replacing in place rather than a reading-order decision. On a compact row it comes
     * first, where it does the heading's duty, so a reader scanning the transcript can separate "a
     * decision happened here" from "a decision you made earlier was applied here" without reading either.
     */
    private fun buildOutcomeRow() {
        val current = outcome ?: return
        val row = JPanel()
        row.layout = BoxLayout(row, BoxLayout.X_AXIS)
        row.isOpaque = false
        val glyph = JLabel(current.glyph)
        // The compact verbs are long enough in the bold label role to clip, and the transcript's scroll
        // pane never shows a horizontal bar. The `<html>` prefix that makes the label wrap is safe for
        // exactly the reason the truncation footers are: this string is extension-authored and contains
        // no model byte at position 0 or at any other offset.
        val verb = JLabel(if (isCompact) "<html>${current.verb}" else current.verb)
        val time = JLabel(current.timePart)
        row.add(glyph)
        row.add(Box.createRigidArea(Dimension(DesignTokens.Spacing.xs, 0)))
        row.add(verb)
        row.add(Box.createRigidArea(Dimension(DesignTokens.Spacing.sm, 0)))
        row.add(time)
        row.add(Box.createHorizontalGlue())
        outcomeGlyphLabel = glyph
        outcomeVerbLabel = verb
        outcomeTimeLabel = time
        outcomeRow = row
    }

    /**
     * The card root's `AccessibleContext` description — the only channel through which a screen-reader
     * user receives the trust distinction sighted users get from the box, so all three of its conditions
     * are required and the description is unsafe if any one is dropped:
     *
     * 1. the tool ID is inline-sanitized, so a multi-line ID cannot be read as several sentences;
     * 2. it is the **final element** with no character after it — mechanically checkable with
     *    `description.endsWith(sanitizedToolId)`;
     * 3. it is immediately preceded by [DISCLOSURE_CLAUSE], so attribution is heard **before** the
     *    attacker-influenceable text, never after it.
     *
     * `{TIER}` renders the badge's own text token exactly, so the audio and the badge say the same word.
     * Nothing else is added: the decision buttons carry their own accessible names from their labels, so
     * restating them here would only lengthen the audio in front of the tool ID.
     */
    private fun updateAccessibleDescription() {
        val current = outcome
        val prefix =
            when {
                current != null -> "${current.verb} ${current.timePart}."
                catalogTitle != null -> "$HEADING. Tier: ${tierTextFor(tier)}. $catalogTitle."
                // The unknown-tool title already ends in a period, so it is spelled out rather than
                // substituted into a "{title}." template — substitution would produce "it..".
                else -> "$HEADING. Tier: ${tierTextFor(tier)}. $UNKNOWN_TOOL_TITLE"
            }
        // getAccessibleContext(), never the `accessibleContext` property: from inside a JComponent
        // subclass Kotlin resolves that name to Component's PROTECTED FIELD, which stays null until the
        // getter lazily creates the context — so the property form NPEs on the first card ever built.
        getAccessibleContext().accessibleDescription = "$prefix $DISCLOSURE_CLAUSE$sanitizedToolId"
    }

    /**
     * A plain [JButton] with no colour of its own.
     *
     * Not `primaryButton`: that fills with the 10 % accent, whose reserved list does not include a
     * security affirmative, and making `Approve once` visually dominant is the opposite of the goal.
     * Not `statusError` on `Deny` either: deny is the safe, fully recoverable outcome, and colouring it
     * red would miscolour the safe action as dangerous. There is deliberately no recommended action.
     *
     * `isFocusPainted = true` is a deliberate deviation from `ActionCard`'s buttons and from every
     * `ChatPanel` toolbar button (`sendBtn`, `cancelBtn`, `clearChatBtn`, `toolsBtn`, …), all of which set
     * `isFocusPainted = false`: a keyboard user must see which pole is focused before pressing Space.
     */
    private fun decisionButton(
        label: String,
        tooltip: String?,
        decision: ToolDecision,
    ): JButton =
        JButton(label)
            .apply {
                font = DesignTokens.Typography.body
                isFocusPainted = true
                toolTipText = tooltip
                addActionListener { onDecision(decision) }
            }.also { decisionButtons.add(it) }

    /**
     * Three-stage args disclosure — collapsed, preview, full.
     *
     * Collapsed means `isVisible = false`, not zero height: a hidden component contributes nothing to
     * the layout, which keeps the height-capping wrapper installed by `SessionPanel.addComponent`
     * correct. There is no nested scroll pane — the transcript's own does the scrolling, and a nested
     * one would hide args below a fold and create the wheel trap.
     */
    private fun updateArgsView() {
        argsToggle.text =
            if (expanded) {
                "$GLYPH_EXPANDED Hide arguments"
            } else {
                "$GLYPH_COLLAPSED Show arguments ($totalChars characters)"
            }
        argsArea.isVisible = expanded
        argsArea.text = if (argsStage == ArgsStage.FULL) fullArgs else previewArgs
        argsArea.caretPosition = 0

        val footer = footerTextFor(argsStage, previewTruncated, ceilingEngaged, previewShownChars, totalChars)
        truncationFooter.text = footer.orEmpty()
        truncationFooter.isVisible = expanded && footer != null
        showAllButton.text = showAllLabelFor(totalChars)
        showAllButton.isVisible = expanded && argsStage == ArgsStage.PREVIEW && previewTruncated
        overflowRow.isVisible = truncationFooter.isVisible || showAllButton.isVisible

        revalidate()
        repaint()
    }

    /**
     * The tier badge — outlined, never filled.
     *
     * Structured exactly like `Components.toolBadge` (rounded rect at paint time, caption font, its
     * `EmptyBorder(2, 6, 2, 6)` padding, foreground re-applied on theme switch) but with a coloured
     * outline instead of a coloured fill. A filled pill was rejected on measured contrast grounds
     * (white on the warning token is ~2.70:1, far below the 4.5:1 AA threshold), and the
     * outlined form puts badge text in exactly the same foreground/background relationship as ordinary
     * body text, so it introduces no new contrast obligation.
     *
     * **The text is the load-bearing channel; colour never carries text on this card.** The `when` is
     * exhaustive including `AUTO` so a future tier cannot render blank, even though an `AUTO` call
     * produces no card at all (D-02).
     *
     * Not promoted to `Components.kt`: one caller, and Phase 13's "avoid premature generalisation"
     * stance applies until a second one exists (FLAG-22-05).
     */
    private fun tierBadge(tier: SecTier): JLabel =
        object : JLabel("Tier: ${tierTextFor(tier)}") {
            override fun paintComponent(g: Graphics) {
                val g2d = g as Graphics2D
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                // Re-read at paint time so the badge always reflects the active Burp theme, even if it
                // was created under a different one (the FLAG-10-01 handling in Components.kt:447-451).
                g2d.color = DesignTokens.Colors.cardSurface
                g2d.fillRoundRect(0, 0, width, height, BADGE_ARC, BADGE_ARC)
                super.paintComponent(g)
            }

            override fun updateUI() {
                super.updateUI()
                font = DesignTokens.Typography.caption
                foreground = DesignTokens.Colors.onSurface
                border =
                    CompoundBorder(
                        LineBorder(tierColorFor(tier), 1, true),
                        EmptyBorder(BADGE_PAD_VERTICAL, BADGE_PAD_HORIZONTAL, BADGE_PAD_VERTICAL, BADGE_PAD_HORIZONTAL),
                    )
            }
        }.apply {
            isOpaque = false
            font = DesignTokens.Typography.caption
            foreground = DesignTokens.Colors.onSurface
            border =
                CompoundBorder(
                    LineBorder(tierColorFor(tier), 1, true),
                    EmptyBorder(BADGE_PAD_VERTICAL, BADGE_PAD_HORIZONTAL, BADGE_PAD_VERTICAL, BADGE_PAD_HORIZONTAL),
                )
        }

    /**
     * Re-applies every token-derived value. Called at the end of `init {}` and again on every theme
     * switch. No token is cached in a `val` at construction — [DesignTokens] properties are computed
     * `get`s for exactly this reason.
     */
    private fun applyTheme() {
        background = DesignTokens.Colors.cardSurface
        // Only PENDING cards carry a coloured strip. Scanning the transcript therefore answers "is
        // anything waiting for me" with one glance and no reading.
        val accent = if (resolved) DesignTokens.Colors.borderSubtle else tierColorFor(tier)
        border =
            CompoundBorder(
                CompoundBorder(
                    MatteBorder(0, ACCENT_STRIP_WIDTH, 0, 0, accent),
                    LineBorder(DesignTokens.Colors.border, 1, true),
                ),
                EmptyBorder(
                    DesignTokens.Spacing.sm,
                    DesignTokens.Spacing.md,
                    DesignTokens.Spacing.sm,
                    DesignTokens.Spacing.md,
                ),
            )

        headingLabel.font = DesignTokens.Typography.sectionTitle
        headingLabel.foreground = DesignTokens.Colors.onSurface
        titleLabel.font = DesignTokens.Typography.body
        titleLabel.foreground = DesignTokens.Colors.onSurface
        tierReasonLabel.font = DesignTokens.Typography.caption
        tierReasonLabel.foreground = DesignTokens.Colors.onSurfaceVariant
        repeatLabel.font = DesignTokens.Typography.caption
        repeatLabel.foreground = DesignTokens.Colors.statusWarning
        trustLabel.font = DesignTokens.Typography.caption
        trustLabel.foreground = DesignTokens.Colors.onSurfaceVariant
        truncationFooter.font = DesignTokens.Typography.caption
        truncationFooter.foreground = DesignTokens.Colors.onSurfaceVariant
        sessionScopeLabel.font = DesignTokens.Typography.caption
        sessionScopeLabel.foreground = DesignTokens.Colors.onSurfaceVariant

        // One call each supplies the monospace font, the 1 px outline and the input background — the
        // three containment channels of Rule T-1 at once, which is why the design-system builder is
        // used here instead of hand-set properties.
        applyFieldStyle(toolIdField)
        applyAreaStyle(argsArea)

        argsToggle.font = DesignTokens.Typography.body
        showAllButton.font = DesignTokens.Typography.body
        decisionButtons.forEach { it.font = DesignTokens.Typography.body }

        outcomeGlyphLabel?.font = DesignTokens.Typography.body
        outcomeGlyphLabel?.foreground =
            if (outcome?.approved == true) DesignTokens.Colors.statusSuccess else DesignTokens.Colors.statusError
        outcomeVerbLabel?.font = DesignTokens.Typography.label
        outcomeVerbLabel?.foreground = DesignTokens.Colors.onSurface
        outcomeTimeLabel?.font = DesignTokens.Typography.caption
        outcomeTimeLabel?.foreground = DesignTokens.Colors.onSurfaceVariant
    }

    companion object {
        /**
         * The compact resolved row: a **receipt**, not a prompt.
         *
         * States 2 and 3 are not decisions. The gate consulted the session sets, applied a decision the
         * user already made, and moved on. Both variants ship (FLAG-22-03): session-denied is required,
         * because otherwise the denial is invisible and the chain appears to stall, and session-approved
         * costs one branch and the card is a record.
         *
         * The tier is fixed at `CONFIRM` rather than taken from the caller because it is invariant here:
         * both session sets can only be populated by `Approve for session` / `Deny for session`, which
         * only a `CONFIRM` card renders. `CONFIRM_EACH` has no session memory in either direction.
         */
        internal fun compact(
            decision: ToolDecision,
            catalogTitle: String?,
            modelSuppliedToolId: String,
            modelSuppliedArgsJson: String?,
        ): ToolApprovalCard {
            require(decision == ToolDecision.SESSION_APPROVED || decision == ToolDecision.SESSION_DENIED) {
                "A compact resolved row records a decision a human made EARLIER and the gate applied to " +
                    "this call without asking anyone, so only SESSION_APPROVED and SESSION_DENIED can " +
                    "occupy one. Got $decision."
            }
            return ToolApprovalCard(
                tier = SecTier.CONFIRM,
                catalogTitle = catalogTitle,
                modelSuppliedToolId = modelSuppliedToolId,
                modelSuppliedArgsJson = modelSuppliedArgsJson,
                offersSessionActions = false,
                repeatCount = 1,
                // Supplied here, inside the class, rather than exposed on this factory: a compact row
                // renders no decision button so nothing can invoke it, and keeping it off the factory
                // signature means no caller can ship a card whose buttons do nothing.
                onDecision = { },
                onRequestFocusRestore = null,
                compactDecision = decision,
            )
        }
    }
}

/** Adds one full-width row and advances to the next. [constraints] is mutated and reused by design. */
private fun JPanel.addRow(
    component: JComponent,
    constraints: GridBagConstraints,
    insets: Insets,
) {
    constraints.insets = insets
    add(component, constraints)
    constraints.gridy++
}

/**
 * Channel 2 of tier legibility, and always redundant with the badge text. `AUTO` is specified so the
 * `when` is exhaustive; it is unreachable because an `AUTO` call renders no card (D-02).
 */
private fun tierColorFor(tier: SecTier): Color =
    when (tier) {
        SecTier.AUTO -> DesignTokens.Colors.statusSuccess
        SecTier.CONFIRM -> DesignTokens.Colors.statusWarning
        SecTier.CONFIRM_EACH -> DesignTokens.Colors.statusError
    }

/** Channel 1 — the load-bearing one. Also rendered verbatim into the accessible description. */
private fun tierTextFor(tier: SecTier): String =
    when (tier) {
        SecTier.AUTO -> "AUTO"
        SecTier.CONFIRM -> "CONFIRM"
        SecTier.CONFIRM_EACH -> "CONFIRM EACH"
    }

/** Row 2 — what the buttons on THIS card mean. Reconciles the tier with the actions offered. */
private fun tierReasonFor(tier: SecTier): String =
    when (tier) {
        SecTier.CONFIRM -> TIER_REASON_CONFIRM
        else -> TIER_REASON_CONFIRM_EACH
    }

/**
 * Row 8. A bare ellipsis is forbidden here: on a card whose whole purpose is authorisation it reads as
 * "nothing important follows".
 *
 * Both truncated forms take an `<html>` prefix at position 0 so they wrap — the transcript's scroll
 * pane never shows a horizontal bar, so an over-wide label clips with no way to read the rest. That is
 * not a Rule T-2 violation: these are extension-authored templates whose only interpolations are
 * extension-computed integers, so no model byte can reach position 0 or any other offset in them. The
 * exemption covers only label rows carrying zero model-supplied text.
 */
private fun footerTextFor(
    stage: ArgsStage,
    previewTruncated: Boolean,
    ceilingEngaged: Boolean,
    shown: Int,
    total: Int,
): String? =
    when {
        stage == ArgsStage.PREVIEW && previewTruncated ->
            "<html>Showing the first $shown of $total characters. $ARGS_SENT_IN_FULL"
        stage == ArgsStage.PREVIEW -> null
        ceilingEngaged ->
            "<html>Showing the first ${Defaults.MAX_CONTEXT_TOTAL_CHARS} of $total characters. " +
                "This is the maximum this card will display. $ARGS_SENT_IN_FULL"
        // Reserved for the case where everything really is on screen, and never generated otherwise —
        // this is exactly the case where it would be a false statement.
        else -> "Showing all $total characters."
    }

/** Labelled so the button never promises more than it delivers. */
private fun showAllLabelFor(total: Int): String =
    if (total <= Defaults.MAX_CONTEXT_TOTAL_CHARS) {
        "Show all $total characters"
    } else {
        "Show first ${Defaults.MAX_CONTEXT_TOTAL_CHARS} characters"
    }

/**
 * Splits one outcome line from the Copywriting Contract into the three labels the outcome row renders.
 *
 * Every string here is verbatim from that contract. The `when` is exhaustive over [ToolDecision] so a
 * future decision value cannot silently render a blank row.
 */
private fun outcomeFor(
    decision: ToolDecision,
    implicitReason: ImplicitDenyReason?,
    time: String,
): Outcome =
    when (decision) {
        ToolDecision.APPROVE_ONCE -> Outcome(GLYPH_APPROVED, "Approved once", "— $time", approved = true)
        ToolDecision.APPROVE_SESSION -> Outcome(GLYPH_APPROVED, "Approved for this chat", "— $time", approved = true)
        ToolDecision.DENY -> Outcome(GLYPH_DENIED, "Denied", "— $time", approved = false)
        ToolDecision.DENY_SESSION -> Outcome(GLYPH_DENIED, "Denied for this chat", "— $time", approved = false)
        ToolDecision.IMPLICIT_DENY ->
            Outcome(
                GLYPH_DENIED,
                // Only NEW_MESSAGE leaves a surviving surface. The other four teardown paths destroy the
                // transcript or the whole panel, so their durable record is the SC3 audit event, not this
                // row. If one ever does reach here, the contract's own line is used minus the clause that
                // would be false — saying less beats inventing copy for a state that is not designed.
                if (implicitReason == null || implicitReason == ImplicitDenyReason.NEW_MESSAGE) {
                    "Denied automatically — you sent a new message"
                } else {
                    "Denied automatically"
                },
                "($time)",
                approved = false,
            )
        ToolDecision.SESSION_APPROVED ->
            Outcome(GLYPH_APPROVED, "Ran without asking — approved for this chat", "($time)", approved = true)
        ToolDecision.AUTO_APPROVED ->
            Outcome(GLYPH_APPROVED, "Ran without asking — automatic approval enabled", "($time)", approved = true)
        ToolDecision.SESSION_DENIED ->
            Outcome(GLYPH_DENIED, "Blocked automatically — you denied this tool for this chat", "($time)", approved = false)
        // D-02: an AUTO-tier call runs with no card at all, so no AUTO outcome row can exist and the
        // Copywriting Contract deliberately specifies no copy for one. Reusing another branch's line
        // would put a human-decision sentence on a call no human saw — the exact conflation
        // ToolDecision's own KDoc says makes "did a human authorise this invocation?" unanswerable.
        // This is a programming error at the call site, not a state a user can reach, so it fails loudly.
        ToolDecision.AUTO -> error("ToolApprovalCard cannot render an AUTO outcome: an AUTO-tier call renders no card (D-02).")
    }

/** The transcript's existing timestamp format, reused rather than duplicated (`ChatPanel.ChatMessagePanel`). */
private fun nowTimestamp(): String = SimpleDateFormat(TIMESTAMP_PATTERN).format(Date())

/** English ordinal for the repeat counter: 2nd, 3rd, 4th, 11th, 21st. */
private fun ordinalFor(n: Int): String {
    val suffix =
        when {
            n % ORDINAL_CENTURY in ORDINAL_TEEN_FIRST..ORDINAL_TEEN_LAST -> "th"
            n % ORDINAL_DECADE == 1 -> "st"
            n % ORDINAL_DECADE == 2 -> "nd"
            n % ORDINAL_DECADE == ORDINAL_THIRD -> "rd"
            else -> "th"
        }
    return "$n$suffix"
}
