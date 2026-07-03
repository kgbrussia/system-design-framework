package pro.curator.antibot.server

import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopePayload
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.protocol.RiskLevel

/**
 * Server-side risk scoring (guide §19). Never a hard yes/no on the client:
 * signals are weighted into a score, which maps to a decision + reason codes.
 *
 * The Play Integrity verdict is computed by [PlayIntegrityVerifier] and passed
 * in; a null verdict means "not evaluated" (feature flag off) and is neutral.
 */
public class RiskEngine(
    private val config: RiskConfig = RiskConfig(),
) {
    public data class RiskConfig(
        val challengeThreshold: Int = 40,
        val denyThreshold: Int = 70,
        // Feature flags (guide §15.6).
        val playIntegrityEnabled: Boolean = false,
        val requirePlayIntegrity: Boolean = false,
        val challengeEnabled: Boolean = true,
        // Shadow mode: compute + report the decision but never actually block (§19.5).
        val shadowMode: Boolean = false,
    )

    public data class Assessment(
        val decision: Decision,
        val level: RiskLevel,
        val reasons: List<ReasonCode>,
        val score: Int,
        val shadowed: Boolean,
    )

    /**
     * @param playIntegrity result of Play Integrity verification, or null if the
     *   feature is disabled (then it is not scored at all).
     */
    public fun assess(payload: EnvelopePayload, playIntegrity: PlayIntegrityAssessment?): Assessment {
        var score = 0
        val reasons = mutableListOf<ReasonCode>()
        val integrity = payload.integrity

        if (integrity.rooted) {
            score += 45; reasons += ReasonCode.ROOT_DETECTED
        }
        if (integrity.emulator) {
            score += 35; reasons += ReasonCode.EMULATOR_DETECTED
        }
        if (integrity.debuggerAttached) {
            score += 30; reasons += ReasonCode.DEBUGGER_DETECTED
        }
        if (integrity.hookingDetected) {
            score += 55; reasons += ReasonCode.HOOKING_DETECTED
        }
        if (payload.telemetry.debuggable) {
            score += 10
        }

        // Play Integrity is the strongest signal when enabled (guide §11).
        if (playIntegrity != null) {
            when (playIntegrity.status) {
                PlayIntegrityStatus.PASSED -> score -= 20 // strong trust signal lowers risk
                PlayIntegrityStatus.FAILED -> {
                    score += 50; reasons += ReasonCode.PLAY_INTEGRITY_FAILED
                }
                PlayIntegrityStatus.UNAVAILABLE -> {
                    reasons += ReasonCode.INTEGRITY_UNAVAILABLE
                    score += if (config.requirePlayIntegrity) 40 else 15
                }
            }
        }

        score = score.coerceIn(0, 100)

        var rawDecision = when {
            score >= config.denyThreshold -> Decision.DENY
            score >= config.challengeThreshold -> Decision.CHALLENGE
            else -> Decision.ALLOW
        }
        // If challenges are disabled, a would-be CHALLENGE falls back to DENY.
        if (rawDecision == Decision.CHALLENGE && !config.challengeEnabled) {
            rawDecision = Decision.DENY
        }
        if (rawDecision == Decision.CHALLENGE) reasons += ReasonCode.CHALLENGE_REQUIRED

        val level = when {
            score >= config.denyThreshold -> RiskLevel.HIGH
            score >= config.challengeThreshold -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
        if (reasons.isEmpty()) reasons += ReasonCode.OK

        // In shadow mode we still ALLOW, but report what we *would* have done.
        val effective = if (config.shadowMode) Decision.ALLOW else rawDecision
        return Assessment(
            decision = effective,
            level = level,
            reasons = reasons,
            score = score,
            shadowed = config.shadowMode && rawDecision != Decision.ALLOW,
        )
    }
}
