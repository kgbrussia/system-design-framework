package pro.curator.antibot.server

import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopePayload
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.protocol.RiskLevel

/**
 * Server-side risk scoring (guide §19). Never a hard yes/no on the client:
 * signals are weighted into a score, which maps to a decision + reason codes.
 *
 * PlayIntegrity verification is stubbed here (needs a Google Cloud project);
 * the hook [verifyPlayIntegrity] shows exactly where it plugs in.
 */
public class RiskEngine(
    private val config: RiskConfig = RiskConfig(),
) {
    public data class RiskConfig(
        val challengeThreshold: Int = 40,
        val denyThreshold: Int = 70,
        // Shadow mode: compute + report the decision but never actually block (rollout §19.5).
        val shadowMode: Boolean = false,
        val requirePlayIntegrity: Boolean = false,
    )

    public data class Assessment(
        val decision: Decision,
        val level: RiskLevel,
        val reasons: List<ReasonCode>,
        val score: Int,
        val shadowed: Boolean,
    )

    public fun assess(payload: EnvelopePayload): Assessment {
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

        // Play Integrity is the strongest signal when present (guide §11).
        val piResult = verifyPlayIntegrity(integrity.playIntegrityToken, payload.nonce)
        when (piResult) {
            PlayIntegrityResult.UNAVAILABLE -> {
                reasons += ReasonCode.INTEGRITY_UNAVAILABLE
                score += if (config.requirePlayIntegrity) 40 else 15
            }
            PlayIntegrityResult.FAILED -> {
                score += 50; reasons += ReasonCode.ATTESTATION_FAILED
            }
            PlayIntegrityResult.PASSED -> score -= 20 // strong trust signal lowers risk
        }

        score = score.coerceIn(0, 100)

        val rawDecision = when {
            score >= config.denyThreshold -> Decision.DENY
            score >= config.challengeThreshold -> Decision.CHALLENGE
            else -> Decision.ALLOW
        }
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

    private enum class PlayIntegrityResult { PASSED, FAILED, UNAVAILABLE }

    /**
     * STUB. Real implementation calls Google Play Integrity server API to decrypt
     * & verify the token, checks the request hash == our nonce, and reads the
     * appIntegrity / deviceIntegrity verdicts.
     */
    private fun verifyPlayIntegrity(token: String?, expectedNonce: String): PlayIntegrityResult {
        if (token.isNullOrBlank()) return PlayIntegrityResult.UNAVAILABLE
        // Demo heuristic so the pipeline is exercisable without Google credentials:
        // a token that echoes the nonce is treated as PASSED.
        return if (token.contains(expectedNonce)) PlayIntegrityResult.PASSED else PlayIntegrityResult.FAILED
    }
}
