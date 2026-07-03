package pro.curator.antibot.server

import pro.curator.antibot.protocol.AttestationResponse
import pro.curator.antibot.protocol.Challenge
import pro.curator.antibot.protocol.ChallengeCrypto
import pro.curator.antibot.protocol.ChallengeSolution
import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopeCrypto
import pro.curator.antibot.protocol.OpenResult
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.protocol.RiskLevel
import pro.curator.antibot.protocol.SealedEnvelope
import pro.curator.antibot.protocol.TrustToken
import pro.curator.antibot.protocol.TrustTokenClaims
import pro.curator.antibot.protocol.VerifyResponse
import java.security.KeyPair
import java.util.UUID

/**
 * Orchestrates steps 5-7 of the flow on the server:
 *   consume nonce -> open envelope -> timestamp -> Play Integrity -> risk score
 *   -> trust token (or WebView challenge).
 */
public class AttestationService(
    private val serverKeys: KeyPair,
    private val nonceStore: NonceStore,
    private val riskEngine: RiskEngine,
    private val riskConfig: RiskEngine.RiskConfig,
    private val playIntegrityVerifier: PlayIntegrityVerifier,
    private val challengeStore: ChallengeStore,
    private val tokenTtlSeconds: Long = 300,
    private val timestampWindowMillis: Long = 120_000,
    private val issuer: String = "curator-antibot",
    private val clock: () -> Long = System::currentTimeMillis,
) {
    public suspend fun attest(env: SealedEnvelope): AttestationResponse {
        // 1) Nonce must be valid and unused (anti-replay). Consume atomically.
        when (val consumed = nonceStore.consume(env.nonce)) {
            is NonceStore.ConsumeResult.Rejected -> return deny(consumed.reason)
            NonceStore.ConsumeResult.Ok -> Unit
        }

        // 2) Open the protected envelope (verify signature + decrypt + bind fields).
        val opened = when (val result = EnvelopeCrypto.open(env, serverKeys.private)) {
            is OpenResult.Failure -> return deny(result.reason)
            is OpenResult.Ok -> result.opened
        }
        val payload = opened.payload

        // 3) Timestamp window (freshness; tolerates modest clock skew).
        val now = clock()
        if (kotlin.math.abs(now - payload.timestamp) > timestampWindowMillis) {
            return deny(ReasonCode.TIMESTAMP_OUT_OF_WINDOW)
        }

        // 4) Play Integrity verification (feature-flagged, guide §11).
        val piAssessment = if (riskConfig.playIntegrityEnabled) {
            val token = payload.integrity.playIntegrityToken
            if (token.isNullOrBlank()) {
                PlayIntegrityAssessment(PlayIntegrityStatus.UNAVAILABLE, note = "no-token")
            } else {
                playIntegrityVerifier.verify(token, payload.nonce, payload.telemetry.packageName)
            }
        } else {
            null // not evaluated when the flag is off
        }

        // 5) Risk scoring.
        val assessment = riskEngine.assess(payload, piAssessment)

        // 6) Decision -> token / challenge / deny.
        return when (assessment.decision) {
            Decision.ALLOW -> allow(payload.clientIdPublicKey, assessment.level, assessment.reasons, assessment.shadowed)
            Decision.DENY -> AttestationResponse(
                decision = Decision.DENY,
                riskLevel = assessment.level,
                reasonCodes = assessment.reasons,
                shadow = assessment.shadowed,
            )
            Decision.CHALLENGE -> {
                val issued = challengeStore.issue(payload.clientIdPublicKey)
                val pageUrl = "${Protocol.PATH_CHALLENGE_PAGE}?cid=${issued.challengeId}&n=${issued.challengeNonce}"
                AttestationResponse(
                    decision = Decision.CHALLENGE,
                    riskLevel = assessment.level,
                    reasonCodes = assessment.reasons,
                    shadow = assessment.shadowed,
                    challenge = Challenge(
                        challengeId = issued.challengeId,
                        challengeNonce = issued.challengeNonce,
                        pageUrl = pageUrl,
                        expiresAt = issued.expiresAt,
                    ),
                )
            }
        }
    }

    /** Verifies a WebView challenge solution and, if valid, issues a trust token (guide §14). */
    public fun verifyChallenge(solution: ChallengeSolution): AttestationResponse {
        val consumed = when (val r = challengeStore.consume(solution.challengeId, solution.clientIdPublicKey)) {
            is ChallengeStore.ConsumeResult.Rejected -> return deny(r.reason)
            is ChallengeStore.ConsumeResult.Ok -> r
        }
        val expected = ChallengeCrypto.expectedAnswer(solution.challengeId, consumed.challengeNonce)
        if (!constantTimeEquals(expected, solution.answer)) {
            return deny(ReasonCode.CHALLENGE_FAILED)
        }
        // Passed the step-up: issue a token at MEDIUM trust.
        return allow(solution.clientIdPublicKey, RiskLevel.MEDIUM, listOf(ReasonCode.OK), shadow = false)
    }

    /** Stateless verification for the application backend (or the demo protected route). */
    public fun verify(token: String): VerifyResponse =
        when (val r = TrustToken.verify(token, serverKeys.public, clock() / 1000)) {
            is TrustToken.VerifyResult.Valid -> VerifyResponse(true, ReasonCode.OK, r.claims)
            is TrustToken.VerifyResult.Invalid -> VerifyResponse(false, r.reason)
        }

    private fun allow(
        clientIdPublicKey: String,
        level: RiskLevel,
        reasons: List<ReasonCode>,
        shadow: Boolean,
    ): AttestationResponse {
        val nowSec = clock() / 1000
        val claims = TrustTokenClaims(
            sub = subjectFor(clientIdPublicKey),
            iss = issuer,
            iat = nowSec,
            exp = nowSec + tokenTtlSeconds,
            lvl = level,
            jti = UUID.randomUUID().toString(),
        )
        return AttestationResponse(
            decision = Decision.ALLOW,
            riskLevel = level,
            reasonCodes = reasons,
            trustToken = TrustToken.issue(claims, serverKeys.private),
            ttlSeconds = tokenTtlSeconds,
            shadow = shadow,
        )
    }

    private fun subjectFor(clientPubEncoded: String): String =
        CryptoPrimitives.sha256Hex(clientPubEncoded.toByteArray()).take(24)

    private fun deny(reason: ReasonCode) = AttestationResponse(
        decision = Decision.DENY,
        riskLevel = RiskLevel.HIGH,
        reasonCodes = listOf(reason),
    )

    private fun constantTimeEquals(a: String, b: String): Boolean {
        val ab = a.toByteArray()
        val bb = b.toByteArray()
        if (ab.size != bb.size) return false
        var result = 0
        for (i in ab.indices) result = result or (ab[i].toInt() xor bb[i].toInt())
        return result == 0
    }
}
