package pro.curator.antibot.server

import pro.curator.antibot.protocol.AttestationResponse
import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopeCrypto
import pro.curator.antibot.protocol.OpenResult
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
 *   consume nonce -> open envelope -> check timestamp -> risk score -> issue trust token.
 */
public class AttestationService(
    private val serverKeys: KeyPair,
    private val nonceStore: NonceStore,
    private val riskEngine: RiskEngine,
    private val tokenTtlSeconds: Long = 300,
    private val timestampWindowMillis: Long = 120_000,
    private val issuer: String = "curator-antibot",
    private val clock: () -> Long = System::currentTimeMillis,
) {
    public fun attest(env: SealedEnvelope): AttestationResponse {
        // 1) Nonce must be valid and unused (anti-replay). Consume atomically.
        when (val consumed = nonceStore.consume(env.nonce)) {
            is NonceStore.ConsumeResult.Rejected ->
                return deny(consumed.reason)
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

        // 4) Risk scoring.
        val assessment = riskEngine.assess(payload)

        // 5) Decision -> token.
        return when (assessment.decision) {
            Decision.DENY -> AttestationResponse(
                decision = Decision.DENY,
                riskLevel = assessment.level,
                reasonCodes = assessment.reasons,
                shadow = assessment.shadowed,
            )
            Decision.CHALLENGE -> AttestationResponse(
                decision = Decision.CHALLENGE,
                riskLevel = assessment.level,
                reasonCodes = assessment.reasons,
                shadow = assessment.shadowed,
            )
            Decision.ALLOW -> {
                val nowSec = now / 1000
                val subject = subjectFor(payload.clientIdPublicKey)
                val claims = TrustTokenClaims(
                    sub = subject,
                    iss = issuer,
                    iat = nowSec,
                    exp = nowSec + tokenTtlSeconds,
                    lvl = assessment.level,
                    jti = UUID.randomUUID().toString(),
                )
                val token = TrustToken.issue(claims, serverKeys.private)
                AttestationResponse(
                    decision = Decision.ALLOW,
                    riskLevel = assessment.level,
                    reasonCodes = assessment.reasons,
                    trustToken = token,
                    ttlSeconds = tokenTtlSeconds,
                    shadow = assessment.shadowed,
                )
            }
        }
    }

    /** Stateless verification for the application backend (or a demo protected route). */
    public fun verify(token: String): VerifyResponse =
        when (val r = TrustToken.verify(token, serverKeys.public, clock() / 1000)) {
            is TrustToken.VerifyResult.Valid -> VerifyResponse(true, ReasonCode.OK, r.claims)
            is TrustToken.VerifyResult.Invalid -> VerifyResponse(false, r.reason)
        }

    private fun subjectFor(clientPubEncoded: String): String =
        pro.curator.antibot.protocol.CryptoPrimitives
            .sha256Hex(clientPubEncoded.toByteArray()).take(24)

    private fun deny(reason: ReasonCode) = AttestationResponse(
        decision = Decision.DENY,
        riskLevel = RiskLevel.HIGH,
        reasonCodes = listOf(reason),
    )
}
