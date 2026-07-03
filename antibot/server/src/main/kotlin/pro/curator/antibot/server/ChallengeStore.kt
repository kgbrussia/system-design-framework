package pro.curator.antibot.server

import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.ReasonCode
import java.util.concurrent.ConcurrentHashMap

/**
 * Stores issued WebView challenges (guide §14). Like the nonce store, each
 * challenge is single-use with a short TTL, and it is bound to the client
 * identity key that triggered it (so a solution can't be reused by another client).
 */
public class ChallengeStore(
    private val ttlMillis: Long = 120_000,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    public data class Issued(
        val challengeId: String,
        val challengeNonce: String,
        val expiresAt: Long,
    )

    private data class Entry(
        val challengeNonce: String,
        val clientIdPublicKey: String,
        val expiresAt: Long,
    )

    private val entries = ConcurrentHashMap<String, Entry>()

    public fun issue(clientIdPublicKey: String): Issued {
        purgeExpired()
        val id = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(16))
        val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(16))
        val expiresAt = clock() + ttlMillis
        entries[id] = Entry(nonce, clientIdPublicKey, expiresAt)
        return Issued(id, nonce, expiresAt)
    }

    public sealed interface ConsumeResult {
        public data class Ok(val challengeNonce: String) : ConsumeResult
        public data class Rejected(val reason: ReasonCode) : ConsumeResult
    }

    /** Validates and consumes a challenge for the given client (one-time use). */
    public fun consume(challengeId: String, clientIdPublicKey: String): ConsumeResult {
        val entry = entries.remove(challengeId)
            ?: return ConsumeResult.Rejected(ReasonCode.CHALLENGE_FAILED)
        if (clock() >= entry.expiresAt) return ConsumeResult.Rejected(ReasonCode.CHALLENGE_EXPIRED)
        if (entry.clientIdPublicKey != clientIdPublicKey) {
            return ConsumeResult.Rejected(ReasonCode.CHALLENGE_FAILED)
        }
        return ConsumeResult.Ok(entry.challengeNonce)
    }

    public fun size(): Int = entries.size

    private fun purgeExpired() {
        val now = clock()
        entries.entries.removeIf { it.value.expiresAt <= now }
    }
}
