package pro.curator.antibot.server

import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.ReasonCode
import java.util.concurrent.ConcurrentHashMap

/**
 * Single-use nonce store — the backbone of replay protection (guide §8.8).
 *
 * A nonce is:
 *   - random and server-issued,
 *   - valid only for a short window,
 *   - accepted exactly ONCE (consume() removes it),
 * so a captured envelope can never be replayed.
 *
 * In-memory here for the demo; in production this is a shared TTL store (Redis).
 */
public class NonceStore(
    private val ttlMillis: Long = 60_000,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private data class Entry(val expiresAt: Long)

    private val entries = ConcurrentHashMap<String, Entry>()

    public fun issue(): Pair<String, Long> {
        purgeExpired()
        val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(32))
        val now = clock()
        val expiresAt = now + ttlMillis
        entries[nonce] = Entry(expiresAt)
        return nonce to expiresAt
    }

    public sealed interface ConsumeResult {
        public data object Ok : ConsumeResult
        public data class Rejected(val reason: ReasonCode) : ConsumeResult
    }

    /** Validates and atomically consumes the nonce (one-time use). */
    public fun consume(nonce: String): ConsumeResult {
        val entry = entries.remove(nonce)
            ?: return ConsumeResult.Rejected(ReasonCode.NONCE_UNKNOWN) // unknown or already used
        return if (clock() >= entry.expiresAt) {
            ConsumeResult.Rejected(ReasonCode.NONCE_EXPIRED)
        } else {
            ConsumeResult.Ok
        }
    }

    public fun size(): Int = entries.size

    private fun purgeExpired() {
        val now = clock()
        entries.entries.removeIf { it.value.expiresAt <= now }
    }
}
