package pro.curator.antibot.sdk

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import pro.curator.antibot.protocol.ReasonCode
import kotlin.math.pow
import kotlin.random.Random

/**
 * Owns the trust token lifecycle (guide §13): cache, proactive refresh,
 * single-flight refresh, and exponential backoff with jitter.
 */
public class TokenManager(
    private val client: AttestationClient,
    private val config: AntiBotConfig,
    private val storage: TokenStorage = InMemoryTokenStorage(),
    private val clock: Clock = SystemClock,
    private val logger: Logger = Logger(config.debug),
) {
    private val refreshMutex = Mutex()

    private fun cached(): StoredToken? = storage.load()

    private fun StoredToken.isFresh(now: Long): Boolean = now < expiresAtMillis
    private fun StoredToken.needsProactiveRefresh(now: Long): Boolean =
        now >= (expiresAtMillis - config.refreshSkewMillis)

    /** Non-blocking peek used by the interceptor's fast path. */
    public fun cachedTokenOrNull(): String? {
        val t = cached() ?: return null
        return if (t.isFresh(clock.nowMillis())) t.value else null
    }

    public fun invalidate() {
        logger.d("token invalidated")
        storage.clear()
    }

    /**
     * Returns a usable token, refreshing if missing or near expiry. Single-flight:
     * concurrent callers coalesce onto one refresh instead of stampeding the server.
     */
    public suspend fun getToken(): TokenResult {
        val now = clock.nowMillis()
        val current = cached()
        if (current != null && current.isFresh(now) && !current.needsProactiveRefresh(now)) {
            return TokenResult.Success(current.value, current.expiresAtMillis)
        }

        return refreshMutex.withLock {
            // Re-check inside the lock: another caller may have just refreshed.
            val fresh = cached()
            val nowInner = clock.nowMillis()
            if (fresh != null && fresh.isFresh(nowInner) && !fresh.needsProactiveRefresh(nowInner)) {
                return@withLock TokenResult.Success(fresh.value, fresh.expiresAtMillis)
            }
            refreshWithBackoff()
        }
    }

    /** Force a refresh (e.g. after a 401). Also single-flight. */
    public suspend fun forceRefresh(): TokenResult = refreshMutex.withLock { refreshWithBackoff() }

    private suspend fun refreshWithBackoff(): TokenResult {
        var attempt = 0
        var lastReason = ReasonCode.UNKNOWN
        while (attempt <= config.maxRetries) {
            when (val outcome = client.obtainToken()) {
                is AttestationClient.Outcome.Token -> {
                    val expiresAt = clock.nowMillis() + outcome.ttlSeconds * 1000
                    storage.save(StoredToken(outcome.value, expiresAt))
                    return TokenResult.Success(outcome.value, expiresAt)
                }
                is AttestationClient.Outcome.Rejected -> {
                    // A verdict (DENY/CHALLENGE) is not a transient error — do not retry-hammer.
                    invalidate()
                    return TokenResult.Failure(outcome.reason, retryable = false)
                }
                is AttestationClient.Outcome.Error -> {
                    lastReason = outcome.reason
                    if (!outcome.retryable || attempt == config.maxRetries) {
                        return TokenResult.Failure(outcome.reason, retryable = outcome.retryable)
                    }
                    val backoff = backoffMillis(attempt)
                    logger.d("refresh attempt ${attempt + 1} failed, backing off ${backoff}ms")
                    delay(backoff)
                    attempt++
                }
            }
        }
        return TokenResult.Failure(lastReason, retryable = true)
    }

    /** Exponential backoff with full jitter (guide §13.3). */
    private fun backoffMillis(attempt: Int): Long {
        val base = (500.0 * 2.0.pow(attempt)).toLong().coerceAtMost(8_000)
        return Random.nextLong(0, base + 1)
    }
}
