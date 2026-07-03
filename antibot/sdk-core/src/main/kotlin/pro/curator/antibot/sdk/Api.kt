package pro.curator.antibot.sdk

import pro.curator.antibot.protocol.IntegrityVerdict
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.protocol.Telemetry
import java.security.KeyPair
import java.security.PublicKey

/**
 * Platform-agnostic public API of the SDK core.
 *
 * The Android layer (`sdk-android`) supplies the platform pieces via these
 * interfaces and exposes a friendly `AntiBot` facade; everything here is pure
 * Kotlin so it unit-tests on the JVM (guide §21.1).
 */

/** What to do when a trust token cannot be obtained (guide §15.2). */
public enum class FailureMode {
    /** Let the request through without a token (don't block real users on our outages). */
    FAIL_OPEN,

    /** Hold the request back when there is no token (favor security). */
    FAIL_CLOSED,
}

/** Result of asking the SDK for a trust token. */
public sealed interface TokenResult {
    public data class Success(val token: String, val expiresAtMillis: Long) : TokenResult
    public data class Failure(val reason: ReasonCode, val retryable: Boolean) : TokenResult
}

/** Immutable configuration, built with [Builder] so options can grow without breaking callers. */
public class AntiBotConfig private constructor(
    public val siteKey: String,
    public val baseUrl: String,
    public val serverPublicKey: PublicKey,
    public val requestTimeoutMillis: Long,
    public val failureMode: FailureMode,
    public val refreshSkewMillis: Long,
    public val interceptorWaitMillis: Long,
    public val maxRetries: Int,
    public val debug: Boolean,
    public val featureFlags: FeatureFlags,
) {
    public class Builder(
        private val siteKey: String,
        private val baseUrl: String,
        private val serverPublicKey: PublicKey,
    ) {
        private var requestTimeoutMillis: Long = 8_000
        private var failureMode: FailureMode = FailureMode.FAIL_OPEN
        private var refreshSkewMillis: Long = 60_000 // refresh 1 min before expiry
        private var interceptorWaitMillis: Long = 1_500
        private var maxRetries: Int = 3
        private var debug: Boolean = false
        private var featureFlags: FeatureFlags = FeatureFlags()

        public fun requestTimeoutMillis(value: Long): Builder = apply { requestTimeoutMillis = value }
        public fun failureMode(value: FailureMode): Builder = apply { failureMode = value }
        public fun refreshSkewMillis(value: Long): Builder = apply { refreshSkewMillis = value }
        public fun interceptorWaitMillis(value: Long): Builder = apply { interceptorWaitMillis = value }
        public fun maxRetries(value: Int): Builder = apply { maxRetries = value }
        public fun debug(value: Boolean): Builder = apply { debug = value }
        public fun featureFlags(value: FeatureFlags): Builder = apply { featureFlags = value }

        public fun build(): AntiBotConfig = AntiBotConfig(
            siteKey = siteKey,
            baseUrl = baseUrl.trimEnd('/'),
            serverPublicKey = serverPublicKey,
            requestTimeoutMillis = requestTimeoutMillis,
            failureMode = failureMode,
            refreshSkewMillis = refreshSkewMillis,
            interceptorWaitMillis = interceptorWaitMillis,
            maxRetries = maxRetries,
            debug = debug,
            featureFlags = featureFlags,
        )
    }
}

/** Remotely-controllable toggles (guide §15.6). In production these come from the server. */
public data class FeatureFlags(
    val collectTelemetry: Boolean = true,
    val runIntegrityChecks: Boolean = true,
    val attachTokenHeader: Boolean = true,
)

// ---- Provider interfaces implemented by the Android layer (or fakes in tests) ----

/** Collects compact telemetry (guide §10). */
public fun interface TelemetryProvider {
    public fun collect(): Telemetry
}

/** Runs local detectors + Play Integrity, bound to the given nonce (guide §11-12). */
public fun interface IntegrityProvider {
    public suspend fun verdict(nonce: String): IntegrityVerdict
}

/**
 * Supplies the client's long-term identity key pair used to sign envelopes.
 * On Android this is Keystore-backed (the private key never leaves the TEE);
 * the [KeyPair] simply carries a handle to it (guide §13.2).
 */
public fun interface ClientKeyProvider {
    public fun identityKeyPair(): KeyPair
}

/** Persists the short-lived trust token (guide §13). */
public interface TokenStorage {
    public fun load(): StoredToken?
    public fun save(token: StoredToken)
    public fun clear()
}

public data class StoredToken(val value: String, val expiresAtMillis: Long)

/** Injectable clock for deterministic tests of TTL / refresh. */
public fun interface Clock {
    public fun nowMillis(): Long
}

public object SystemClock : Clock {
    override fun nowMillis(): Long = System.currentTimeMillis()
}

/** In-memory token storage; the default for the short-lived token (guide §13.2). */
public class InMemoryTokenStorage : TokenStorage {
    @Volatile private var token: StoredToken? = null
    override fun load(): StoredToken? = token
    override fun save(token: StoredToken) { this.token = token }
    override fun clear() { token = null }
}
