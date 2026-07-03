package pro.curator.antibot.sdk

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import okhttp3.Interceptor
import pro.curator.antibot.protocol.CryptoPrimitives
import java.security.KeyPair

/**
 * Platform-agnostic facade wiring the pieces together. The Android layer builds
 * one of these from a `Context` and exposes the `AntiBot` singleton on top.
 */
public class AntiBotClient(
    private val config: AntiBotConfig,
    telemetryProvider: TelemetryProvider,
    integrityProvider: IntegrityProvider,
    clientKeyProvider: ClientKeyProvider,
    tokenStorage: TokenStorage = InMemoryTokenStorage(),
    clock: Clock = SystemClock,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    private val logger = Logger(config.debug)

    private val attestationClient = AttestationClient(
        config = config,
        telemetryProvider = telemetryProvider,
        integrityProvider = integrityProvider,
        clientKeyProvider = clientKeyProvider,
        clock = clock,
        logger = logger,
    )

    private val tokenManager = TokenManager(
        client = attestationClient,
        config = config,
        storage = tokenStorage,
        clock = clock,
        logger = logger,
    )

    /** Kick off the bootstrap flow early (call from init) so a token is ready. */
    public fun warmUp() {
        scope.launch { tokenManager.getToken() }
    }

    /** Suspend accessor for a token (guide API §5.5). */
    public suspend fun getToken(): TokenResult = tokenManager.getToken()

    /** The OkHttp interceptor the host adds to its client — one-line integration. */
    public fun interceptor(): Interceptor = AntiBotInterceptor(tokenManager, config, scope, logger)

    public fun invalidateToken(): Unit = tokenManager.invalidate()
}

/**
 * Simple JVM client-key provider (ephemeral EC key in memory). On Android this is
 * replaced by a Keystore-backed provider so the private key never leaves the TEE.
 */
public class JvmClientKeyProvider(
    private val keyPair: KeyPair = CryptoPrimitives.generateEcKeyPair(),
) : ClientKeyProvider {
    override fun identityKeyPair(): KeyPair = keyPair
}
