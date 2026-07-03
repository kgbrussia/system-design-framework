package pro.curator.antibot.sdk.android

import android.content.Context
import okhttp3.Interceptor
import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.sdk.AntiBotClient
import pro.curator.antibot.sdk.AntiBotConfig
import pro.curator.antibot.sdk.FailureMode
import pro.curator.antibot.sdk.FeatureFlags
import pro.curator.antibot.sdk.TokenResult

/**
 * The single public entry point for Android hosts (guide §5.5).
 *
 * Usage:
 * ```
 * AntiBot.init(
 *     context,
 *     AntiBot.config(siteKey = "…", baseUrl = "https://api.curator.pro", serverPublicKeyBase64Url = "…")
 *         .failureMode(FailureMode.FAIL_OPEN)
 *         .build(),
 * )
 * val client = OkHttpClient.Builder().addInterceptor(AntiBot.interceptor()).build()
 * ```
 *
 * init() is idempotent and takes the applicationContext to avoid leaks (guide §4.2).
 */
public object AntiBot {

    @Volatile private var client: AntiBotClient? = null

    /** Builder pre-filled with an Android Context is created via [init]; this is a convenience for the server key. */
    public fun config(
        siteKey: String,
        baseUrl: String,
        serverPublicKeyBase64Url: String,
    ): AntiBotConfig.Builder =
        AntiBotConfig.Builder(siteKey, baseUrl, CryptoPrimitives.decodePublicKey(serverPublicKeyBase64Url))

    /** Idempotent initialization. Safe to call more than once. */
    @Synchronized
    public fun init(context: Context, config: AntiBotConfig) {
        if (client != null) return
        val appContext = context.applicationContext
        val built = AntiBotClient(
            config = config,
            telemetryProvider = AndroidTelemetryProvider(appContext),
            integrityProvider = AndroidIntegrityProvider(
                context = appContext,
                cloudProjectNumber = null, // configure with your Google Cloud project number
                playIntegrityEnabled = config.featureFlags.playIntegrity,
            ),
            clientKeyProvider = KeystoreClientKeyProvider(),
            challengeSolver = AndroidWebViewChallengeSolver(appContext),
            tokenStorage = EncryptedTokenStorage(appContext),
        )
        client = built
        built.warmUp() // start the bootstrap flow so a token is ready ASAP
    }

    public suspend fun getToken(): TokenResult =
        client?.getToken()
            ?: TokenResult.Failure(pro.curator.antibot.protocol.ReasonCode.SDK_NOT_INITIALIZED, retryable = false)

    /** The OkHttp interceptor for one-line integration into the host's network stack. */
    public fun interceptor(): Interceptor =
        requireNotNull(client) { "AntiBot.init(...) must be called before interceptor()" }.interceptor()

    public fun invalidateToken() { client?.invalidateToken() }

    public fun isInitialized(): Boolean = client != null

    // Re-export common enums so hosts don't need to import sdk-core directly.
    public val FAIL_OPEN: FailureMode = FailureMode.FAIL_OPEN
    public val FAIL_CLOSED: FailureMode = FailureMode.FAIL_CLOSED

    public fun defaultFeatureFlags(): FeatureFlags = FeatureFlags()
}
