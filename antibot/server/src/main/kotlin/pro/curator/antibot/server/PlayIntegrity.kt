package pro.curator.antibot.server

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import pro.curator.antibot.protocol.AntiBotJson
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Full server-side Play Integrity verification (guide §11).
 *
 * The ONLY thing left as a pluggable stub is the credentials/configuration:
 * obtaining the Google OAuth access token for the service account is behind
 * [AccessTokenProvider]. Everything else — the real HTTP call to
 * `decodeIntegrityToken`, verdict parsing, nonce binding — is implemented.
 *
 * Enabled/disabled via a feature flag on the server (RiskEngine.RiskConfig).
 */

public enum class PlayIntegrityStatus { PASSED, FAILED, UNAVAILABLE }

public data class PlayIntegrityAssessment(
    val status: PlayIntegrityStatus,
    val appVerdict: String? = null,
    val deviceVerdicts: List<String> = emptyList(),
    val licensingVerdict: String? = null,
    val note: String? = null,
)

/**
 * The stubbed configuration point. A production deployment supplies a provider
 * that mints a short-lived OAuth2 access token from a Google service account
 * (scope https://www.googleapis.com/auth/playintegrity).
 */
public fun interface AccessTokenProvider {
    public suspend fun accessToken(): String?
}

/** Default: no credentials configured -> Play Integrity gracefully unavailable. */
public object StubAccessTokenProvider : AccessTokenProvider {
    override suspend fun accessToken(): String? = null
}

/** Inject a pre-obtained token (tests, or an external token minter). */
public class StaticAccessTokenProvider(private val token: String) : AccessTokenProvider {
    override suspend fun accessToken(): String = token
}

public interface PlayIntegrityVerifier {
    public suspend fun verify(token: String, expectedNonce: String, packageName: String): PlayIntegrityAssessment
}

/** Used when the feature flag is off. */
public object DisabledPlayIntegrityVerifier : PlayIntegrityVerifier {
    override suspend fun verify(token: String, expectedNonce: String, packageName: String): PlayIntegrityAssessment =
        PlayIntegrityAssessment(PlayIntegrityStatus.UNAVAILABLE, note = "play-integrity-disabled")
}

public class GooglePlayIntegrityVerifier(
    private val accessTokenProvider: AccessTokenProvider = StubAccessTokenProvider,
    private val apiBaseUrl: String = "https://playintegrity.googleapis.com",
    private val httpClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build(),
) : PlayIntegrityVerifier {

    override suspend fun verify(
        token: String,
        expectedNonce: String,
        packageName: String,
    ): PlayIntegrityAssessment = withContext(Dispatchers.IO) {
        val accessToken = accessTokenProvider.accessToken()
            ?: return@withContext PlayIntegrityAssessment(
                PlayIntegrityStatus.UNAVAILABLE, note = "no-credentials-configured",
            )

        try {
            val url = "$apiBaseUrl/v1/$packageName:decodeIntegrityToken"
            val body = AntiBotJson.encodeToString(DecodeRequest(token))
            val request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(8))
                .header("Authorization", "Bearer $accessToken")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() !in 200..299) {
                return@withContext PlayIntegrityAssessment(
                    PlayIntegrityStatus.UNAVAILABLE, note = "http-${response.statusCode()}",
                )
            }

            val decoded = AntiBotJson.decodeFromString<DecodeResponse>(response.body())
            evaluate(decoded, expectedNonce, packageName)
        } catch (e: Exception) {
            PlayIntegrityAssessment(PlayIntegrityStatus.UNAVAILABLE, note = "error:${e.javaClass.simpleName}")
        }
    }

    private fun evaluate(
        decoded: DecodeResponse,
        expectedNonce: String,
        packageName: String,
    ): PlayIntegrityAssessment {
        val payload = decoded.tokenPayloadExternal
            ?: return PlayIntegrityAssessment(PlayIntegrityStatus.FAILED, note = "empty-payload")

        val request = payload.requestDetails
        // Bind the verdict to OUR nonce (anti-replay) and package.
        if (request?.nonce != expectedNonce) {
            return PlayIntegrityAssessment(PlayIntegrityStatus.FAILED, note = "nonce-mismatch")
        }
        if (request.requestPackageName != null && request.requestPackageName != packageName) {
            return PlayIntegrityAssessment(PlayIntegrityStatus.FAILED, note = "package-mismatch")
        }

        val appVerdict = payload.appIntegrity?.appRecognitionVerdict
        val deviceVerdicts = payload.deviceIntegrity?.deviceRecognitionVerdict ?: emptyList()
        val licensing = payload.accountDetails?.appLicensingVerdict

        val appOk = appVerdict == "PLAY_RECOGNIZED"
        val deviceOk = deviceVerdicts.any {
            it == "MEETS_DEVICE_INTEGRITY" || it == "MEETS_STRONG_INTEGRITY"
        }

        val status = if (appOk && deviceOk) PlayIntegrityStatus.PASSED else PlayIntegrityStatus.FAILED
        return PlayIntegrityAssessment(
            status = status,
            appVerdict = appVerdict,
            deviceVerdicts = deviceVerdicts,
            licensingVerdict = licensing,
            note = if (status == PlayIntegrityStatus.PASSED) "ok" else "weak-verdict",
        )
    }

    // ---- Google decodeIntegrityToken request/response models ----

    @Serializable
    private data class DecodeRequest(
        @SerialName("integrity_token") val integrityToken: String,
    )

    @Serializable
    private data class DecodeResponse(
        val tokenPayloadExternal: TokenPayloadExternal? = null,
    )

    @Serializable
    private data class TokenPayloadExternal(
        val requestDetails: RequestDetails? = null,
        val appIntegrity: AppIntegrity? = null,
        val deviceIntegrity: DeviceIntegrity? = null,
        val accountDetails: AccountDetails? = null,
    )

    @Serializable
    private data class RequestDetails(
        val requestPackageName: String? = null,
        val nonce: String? = null,
        val timestampMillis: String? = null,
    )

    @Serializable
    private data class AppIntegrity(
        val appRecognitionVerdict: String? = null,
        val packageName: String? = null,
        val versionCode: String? = null,
    )

    @Serializable
    private data class DeviceIntegrity(
        val deviceRecognitionVerdict: List<String> = emptyList(),
    )

    @Serializable
    private data class AccountDetails(
        val appLicensingVerdict: String? = null,
    )
}
