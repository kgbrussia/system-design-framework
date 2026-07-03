package pro.curator.antibot.sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import pro.curator.antibot.protocol.AntiBotJson
import pro.curator.antibot.protocol.AttestationResponse
import pro.curator.antibot.protocol.ChallengeSolution
import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopeCrypto
import pro.curator.antibot.protocol.EnvelopePayload
import pro.curator.antibot.protocol.NonceRequest
import pro.curator.antibot.protocol.NonceResponse
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.protocol.SealedEnvelope
import java.util.concurrent.TimeUnit
import kotlinx.serialization.encodeToString

/**
 * Runs the bootstrap flow (guide §9): nonce -> telemetry+integrity -> sealed
 * envelope -> attestation -> trust token.
 *
 * Uses its OWN OkHttp client, deliberately WITHOUT the AntiBotInterceptor, so
 * SDK's own calls never recurse through the interceptor (guide §7.4).
 */
public class AttestationClient(
    private val config: AntiBotConfig,
    private val telemetryProvider: TelemetryProvider,
    private val integrityProvider: IntegrityProvider,
    private val clientKeyProvider: ClientKeyProvider,
    private val challengeSolver: WebViewChallengeSolver = NoWebViewChallengeSolver,
    private val clock: Clock = SystemClock,
    private val logger: Logger = Logger(config.debug),
    httpClient: OkHttpClient? = null,
) {
    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    private val http: OkHttpClient = httpClient ?: OkHttpClient.Builder()
        .connectTimeout(config.requestTimeoutMillis, TimeUnit.MILLISECONDS)
        .readTimeout(config.requestTimeoutMillis, TimeUnit.MILLISECONDS)
        .writeTimeout(config.requestTimeoutMillis, TimeUnit.MILLISECONDS)
        .retryOnConnectionFailure(true)
        .build()

    public sealed interface Outcome {
        public data class Token(val value: String, val ttlSeconds: Long) : Outcome
        public data class Rejected(val reason: ReasonCode) : Outcome
        public data class Error(val reason: ReasonCode, val retryable: Boolean) : Outcome
    }

    public suspend fun obtainToken(): Outcome = withContext(Dispatchers.IO) {
        try {
            // Step 1: bootstrap nonce
            val telemetry = if (config.featureFlags.collectTelemetry) {
                telemetryProvider.collect()
            } else {
                telemetryProvider.collect() // telemetry is always needed to identify the app
            }
            val nonceResp = requestNonce(telemetry.packageName)
                ?: return@withContext Outcome.Error(ReasonCode.NETWORK_ERROR, retryable = true)

            if (nonceResp.protocolVersion != Protocol.VERSION) {
                return@withContext Outcome.Rejected(ReasonCode.PROTOCOL_MISMATCH)
            }

            // Steps 2-3: telemetry + integrity, bound to the nonce
            val integrity = if (config.featureFlags.runIntegrityChecks) {
                integrityProvider.verdict(nonceResp.nonce)
            } else {
                pro.curator.antibot.protocol.IntegrityVerdict(
                    rooted = false, emulator = false, debuggerAttached = false,
                    hookingDetected = false, playServicesAvailable = false,
                )
            }

            // Step 4: protected envelope
            val identity = clientKeyProvider.identityKeyPair()
            val payload = EnvelopePayload(
                nonce = nonceResp.nonce,
                timestamp = clock.nowMillis(),
                clientIdPublicKey = pro.curator.antibot.protocol.CryptoPrimitives
                    .encodePublicKey(identity.public),
                telemetry = telemetry,
                integrity = integrity,
            )
            val envelope = EnvelopeCrypto.seal(
                payload = payload,
                serverPublicKey = config.serverPublicKey,
                clientIdentityPrivateKey = identity.private,
                clientIdentityPublicKey = identity.public,
            )

            // Steps 5-7: attestation
            val attestation = postAttest(envelope)
                ?: return@withContext Outcome.Error(ReasonCode.NETWORK_ERROR, retryable = true)

            interpret(attestation)
        } catch (e: Exception) {
            logger.e("attestation flow failed", e)
            Outcome.Error(ReasonCode.NETWORK_ERROR, retryable = true)
        }
    }

    private suspend fun interpret(attestation: AttestationResponse): Outcome =
        when (attestation.decision) {
            Decision.ALLOW -> {
                val token = attestation.trustToken
                if (token.isNullOrBlank()) {
                    Outcome.Error(ReasonCode.ATTESTATION_FAILED, retryable = true)
                } else {
                    logger.d("attestation ALLOW, ttl=${attestation.ttlSeconds}s")
                    Outcome.Token(token, attestation.ttlSeconds)
                }
            }
            Decision.CHALLENGE -> handleChallenge(attestation)
            Decision.DENY -> {
                logger.d("attestation DENY: ${attestation.reasonCodes}")
                Outcome.Rejected(attestation.reasonCodes.firstOrNull() ?: ReasonCode.ATTESTATION_FAILED)
            }
        }

    /** Step-up: solve the WebView challenge and re-submit for a token (guide §14). */
    private suspend fun handleChallenge(attestation: AttestationResponse): Outcome {
        val challenge = attestation.challenge
        if (!config.featureFlags.webViewChallenge || challenge == null) {
            logger.d("challenge required but disabled/absent")
            return Outcome.Rejected(ReasonCode.CHALLENGE_REQUIRED)
        }
        logger.d("solving WebView challenge ${challenge.challengeId}")
        return when (val solved = challengeSolver.solve(challenge, config.baseUrl)) {
            is ChallengeResult.Failed -> Outcome.Rejected(solved.reason)
            is ChallengeResult.Solved -> {
                val identity = clientKeyProvider.identityKeyPair()
                val solution = ChallengeSolution(
                    challengeId = challenge.challengeId,
                    answer = solved.answer,
                    clientIdPublicKey = pro.curator.antibot.protocol.CryptoPrimitives
                        .encodePublicKey(identity.public),
                )
                val verifyResp = postChallengeVerify(solution)
                    ?: return Outcome.Error(ReasonCode.NETWORK_ERROR, retryable = true)
                // The verify response is a normal AttestationResponse (ALLOW/DENY),
                // never another CHALLENGE — interpret without recursing further.
                when (verifyResp.decision) {
                    Decision.ALLOW -> verifyResp.trustToken
                        ?.let { Outcome.Token(it, verifyResp.ttlSeconds) }
                        ?: Outcome.Error(ReasonCode.ATTESTATION_FAILED, retryable = true)
                    else -> Outcome.Rejected(verifyResp.reasonCodes.firstOrNull() ?: ReasonCode.CHALLENGE_FAILED)
                }
            }
        }
    }

    private fun requestNonce(packageName: String): NonceResponse? {
        val body = AntiBotJson.encodeToString(NonceRequest(BuildInfo.SDK_VERSION, packageName))
            .toRequestBody(jsonMedia)
        val request = Request.Builder()
            .url(config.baseUrl + Protocol.PATH_NONCE)
            .post(body)
            .build()
        http.newCall(request).execute().use { resp ->
            if (!resp.isSuccessful) return null
            val text = resp.body?.string() ?: return null
            return AntiBotJson.decodeFromString<NonceResponse>(text)
        }
    }

    private fun postAttest(envelope: SealedEnvelope): AttestationResponse? {
        val body = AntiBotJson.encodeToString(envelope).toRequestBody(jsonMedia)
        val request = Request.Builder()
            .url(config.baseUrl + Protocol.PATH_ATTEST)
            .header(Protocol.PROTOCOL_VERSION_HEADER, Protocol.VERSION.toString())
            .post(body)
            .build()
        http.newCall(request).execute().use { resp ->
            val text = resp.body?.string() ?: return null
            if (!resp.isSuccessful && resp.code != 200) {
                // The server returns a structured AttestationResponse even for DENY (200).
                return runCatching { AntiBotJson.decodeFromString<AttestationResponse>(text) }.getOrNull()
            }
            return AntiBotJson.decodeFromString<AttestationResponse>(text)
        }
    }

    private fun postChallengeVerify(solution: ChallengeSolution): AttestationResponse? {
        val body = AntiBotJson.encodeToString(solution).toRequestBody(jsonMedia)
        val request = Request.Builder()
            .url(config.baseUrl + Protocol.PATH_CHALLENGE_VERIFY)
            .post(body)
            .build()
        http.newCall(request).execute().use { resp ->
            val text = resp.body?.string() ?: return null
            return runCatching { AntiBotJson.decodeFromString<AttestationResponse>(text) }.getOrNull()
        }
    }
}

/** Tiny logger; silent unless debug mode is on (guide §15.5 — no chatty release logs). */
public class Logger(private val enabled: Boolean) {
    public fun d(message: String) { if (enabled) println("[AntiBot] $message") }
    public fun e(message: String, t: Throwable? = null) {
        if (enabled) { println("[AntiBot][E] $message"); t?.printStackTrace() }
    }
}

public object BuildInfo {
    public const val SDK_VERSION: String = "1.0.0"
}
