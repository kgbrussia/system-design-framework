package pro.curator.antibot.sdk

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import pro.curator.antibot.protocol.AntiBotJson
import pro.curator.antibot.protocol.AttestationResponse
import pro.curator.antibot.protocol.Challenge
import pro.curator.antibot.protocol.ChallengeCrypto
import pro.curator.antibot.protocol.ChallengeSolution
import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.NonceResponse
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.protocol.RiskLevel
import pro.curator.antibot.protocol.Telemetry
import pro.curator.antibot.protocol.TrustToken
import pro.curator.antibot.protocol.TrustTokenClaims
import java.security.KeyPair
import java.util.UUID

/**
 * Verifies the SDK-side WebView challenge path: server asks for a CHALLENGE, the
 * (faked) WebView solver produces the answer, the SDK re-submits and gets a token.
 */
class SdkChallengeTest {

    private lateinit var server: MockWebServer
    private val serverKeys: KeyPair = CryptoPrimitives.generateEcKeyPair()

    private val telemetryProvider = TelemetryProvider {
        Telemetry(
            packageName = "com.example.host", appVersionName = "1.0.0", appVersionCode = 1,
            signingCertSha256 = "cd".repeat(32), sdkVersion = "1.0.0", osSdkInt = 34, osRelease = "14",
            deviceModel = "Pixel", deviceManufacturer = "Google", deviceBrand = "google",
            buildFingerprint = "fp", hardware = "hw", locale = "ru_RU", timeZone = "UTC", debuggable = false,
        )
    }
    private val integrityProvider = IntegrityProvider { _ ->
        pro.curator.antibot.protocol.IntegrityVerdict(false, true, true, false, true)
    }

    /** Fake solver: computes the same answer the real WebView JS would. */
    private val fakeSolver = WebViewChallengeSolver { challenge: Challenge, _ ->
        ChallengeResult.Solved(ChallengeCrypto.expectedAnswer(challenge.challengeId, challenge.challengeNonce))
    }

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when (request.path) {
                Protocol.PATH_NONCE -> {
                    val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(32))
                    MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                        .setBody(AntiBotJson.encodeToString(
                            NonceResponse(nonce, System.currentTimeMillis(), System.currentTimeMillis() + 60_000),
                        ))
                }
                Protocol.PATH_ATTEST -> {
                    // Always ask for a challenge.
                    val cid = "cid-1"
                    val cnonce = "cnonce-1"
                    val resp = AttestationResponse(
                        decision = Decision.CHALLENGE,
                        riskLevel = RiskLevel.MEDIUM,
                        reasonCodes = listOf(ReasonCode.CHALLENGE_REQUIRED),
                        challenge = Challenge(cid, cnonce, "${Protocol.PATH_CHALLENGE_PAGE}?cid=$cid&n=$cnonce",
                            System.currentTimeMillis() + 120_000),
                    )
                    MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                        .setBody(AntiBotJson.encodeToString(resp))
                }
                Protocol.PATH_CHALLENGE_VERIFY -> {
                    val solution = AntiBotJson.decodeFromString<ChallengeSolution>(request.body.readUtf8())
                    val expected = ChallengeCrypto.expectedAnswer(solution.challengeId, "cnonce-1")
                    val resp = if (solution.answer == expected) {
                        val now = System.currentTimeMillis() / 1000
                        val token = TrustToken.issue(
                            TrustTokenClaims("sub", "curator", now, now + 300, RiskLevel.MEDIUM, UUID.randomUUID().toString()),
                            serverKeys.private,
                        )
                        AttestationResponse(Decision.ALLOW, RiskLevel.MEDIUM, listOf(ReasonCode.OK), token, 300)
                    } else {
                        AttestationResponse(Decision.DENY, RiskLevel.HIGH, listOf(ReasonCode.CHALLENGE_FAILED))
                    }
                    MockResponse().setResponseCode(200).addHeader("Content-Type", "application/json")
                        .setBody(AntiBotJson.encodeToString(resp))
                }
                else -> MockResponse().setResponseCode(404)
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() { server.shutdown() }

    private fun client(solver: WebViewChallengeSolver, flags: FeatureFlags = FeatureFlags()): AntiBotClient {
        val config = AntiBotConfig.Builder("test", server.url("/").toString(), serverKeys.public)
            .debug(true).featureFlags(flags).build()
        return AntiBotClient(config, telemetryProvider, integrityProvider, JvmClientKeyProvider(), solver)
    }

    @Test
    fun `challenge is solved via the solver and a token is issued`() = runBlocking {
        val result = client(fakeSolver).getToken()
        assertInstanceOf(TokenResult.Success::class.java, result)
    }

    @Test
    fun `no solver means challenge cannot be satisfied`() = runBlocking {
        val result = client(NoWebViewChallengeSolver).getToken()
        assertInstanceOf(TokenResult.Failure::class.java, result)
    }

    @Test
    fun `challenge disabled by feature flag is not attempted`() = runBlocking {
        val result = client(fakeSolver, FeatureFlags(webViewChallenge = false)).getToken()
        val failure = assertInstanceOf(TokenResult.Failure::class.java, result)
        assertEquals(ReasonCode.CHALLENGE_REQUIRED, failure.reason)
    }
}
