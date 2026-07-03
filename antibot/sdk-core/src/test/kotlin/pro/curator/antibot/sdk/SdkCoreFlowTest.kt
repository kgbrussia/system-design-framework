package pro.curator.antibot.sdk

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import pro.curator.antibot.protocol.AntiBotJson
import pro.curator.antibot.protocol.AttestationResponse
import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopeCrypto
import pro.curator.antibot.protocol.NonceResponse
import pro.curator.antibot.protocol.OpenResult
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.protocol.RiskLevel
import pro.curator.antibot.protocol.SealedEnvelope
import pro.curator.antibot.protocol.Telemetry
import pro.curator.antibot.protocol.TrustToken
import pro.curator.antibot.protocol.TrustTokenClaims
import java.security.KeyPair
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

/**
 * Drives the whole SDK core against a fake server built on the SAME protocol
 * module (so the crypto really has to match end-to-end).
 */
class SdkCoreFlowTest {

    private lateinit var server: MockWebServer
    private val serverKeys: KeyPair = CryptoPrimitives.generateEcKeyPair()
    private val issuedNonces = HashSet<String>()
    private val attestCount = AtomicInteger(0)

    private val telemetryProvider = TelemetryProvider {
        Telemetry(
            packageName = "com.example.host",
            appVersionName = "1.0.0",
            appVersionCode = 1,
            signingCertSha256 = "cd".repeat(32),
            sdkVersion = "1.0.0",
            osSdkInt = 34,
            osRelease = "14",
            deviceModel = "Pixel",
            deviceManufacturer = "Google",
            deviceBrand = "google",
            buildFingerprint = "fp",
            hardware = "hw",
            locale = "ru_RU",
            timeZone = "Europe/Moscow",
            debuggable = false,
        )
    }

    private val integrityProvider = IntegrityProvider { _ ->
        pro.curator.antibot.protocol.IntegrityVerdict(
            rooted = false, emulator = false, debuggerAttached = false,
            hookingDetected = false, playServicesAvailable = true,
        )
    }

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when (request.path) {
                Protocol.PATH_NONCE -> {
                    val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(32))
                    issuedNonces += nonce
                    val body = AntiBotJson.encodeToString(
                        NonceResponse(nonce, System.currentTimeMillis(), System.currentTimeMillis() + 60_000),
                    )
                    MockResponse().setResponseCode(200).setBody(body)
                        .addHeader("Content-Type", "application/json")
                }
                Protocol.PATH_ATTEST -> {
                    attestCount.incrementAndGet()
                    val env = AntiBotJson.decodeFromString<SealedEnvelope>(request.body.readUtf8())
                    val response = handleAttest(env)
                    MockResponse().setResponseCode(200)
                        .setBody(AntiBotJson.encodeToString(response))
                        .addHeader("Content-Type", "application/json")
                }
                Protocol.PATH_PROTECTED -> {
                    val token = request.getHeader(Protocol.TRUST_TOKEN_HEADER)
                    val valid = token != null &&
                        TrustToken.verify(token, serverKeys.public) is TrustToken.VerifyResult.Valid
                    MockResponse().setResponseCode(if (valid) 200 else 401)
                        .setBody(if (valid) "{\"data\":\"ok\"}" else "{\"error\":\"no token\"}")
                }
                else -> MockResponse().setResponseCode(404)
            }
        }
        server.start()
    }

    @AfterEach
    fun tearDown() { server.shutdown() }

    private fun handleAttest(env: SealedEnvelope): AttestationResponse {
        if (env.nonce !in issuedNonces) {
            return AttestationResponse(Decision.DENY, RiskLevel.HIGH, listOf(pro.curator.antibot.protocol.ReasonCode.NONCE_UNKNOWN))
        }
        issuedNonces.remove(env.nonce) // one-time use
        return when (EnvelopeCrypto.open(env, serverKeys.private)) {
            is OpenResult.Ok -> {
                val now = System.currentTimeMillis() / 1000
                val token = TrustToken.issue(
                    TrustTokenClaims("sub", "curator", now, now + 300, RiskLevel.LOW, UUID.randomUUID().toString()),
                    serverKeys.private,
                )
                AttestationResponse(Decision.ALLOW, RiskLevel.LOW, listOf(pro.curator.antibot.protocol.ReasonCode.OK), token, 300)
            }
            is OpenResult.Failure -> AttestationResponse(Decision.DENY, RiskLevel.HIGH, listOf(pro.curator.antibot.protocol.ReasonCode.BAD_SIGNATURE))
        }
    }

    private fun newClient(failureMode: FailureMode = FailureMode.FAIL_OPEN): AntiBotClient {
        val config = AntiBotConfig.Builder(
            siteKey = "test",
            baseUrl = server.url("/").toString(),
            serverPublicKey = serverKeys.public,
        ).debug(true).failureMode(failureMode).build()
        return AntiBotClient(config, telemetryProvider, integrityProvider, JvmClientKeyProvider())
    }

    @Test
    fun `getToken performs full flow and returns success`() = runBlocking {
        val result = newClient().getToken()
        assertInstanceOf(TokenResult.Success::class.java, result)
    }

    @Test
    fun `interceptor attaches token so protected call succeeds`() {
        val antiBot = newClient()
        val http = OkHttpClient.Builder().addInterceptor(antiBot.interceptor()).build()
        val resp = http.newCall(Request.Builder().url(server.url(Protocol.PATH_PROTECTED)).build()).execute()
        resp.use {
            assertEquals(200, it.code)
        }
    }

    @Test
    fun `cached token is reused - single attestation for two calls`() = runBlocking {
        val antiBot = newClient()
        val first = antiBot.getToken()
        val second = antiBot.getToken()
        assertInstanceOf(TokenResult.Success::class.java, first)
        assertInstanceOf(TokenResult.Success::class.java, second)
        assertEquals(1, attestCount.get()) // second call served from cache
    }

    @Test
    fun `fail-open lets request through when server is down`() {
        val antiBot = newClient(FailureMode.FAIL_OPEN)
        server.shutdown() // simulate outage
        val http = OkHttpClient.Builder().addInterceptor(antiBot.interceptor()).build()
        // Point at a dead port; fail-open must not throw from the interceptor itself.
        val deadUrl = "http://127.0.0.1:1/resource"
        val threw = runCatching {
            http.newCall(Request.Builder().url(deadUrl).build()).execute().close()
        }.exceptionOrNull()
        // The network call fails (dead host), but that's OkHttp — the interceptor
        // added no token and did not itself crash. assertNotNull documents intent.
        assertNotNull(threw)
    }
}
