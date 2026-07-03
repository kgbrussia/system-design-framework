package pro.curator.antibot.server

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import pro.curator.antibot.protocol.AntiBotJson
import pro.curator.antibot.protocol.AttestationResponse
import pro.curator.antibot.protocol.Challenge
import pro.curator.antibot.protocol.ChallengeCrypto
import pro.curator.antibot.protocol.ChallengeSolution
import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopeCrypto
import pro.curator.antibot.protocol.EnvelopePayload
import pro.curator.antibot.protocol.IntegrityVerdict
import pro.curator.antibot.protocol.NonceRequest
import pro.curator.antibot.protocol.NonceResponse
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.protocol.RiskLevel
import pro.curator.antibot.protocol.SealedEnvelope
import pro.curator.antibot.protocol.Telemetry
import java.security.KeyPair

class ChallengeAndPlayIntegrityTest {

    private val serverKeys: KeyPair = CryptoPrimitives.generateEcKeyPair()
    private val clientId: KeyPair = CryptoPrimitives.generateEcKeyPair()
    private val clientPub = CryptoPrimitives.encodePublicKey(clientId.public)

    private fun telemetry() = Telemetry(
        packageName = "com.example.host", appVersionName = "1.0.0", appVersionCode = 1,
        signingCertSha256 = "ab".repeat(32), sdkVersion = "1.0.0", osSdkInt = 34, osRelease = "14",
        deviceModel = "Pixel", deviceManufacturer = "Google", deviceBrand = "google",
        buildFingerprint = "fp", hardware = "hw", locale = "ru_RU", timeZone = "UTC", debuggable = false,
    )

    private fun seal(nonce: String, integrity: IntegrityVerdict): SealedEnvelope {
        val payload = EnvelopePayload(
            nonce = nonce,
            timestamp = System.currentTimeMillis(),
            clientIdPublicKey = clientPub,
            telemetry = telemetry(),
            integrity = integrity,
        )
        return EnvelopeCrypto.seal(payload, serverKeys.public, clientId.private, clientId.public)
    }

    // ---- WebView challenge flow ----

    @Test
    fun `medium-risk device is challenged, solves it, gets a token`() = testApplication {
        application { antiBotModule(ServerContext(serverKeys)) }

        val nonce = AntiBotJson.decodeFromString<NonceResponse>(
            client.post(Protocol.PATH_NONCE) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(NonceRequest("1.0.0", "com.example.host")))
            }.bodyAsText(),
        ).nonce

        // emulator(35) + debugger(30) = 65 -> CHALLENGE (>=40, <70).
        val mediumRisk = IntegrityVerdict(
            rooted = false, emulator = true, debuggerAttached = true,
            hookingDetected = false, playServicesAvailable = true,
        )
        val attestResp = AntiBotJson.decodeFromString<AttestationResponse>(
            client.post(Protocol.PATH_ATTEST) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(seal(nonce, mediumRisk)))
            }.bodyAsText(),
        )
        assertEquals(Decision.CHALLENGE, attestResp.decision)
        val challenge: Challenge = requireNotNull(attestResp.challenge)

        // Simulate the WebView JS solving it.
        val answer = ChallengeCrypto.expectedAnswer(challenge.challengeId, challenge.challengeNonce)
        val verifyResp = AntiBotJson.decodeFromString<AttestationResponse>(
            client.post(Protocol.PATH_CHALLENGE_VERIFY) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(ChallengeSolution(challenge.challengeId, answer, clientPub)))
            }.bodyAsText(),
        )
        assertEquals(Decision.ALLOW, verifyResp.decision)
        assertNotNull(verifyResp.trustToken)

        val protectedResp = client.get(Protocol.PATH_PROTECTED) {
            header(Protocol.TRUST_TOKEN_HEADER, verifyResp.trustToken)
        }
        assertEquals(HttpStatusCode.OK, protectedResp.status)
    }

    @Test
    fun `wrong challenge answer is denied`() = testApplication {
        application { antiBotModule(ServerContext(serverKeys)) }
        val nonce = AntiBotJson.decodeFromString<NonceResponse>(
            client.post(Protocol.PATH_NONCE) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(NonceRequest("1.0.0", "com.example.host")))
            }.bodyAsText(),
        ).nonce
        val challenge = AntiBotJson.decodeFromString<AttestationResponse>(
            client.post(Protocol.PATH_ATTEST) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(seal(nonce, IntegrityVerdict(false, true, true, false, true))))
            }.bodyAsText(),
        ).challenge!!

        val bad = AntiBotJson.decodeFromString<AttestationResponse>(
            client.post(Protocol.PATH_CHALLENGE_VERIFY) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(ChallengeSolution(challenge.challengeId, "deadbeef", clientPub)))
            }.bodyAsText(),
        )
        assertEquals(Decision.DENY, bad.decision)
        assertNull(bad.trustToken)
    }

    @Test
    fun `challenge page is served as html`() = testApplication {
        application { antiBotModule(ServerContext(serverKeys)) }
        val resp = client.get("${Protocol.PATH_CHALLENGE_PAGE}?cid=abc&n=xyz")
        assertEquals(HttpStatusCode.OK, resp.status)
        val body = resp.bodyAsText()
        assert(body.contains("AntiBotBridge")) { "page must wire the JS bridge" }
        assert(body.contains("sha256")) { "page must compute the answer" }
    }

    // ---- Play Integrity full verification (feature-flagged) ----

    @Test
    fun `GooglePlayIntegrityVerifier parses a PASSED verdict and binds the nonce`() = runBlocking {
        val google = MockWebServer()
        val nonce = "test-nonce-123"
        val decodeJson = """
            {"tokenPayloadExternal":{
              "requestDetails":{"requestPackageName":"com.example.host","nonce":"$nonce","timestampMillis":"1700000000000"},
              "appIntegrity":{"appRecognitionVerdict":"PLAY_RECOGNIZED","packageName":"com.example.host"},
              "deviceIntegrity":{"deviceRecognitionVerdict":["MEETS_DEVICE_INTEGRITY","MEETS_STRONG_INTEGRITY"]},
              "accountDetails":{"appLicensingVerdict":"LICENSED"}
            }}
        """.trimIndent()
        google.enqueue(MockResponse().setResponseCode(200).setBody(decodeJson))
        google.enqueue(MockResponse().setResponseCode(200).setBody(decodeJson))
        google.start()

        val verifier = GooglePlayIntegrityVerifier(
            accessTokenProvider = StaticAccessTokenProvider("fake-oauth-token"),
            apiBaseUrl = google.url("/").toString().trimEnd('/'),
        )

        val passed = verifier.verify("integrity-token", nonce, "com.example.host")
        assertEquals(PlayIntegrityStatus.PASSED, passed.status)

        // A verdict for a different nonce must be rejected (anti-replay binding).
        val mismatch = verifier.verify("integrity-token", "other-nonce", "com.example.host")
        assertEquals(PlayIntegrityStatus.FAILED, mismatch.status)

        google.shutdown()
    }

    @Test
    fun `Play Integrity gracefully unavailable when no credentials configured`() = runBlocking {
        val verifier = GooglePlayIntegrityVerifier(accessTokenProvider = StubAccessTokenProvider)
        val result = verifier.verify("token", "nonce", "com.example.host")
        assertEquals(PlayIntegrityStatus.UNAVAILABLE, result.status)
    }

    @Test
    fun `enabling Play Integrity with a FAILED verdict denies a would-be-clean device`() = testApplication {
        // Inject a fake verifier that fails, with the feature flag ON.
        val failing = object : PlayIntegrityVerifier {
            override suspend fun verify(token: String, expectedNonce: String, packageName: String) =
                PlayIntegrityAssessment(PlayIntegrityStatus.FAILED, note = "test")
        }
        val ctx = ServerContext(
            serverKeys = serverKeys,
            riskConfig = RiskEngine.RiskConfig(playIntegrityEnabled = true, challengeEnabled = false),
            playIntegrityVerifier = failing,
        )
        application { antiBotModule(ctx) }

        val nonce = AntiBotJson.decodeFromString<NonceResponse>(
            client.post(Protocol.PATH_NONCE) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(NonceRequest("1.0.0", "com.example.host")))
            }.bodyAsText(),
        ).nonce
        // Clean device signals, but Play Integrity FAILED (+50) -> DENY.
        val clean = IntegrityVerdict(false, false, false, false, true, playIntegrityToken = "some-token")
        val resp = AntiBotJson.decodeFromString<AttestationResponse>(
            client.post(Protocol.PATH_ATTEST) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(seal(nonce, clean)))
            }.bodyAsText(),
        )
        assertEquals(Decision.DENY, resp.decision)
    }
}
