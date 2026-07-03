package pro.curator.antibot.protocol

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EnvelopeCryptoTest {

    private fun samplePayload(nonce: String, clientPubEncoded: String) = EnvelopePayload(
        nonce = nonce,
        timestamp = System.currentTimeMillis(),
        clientIdPublicKey = clientPubEncoded,
        telemetry = Telemetry(
            packageName = "com.example.host",
            appVersionName = "3.4.1",
            appVersionCode = 3401,
            signingCertSha256 = "ab".repeat(32),
            sdkVersion = "1.0.0",
            osSdkInt = 34,
            osRelease = "14",
            deviceModel = "Pixel 8",
            deviceManufacturer = "Google",
            deviceBrand = "google",
            buildFingerprint = "google/shiba/shiba:14",
            hardware = "shiba",
            locale = "ru_RU",
            timeZone = "Europe/Moscow",
            debuggable = false,
        ),
        integrity = IntegrityVerdict(
            rooted = false,
            emulator = false,
            debuggerAttached = false,
            hookingDetected = false,
            playServicesAvailable = true,
            playIntegrityToken = null,
        ),
    )

    @Test
    fun `seal then open round-trips and binds all fields`() {
        val server = CryptoPrimitives.generateEcKeyPair()
        val clientId = CryptoPrimitives.generateEcKeyPair()
        val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(32))
        val clientPubEncoded = CryptoPrimitives.encodePublicKey(clientId.public)

        val payload = samplePayload(nonce, clientPubEncoded)
        val env = EnvelopeCrypto.seal(payload, server.public, clientId.private, clientId.public)

        val result = EnvelopeCrypto.open(env, server.private)
        assertInstanceOf(OpenResult.Ok::class.java, result)
        val opened = (result as OpenResult.Ok).opened
        assertEquals(nonce, opened.payload.nonce)
        assertEquals("com.example.host", opened.payload.telemetry.packageName)
    }

    @Test
    fun `tampered ciphertext is rejected`() {
        val server = CryptoPrimitives.generateEcKeyPair()
        val clientId = CryptoPrimitives.generateEcKeyPair()
        val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(32))
        val payload = samplePayload(nonce, CryptoPrimitives.encodePublicKey(clientId.public))

        val env = EnvelopeCrypto.seal(payload, server.public, clientId.private, clientId.public)
        // Flip one byte of the ciphertext -> signature no longer matches.
        val bad = env.copy(ciphertext = CryptoPrimitives.b64UrlEncode(
            CryptoPrimitives.b64UrlDecode(env.ciphertext).also { it[0] = (it[0] + 1).toByte() },
        ))

        val result = EnvelopeCrypto.open(bad, server.private)
        assertInstanceOf(OpenResult.Failure::class.java, result)
    }

    @Test
    fun `wrong server key cannot decrypt`() {
        val server = CryptoPrimitives.generateEcKeyPair()
        val attacker = CryptoPrimitives.generateEcKeyPair()
        val clientId = CryptoPrimitives.generateEcKeyPair()
        val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(32))
        val payload = samplePayload(nonce, CryptoPrimitives.encodePublicKey(clientId.public))

        val env = EnvelopeCrypto.seal(payload, server.public, clientId.private, clientId.public)
        val result = EnvelopeCrypto.open(env, attacker.private)
        assertInstanceOf(OpenResult.Failure::class.java, result)
    }

    @Test
    fun `trust token issue and verify`() {
        val server = CryptoPrimitives.generateEcKeyPair()
        val now = System.currentTimeMillis() / 1000
        val claims = TrustTokenClaims(
            sub = "session-123", iss = "curator", iat = now, exp = now + 300,
            lvl = RiskLevel.LOW, jti = "jti-1",
        )
        val token = TrustToken.issue(claims, server.private)
        val ok = TrustToken.verify(token, server.public, nowSeconds = now + 10)
        assertInstanceOf(TrustToken.VerifyResult.Valid::class.java, ok)

        val expired = TrustToken.verify(token, server.public, nowSeconds = now + 400)
        assertInstanceOf(TrustToken.VerifyResult.Invalid::class.java, expired)
    }

    @Test
    fun `public key survives encode-decode`() {
        val kp = CryptoPrimitives.generateEcKeyPair()
        val encoded = CryptoPrimitives.encodePublicKey(kp.public)
        val decoded = CryptoPrimitives.decodePublicKey(encoded)
        assertTrue(kp.public.encoded.contentEquals(decoded.encoded))
    }
}
