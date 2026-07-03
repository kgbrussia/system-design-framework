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
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import pro.curator.antibot.protocol.AntiBotJson
import pro.curator.antibot.protocol.AttestationResponse
import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.Decision
import pro.curator.antibot.protocol.EnvelopeCrypto
import pro.curator.antibot.protocol.EnvelopePayload
import pro.curator.antibot.protocol.IntegrityVerdict
import pro.curator.antibot.protocol.NonceRequest
import pro.curator.antibot.protocol.NonceResponse
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.protocol.SealedEnvelope
import pro.curator.antibot.protocol.Telemetry
import java.security.KeyPair

class FullFlowTest {

    private val serverKeys: KeyPair = CryptoPrimitives.generateEcKeyPair()

    private fun cleanTelemetry() = Telemetry(
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
    )

    private fun sealFor(nonce: String, integrity: IntegrityVerdict): SealedEnvelope {
        val clientId = CryptoPrimitives.generateEcKeyPair()
        val payload = EnvelopePayload(
            nonce = nonce,
            timestamp = System.currentTimeMillis(),
            clientIdPublicKey = CryptoPrimitives.encodePublicKey(clientId.public),
            telemetry = cleanTelemetry(),
            integrity = integrity,
        )
        return EnvelopeCrypto.seal(payload, serverKeys.public, clientId.private, clientId.public)
    }

    @Test
    fun `clean device gets a trust token and can call protected`() = testApplication {
        application { antiBotModule(ServerContext(serverKeys)) }

        // Step 1: nonce
        val nonceResp = client.post(Protocol.PATH_NONCE) {
            contentType(ContentType.Application.Json)
            setBody(AntiBotJson.encodeToString(NonceRequest("1.0.0", "com.example.host")))
        }
        assertEquals(HttpStatusCode.OK, nonceResp.status)
        val nonce = AntiBotJson.decodeFromString<NonceResponse>(nonceResp.bodyAsText()).nonce

        // Steps 2-5: seal + attest
        val env = sealFor(
            nonce,
            IntegrityVerdict(
                rooted = false, emulator = false, debuggerAttached = false,
                hookingDetected = false, playServicesAvailable = true,
            ),
        )
        val attestResp = client.post(Protocol.PATH_ATTEST) {
            contentType(ContentType.Application.Json)
            setBody(AntiBotJson.encodeToString(env))
        }
        val attestation = AntiBotJson.decodeFromString<AttestationResponse>(attestResp.bodyAsText())
        assertEquals(Decision.ALLOW, attestation.decision)
        assertNotNull(attestation.trustToken)

        // Step 8: call protected with the token
        val protectedResp = client.get(Protocol.PATH_PROTECTED) {
            header(Protocol.TRUST_TOKEN_HEADER, attestation.trustToken)
        }
        assertEquals(HttpStatusCode.OK, protectedResp.status)
    }

    @Test
    fun `protected route rejects request without token`() = testApplication {
        application { antiBotModule(ServerContext(serverKeys)) }
        val resp = client.get(Protocol.PATH_PROTECTED)
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
    }

    @Test
    fun `nonce cannot be reused (replay protection)`() = testApplication {
        application { antiBotModule(ServerContext(serverKeys)) }
        val nonce = AntiBotJson.decodeFromString<NonceResponse>(
            client.post(Protocol.PATH_NONCE) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(NonceRequest("1.0.0", "com.example.host")))
            }.bodyAsText(),
        ).nonce

        val clean = IntegrityVerdict(false, false, false, false, true)
        val first = client.post(Protocol.PATH_ATTEST) {
            contentType(ContentType.Application.Json)
            setBody(AntiBotJson.encodeToString(sealFor(nonce, clean)))
        }
        assertEquals(Decision.ALLOW, AntiBotJson.decodeFromString<AttestationResponse>(first.bodyAsText()).decision)

        // Reuse the SAME nonce -> must be denied.
        val second = client.post(Protocol.PATH_ATTEST) {
            contentType(ContentType.Application.Json)
            setBody(AntiBotJson.encodeToString(sealFor(nonce, clean)))
        }
        val secondBody = AntiBotJson.decodeFromString<AttestationResponse>(second.bodyAsText())
        assertEquals(Decision.DENY, secondBody.decision)
        assertNull(secondBody.trustToken)
    }

    @Test
    fun `rooted plus hooked device is denied`() = testApplication {
        application { antiBotModule(ServerContext(serverKeys)) }
        val nonce = AntiBotJson.decodeFromString<NonceResponse>(
            client.post(Protocol.PATH_NONCE) {
                contentType(ContentType.Application.Json)
                setBody(AntiBotJson.encodeToString(NonceRequest("1.0.0", "com.example.host")))
            }.bodyAsText(),
        ).nonce

        val hostile = IntegrityVerdict(
            rooted = true, emulator = false, debuggerAttached = false,
            hookingDetected = true, playServicesAvailable = true,
        )
        val resp = client.post(Protocol.PATH_ATTEST) {
            contentType(ContentType.Application.Json)
            setBody(AntiBotJson.encodeToString(sealFor(nonce, hostile)))
        }
        val body = AntiBotJson.decodeFromString<AttestationResponse>(resp.bodyAsText())
        assertEquals(Decision.DENY, body.decision)
        assertTrue(body.reasonCodes.isNotEmpty())
    }
}
