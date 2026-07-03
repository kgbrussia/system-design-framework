package pro.curator.antibot.protocol

import kotlinx.serialization.Serializable

/**
 * Wire models shared by the SDK and the Ktor server.
 *
 * The whole anti-bot flow from the guide maps onto these:
 *   nonce -> telemetry + integrity -> protected envelope -> attestation -> trust token
 */

/** Constants of the protocol. Bumping [VERSION] lets client and server negotiate format. */
public object Protocol {
    public const val VERSION: Int = 1

    // HTTP header the interceptor attaches to every host request.
    public const val TRUST_TOKEN_HEADER: String = "X-AntiBot-Token"
    public const val PROTOCOL_VERSION_HEADER: String = "X-AntiBot-Proto"

    // Endpoints.
    public const val PATH_NONCE: String = "/v1/nonce"
    public const val PATH_ATTEST: String = "/v1/attest"
    public const val PATH_VERIFY: String = "/v1/verify"
    public const val PATH_PROTECTED: String = "/v1/protected"

    // HKDF info label bound to this envelope scheme.
    public val ENVELOPE_INFO: ByteArray = "curator-antibot/envelope/v1".toByteArray()
}

// ---------------------------------------------------------------------------
// Step 1: bootstrap nonce
// ---------------------------------------------------------------------------

@Serializable
public data class NonceRequest(
    val sdkVersion: String,
    val packageName: String,
)

@Serializable
public data class NonceResponse(
    val nonce: String, // base64url, single-use, server-issued
    val issuedAt: Long, // epoch millis
    val expiresAt: Long, // epoch millis
    val protocolVersion: Int = Protocol.VERSION,
)

// ---------------------------------------------------------------------------
// Step 2-3: telemetry + integrity (the plaintext that gets sealed)
// ---------------------------------------------------------------------------

@Serializable
public data class Telemetry(
    val packageName: String,
    val appVersionName: String,
    val appVersionCode: Long,
    val signingCertSha256: String,
    val sdkVersion: String,
    val osSdkInt: Int,
    val osRelease: String,
    val deviceModel: String,
    val deviceManufacturer: String,
    val deviceBrand: String,
    val buildFingerprint: String,
    val hardware: String,
    val locale: String,
    val timeZone: String,
    val debuggable: Boolean,
)

/** Local detector results + Play Integrity outcome. All optional/soft signals. */
@Serializable
public data class IntegrityVerdict(
    val rooted: Boolean,
    val emulator: Boolean,
    val debuggerAttached: Boolean,
    val hookingDetected: Boolean,
    val playServicesAvailable: Boolean,
    // Raw Play Integrity token, verified server-side (null when unavailable).
    val playIntegrityToken: String? = null,
    // Extra reason strings collected by individual detectors (for observability).
    val detectorNotes: List<String> = emptyList(),
)

/** The plaintext payload that is encrypted into the protected envelope. */
@Serializable
public data class EnvelopePayload(
    val nonce: String, // must equal the server-issued nonce (binding / anti-replay)
    val timestamp: Long, // client clock, epoch millis (checked against a window)
    val clientIdPublicKey: String, // client's long-term identity key (bound & echoed)
    val telemetry: Telemetry,
    val integrity: IntegrityVerdict,
    val protocolVersion: Int = Protocol.VERSION,
)

// ---------------------------------------------------------------------------
// Step 4-5: protected envelope + attestation request
// ---------------------------------------------------------------------------

/**
 * The sealed envelope actually sent to /v1/attest.
 *
 * Hybrid scheme:
 *  - client generates an ephemeral EC key, does ECDH with the server's static
 *    public key, HKDF -> AES-256-GCM key, encrypts the payload (AAD = nonce);
 *  - client signs iv||ciphertext||nonce with its long-term identity key (ES256).
 *
 * A passive interceptor (Burp/mitmproxy) only sees ciphertext bound to a
 * single-use nonce, so it can neither read nor replay it.
 */
@Serializable
public data class SealedEnvelope(
    val protocolVersion: Int,
    val nonce: String,
    val ephemeralPublicKey: String, // base64url X.509, client ephemeral (for ECDH)
    val clientIdPublicKey: String, // base64url X.509, client identity (verifies signature)
    val iv: String, // base64url
    val ciphertext: String, // base64url (AES-GCM, tag appended)
    val signature: String, // base64url ES256 over iv||ciphertext||nonce
)

// ---------------------------------------------------------------------------
// Step 6-7: server verdict + trust token
// ---------------------------------------------------------------------------

public enum class Decision { ALLOW, CHALLENGE, DENY }

public enum class RiskLevel { LOW, MEDIUM, HIGH }

/** Machine-readable reason codes surfaced to clients and dashboards. */
public enum class ReasonCode {
    OK,
    NETWORK_ERROR,
    SDK_NOT_INITIALIZED,
    NONCE_EXPIRED,
    NONCE_REUSED,
    NONCE_UNKNOWN,
    BAD_SIGNATURE,
    DECRYPT_FAILED,
    TIMESTAMP_OUT_OF_WINDOW,
    PROTOCOL_MISMATCH,
    ATTESTATION_FAILED,
    INTEGRITY_UNAVAILABLE,
    ROOT_DETECTED,
    EMULATOR_DETECTED,
    DEBUGGER_DETECTED,
    HOOKING_DETECTED,
    RATE_LIMITED,
    UNKNOWN,
}

@Serializable
public data class AttestationResponse(
    val decision: Decision,
    val riskLevel: RiskLevel,
    val reasonCodes: List<ReasonCode>,
    val trustToken: String? = null, // present when decision == ALLOW
    val ttlSeconds: Long = 0,
    // In shadow mode the server would have blocked but still ALLOWs; useful for rollout.
    val shadow: Boolean = false,
)

@Serializable
public data class TrustTokenClaims(
    val sub: String, // subject: opaque client/session id
    val iss: String, // issuer
    val iat: Long, // issued-at, epoch seconds
    val exp: Long, // expiry, epoch seconds
    val lvl: RiskLevel,
    val jti: String, // unique token id (helps replay accounting)
)

@Serializable
public data class VerifyResponse(
    val valid: Boolean,
    val reason: ReasonCode,
    val claims: TrustTokenClaims? = null,
)

@Serializable
public data class ErrorResponse(
    val reason: ReasonCode,
    val message: String,
)
