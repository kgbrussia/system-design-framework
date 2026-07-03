package pro.curator.antibot.protocol

import kotlinx.serialization.encodeToString
import java.security.PrivateKey
import java.security.PublicKey

/**
 * Compact, JWT-like trust token signed with the server's EC key (ES256-style).
 *
 * Format:  base64url(headerJson) "." base64url(claimsJson) "." base64url(signature)
 * Signature covers the "header.claims" string. The application backend verifies
 * it statelessly with the server's public key and checks expiry (short TTL) — this
 * is the "pass" the OkHttp interceptor attaches to every request.
 */
public object TrustToken {

    private const val HEADER = """{"alg":"ES256","typ":"CTT"}"""

    public fun issue(claims: TrustTokenClaims, serverPrivateKey: PrivateKey): String {
        val headerB64 = CryptoPrimitives.b64UrlEncode(HEADER.toByteArray())
        val claimsB64 = CryptoPrimitives.b64UrlEncode(AntiBotJson.encodeToString(claims).toByteArray())
        val signingInput = "$headerB64.$claimsB64"
        val signature = CryptoPrimitives.sign(serverPrivateKey, signingInput.toByteArray())
        val sigB64 = CryptoPrimitives.b64UrlEncode(signature)
        return "$signingInput.$sigB64"
    }

    public sealed interface VerifyResult {
        public data class Valid(val claims: TrustTokenClaims) : VerifyResult
        public data class Invalid(val reason: ReasonCode) : VerifyResult
    }

    public fun verify(
        token: String,
        serverPublicKey: PublicKey,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
    ): VerifyResult {
        val parts = token.split(".")
        if (parts.size != 3) return VerifyResult.Invalid(ReasonCode.ATTESTATION_FAILED)

        val signingInput = "${parts[0]}.${parts[1]}"
        val signature = try {
            CryptoPrimitives.b64UrlDecode(parts[2])
        } catch (_: Exception) {
            return VerifyResult.Invalid(ReasonCode.BAD_SIGNATURE)
        }

        if (!CryptoPrimitives.verify(serverPublicKey, signingInput.toByteArray(), signature)) {
            return VerifyResult.Invalid(ReasonCode.BAD_SIGNATURE)
        }

        val claims = try {
            AntiBotJson.decodeFromString<TrustTokenClaims>(String(CryptoPrimitives.b64UrlDecode(parts[1])))
        } catch (_: Exception) {
            return VerifyResult.Invalid(ReasonCode.ATTESTATION_FAILED)
        }

        if (nowSeconds >= claims.exp) return VerifyResult.Invalid(ReasonCode.NONCE_EXPIRED)

        return VerifyResult.Valid(claims)
    }
}
