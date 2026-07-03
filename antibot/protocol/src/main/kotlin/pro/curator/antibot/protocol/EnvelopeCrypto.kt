package pro.curator.antibot.protocol

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.PrivateKey
import java.security.PublicKey

/** Shared JSON config. Lenient defaults keep old SDKs working against newer servers. */
public val AntiBotJson: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = false
}

/** Result of opening an envelope on the server side. */
public data class OpenedEnvelope(
    val payload: EnvelopePayload,
    val clientIdPublicKey: PublicKey,
)

public sealed interface OpenResult {
    public data class Ok(val opened: OpenedEnvelope) : OpenResult
    public data class Failure(val reason: ReasonCode) : OpenResult
}

/**
 * Seals/opens the [SealedEnvelope]. Used by BOTH sides:
 *   - the SDK calls [seal];
 *   - the server calls [open].
 * Because both use this identical code, the wire format can never drift.
 */
public object EnvelopeCrypto {

    /**
     * SDK side. Encrypts [payload] for [serverPublicKey] and signs it with the
     * client's long-term [clientIdentityPrivateKey].
     */
    public fun seal(
        payload: EnvelopePayload,
        serverPublicKey: PublicKey,
        clientIdentityPrivateKey: PrivateKey,
        clientIdentityPublicKey: PublicKey,
    ): SealedEnvelope {
        val nonceBytes = CryptoPrimitives.b64UrlDecode(payload.nonce)

        // Ephemeral EC key for forward-secret ECDH with the server's static key.
        val ephemeral = CryptoPrimitives.generateEcKeyPair()
        val shared = CryptoPrimitives.ecdh(ephemeral.private, serverPublicKey)
        val aesKey = CryptoPrimitives.deriveAesKey(shared, salt = nonceBytes, info = Protocol.ENVELOPE_INFO)

        val plaintext = AntiBotJson.encodeToString(payload).toByteArray()
        val iv = CryptoPrimitives.aesGcmIv()
        val ciphertext = CryptoPrimitives.aesGcmEncrypt(aesKey, iv, plaintext, aad = nonceBytes)

        // Sign iv || ciphertext || nonce so the server can attribute & integrity-check
        // the envelope before spending work on decryption.
        val toSign = iv + ciphertext + nonceBytes
        val signature = CryptoPrimitives.sign(clientIdentityPrivateKey, toSign)

        return SealedEnvelope(
            protocolVersion = Protocol.VERSION,
            nonce = payload.nonce,
            ephemeralPublicKey = CryptoPrimitives.encodePublicKey(ephemeral.public),
            clientIdPublicKey = CryptoPrimitives.encodePublicKey(clientIdentityPublicKey),
            iv = CryptoPrimitives.b64UrlEncode(iv),
            ciphertext = CryptoPrimitives.b64UrlEncode(ciphertext),
            signature = CryptoPrimitives.b64UrlEncode(signature),
        )
    }

    /**
     * Server side. Verifies the signature, decrypts the payload and binds every
     * field (nonce, client key) to prevent swaps. Nonce freshness/one-time-use is
     * checked by the caller (it owns the nonce store).
     */
    public fun open(env: SealedEnvelope, serverPrivateKey: PrivateKey): OpenResult {
        if (env.protocolVersion != Protocol.VERSION) {
            return OpenResult.Failure(ReasonCode.PROTOCOL_MISMATCH)
        }

        val nonceBytes = try {
            CryptoPrimitives.b64UrlDecode(env.nonce)
        } catch (_: Exception) {
            return OpenResult.Failure(ReasonCode.NONCE_UNKNOWN)
        }

        val clientIdPub = try {
            CryptoPrimitives.decodePublicKey(env.clientIdPublicKey)
        } catch (_: Exception) {
            return OpenResult.Failure(ReasonCode.BAD_SIGNATURE)
        }

        val iv = CryptoPrimitives.b64UrlDecode(env.iv)
        val ciphertext = CryptoPrimitives.b64UrlDecode(env.ciphertext)
        val signature = CryptoPrimitives.b64UrlDecode(env.signature)

        // 1) authenticate the sender + integrity of the sealed bytes.
        val signed = iv + ciphertext + nonceBytes
        if (!CryptoPrimitives.verify(clientIdPub, signed, signature)) {
            return OpenResult.Failure(ReasonCode.BAD_SIGNATURE)
        }

        // 2) ECDH with the client's ephemeral key -> same AES key -> decrypt.
        val payload: EnvelopePayload = try {
            val ephemeralPub = CryptoPrimitives.decodePublicKey(env.ephemeralPublicKey)
            val shared = CryptoPrimitives.ecdh(serverPrivateKey, ephemeralPub)
            val aesKey = CryptoPrimitives.deriveAesKey(shared, salt = nonceBytes, info = Protocol.ENVELOPE_INFO)
            val plaintext = CryptoPrimitives.aesGcmDecrypt(aesKey, iv, ciphertext, aad = nonceBytes)
            AntiBotJson.decodeFromString(String(plaintext))
        } catch (_: Exception) {
            return OpenResult.Failure(ReasonCode.DECRYPT_FAILED)
        }

        // 3) bind everything: the encrypted payload must reference the same nonce and
        //    the same identity key that signed the envelope (defeats field swapping).
        if (payload.nonce != env.nonce) {
            return OpenResult.Failure(ReasonCode.NONCE_UNKNOWN)
        }
        if (payload.clientIdPublicKey != env.clientIdPublicKey) {
            return OpenResult.Failure(ReasonCode.BAD_SIGNATURE)
        }
        if (payload.protocolVersion != Protocol.VERSION) {
            return OpenResult.Failure(ReasonCode.PROTOCOL_MISMATCH)
        }

        return OpenResult.Ok(OpenedEnvelope(payload, clientIdPub))
    }
}
