package pro.curator.antibot.protocol

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Low-level cryptographic building blocks shared by the SDK and the server.
 *
 * Everything here is plain JCA (java.security / javax.crypto), so the exact same
 * code runs on the JVM and on Android. Keeping this in ONE shared module is what
 * guarantees the client and the server always agree on the wire format.
 *
 * Curve: NIST P-256 (secp256r1). Hash: SHA-256. AEAD: AES-256-GCM.
 */
public object CryptoPrimitives {

    private const val EC_CURVE = "secp256r1"
    private const val SIG_ALG = "SHA256withECDSA"
    private const val AES_GCM = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    private const val AES_KEY_BYTES = 32

    private val secureRandom = SecureRandom()

    // ---- Base64URL (no padding) — the single string encoding used on the wire ----

    private val urlEncoder = Base64.getUrlEncoder().withoutPadding()
    private val urlDecoder = Base64.getUrlDecoder()

    public fun b64UrlEncode(bytes: ByteArray): String = urlEncoder.encodeToString(bytes)

    public fun b64UrlDecode(text: String): ByteArray = urlDecoder.decode(text)

    // ---- Random ----

    public fun randomBytes(size: Int): ByteArray = ByteArray(size).also { secureRandom.nextBytes(it) }

    // ---- EC key handling (P-256) ----

    public fun generateEcKeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec(EC_CURVE), secureRandom)
        return gen.generateKeyPair()
    }

    /** X.509 (SubjectPublicKeyInfo) encoding, base64url. This is how a public key travels. */
    public fun encodePublicKey(key: PublicKey): String = b64UrlEncode(key.encoded)

    public fun decodePublicKey(encoded: String): PublicKey {
        val spec = X509EncodedKeySpec(b64UrlDecode(encoded))
        return KeyFactory.getInstance("EC").generatePublic(spec)
    }

    /** PKCS#8 encoding, base64url. Used only to persist the server's own private key. */
    public fun encodePrivateKey(key: PrivateKey): String = b64UrlEncode(key.encoded)

    public fun decodePrivateKey(encoded: String): PrivateKey {
        val spec = PKCS8EncodedKeySpec(b64UrlDecode(encoded))
        return KeyFactory.getInstance("EC").generatePrivate(spec)
    }

    // ---- Signatures (ES256-style: SHA256withECDSA) ----

    public fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray {
        val sig = java.security.Signature.getInstance(SIG_ALG)
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    public fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean =
        try {
            val sig = java.security.Signature.getInstance(SIG_ALG)
            sig.initVerify(publicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (_: Exception) {
            false
        }

    // ---- ECDH + HKDF-SHA256 -> a fresh AES-256 key ----

    public fun ecdh(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(publicKey, true)
        return ka.generateSecret()
    }

    /** HKDF-SHA256 (RFC 5869) extract-then-expand. */
    public fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hmac = "HmacSHA256"
        // extract
        val extractMac = Mac.getInstance(hmac)
        val saltKey = if (salt.isEmpty()) ByteArray(32) else salt
        extractMac.init(SecretKeySpec(saltKey, hmac))
        val prk = extractMac.doFinal(ikm)
        // expand
        val expandMac = Mac.getInstance(hmac)
        expandMac.init(SecretKeySpec(prk, hmac))
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            expandMac.reset()
            expandMac.update(t)
            expandMac.update(info)
            expandMac.update(counter.toByte())
            t = expandMac.doFinal()
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    public fun deriveAesKey(sharedSecret: ByteArray, salt: ByteArray, info: ByteArray): SecretKeySpec {
        val keyBytes = hkdfSha256(sharedSecret, salt, info, AES_KEY_BYTES)
        return SecretKeySpec(keyBytes, "AES")
    }

    // ---- AES-256-GCM (AEAD: confidentiality + integrity) ----

    public fun aesGcmIv(): ByteArray = randomBytes(GCM_IV_BYTES)

    public fun aesGcmEncrypt(key: SecretKeySpec, iv: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    public fun aesGcmDecrypt(key: SecretKeySpec, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    // ---- SHA-256 ----

    public fun sha256(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)

    public fun sha256Hex(data: ByteArray): String =
        sha256(data).joinToString("") { "%02x".format(it) }
}
