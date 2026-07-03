package pro.curator.antibot.sdk.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import pro.curator.antibot.sdk.ClientKeyProvider
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore

/**
 * Client identity key backed by the Android Keystore (guide §13.2).
 *
 * The EC private key is generated inside the Keystore and NEVER leaves the
 * secure hardware (TEE/StrongBox where available). We only ever hold a handle;
 * signing happens in the Keystore. The public key is exported and sent to the
 * server so it can verify envelope signatures.
 *
 * Note: only the long-term IDENTITY key (for signing) lives here. The ephemeral
 * ECDH key used per-envelope is generated in software by EnvelopeCrypto.seal.
 */
public class KeystoreClientKeyProvider(
    private val alias: String = "curator_antibot_identity_key",
    private val requireStrongBox: Boolean = false,
) : ClientKeyProvider {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun identityKeyPair(): KeyPair = loadExisting() ?: generate()

    private fun loadExisting(): KeyPair? = try {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        entry?.let { KeyPair(it.certificate.publicKey, it.privateKey) }
    } catch (_: Throwable) {
        null
    }

    private fun generate(): KeyPair {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (requireStrongBox) setIsStrongBoxBacked(true)
            }
            .build()
        generator.initialize(spec)
        return generator.generateKeyPair()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
