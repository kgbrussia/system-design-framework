package pro.curator.antibot.server

import pro.curator.antibot.protocol.CryptoPrimitives
import java.security.KeyPair

/**
 * Holds the server's long-term attestation key pair and wired services.
 *
 * The private key stays on the server; the PUBLIC key is what the SDK is
 * configured with (so it can seal envelopes to us and verify trust tokens).
 * The key can be supplied via env vars for stable deployments, otherwise a
 * fresh pair is generated on boot (fine for local runs and tests).
 */
public class ServerContext(
    public val serverKeys: KeyPair,
    riskConfig: RiskEngine.RiskConfig = RiskEngine.RiskConfig(),
    nonceTtlMillis: Long = 60_000,
) {
    public val nonceStore: NonceStore = NonceStore(ttlMillis = nonceTtlMillis)
    public val riskEngine: RiskEngine = RiskEngine(riskConfig)
    public val attestationService: AttestationService =
        AttestationService(serverKeys, nonceStore, riskEngine)

    /** Base64url X.509 public key — copy this into the SDK config. */
    public val publicKeyEncoded: String = CryptoPrimitives.encodePublicKey(serverKeys.public)

    public companion object {
        public fun fromEnvOrGenerate(): ServerContext {
            val priv = System.getenv("ANTIBOT_SERVER_PRIVATE_KEY")
            val pub = System.getenv("ANTIBOT_SERVER_PUBLIC_KEY")
            val keys = if (!priv.isNullOrBlank() && !pub.isNullOrBlank()) {
                KeyPair(CryptoPrimitives.decodePublicKey(pub), CryptoPrimitives.decodePrivateKey(priv))
            } else {
                CryptoPrimitives.generateEcKeyPair()
            }
            val shadow = System.getenv("ANTIBOT_SHADOW_MODE")?.toBoolean() ?: false
            return ServerContext(keys, RiskEngine.RiskConfig(shadowMode = shadow))
        }
    }
}
