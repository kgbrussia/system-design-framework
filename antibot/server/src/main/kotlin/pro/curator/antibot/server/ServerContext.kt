package pro.curator.antibot.server

import pro.curator.antibot.protocol.CryptoPrimitives
import java.security.KeyPair

/**
 * Holds the server's long-term attestation key pair and wired services.
 *
 * The private key stays on the server; the PUBLIC key is what the SDK is
 * configured with (so it can seal envelopes to us and verify trust tokens).
 */
public class ServerContext(
    public val serverKeys: KeyPair,
    public val riskConfig: RiskEngine.RiskConfig = RiskEngine.RiskConfig(),
    playIntegrityVerifier: PlayIntegrityVerifier = DisabledPlayIntegrityVerifier,
    nonceTtlMillis: Long = 60_000,
) {
    public val nonceStore: NonceStore = NonceStore(ttlMillis = nonceTtlMillis)
    public val challengeStore: ChallengeStore = ChallengeStore()
    public val riskEngine: RiskEngine = RiskEngine(riskConfig)
    public val attestationService: AttestationService = AttestationService(
        serverKeys = serverKeys,
        nonceStore = nonceStore,
        riskEngine = riskEngine,
        riskConfig = riskConfig,
        playIntegrityVerifier = playIntegrityVerifier,
        challengeStore = challengeStore,
    )

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

            val riskConfig = RiskEngine.RiskConfig(
                playIntegrityEnabled = envFlag("ANTIBOT_PLAY_INTEGRITY_ENABLED", default = false),
                requirePlayIntegrity = envFlag("ANTIBOT_REQUIRE_PLAY_INTEGRITY", default = false),
                challengeEnabled = envFlag("ANTIBOT_CHALLENGE_ENABLED", default = true),
                shadowMode = envFlag("ANTIBOT_SHADOW_MODE", default = false),
            )

            // Play Integrity credentials are the ONLY stubbed part. Configure a real
            // service-account token minter here; a static token can be injected via env
            // for testing, otherwise verification is gracefully unavailable.
            val accessTokenProvider: AccessTokenProvider =
                System.getenv("ANTIBOT_PLAY_INTEGRITY_ACCESS_TOKEN")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { StaticAccessTokenProvider(it) }
                    ?: StubAccessTokenProvider

            val verifier = if (riskConfig.playIntegrityEnabled) {
                GooglePlayIntegrityVerifier(accessTokenProvider)
            } else {
                DisabledPlayIntegrityVerifier
            }

            return ServerContext(keys, riskConfig, verifier)
        }

        private fun envFlag(name: String, default: Boolean): Boolean =
            System.getenv(name)?.toBooleanStrictOrNull() ?: default
    }
}
