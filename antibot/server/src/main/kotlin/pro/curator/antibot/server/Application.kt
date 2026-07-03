package pro.curator.antibot.server

import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.plugins.defaultheaders.DefaultHeaders
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable
import org.slf4j.event.Level
import pro.curator.antibot.protocol.AntiBotJson
import pro.curator.antibot.protocol.ErrorResponse
import pro.curator.antibot.protocol.NonceRequest
import pro.curator.antibot.protocol.NonceResponse
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.protocol.SealedEnvelope

@Serializable
public data class VerifyRequest(val token: String)

@Serializable
public data class PublicKeyResponse(val publicKey: String, val protocolVersion: Int = Protocol.VERSION)

/**
 * Ktor application module. Split from main() so tests can install it into the
 * test host with a fixed [ServerContext].
 */
public fun Application.antiBotModule(context: ServerContext) {
    install(ContentNegotiation) { json(AntiBotJson) }
    install(DefaultHeaders)
    install(CallLogging) { level = Level.INFO }
    install(CORS) {
        anyHost() // demo only; lock this down in production
        allowHeader(Protocol.TRUST_TOKEN_HEADER)
        allowHeader(Protocol.PROTOCOL_VERSION_HEADER)
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.application.environment.log.error("Unhandled error", cause)
            call.respond(
                HttpStatusCode.InternalServerError,
                ErrorResponse(ReasonCode.UNKNOWN, cause.message ?: "internal error"),
            )
        }
    }

    routing {
        get("/health") { call.respond(mapOf("status" to "ok")) }

        // Dev helper: hand the SDK the public key to configure itself with.
        get("/v1/pubkey") {
            call.respond(PublicKeyResponse(context.publicKeyEncoded))
        }

        // Step 1: bootstrap nonce.
        post(Protocol.PATH_NONCE) {
            val req = runCatching { call.receive<NonceRequest>() }.getOrNull()
            if (req == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse(ReasonCode.UNKNOWN, "bad nonce request"))
                return@post
            }
            val (nonce, expiresAt) = context.nonceStore.issue()
            call.respond(
                NonceResponse(
                    nonce = nonce,
                    issuedAt = System.currentTimeMillis(),
                    expiresAt = expiresAt,
                ),
            )
        }

        // Steps 5-7: attestation -> trust token.
        post(Protocol.PATH_ATTEST) {
            val env = runCatching { call.receive<SealedEnvelope>() }.getOrNull()
            if (env == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse(ReasonCode.UNKNOWN, "bad envelope"))
                return@post
            }
            val response = context.attestationService.attest(env)
            call.respond(response)
        }

        // Stateless trust-token verification (the application backend calls this,
        // or verifies locally with the public key).
        post(Protocol.PATH_VERIFY) {
            val req = runCatching { call.receive<VerifyRequest>() }.getOrNull()
            if (req == null) {
                call.respond(HttpStatusCode.BadRequest, ErrorResponse(ReasonCode.UNKNOWN, "bad verify request"))
                return@post
            }
            call.respond(context.attestationService.verify(req.token))
        }

        // Demo protected resource: enforces the trust token from the header.
        get(Protocol.PATH_PROTECTED) {
            val token = call.request.headers[Protocol.TRUST_TOKEN_HEADER]
            if (token.isNullOrBlank()) {
                call.respond(HttpStatusCode.Unauthorized, ErrorResponse(ReasonCode.ATTESTATION_FAILED, "missing token"))
                return@get
            }
            val verify = context.attestationService.verify(token)
            if (verify.valid) {
                call.respond(mapOf("data" to "secret payload", "riskLevel" to verify.claims?.lvl?.name))
            } else {
                call.respond(HttpStatusCode.Unauthorized, ErrorResponse(verify.reason, "invalid token"))
            }
        }
    }
}

public fun main() {
    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080
    val context = ServerContext.fromEnvOrGenerate()
    // So integrators can grab the key from logs on first boot.
    org.slf4j.LoggerFactory.getLogger("antibot")
        .info("Server public key (configure the SDK with this):\n{}", context.publicKeyEncoded)
    embeddedServer(Netty, port = port) { antiBotModule(context) }.start(wait = true)
}
