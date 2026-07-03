package pro.curator.antibot.sdk

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import pro.curator.antibot.protocol.Protocol

/**
 * The one-line integration point (guide §7). The host adds this to its own
 * OkHttpClient and every request automatically carries a fresh trust token.
 *
 * Design rules honored here:
 *  - the fast path only READS a cached token; heavy work is done ahead of time;
 *  - a bounded wait (interceptorWaitMillis) covers the cold-start case;
 *  - FAIL_OPEN lets the request proceed without a token; FAIL_CLOSED can hold it;
 *  - on 401/403 the token is invalidated and refreshed asynchronously.
 */
public class AntiBotInterceptor(
    private val tokenManager: TokenManager,
    private val config: AntiBotConfig,
    private val scope: CoroutineScope,
    private val logger: Logger = Logger(config.debug),
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()

        if (!config.featureFlags.attachTokenHeader) {
            return chain.proceed(original)
        }

        val token = resolveToken()

        val request = if (token != null) {
            original.newBuilder()
                .header(Protocol.TRUST_TOKEN_HEADER, token)
                .header(Protocol.PROTOCOL_VERSION_HEADER, Protocol.VERSION.toString())
                .build()
        } else {
            if (config.failureMode == FailureMode.FAIL_CLOSED) {
                logger.d("no token + FAIL_CLOSED -> short-circuiting request")
                return failClosedResponse(chain)
            }
            original // FAIL_OPEN: proceed without a token
        }

        val response = chain.proceed(request)

        // React to the server's verdict on the trust token.
        if (response.code == 401 || response.code == 403) {
            logger.d("server rejected token (${response.code}); invalidating + refreshing async")
            tokenManager.invalidate()
            scope.launch(Dispatchers.IO) { tokenManager.forceRefresh() }
        }

        return response
    }

    private fun resolveToken(): String? {
        tokenManager.cachedTokenOrNull()?.let { return it }
        // Cold start: bounded blocking wait so we don't hang the request.
        return runBlocking {
            withTimeoutOrNull(config.interceptorWaitMillis) {
                (tokenManager.getToken() as? TokenResult.Success)?.token
            }
        }
    }

    private fun failClosedResponse(chain: Interceptor.Chain): Response =
        Response.Builder()
            .request(chain.request())
            .protocol(okhttp3.Protocol.HTTP_1_1)
            .code(428) // Precondition Required — no trust token available
            .message("AntiBot: trust token unavailable (FAIL_CLOSED)")
            .body("".toResponseBody("text/plain".toMediaTypeOrNull()))
            .build()
}
