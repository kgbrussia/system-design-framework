package pro.curator.antibot.demo

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import pro.curator.antibot.protocol.Protocol
import pro.curator.antibot.sdk.FailureMode
import pro.curator.antibot.sdk.TokenResult
import pro.curator.antibot.sdk.android.AntiBot
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class DemoUiState(
    val baseUrl: String = "http://10.0.2.2:8080",
    val connected: Boolean = false,
    val busy: Boolean = false,
    val log: List<String> = emptyList(),
)

/**
 * Drives the demo: connect (fetch the server key + init the SDK), obtain a trust
 * token, and call a protected endpoint through the SDK's OkHttp interceptor.
 */
class DemoViewModel(app: Application) : AndroidViewModel(app) {

    var state by mutableStateOf(DemoUiState())
        private set

    // Plain client used only to bootstrap the demo (fetch the public key).
    private val bootstrapClient = OkHttpClient()

    // Client with the AntiBot interceptor — every request carries a trust token.
    private var protectedClient: OkHttpClient? = null

    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun onBaseUrlChange(value: String) {
        state = state.copy(baseUrl = value)
    }

    /**
     * Step 0: fetch the server public key from /v1/pubkey and initialize the SDK.
     * NOTE: fetching the key is a demo convenience. A production app PINS the key
     * into the binary instead of trusting the server to hand it over.
     */
    fun connect() = launchBusy {
        val base = state.baseUrl.trimEnd('/')
        log("Connecting to $base …")
        val publicKey = withContext(Dispatchers.IO) {
            bootstrapClient.newCall(Request.Builder().url("$base${Protocol.PATH_PUBKEY}").build())
                .execute().use { resp ->
                    val body = resp.body?.string().orEmpty()
                    JSONObject(body).getString("publicKey")
                }
        }
        log("Got server public key (${publicKey.take(16)}…)")

        AntiBot.init(
            context = getApplication(),
            config = AntiBot.config(
                siteKey = "demo-site-key",
                baseUrl = base,
                serverPublicKeyBase64Url = publicKey,
            ).failureMode(FailureMode.FAIL_OPEN)
                .debug(true)
                .build(),
        )
        protectedClient = OkHttpClient.Builder()
            .addInterceptor(AntiBot.interceptor())
            .build()

        state = state.copy(connected = true)
        log("SDK initialized. Ready.")
    }

    /** Step 1-7: run the attestation flow and show the resulting trust token. */
    fun getToken() = launchBusy {
        if (!state.connected) { log("Connect first."); return@launchBusy }
        log("Requesting trust token …")
        when (val result = AntiBot.getToken()) {
            is TokenResult.Success ->
                log("TOKEN OK: ${result.token.take(24)}…  (expires ${Date(result.expiresAtMillis)})")
            is TokenResult.Failure ->
                log("TOKEN FAILED: ${result.reason} (retryable=${result.retryable})")
        }
    }

    /** Step 8: call the protected endpoint; the interceptor attaches the token. */
    fun callProtected() = launchBusy {
        val client = protectedClient
        if (client == null) { log("Connect first."); return@launchBusy }
        val url = "${state.baseUrl.trimEnd('/')}${Protocol.PATH_PROTECTED}"
        log("GET $url")
        val (code, body) = withContext(Dispatchers.IO) {
            client.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                resp.code to (resp.body?.string().orEmpty())
            }
        }
        log("← HTTP $code  $body")
    }

    fun clearToken() {
        AntiBot.invalidateToken()
        log("Trust token invalidated.")
    }

    private fun launchBusy(block: suspend () -> Unit) {
        if (state.busy) return
        viewModelScope.launch {
            state = state.copy(busy = true)
            try {
                block()
            } catch (e: Exception) {
                log("ERROR: ${e.message}")
            } finally {
                state = state.copy(busy = false)
            }
        }
    }

    private fun log(line: String) {
        val stamped = "${timeFmt.format(Date())}  $line"
        state = state.copy(log = state.log + stamped)
    }
}
