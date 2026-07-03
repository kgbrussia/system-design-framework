package pro.curator.antibot.sdk.android

import android.annotation.SuppressLint
import android.content.Context
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import pro.curator.antibot.protocol.Challenge
import pro.curator.antibot.protocol.ReasonCode
import pro.curator.antibot.sdk.ChallengeResult
import pro.curator.antibot.sdk.WebViewChallengeSolver

/**
 * Solves a step-up challenge in a WebView (guide §14).
 *
 * Loads the server's local challenge page, lets its JS compute the answer, and
 * receives it back through the `AntiBotBridge` JS interface.
 *
 * WebView security (guide §14.2):
 *  - JS is enabled ONLY to run our own trusted page;
 *  - the WebViewClient blocks navigation to any origin other than our baseUrl,
 *    so the JS bridge is never exposed to untrusted content;
 *  - file/content access is disabled;
 *  - the WebView is created off-screen, used once, and destroyed.
 */
public class AndroidWebViewChallengeSolver(
    private val context: Context,
    private val timeoutMillis: Long = 15_000,
) : WebViewChallengeSolver {

    @SuppressLint("SetJavaScriptEnabled")
    override suspend fun solve(challenge: Challenge, baseUrl: String): ChallengeResult {
        val url = resolve(baseUrl, challenge.pageUrl)
        val deferred = CompletableDeferred<String>()

        val answer: String? = withContext(Dispatchers.Main) {
            val webView = WebView(context.applicationContext)
            with(webView.settings) {
                javaScriptEnabled = true
                domStorageEnabled = false
                allowFileAccess = false
                allowContentAccess = false
                @Suppress("DEPRECATION")
                allowFileAccessFromFileURLs = false
                cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
            }

            webView.addJavascriptInterface(
                object {
                    @JavascriptInterface
                    fun onChallengeSolved(answer: String) {
                        if (!deferred.isCompleted) deferred.complete(answer)
                    }
                },
                BRIDGE_NAME,
            )

            // Confine the WebView to our trusted origin.
            webView.webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    val target = request?.url?.toString() ?: return true
                    return !target.startsWith(baseUrl) // true = block the navigation
                }
            }

            webView.loadUrl(url)

            val result = withTimeoutOrNull(timeoutMillis) { deferred.await() }

            webView.stopLoading()
            webView.removeJavascriptInterface(BRIDGE_NAME)
            webView.destroy()
            result
        }

        return if (answer != null) {
            ChallengeResult.Solved(answer)
        } else {
            ChallengeResult.Failed(ReasonCode.CHALLENGE_FAILED)
        }
    }

    private fun resolve(baseUrl: String, pageUrl: String): String =
        if (pageUrl.startsWith("http")) pageUrl else baseUrl.trimEnd('/') + pageUrl

    private companion object {
        const val BRIDGE_NAME = "AntiBotBridge"
    }
}
