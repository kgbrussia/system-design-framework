package pro.curator.antibot.sdk.android

import android.content.Context
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import pro.curator.antibot.protocol.IntegrityVerdict
import pro.curator.antibot.sdk.IntegrityProvider
import kotlin.coroutines.resume

/**
 * Combines the local detectors (§12) with the Play Integrity verdict (§11),
 * all bound to the server nonce. Every step degrades gracefully: a failing
 * detector or an unavailable Play Integrity never throws into the flow.
 */
public class AndroidIntegrityProvider(
    private val context: Context,
    private val cloudProjectNumber: Long? = null,
) : IntegrityProvider {

    override suspend fun verdict(nonce: String): IntegrityVerdict {
        val notes = mutableListOf<String>()

        val root = safeDetect { RootDetector.detect(context) }
        val emulator = safeDetect { EmulatorDetector.detect() }
        val debugger = safeDetect { DebuggerDetector.detect(context) }
        val hooking = safeDetect { HookingDetector.detect() }
        notes += root.notes.map { "root:$it" }
        notes += emulator.notes.map { "emu:$it" }
        notes += debugger.notes.map { "dbg:$it" }
        notes += hooking.notes.map { "hook:$it" }

        val playAvailable = isPlayServicesAvailable()
        val playToken = if (playAvailable) requestPlayIntegrityToken(nonce) else null

        return IntegrityVerdict(
            rooted = root.detected,
            emulator = emulator.detected,
            debuggerAttached = debugger.detected,
            hookingDetected = hooking.detected,
            playServicesAvailable = playAvailable,
            playIntegrityToken = playToken,
            detectorNotes = notes,
        )
    }

    private fun isPlayServicesAvailable(): Boolean = try {
        GoogleApiAvailability.getInstance()
            .isGooglePlayServicesAvailable(context) == com.google.android.gms.common.ConnectionResult.SUCCESS
    } catch (_: Throwable) {
        false
    }

    /**
     * Requests a Play Integrity token bound to [nonce]. Returns null on any
     * failure (no Play, quota, offline) so the server can fall back (guide §11.5).
     */
    private suspend fun requestPlayIntegrityToken(nonce: String): String? = try {
        val manager = IntegrityManagerFactory.create(context)
        val requestBuilder = IntegrityTokenRequest.builder().setNonce(nonce)
        cloudProjectNumber?.let { requestBuilder.setCloudProjectNumber(it) }
        suspendCancellableCoroutine { cont ->
            manager.requestIntegrityToken(requestBuilder.build())
                .addOnSuccessListener { response -> cont.resume(response.token()) }
                .addOnFailureListener { cont.resume(null) }
        }
    } catch (_: Throwable) {
        null
    }

    private inline fun safeDetect(block: () -> DetectionResult): DetectionResult =
        try { block() } catch (_: Throwable) { DetectionResult(false, emptyList()) }
}
