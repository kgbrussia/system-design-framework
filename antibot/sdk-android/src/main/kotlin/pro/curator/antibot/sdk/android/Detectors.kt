package pro.curator.antibot.sdk.android

import android.content.Context
import android.os.Build
import android.os.Debug
import java.io.File

/**
 * Local environment detectors (guide §12).
 *
 * Every detector is a SIGNAL, not a verdict: individually bypassable on a device
 * the attacker controls, so results are shipped to the server for risk scoring
 * rather than used to block locally. Multiple independent checks per detector
 * raise the cost of a clean bypass.
 */

internal data class DetectionResult(val detected: Boolean, val notes: List<String>)

internal object RootDetector {
    private val suPaths = arrayOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
        "/system/bin/.ext/.su", "/system/app/Superuser.apk", "/vendor/bin/su",
    )
    private val rootPackages = arrayOf(
        "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
    )

    fun detect(context: Context): DetectionResult {
        val notes = mutableListOf<String>()
        if (suPaths.any { runCatching { File(it).exists() }.getOrDefault(false) }) notes += "su-binary"
        if (Build.TAGS?.contains("test-keys") == true) notes += "test-keys"
        val pm = context.packageManager
        rootPackages.forEach { pkg ->
            runCatching { pm.getPackageInfo(pkg, 0); notes += "pkg:$pkg" }
        }
        if (canExecSu()) notes += "which-su"
        // /system writable would mean the read-only guarantee is broken.
        if (runCatching { File("/system").canWrite() }.getOrDefault(false)) notes += "system-writable"
        return DetectionResult(notes.isNotEmpty(), notes)
    }

    private fun canExecSu(): Boolean = runCatching {
        val p = Runtime.getRuntime().exec(arrayOf("which", "su"))
        val ok = p.inputStream.bufferedReader().readLine() != null
        p.destroy()
        ok
    }.getOrDefault(false)
}

internal object EmulatorDetector {
    fun detect(): DetectionResult {
        val notes = mutableListOf<String>()
        val fp = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val product = Build.PRODUCT.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        val hardware = Build.HARDWARE.lowercase()

        if (fp.startsWith("generic") || fp.contains("emulator") || fp.contains("sdk_gphone")) notes += "fingerprint"
        if (model.contains("emulator") || model.contains("android sdk built for")) notes += "model"
        if (product.contains("sdk") || product.contains("emulator") || product == "google_sdk") notes += "product"
        if (manufacturer.contains("genymotion")) notes += "genymotion"
        if (hardware.contains("goldfish") || hardware.contains("ranchu")) notes += "qemu-hw"
        if (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) notes += "generic"
        listOf("/dev/socket/qemud", "/dev/qemu_pipe", "/system/bin/qemu-props").forEach {
            if (runCatching { File(it).exists() }.getOrDefault(false)) notes += "qemu-file"
        }
        return DetectionResult(notes.isNotEmpty(), notes)
    }
}

internal object DebuggerDetector {
    fun detect(context: Context): DetectionResult {
        val notes = mutableListOf<String>()
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) notes += "debugger-connected"
        val debuggable = (context.applicationInfo.flags and
            android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (debuggable) notes += "flag-debuggable"
        // TracerPid != 0 means another process (a debugger) is tracing us.
        runCatching {
            File("/proc/self/status").readLines().firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(":")?.trim()?.toIntOrNull()
                ?.let { if (it != 0) notes += "tracer-pid:$it" }
        }
        return DetectionResult(notes.isNotEmpty(), notes)
    }
}

internal object HookingDetector {
    private val suspiciousLibs = arrayOf("frida", "gadget", "xposed", "substrate", "lsposed")

    fun detect(): DetectionResult {
        val notes = mutableListOf<String>()
        // Loaded libraries in our own memory map.
        runCatching {
            val maps = File("/proc/self/maps").readText().lowercase()
            suspiciousLibs.forEach { if (maps.contains(it)) notes += "maps:$it" }
        }
        // Frida default artifacts.
        listOf("/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server").forEach {
            if (runCatching { File(it).exists() }.getOrDefault(false)) notes += "frida-file"
        }
        // Xposed leaves a tell-tale class on the classpath.
        runCatching {
            Class.forName("de.robv.android.xposed.XposedBridge"); notes += "xposed-class"
        }
        // A thread named after Frida's JS loop is a classic tell.
        runCatching {
            Thread.getAllStackTraces().keys.forEach { t ->
                if (t.name.contains("gum-js") || t.name.contains("gmain") && t.name.contains("frida")) {
                    notes += "frida-thread"
                }
            }
        }
        return DetectionResult(notes.isNotEmpty(), notes.distinct())
    }
}
