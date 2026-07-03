package pro.curator.antibot.sdk.android

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import pro.curator.antibot.protocol.CryptoPrimitives
import pro.curator.antibot.protocol.Telemetry
import pro.curator.antibot.sdk.BuildInfo
import pro.curator.antibot.sdk.TelemetryProvider
import java.util.Locale
import java.util.TimeZone

/**
 * Collects compact, permission-free telemetry (guide §10). Everything is wrapped
 * so a missing signal degrades to "unknown" instead of crashing the host.
 */
public class AndroidTelemetryProvider(
    private val context: Context,
) : TelemetryProvider {

    override fun collect(): Telemetry {
        val pkg = context.packageName
        val pm = context.packageManager
        val (versionName, versionCode) = versionInfo(pm, pkg)
        return Telemetry(
            packageName = pkg,
            appVersionName = versionName,
            appVersionCode = versionCode,
            signingCertSha256 = signingCertSha256(pm, pkg),
            sdkVersion = BuildInfo.SDK_VERSION,
            osSdkInt = Build.VERSION.SDK_INT,
            osRelease = Build.VERSION.RELEASE ?: "unknown",
            deviceModel = Build.MODEL ?: "unknown",
            deviceManufacturer = Build.MANUFACTURER ?: "unknown",
            deviceBrand = Build.BRAND ?: "unknown",
            buildFingerprint = Build.FINGERPRINT ?: "unknown",
            hardware = Build.HARDWARE ?: "unknown",
            locale = safe { Locale.getDefault().toString() } ?: "unknown",
            timeZone = safe { TimeZone.getDefault().id } ?: "unknown",
            debuggable = (context.applicationInfo.flags and
                android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0,
        )
    }

    @Suppress("DEPRECATION")
    private fun versionInfo(pm: PackageManager, pkg: String): Pair<String, Long> = safe {
        val info: PackageInfo = pm.getPackageInfo(pkg, 0)
        val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode
        else info.versionCode.toLong()
        (info.versionName ?: "unknown") to code
    } ?: ("unknown" to -1L)

    /** SHA-256 of the app signing certificate (guide §10.3) — catches re-signed clones. */
    @Suppress("DEPRECATION")
    private fun signingCertSha256(pm: PackageManager, pkg: String): String = safe {
        val certBytes: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
            info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
        } else {
            val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
            info.signatures?.firstOrNull()?.toByteArray()
        }
        certBytes?.let { CryptoPrimitives.sha256Hex(it) }
    } ?: "unknown"

    private inline fun <T> safe(block: () -> T): T? = try { block() } catch (_: Throwable) { null }
}
