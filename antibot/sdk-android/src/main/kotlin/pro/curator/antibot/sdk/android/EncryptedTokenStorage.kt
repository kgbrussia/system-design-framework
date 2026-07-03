package pro.curator.antibot.sdk.android

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import pro.curator.antibot.sdk.StoredToken
import pro.curator.antibot.sdk.TokenStorage

/**
 * Persists the short-lived trust token in EncryptedSharedPreferences, encrypted
 * with a Keystore-backed master key (guide §13.2). Falls back to in-memory-only
 * behavior if the secure store cannot be created, so the host never crashes.
 */
public class EncryptedTokenStorage(
    context: Context,
) : TokenStorage {

    private val prefs: SharedPreferences? = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "curator_antibot_secure",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (_: Throwable) {
        null
    }

    @Volatile private var memoryFallback: StoredToken? = null

    override fun load(): StoredToken? {
        val p = prefs ?: return memoryFallback
        val value = p.getString(KEY_VALUE, null) ?: return null
        val expiry = p.getLong(KEY_EXPIRY, 0)
        return StoredToken(value, expiry)
    }

    override fun save(token: StoredToken) {
        val p = prefs
        if (p == null) { memoryFallback = token; return }
        p.edit().putString(KEY_VALUE, token.value).putLong(KEY_EXPIRY, token.expiresAtMillis).apply()
    }

    override fun clear() {
        memoryFallback = null
        prefs?.edit()?.remove(KEY_VALUE)?.remove(KEY_EXPIRY)?.apply()
    }

    private companion object {
        const val KEY_VALUE = "trust_token"
        const val KEY_EXPIRY = "trust_token_expiry"
    }
}
