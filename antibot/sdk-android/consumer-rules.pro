# Consumer ProGuard/R8 rules shipped to the host app (guide §5.6).
# Keep the public API and serializable models the host / reflection relies on.

-keep public class pro.curator.antibot.sdk.android.AntiBot { public *; }
-keep public class pro.curator.antibot.sdk.AntiBotConfig { *; }
-keep public class pro.curator.antibot.sdk.AntiBotConfig$Builder { public *; }

# kotlinx.serialization generated serializers for the wire models.
-keepclassmembers class pro.curator.antibot.protocol.** {
    *** Companion;
}
-keepclasseswithmembers class pro.curator.antibot.protocol.** {
    kotlinx.serialization.KSerializer serializer(...);
}
