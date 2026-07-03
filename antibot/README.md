# CURATOR Anti-Bot — Android SDK + Ktor server (reference implementation)

Рабочая реализация мобильного anti-bot ядра из
[`ANTIBOT_ANDROID_SDK_INTERVIEW_GUIDE.md`](../ANTIBOT_ANDROID_SDK_INTERVIEW_GUIDE.md):
Android SDK, который собирает телеметрию, проверяет целостность среды, получает
короткоживущий **trust token** и бесшовно вешает его на сетевые запросы, и
**Ktor-сервер** аттестации, в который этот SDK ходит.

Криптография настоящая и работает end-to-end (ECDH P-256 + HKDF-SHA256 +
AES-256-GCM для «конверта», ES256-подписи, одноразовый nonce + короткий TTL
против replay). Общий модуль `protocol` используется **и клиентом, и сервером**,
поэтому формат на проводе не может «разъехаться».

## Модули

| Модуль | Стек | Собирается без Android SDK | Назначение |
|---|---|---|---|
| `protocol` | Kotlin/JVM, kotlinx.serialization, JCA | ✅ | DTO + криптография (envelope, trust token), общие для клиента и сервера |
| `sdk-core` | Kotlin/JVM, OkHttp, Coroutines | ✅ | Ядро SDK: flow, TokenManager (single-flight + backoff), OkHttp-interceptor |
| `sdk-android` | Android library, Keystore, EncryptedSharedPreferences, Play Integrity | ❌ (нужен Android SDK) | Тонкий Android-слой: телеметрия, детекторы, Keystore, `AntiBot` фасад |
| `server` | Ktor 3, Netty, kotlinx.serialization | ✅ | Сервер аттестации: `/nonce`, `/attest`, `/verify`, risk scoring, выдача токена |

> `sdk-android` автоматически исключается из сборки, если не найден Android SDK
> (см. `settings.gradle.kts`), поэтому `gradle :server:build` и `gradle test`
> работают на обычной JVM/CI. Откройте проект в Android Studio (или задайте
> `ANDROID_HOME`), чтобы собрать Android-модуль.

## Как это отражает гайд

Полный flow (§9 гайда) реализован буквально:

```
bootstrap nonce ──▶ telemetry + integrity ──▶ protected envelope ──▶ attestation ──▶ trust token
   /v1/nonce          AndroidTelemetryProvider    EnvelopeCrypto.seal    /v1/attest       TrustToken
                      AndroidIntegrityProvider    (ECDH+AESGCM+ES256)    RiskEngine
```

- **Клиенту не доверяем, решение на сервере** — детекторы дают *сигналы*, финальное
  решение принимает `RiskEngine` на сервере (§2.3, §12, §19).
- **Replay-защита** — `NonceStore` выдаёт одноразовый nonce с TTL, `consume()`
  атомарно его «съедает» (§8.8).
- **Короткоживущий токен** — `TrustToken` (ES256, TTL по умолчанию 300с),
  проактивное обновление и single-flight в `TokenManager` (§8.7, §13).
- **Бесшовная интеграция** — `AntiBotInterceptor` вешает токен на каждый запрос;
  свой отдельный HTTP-клиент у SDK против рекурсии (§7).
- **Graceful degradation** — `FailureMode.FAIL_OPEN/FAIL_CLOSED`, таймауты,
  backoff+jitter, feature flags (§15).

## Сборка и тесты (JVM, без Android)

```bash
cd antibot
gradle test                 # protocol + sdk-core + server, все тесты
gradle :server:run          # поднять сервер на :8080 (в логах напечатается public key)
```

Что покрыто тестами:
- `protocol` — round-trip envelope, отклонение подделки, неверный ключ, trust token TTL.
- `server` — весь flow через Ktor test host: чистое устройство → токен → защищённый роут;
  reuse nonce → DENY; root+hooking → DENY; запрос без токена → 401.
- `sdk-core` — SDK против фейкового сервера на MockWebServer: `getToken()`, interceptor
  проставляет токен, кеш переиспользуется (одна аттестация на два вызова), fail-open.

## Запуск сервера вручную и проверка

```bash
gradle :server:run
# в логах: "Server public key (configure the SDK with this): <base64url>"

curl -s localhost:8080/health
curl -s localhost:8080/v1/pubkey            # публичный ключ для конфигурации SDK
curl -s -X POST localhost:8080/v1/nonce \
     -H 'Content-Type: application/json' \
     -d '{"sdkVersion":"1.0.0","packageName":"com.example.host"}'
```

Полный envelope-flow удобнее гонять из кода — см. `server/src/test/.../FullFlowTest.kt`
и `sdk-core/src/test/.../SdkCoreFlowTest.kt`.

Стабильный ключ сервера (чтобы токены переживали рестарт) задаётся через env:

```bash
ANTIBOT_SERVER_PRIVATE_KEY=<b64url pkcs8> ANTIBOT_SERVER_PUBLIC_KEY=<b64url x509> \
ANTIBOT_SHADOW_MODE=false gradle :server:run
```

## Интеграция в Android-приложение (integration guide)

```kotlin
// 1) Инициализация (обычно в Application.onCreate). Идемпотентно, берёт applicationContext.
AntiBot.init(
    context = this,
    config = AntiBot.config(
        siteKey = "your-site-key",
        baseUrl = "https://api.curator.pro",
        serverPublicKeyBase64Url = BuildConfig.ANTIBOT_SERVER_KEY, // из /v1/pubkey
    ).failureMode(FailureMode.FAIL_OPEN)
        .requestTimeoutMillis(8_000)
        .debug(BuildConfig.DEBUG)
        .build(),
)

// 2) Одна строка — и все запросы приложения несут trust token.
val http = OkHttpClient.Builder()
    .addInterceptor(AntiBot.interceptor())
    .build()
val retrofit = Retrofit.Builder().client(http).baseUrl("https://api.example.com").build()
```

### Edge cases (обрабатываются)

- **Нет Google Play Services** → `playServicesAvailable=false`, токен Play Integrity
  не запрашивается, сервер делает fallback (reason `INTEGRITY_UNAVAILABLE`).
- **Сервер недоступен / оффлайн** → backoff+jitter, `FAIL_OPEN` не блокирует запрос.
- **Токен протух / отклонён (401/403)** → инвалидация + асинхронное обновление.
- **Часы устройства врут** → timestamp проверяется сервером в окне ±120с; TTL считает сервер.
- **Повторная init()** → безопасно (idempotent).

## Стек

Kotlin 2.1, Ktor 3.0, Coroutines 1.9, kotlinx.serialization 1.7, OkHttp 4.12,
Gradle 8.14 (version catalog), JDK 21. Android: AGP 8.7, minSdk 24, Keystore,
Jetpack Security, Play Integrity.

## Что упрощено (для наглядности, не для прода)

- Play Integrity проверяется заглушкой `RiskEngine.verifyPlayIntegrity` — точка,
  куда подключается реальный серверный вызов Google (нужен Google Cloud проект).
- `NonceStore` и rate-limiting — in-memory; в проде это общий TTL-store (Redis).
- CORS `anyHost()` и незапиненный TLS — только для локального демо.
