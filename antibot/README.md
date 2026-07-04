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
| `demo-app` | Android app, Jetpack Compose, Material3 | ❌ (нужен Android SDK) | Пример хост-приложения: интеграция SDK и весь путь на экране |
| `server` | Ktor 3, Netty, kotlinx.serialization | ✅ | Сервер аттестации: `/nonce`, `/attest`, `/verify`, risk scoring, выдача токена |

> 📖 Подробный разбор кода по шагам (для junior-разработчика, с крипто-ликбезом,
> описанием каждой функции/модели и «почему так») — в
> [`CODE_WALKTHROUGH.md`](CODE_WALKTHROUGH.md).

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

## Play Integrity (полная серверная верификация)

Верификация вердикта Play Integrity реализована полностью на сервере
(`GooglePlayIntegrityVerifier`): реальный вызов Google
`POST /v1/{packageName}:decodeIntegrityToken`, разбор вердиктов
(`appRecognitionVerdict`, `deviceRecognitionVerdict`, `appLicensingVerdict`),
**привязка к nonce** (anti-replay) и к packageName, подача результата в risk scoring.

**Заглушкой оставлена только настройка** — получение OAuth-токена сервисного
аккаунта Google: интерфейс `AccessTokenProvider`. По умолчанию `StubAccessTokenProvider`
(credentials не заданы → Play Integrity gracefully unavailable). Для теста/ручного
запуска можно подставить готовый токен через `StaticAccessTokenProvider` или env
`ANTIBOT_PLAY_INTEGRITY_ACCESS_TOKEN`.

Всё закрыто **фиче-флагами**:
- Сервер: `ANTIBOT_PLAY_INTEGRITY_ENABLED` (по умолчанию `false`),
  `ANTIBOT_REQUIRE_PLAY_INTEGRITY` (жёсткость при отсутствии вердикта).
- Клиент: `FeatureFlags.playIntegrity` — запрашивать ли токен на устройстве.

Клиент (`AndroidIntegrityProvider`) уже запрашивает Play Integrity токен через
`IntegrityManager`, привязывая его к серверному nonce.

## WebView challenge (step-up)

Когда risk score попадает в «средний» диапазон, сервер возвращает
`Decision.CHALLENGE` с объектом `Challenge` (§14 гайда). Дальше:

1. Сервер отдаёт **локальную тестовую HTML-страницу** по
   `GET /v1/challenge/page?cid=…&n=…` (`ChallengePage`). Её JS вычисляет
   `sha256("curator:cid:n")` и возвращает ответ нативу через JS-bridge
   `AntiBotBridge.onChallengeSolved(...)`.
2. `AndroidWebViewChallengeSolver` загружает страницу в WebView (JS только для
   доверенного origin, навигация наружу заблокирована, WebView одноразовый),
   получает ответ.
3. SDK шлёт `POST /v1/challenge/verify`, сервер сверяет ответ и выдаёт trust token.

Страница **локальная и тестовая** — её единственная задача проверить связку
натив ↔ WebView ↔ сервер. Реальный JS-challenge был бы непрозрачным и собирал бы
browser fingerprint. Флаг клиента: `FeatureFlags.webViewChallenge`; на сервере —
`ANTIBOT_CHALLENGE_ENABLED` (при выключении CHALLENGE вырождается в DENY).

Покрыто тестами: `ChallengeAndPlayIntegrityTest` (challenge-flow, неверный ответ,
отдача HTML, парсинг вердикта Google через MockWebServer, DENY при FAILED),
`SdkChallengeTest` (SDK решает challenge через солвер, нет солвера → отказ, флаг off).

## Пример хост-приложения (`demo-app`)

Android-приложение на Jetpack Compose, показывающее интеграцию SDK «вживую».
Экран даёт кнопки на весь путь и лог результата:

1. **Connect & Init** — тянет публичный ключ с `GET /v1/pubkey` и вызывает
   `AntiBot.init(...)` (в проде ключ **пинится** в приложение, а не забирается с
   сервера — это отмечено в коде и на экране).
2. **Get Trust Token** — `AntiBot.getToken()` → показывает токен и срок/или reason code.
3. **Call /v1/protected** — обычный `OkHttpClient` с `AntiBot.interceptor()`
   ходит на защищённый роут; interceptor сам вешает trust token.
4. **Invalidate Token** — сброс токена (демо реакции на 401/протухание).

Запуск:
```bash
# 1) поднять сервер
gradle :server:run
# 2) открыть antibot/ в Android Studio, запустить конфигурацию demo-app на эмуляторе
# 3) в приложении оставить URL http://10.0.2.2:8080 (10.0.2.2 = хост эмулятора) и нажать Connect
```

`demo-app` (как и `sdk-android`) требует Android SDK и автоматически исключается
из чистой JVM-сборки. Разрешён cleartext HTTP только для локального тест-сервера
(`network_security_config.xml`) — в проде только HTTPS (+ pinning).

## Стек

Kotlin 2.1, Ktor 3.0, Coroutines 1.9, kotlinx.serialization 1.7, OkHttp 4.12,
Gradle 8.14 (version catalog), JDK 21. Android: AGP 8.7, minSdk 24, Keystore,
Jetpack Security, Play Integrity.

## Что упрощено (для наглядности, не для прода)

- Play Integrity проверяется заглушкой `RiskEngine.verifyPlayIntegrity` — точка,
  куда подключается реальный серверный вызов Google (нужен Google Cloud проект).
- `NonceStore` и rate-limiting — in-memory; в проде это общий TTL-store (Redis).
- CORS `anyHost()` и незапиненный TLS — только для локального демо.
