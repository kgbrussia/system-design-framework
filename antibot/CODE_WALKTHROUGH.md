# Как работает Anti-Bot SDK — разбор кода по шагам

> **Для кого этот файл.** Для разработчика (в том числе junior), который открыл этот репозиторий и хочет **точно понять, как устроен код**: что делает каждый класс, каждая функция, каждое поле модели, и **почему** сделано именно так. Отдельно и подробно разобрана криптография — с нуля, «на пальцах».
>
> **Как читать.** Идите по порядку. Сначала — общая картина и крипто-ликбез (без него флоу не понять). Потом — **главная часть**: весь путь запроса шаг за шагом, где на каждом шаге показан конкретный код и модели. В конце — справочник «файл за файлом» и раздел «почему так, а не иначе».
>
> Родственные документы: [`README.md`](README.md) — как собрать/запустить; [`../ANTIBOT_ANDROID_SDK_INTERVIEW_GUIDE.md`](../ANTIBOT_ANDROID_SDK_INTERVIEW_GUIDE.md) — теория анти-бота. Здесь — **сам код**.

---

## Оглавление

1. [Общая картина: кто с кем говорит](#1)
2. [Крипто-ликбез с нуля](#2)
3. [Флоу шаг за шагом (главная часть)](#3)
4. [Справочник: файл за файлом](#4)
5. [Почему так, а не иначе (дизайн-решения)](#5)
6. [Глоссарий](#6)

<a id="1"></a>
## 1. Общая картина: кто с кем говорит

Есть три участника:

- **Хост-приложение** — чужое Android-приложение, которое встроило наш SDK (в репозитории его роль играет `demo-app`).
- **SDK** — наша библиотека внутри хоста. Делится на два модуля:
  - `sdk-core` — «мозг» на чистом Kotlin (логика, сеть, токены). Не знает про Android → тестируется на обычной JVM.
  - `sdk-android` — тонкая «обвязка» под Android (сбор данных с устройства, Keystore, WebView).
- **Сервер** (`server`) — бэкенд аттестации на Ktor. Он решает, доверять ли клиенту.

И связующий модуль **`protocol`** — это общий словарь между клиентом и сервером: модели данных (что летит по сети) и криптография. **Один и тот же код** `protocol` подключён и к SDK, и к серверу — поэтому они не могут «разойтись» в формате.

```
         ХОСТ-ПРИЛОЖЕНИЕ (demo-app)
        ┌──────────────────────────────────────┐
        │  sdk-android  (телеметрия, детекторы, │
        │               Keystore, WebView)      │
        │        │                              │
        │        ▼                              │        СЕРВЕР (Ktor)
        │  sdk-core (flow, токены, interceptor) │◄──────►  /v1/nonce
        │        │                              │  HTTP    /v1/attest
        │        ▼                              │          /v1/challenge/*
        │  protocol (модели + крипто) ──────────┼── тот же протокол ──►  protocol (модели + крипто)
        └──────────────────────────────────────┘
```

Весь смысл системы в одной фразе: **клиенту доверять нельзя**. Всё, что делает SDK на телефоне, можно подделать. Поэтому SDK лишь **собирает доказательства** и упаковывает их так, чтобы их было трудно прочитать/подделать/переиграть, а **финальное решение принимает сервер**.

Флоу (упрощённо):

```
[0] AntiBot.init(...)         — хост включает SDK
[1] SDK просит одноразовый nonce у сервера
[2] SDK собирает телеметрию (данные об устройстве/приложении)
[3] SDK проверяет среду (root/эмулятор/отладчик/перехват + Play Integrity)
[4] SDK кладёт всё в «конверт»: шифрует и подписывает, привязывает к nonce
[5] SDK шлёт конверт на /v1/attest
[6] Сервер открывает конверт, проверяет подпись/nonce/время
[7] Сервер считает «риск» и выдаёт короткоживущий trust token (пропуск)
[8] SDK вешает этот токен на каждый обычный запрос приложения (interceptor)
[9] Токен живёт минуты; SDK заранее его обновляет
```

Если риск «средний» — вместо токена сервер может попросить пройти **WebView-челлендж** (шаг 9-бис). Разберём и это.

<a id="2"></a>
## 2. Крипто-ликбез с нуля

Криптография пугает, но здесь используется всего несколько «кубиков». Разберём каждый простыми словами и сразу свяжем с кодом (`protocol/CryptoPrimitives.kt`). **Если понять этот раздел — весь `EnvelopeCrypto` станет очевидным.**

### 2.0 Три задачи, которые вообще решает крипта

1. **Секретность** (чтобы посторонний не прочитал) → *шифрование*.
2. **Целостность + подлинность** (данные не изменили, и они точно от нужного отправителя) → *подпись*.
3. **Свежесть** (это не старая копия, «сыгранная заново») → *nonce + время (TTL)*.

Наш «конверт» использует все три сразу.

### 2.1 Байты и Base64URL — зачем кодировать

Криптография работает с **байтами** (сырыми числами). Но по сети в JSON удобно слать **текст**. Чтобы превратить байты в безопасную текстовую строку, используют **Base64URL** — кодировку, где любые байты становятся строкой из букв/цифр/`-`/`_` (URL-безопасные символы, без `+`, `/`, `=`).

```kotlin
public fun b64UrlEncode(bytes: ByteArray): String = urlEncoder.encodeToString(bytes)
public fun b64UrlDecode(text: String): ByteArray = urlDecoder.decode(text)
```
`urlEncoder = Base64.getUrlEncoder().withoutPadding()` — «withoutPadding» убирает хвостовые `=`, чтобы строка была чище в URL/заголовках. Это **не шифрование** — просто представление байтов текстом. Кодирует/декодирует кто угодно.

### 2.2 Хеш — «отпечаток пальца» данных (SHA-256)

**Хеш-функция** превращает любые данные в короткую строку фиксированной длины (32 байта для SHA-256). Свойства:
- одинаковый вход → всегда одинаковый выход;
- поменяли 1 бит на входе → выход полностью другой;
- по хешу **нельзя** восстановить вход (односторонняя);
- практически невозможно найти два разных входа с одним хешем.

```kotlin
public fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
public fun sha256Hex(data: ByteArray): String = sha256(data).joinToString("") { "%02x".format(it) }
```
`sha256Hex` — тот же хеш, но в виде hex-строки (`"ab3f..."`), удобной для сравнения/логов. В коде хеш используется: как отпечаток сертификата подписи приложения, для вычисления `subject` токена и для тестового challenge-ответа.

> Важно: хеш **сам по себе не секретен** и не доказывает авторство — кто угодно может его пересчитать. Для «данные точно от нужного отправителя» нужен ключ → подпись (2.7).

### 2.3 Симметричное шифрование: AES-256-GCM

**Симметричное** = один и тот же ключ и шифрует, и расшифровывает (как один ключ от замка). **AES** — стандарт шифрования; **256** — длина ключа в битах (32 байта); **GCM** — режим, который даёт не только секретность, но и **целостность** (встроенная проверка, что шифртекст не подменили). Такой режим называют **AEAD**.

```kotlin
public fun aesGcmEncrypt(key: SecretKeySpec, iv: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray
public fun aesGcmDecrypt(key: SecretKeySpec, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray
```
Что за аргументы:
- **key** — секретный ключ (32 байта). У шифрующего и расшифровывающего он должен совпадать.
- **iv (Initialization Vector)** — 12 случайных байт (`aesGcmIv()`), **свои на каждое шифрование**. Зачем: если дважды зашифровать одно и то же одним ключом, но с разными IV — шифртексты будут разными. Это защищает от анализа повторов. IV **не секретен**, его шлют рядом с шифртекстом.
- **aad (Additional Authenticated Data)** — данные, которые **не шифруются**, но «привязываются»: GCM гарантирует, что при расшифровке этот же `aad` был подставлен, иначе — ошибка. Мы кладём в `aad` **nonce** — так шифртекст жёстко привязан к конкретному одноразовому nonce (нельзя переставить в другой запрос).
- **tag** — GCM в конце шифртекста добавляет «печать целостности» (16 байт, `GCM_TAG_BITS=128`). При расшифровке, если хоть один байт шифртекста/aad изменён — расшифровка падает с исключением. Поэтому подделать шифртекст незаметно нельзя.

Константы в коде: `GCM_IV_BYTES=12`, `GCM_TAG_BITS=128`, `AES_KEY_BYTES=32` — это рекомендованные параметры AES-GCM.

Проблема симметрии: обе стороны должны знать один ключ. Как клиент и сервер получат **общий** секретный ключ, ни разу не передав его по сети? Ответ — ECDH (2.5).

### 2.4 Асимметрия: пара ключей и почему EC (эллиптические кривые)

**Асимметричная** крипта = **пара** ключей: **приватный** (секретный, хранит только владелец) и **публичный** (открытый, можно раздавать всем). Они математически связаны: что сделано одним, проверяется/расшифровывается другим, но по публичному **нельзя** вычислить приватный.

Мы используем **EC (Elliptic Curve)** на кривой **P-256** (она же `secp256r1`).

```kotlin
public fun generateEcKeyPair(): KeyPair {
    val gen = KeyPairGenerator.getInstance("EC")
    gen.initialize(ECGenParameterSpec("secp256r1"), secureRandom)
    return gen.generateKeyPair()
}
```
Почему EC, а не RSA: при одинаковой стойкости EC-ключи **гораздо короче** (256 бит EC ≈ 3072 бит RSA) и операции быстрее. На мобильных устройствах это важно (меньше батарея/CPU), и Android Keystore нативно умеет EC. `secureRandom` — криптографически стойкий генератор случайности (нельзя брать обычный `Random`, он предсказуем).

Публичные ключи по сети едут в стандартном формате **X.509** (закодированном Base64URL), приватные (только серверный, для хранения) — в формате **PKCS#8**:
```kotlin
public fun encodePublicKey(key: PublicKey): String = b64UrlEncode(key.encoded)   // X.509
public fun decodePublicKey(encoded: String): PublicKey                            // обратно
public fun encodePrivateKey(key: PrivateKey): String = b64UrlEncode(key.encoded)  // PKCS#8
```

### 2.5 ECDH — как получить общий секрет, не передавая его

Это самый «магический» кубик. **ECDH (Diffie-Hellman на эллиптических кривых)** позволяет двум сторонам вычислить **одинаковый секрет**, обменявшись только **публичными** ключами.

Аналогия с красками: у каждого есть общая база (жёлтая) и свой секретный цвет. Они смешивают базу со своим цветом и обмениваются смесями (публично). Затем каждый добавляет свой секрет к чужой смеси — и оба получают **один и тот же** итоговый цвет, который перехватчик воспроизвести не может (у него нет секретных цветов).

Математически: `ECDH(мой приватный, твой публичный) == ECDH(твой приватный, мой публичный)`. Оба получают одно и то же значение.

```kotlin
public fun ecdh(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
    val ka = KeyAgreement.getInstance("ECDH")
    ka.init(privateKey)
    ka.doPhase(publicKey, true)
    return ka.generateSecret()
}
```
В нашем коде:
- **клиент** делает `ecdh(эфемерный_приватный_клиента, публичный_сервера)`,
- **сервер** делает `ecdh(приватный_сервера, эфемерный_публичный_клиента)`,
- результат — **один и тот же общий секрет**, из которого получится AES-ключ.

«Эфемерный» = одноразовый: клиент генерирует новую EC-пару на каждый конверт. Это даёт **forward secrecy** — даже если позже утечёт какой-то ключ, старые перехваченные конверты не расшифровать, потому что их эфемерные ключи давно выброшены.

### 2.6 HKDF — «причёсываем» секрет в нормальный ключ

Сырой результат ECDH — это точка на кривой, не идеально равномерные байты, и его нельзя напрямую брать как AES-ключ. **HKDF** (key derivation function) «растягивает/выравнивает» секрет в ключ нужной длины, подмешивая контекст.

```kotlin
public fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray
public fun deriveAesKey(sharedSecret: ByteArray, salt: ByteArray, info: ByteArray): SecretKeySpec {
    val keyBytes = hkdfSha256(sharedSecret, salt, info, 32) // 32 байта = AES-256
    return SecretKeySpec(keyBytes, "AES")
}
```
Аргументы:
- **ikm** (input key material) — сырой секрет из ECDH.
- **salt** — «соль», у нас это **nonce**. Значит для каждого nonce получается **другой** AES-ключ, даже если ECDH-секрет совпал.
- **info** — метка контекста: `"curator-antibot/envelope/v1"` (константа `Protocol.ENVELOPE_INFO`). Привязывает ключ к назначению «конверт версии 1», чтобы тот же секрет нельзя было переиспользовать в другом контексте.
- **length=32** — хотим ровно AES-256 ключ.

HKDF внутри — это два шага HMAC-SHA256 (extract → expand), они детерминированы: клиент и сервер из одинаковых входов получат одинаковый ключ.

### 2.7 Подпись ECDSA (ES256) — целостность + подлинность

**Цифровая подпись**: владелец **приватного** ключа «подписывает» данные, а любой обладатель **публичного** ключа может проверить, что подпись настоящая и данные не менялись. Мы используем `SHA256withECDSA` (это и есть «ES256»): сначала данные хешируются SHA-256, потом хеш подписывается EC-приватным ключом.

```kotlin
public fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray
public fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean
```
Чем подпись отличается от MAC/HMAC: для проверки подписи **не нужен секрет**, достаточно публичного ключа. Это важно: сервер подписывает trust token своим приватным ключом, а проверить токен может кто угодно с публичным ключом (например, прикладной бэкенд), не зная секрета.

`verify` обёрнут в `try/catch → false`: любая кривая/битая подпись должна честно вернуть «невалидно», а не уронить процесс.

Где используется:
- **клиент подписывает конверт** своим долгоживущим (identity) ключом → сервер убеждается, что конверт от «того же» клиента и не изменён;
- **сервер подписывает trust token** → все проверяют его публичным ключом.

### 2.8 nonce, TTL и защита от replay

- **nonce** — одноразовое случайное число, которое **выдаёт сервер**. Его цель — «свежесть»: сервер примет ответ, только если он содержит именно этот, недавно выданный nonce, и примет его **ровно один раз**. Это ломает **replay-атаку** (перехватил валидный конверт и шлёшь его снова и снова).
- **TTL (Time To Live)** — срок жизни. У nonce он короткий (минута), у trust token — минуты. Чем короче, тем меньше «окно» для злоупотреблений.
- **timestamp** — клиент кладёт в конверт своё время, сервер проверяет, что оно в пределах окна (±2 минуты). Ещё один барьер против старых копий.

В коде это три независимых барьера, работающих вместе: nonce (одноразовость) + TTL nonce + timestamp-окно.

### 2.9 Как из кубиков собран «конверт» (сводка)

```
Клиент:
  1) взял свежий nonce от сервера
  2) сгенерил эфемерную EC-пару
  3) ECDH(эфемерный.private, сервер.public) → общий секрет
  4) HKDF(секрет, salt=nonce, info="…envelope/v1") → AES-ключ
  5) AES-GCM: шифрует JSON-данные, aad=nonce, свой IV → шифртекст(+tag)
  6) подписал (IV|шифртекст|nonce) своим identity-приватным ключом → signature
  7) отправил: {nonce, эфемерный.public, identity.public, IV, шифртекст, signature}

Сервер:
  1) проверил, что nonce известен, не истёк и не использован (иначе стоп)
  2) проверил signature публичным identity-ключом клиента
  3) ECDH(сервер.private, эфемерный.public) → тот же секрет → тот же AES-ключ
  4) AES-GCM расшифровал (aad=nonce). Если что-то подменено — падает
  5) сверил, что внутри тот же nonce и тот же identity-ключ (защита от подмены полей)
```
Перехватчик (даже сняв TLS) видит только шифртекст, привязанный к одноразовому nonce: прочитать нельзя (нет AES-ключа), подделать нельзя (GCM-tag + подпись), переиграть нельзя (nonce одноразовый + TTL).

Теперь, держа в голове эти кубики, пройдём весь код по шагам.

<a id="3"></a>
## 3. Флоу шаг за шагом (главная часть)

Каждый шаг: **что происходит → какой код → какие модели и зачем их поля.**

### Шаг 0. Инициализация SDK — `AntiBot.init(...)`

Файл: `sdk-android/.../AntiBot.kt`. `AntiBot` — **единственная точка входа** для хоста (объект-синглтон). Хост вызывает это один раз (обычно в `Application.onCreate`).

```kotlin
object AntiBot {
    @Volatile private var client: AntiBotClient? = null

    fun config(siteKey: String, baseUrl: String, serverPublicKeyBase64Url: String): AntiBotConfig.Builder =
        AntiBotConfig.Builder(siteKey, baseUrl, CryptoPrimitives.decodePublicKey(serverPublicKeyBase64Url))

    @Synchronized
    fun init(context: Context, config: AntiBotConfig) {
        if (client != null) return                    // идемпотентность: повторный вызов безопасен
        val appContext = context.applicationContext    // берём application-контекст → нет утечки Activity
        val built = AntiBotClient(
            config = config,
            telemetryProvider = AndroidTelemetryProvider(appContext),
            integrityProvider = AndroidIntegrityProvider(appContext, null, config.featureFlags.playIntegrity),
            clientKeyProvider = KeystoreClientKeyProvider(),
            challengeSolver = AndroidWebViewChallengeSolver(appContext),
            tokenStorage = EncryptedTokenStorage(appContext),
        )
        client = built
        built.warmUp()                                 // сразу в фоне начинаем добывать токен
    }
    fun interceptor(): Interceptor = requireNotNull(client){ "call init() first" }.interceptor()
    suspend fun getToken(): TokenResult = client?.getToken() ?: TokenResult.Failure(SDK_NOT_INITIALIZED, false)
    fun invalidateToken() { client?.invalidateToken() }
    fun isInitialized(): Boolean = client != null
}
```

Что здесь важно и почему:
- **`config(...)`** — удобный конструктор конфига: принимает публичный ключ сервера **строкой** (Base64URL) и сразу превращает его в объект `PublicKey`. Junior-разработчику не надо возиться с криптоклассами.
- **`@Synchronized` + `if (client != null) return`** — **идемпотентность**: даже если хост случайно вызовет `init` дважды/из разных потоков, второй раз ничего не сломается. Для SDK это обязательное свойство.
- **`context.applicationContext`** — берём контекст уровня приложения, а не `Activity`. Если бы держали `Activity`, она не смогла бы освободиться из памяти → **утечка памяти**. Классическая ошибка в SDK.
- **`@Volatile`** — поле `client` пишется в одном потоке, читается в других; `@Volatile` гарантирует видимость записи между потоками.
- Здесь же собирается «дерево» реальных реализаций (телеметрия, детекторы, Keystore, WebView, хранилище) и отдаётся в платформо-независимый `AntiBotClient`. **Вся логика — в `sdk-core`; `sdk-android` только поставляет платформенные детали.** Это и делает ядро тестируемым.
- **`warmUp()`** запускает получение токена сразу в фоне, чтобы к моменту первого реального запроса токен уже был готов (interceptor не будет ждать).

`AntiBotConfig` (модель конфигурации, `sdk-core/Api.kt`) — почему такие поля:

| Поле | Тип | Зачем |
|---|---|---|
| `siteKey` | String | идентификатор клиента/сайта у CURATOR |
| `baseUrl` | String | адрес сервера аттестации (в конструкторе `trimEnd('/')`, чтобы не было двойных `//`) |
| `serverPublicKey` | PublicKey | ключ, которым шифруем конверт и проверяем trust token |
| `requestTimeoutMillis` | Long (8000) | таймаут сетевых вызовов — SDK не должен «подвешивать» приложение |
| `failureMode` | FailureMode (FAIL_OPEN) | что делать, если токена нет: пропускать или блокировать |
| `refreshSkewMillis` | Long (60000) | за сколько до истечения обновлять токен заранее |
| `interceptorWaitMillis` | Long (1500) | сколько interceptor готов подождать токен на «холодном старте» |
| `maxRetries` | Int (3) | сколько раз повторять при сетевых сбоях |
| `debug` | Boolean | подробные логи (в релизе — молчок) |
| `featureFlags` | FeatureFlags | удалённые переключатели фич |

Конфиг **неизменяемый** и строится через **Builder** — это позволяет добавлять новые опции в будущем, не ломая существующий код хоста (обратная совместимость).

`FeatureFlags` — почему нужны: чтобы **включать/выключать части SDK без перевыпуска приложения** (в проде значения приходят с сервера). Поля: `collectTelemetry`, `runIntegrityChecks`, `attachTokenHeader`, `playIntegrity` (запрашивать ли Play Integrity), `webViewChallenge` (решать ли WebView-челленджи). Это «предохранители»: если новая проверка ломает продакшн — её гасят флагом (kill switch).

---

### Шаг 1. Bootstrap nonce — просим у сервера одноразовое число

**Клиент** (`sdk-core/AttestationClient.kt`, метод `requestNonce`):
```kotlin
private fun requestNonce(packageName: String): NonceResponse? {
    val body = AntiBotJson.encodeToString(NonceRequest(BuildInfo.SDK_VERSION, packageName)).toRequestBody(jsonMedia)
    val request = Request.Builder().url(config.baseUrl + Protocol.PATH_NONCE).post(body).build()
    http.newCall(request).execute().use { resp ->
        if (!resp.isSuccessful) return null
        return AntiBotJson.decodeFromString<NonceResponse>(resp.body?.string() ?: return null)
    }
}
```
**Сервер** (`server/Application.kt`, роут `POST /v1/nonce`) зовёт `NonceStore.issue()`:
```kotlin
fun issue(): Pair<String, Long> {
    purgeExpired()
    val nonce = CryptoPrimitives.b64UrlEncode(CryptoPrimitives.randomBytes(32)) // 32 случайных байта
    val expiresAt = clock() + ttlMillis                                          // живёт 60 сек
    entries[nonce] = Entry(expiresAt)                                            // запоминаем
    return nonce to expiresAt
}
```

Модели:
- **`NonceRequest(sdkVersion, packageName)`** — клиент представляется: какая версия SDK и какое приложение. По `packageName` сервер понимает, для какого приложения выдавать/проверять.
- **`NonceResponse(nonce, issuedAt, expiresAt, protocolVersion)`** — `nonce` (Base64URL 32 байта), время выдачи и истечения (чтобы клиент знал срок), `protocolVersion` (клиент сверяет, что говорит с сервером той же версии протокола).

Почему nonce именно **32 случайных байта**: этого достаточно, чтобы его невозможно было угадать/подобрать. `NonceStore` держит выданные nonce в потокобезопасной `ConcurrentHashMap` и удаляет просроченные (`purgeExpired`). **Одноразовость** обеспечит `consume` на шаге 6.

> Зачем вообще этот шаг первым: чтобы всё дальнейшее доказательство было **привязано к свежему nonce**. Без него бот заготовил бы один валидный ответ и слал его вечно (replay).

---

### Шаг 2. Сбор телеметрии — `AndroidTelemetryProvider.collect()`

Файл: `sdk-android/.../AndroidTelemetryProvider.kt`. Собирает **компактный** набор сигналов об устройстве и приложении. Каждый сбор обёрнут в `safe { }` (try/catch), чтобы отсутствие сигнала давало `"unknown"`, а не крэш.

```kotlin
override fun collect(): Telemetry {
    val (versionName, versionCode) = versionInfo(pm, pkg)
    return Telemetry(
        packageName = pkg,
        appVersionName = versionName, appVersionCode = versionCode,
        signingCertSha256 = signingCertSha256(pm, pkg),   // отпечаток сертификата подписи APK
        sdkVersion = BuildInfo.SDK_VERSION,
        osSdkInt = Build.VERSION.SDK_INT, osRelease = Build.VERSION.RELEASE ?: "unknown",
        deviceModel = Build.MODEL, deviceManufacturer = Build.MANUFACTURER, deviceBrand = Build.BRAND,
        buildFingerprint = Build.FINGERPRINT, hardware = Build.HARDWARE,
        locale = Locale.getDefault().toString(), timeZone = TimeZone.getDefault().id,
        debuggable = (applicationInfo.flags and FLAG_DEBUGGABLE) != 0,
    )
}
```

Модель **`Telemetry`** — разбор каждого поля и зачем оно серверу:

| Поле | Что это | Зачем анти-боту |
|---|---|---|
| `packageName` | id приложения (`com.bank.app`) | понять, какое приложение; сверить с ожидаемым |
| `appVersionName` / `appVersionCode` | версия приложения | старые/странные версии — сигнал |
| `signingCertSha256` | SHA-256 сертификата, которым подписан APK | **ловит пересборку/клон**: пересобрали APK → подпись другая → хеш другой |
| `sdkVersion` | версия нашего SDK | совместимость и диагностика |
| `osSdkInt` / `osRelease` | версия Android | несочетаемые версии — сигнал |
| `deviceModel/Manufacturer/Brand` | модель/производитель | распознать фермы одинаковых «устройств» |
| `buildFingerprint` / `hardware` | строка сборки ОС, железо | ловит эмуляторы (`generic`, `goldfish`) |
| `locale` / `timeZone` | локаль, часовой пояс | аномалии/несоответствия |
| `debuggable` | собрано ли приложение отлаживаемым | релизное приложение не должно быть debuggable |

Как считается **`signingCertSha256`** (важный сигнал, `signingCertSha256()`):
```kotlin
val certBytes = if (SDK_INT >= P)
    pm.getPackageInfo(pkg, GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners?.first()?.toByteArray()
else
    pm.getPackageInfo(pkg, GET_SIGNATURES).signatures?.first()?.toByteArray()
certBytes?.let { CryptoPrimitives.sha256Hex(it) } ?: "unknown"
```
На Android 9+ (`SDK_INT >= P`) используется новый API `GET_SIGNING_CERTIFICATES`, на старых — устаревший `GET_SIGNATURES` (поэтому `@Suppress("DEPRECATION")`). Сервер сравнивает этот хеш с **ожидаемым** — сравнение делает сервер, не клиент (клиенту не доверяем).

> Принципы: **никаких персональных данных** (нет IMEI, номеров, контактов) и **никаких runtime-permissions** — всё берётся из `Build`/`PackageManager`, доступных без разрешений. Это и приватно, и не мешает интеграции.

---

### Шаг 3. Проверка среды — `AndroidIntegrityProvider.verdict(nonce)`

Файл: `sdk-android/.../AndroidIntegrityProvider.kt`. Объединяет **локальные детекторы** и **Play Integrity**, всё привязано к `nonce`.

```kotlin
override suspend fun verdict(nonce: String): IntegrityVerdict {
    val root = safeDetect { RootDetector.detect(context) }
    val emulator = safeDetect { EmulatorDetector.detect() }
    val debugger = safeDetect { DebuggerDetector.detect(context) }
    val hooking = safeDetect { HookingDetector.detect() }
    val playAvailable = isPlayServicesAvailable()
    val playToken = if (playIntegrityEnabled && playAvailable) requestPlayIntegrityToken(nonce) else null
    return IntegrityVerdict(
        rooted = root.detected, emulator = emulator.detected,
        debuggerAttached = debugger.detected, hookingDetected = hooking.detected,
        playServicesAvailable = playAvailable, playIntegrityToken = playToken,
        detectorNotes = /* все «улики» для наблюдаемости */,
    )
}
```
`safeDetect { }` гарантирует, что упавший детектор → «не обнаружено», а не крэш всего флоу.

**Детекторы** (`Detectors.kt`) — каждый ищет несколько независимых признаков и возвращает `DetectionResult(detected, notes)`:
- **`RootDetector`** — файлы `su` в системных путях, приложения-суперюзеры (`com.topjohnwu.magisk`), `test-keys` в сборке, возможность записи в `/system`, `which su`.
- **`EmulatorDetector`** — признаки в `Build.FINGERPRINT/MODEL/PRODUCT` (`generic`, `emulator`, `sdk_gphone`), `Build.HARDWARE` (`goldfish`, `ranchu` — это QEMU), файлы вроде `/dev/qemu_pipe`.
- **`DebuggerDetector`** — `Debug.isDebuggerConnected()`, флаг `FLAG_DEBUGGABLE`, и `TracerPid` из `/proc/self/status` (если ≠ 0, кто-то трейсит процесс — отладчик).
- **`HookingDetector`** — подозрительные строки в `/proc/self/maps` (`frida`, `xposed`), файлы `frida-server`, класс `de.robv.android.xposed.XposedBridge`, потоки `gum-js` (Frida).

**Ключевая идея (проговорена в комментарии кода):** каждый детектор — это **сигнал, а не приговор**. На своём устройстве атакующий любой из них обойдёт. Поэтому SDK **не блокирует локально** — он лишь честно сообщает результаты серверу, а решение принимает `RiskEngine`. Много независимых признаков + серверное решение = дорого обходить.

Модель **`IntegrityVerdict`**:

| Поле | Зачем |
|---|---|
| `rooted` / `emulator` / `debuggerAttached` / `hookingDetected` | булевы итоги детекторов — входы для risk scoring |
| `playServicesAvailable` | есть ли Google Play (для graceful degradation) |
| `playIntegrityToken` | подписанный Google вердикт (проверяется на сервере), `null` если недоступен |
| `detectorNotes` | список конкретных «улик» — для отладки и наблюдаемости, не для решения |

**Play Integrity на клиенте** (`requestPlayIntegrityToken`) — запрашивает у Google токен, привязанный к нашему `nonce`:
```kotlin
val manager = IntegrityManagerFactory.create(context)
val req = IntegrityTokenRequest.builder().setNonce(nonce)...build()
suspendCancellableCoroutine { cont ->
    manager.requestIntegrityToken(req)
        .addOnSuccessListener { cont.resume(it.token()) }
        .addOnFailureListener { cont.resume(null) }  // недоступен → null, не крэш
}
```
Здесь Google API отдаёт результат через колбэки (Task); `suspendCancellableCoroutine` превращает колбэки в удобный `suspend`-вызов. `nonce` передаётся Google, чтобы вердикт нельзя было переиграть. Расшифровку/проверку самого токена делает **сервер** (шаг 6-бис) — клиент только пересылает.

---

### Шаг 4. Сборка и запечатывание «конверта»

**Клиент** (`AttestationClient.obtainToken`) собирает `EnvelopePayload` и запечатывает его:
```kotlin
val identity = clientKeyProvider.identityKeyPair()             // долгоживущий ключ клиента (Keystore)
val payload = EnvelopePayload(
    nonce = nonceResp.nonce,
    timestamp = clock.nowMillis(),
    clientIdPublicKey = CryptoPrimitives.encodePublicKey(identity.public),
    telemetry = telemetry,
    integrity = integrity,
)
val envelope = EnvelopeCrypto.seal(payload, config.serverPublicKey, identity.private, identity.public)
```

Модель **`EnvelopePayload`** — это **открытый текст**, который зашифруется:

| Поле | Зачем |
|---|---|
| `nonce` | тот самый серверный nonce (свежесть/привязка) |
| `timestamp` | время клиента — сервер проверит окно ±2 мин |
| `clientIdPublicKey` | публичный identity-ключ клиента; сервер сверит его с тем, что подписал конверт |
| `telemetry` | данные шага 2 |
| `integrity` | вердикты шага 3 |
| `protocolVersion` | версия формата |

Откуда берётся identity-ключ клиента — **`KeystoreClientKeyProvider`** (`sdk-android`):
```kotlin
override fun identityKeyPair(): KeyPair = loadExisting() ?: generate()
private fun generate(): KeyPair {
    val spec = KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(DIGEST_SHA256).build()
    KeyPairGenerator.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair()
}
```
Почему так: ключ создаётся **внутри Android Keystore** и **не покидает** защищённую зону (TEE). Мы держим только «ручку»; когда `CryptoPrimitives.sign` подписывает конверт, операция происходит **внутри** Keystore. Назначение `PURPOSE_SIGN` — этот ключ только для подписи. (Эфемерный ECDH-ключ, наоборот, генерится в софте внутри `seal`, потому что одноразовый.)

Теперь **`EnvelopeCrypto.seal`** — построчно (это применение крипто-кубиков из раздела 2):
```kotlin
fun seal(payload, serverPublicKey, clientIdentityPrivateKey, clientIdentityPublicKey): SealedEnvelope {
    val nonceBytes = b64UrlDecode(payload.nonce)                       // (a)
    val ephemeral = generateEcKeyPair()                               // (b) одноразовая EC-пара
    val shared = ecdh(ephemeral.private, serverPublicKey)             // (c) общий секрет с сервером
    val aesKey = deriveAesKey(shared, salt = nonceBytes, info = ENVELOPE_INFO) // (d) HKDF → AES-256
    val plaintext = AntiBotJson.encodeToString(payload).toByteArray() // (e) JSON → байты
    val iv = aesGcmIv()                                               // (f) случайный IV
    val ciphertext = aesGcmEncrypt(aesKey, iv, plaintext, aad = nonceBytes)     // (g) шифруем, nonce в aad
    val toSign = iv + ciphertext + nonceBytes                         // (h)
    val signature = sign(clientIdentityPrivateKey, toSign)            // (i) подпись identity-ключом
    return SealedEnvelope(VERSION, payload.nonce,
        encodePublicKey(ephemeral.public), encodePublicKey(clientIdentityPublicKey),
        b64UrlEncode(iv), b64UrlEncode(ciphertext), b64UrlEncode(signature))
}
```
- (a) nonce переводим в байты — он будет и «солью» HKDF, и `aad` шифрования.
- (b)-(d) получаем секретный AES-ключ **из воздуха**: клиент и сервер вычислят один и тот же ключ через ECDH+HKDF, ни разу не передав его. Эфемерная пара → forward secrecy.
- (e)-(g) шифруем данные; `aad=nonce` намертво привязывает шифртекст к этому nonce.
- (h)-(i) подписываем `IV|шифртекст|nonce`, чтобы сервер до расшифровки убедился: конверт от нужного клиента и не изменён.

Модель **`SealedEnvelope`** — это то, что реально летит по сети (всё, кроме версии/nonce, — Base64URL):

| Поле | Зачем |
|---|---|
| `protocolVersion` | версия формата (сервер отвергнет чужую) |
| `nonce` | какой nonce используется (эхо; сервер сверит с внутренним) |
| `ephemeralPublicKey` | эфемерный публичный ключ клиента — сервер сделает им ECDH |
| `clientIdPublicKey` | долгоживущий публичный ключ клиента — сервер проверит подпись |
| `iv` | вектор инициализации для расшифровки |
| `ciphertext` | зашифрованные данные (с GCM-tag внутри) |
| `signature` | подпись (IV|ciphertext|nonce) |

> Почему подпись покрывает `iv+ciphertext+nonce`, а не сам payload: подпись должна проверяться **до** расшифровки (сначала аутентифицируем отправителя, потом тратим ресурсы на расшифровку). А содержимое всё равно защищено GCM-tag внутри шифртекста.

---

### Шаг 5. Отправка на аттестацию — `postAttest`

```kotlin
private fun postAttest(envelope: SealedEnvelope): AttestationResponse? {
    val body = AntiBotJson.encodeToString(envelope).toRequestBody(jsonMedia)
    val request = Request.Builder().url(config.baseUrl + Protocol.PATH_ATTEST)
        .header(Protocol.PROTOCOL_VERSION_HEADER, Protocol.VERSION.toString()).post(body).build()
    http.newCall(request).execute().use { resp -> return decode<AttestationResponse>(resp) }
}
```
Отправляется на `POST /v1/attest`. Обратите внимание: `http` здесь — **отдельный** OkHttp-клиент внутри `AttestationClient`, **без** нашего interceptor. Иначе получилась бы бесконечная рекурсия (interceptor → нужен токен → запрос за токеном → interceptor → …). Это важное дизайн-решение (гайд §7.4).

---

### Шаг 6. Сервер открывает конверт — `AttestationService.attest` + `EnvelopeCrypto.open`

Файл: `server/AttestationService.kt`. `attest` — `suspend`, потому что внутри может быть сетевой вызов к Google.
```kotlin
suspend fun attest(env: SealedEnvelope): AttestationResponse {
    // 1) nonce: известен, не истёк, НЕ использован — и сразу «съедаем» его
    when (val consumed = nonceStore.consume(env.nonce)) {
        is Rejected -> return deny(consumed.reason)
        Ok -> Unit
    }
    // 2) открываем конверт (подпись + расшифровка + сверка полей)
    val opened = when (val r = EnvelopeCrypto.open(env, serverKeys.private)) {
        is Failure -> return deny(r.reason); is Ok -> r.opened
    }
    val payload = opened.payload
    // 3) окно времени (свежесть)
    if (abs(now - payload.timestamp) > timestampWindowMillis) return deny(TIMESTAMP_OUT_OF_WINDOW)
    // 4) Play Integrity (если включён флагом)
    val pi = if (riskConfig.playIntegrityEnabled) verifyPI(payload) else null
    // 5) risk scoring
    val assessment = riskEngine.assess(payload, pi)
    // 6) решение → токен / челлендж / отказ
    ...
}
```

**`NonceStore.consume`** — сердце защиты от replay:
```kotlin
fun consume(nonce: String): ConsumeResult {
    val entry = entries.remove(nonce) ?: return Rejected(NONCE_UNKNOWN) // нет или УЖЕ использован
    return if (clock() >= entry.expiresAt) Rejected(NONCE_EXPIRED) else Ok
}
```
`remove` **атомарно** извлекает и удаляет запись: если два запроса придут с одним nonce, `remove` вернёт запись только первому, второму — `null` → `NONCE_UNKNOWN`. Так nonce работает **ровно один раз**.

**`EnvelopeCrypto.open`** — зеркало `seal` (построчно):
```kotlin
fun open(env, serverPrivateKey): OpenResult {
    if (env.protocolVersion != VERSION) return Failure(PROTOCOL_MISMATCH)
    val nonceBytes = b64UrlDecode(env.nonce)
    val clientIdPub = decodePublicKey(env.clientIdPublicKey)
    val iv = b64UrlDecode(env.iv); val ct = b64UrlDecode(env.ciphertext); val sig = b64UrlDecode(env.signature)
    // 1) аутентификация отправителя + целостность запечатанных байт
    if (!verify(clientIdPub, iv + ct + nonceBytes, sig)) return Failure(BAD_SIGNATURE)
    // 2) ECDH с эфемерным ключом клиента → тот же AES-ключ → расшифровка
    val shared = ecdh(serverPrivateKey, decodePublicKey(env.ephemeralPublicKey))
    val aesKey = deriveAesKey(shared, salt = nonceBytes, info = ENVELOPE_INFO)
    val payload = decode(aesGcmDecrypt(aesKey, iv, ct, aad = nonceBytes))   // упадёт, если подменено
    // 3) привязка: внутри должен быть тот же nonce и тот же identity-ключ
    if (payload.nonce != env.nonce) return Failure(NONCE_UNKNOWN)
    if (payload.clientIdPublicKey != env.clientIdPublicKey) return Failure(BAD_SIGNATURE)
    return Ok(OpenedEnvelope(payload, clientIdPub))
}
```
Три уровня проверки: **подпись** (кто отправил и не изменён ли), **расшифровка с GCM-tag** (целостность содержимого + секретность), **сверка полей** (нельзя подставить чужой nonce/ключ). Любая ошибка → `Failure(reason)` → сервер отвечает `DENY` с этим reason.

`OpenResult` — `sealed interface` c `Ok(opened)` / `Failure(reason)`: явные варианты, компилятор заставляет обработать оба.

---

### Шаг 6-бис. Верификация Play Integrity на сервере — `GooglePlayIntegrityVerifier`

Файл: `server/PlayIntegrity.kt`. Включается флагом `playIntegrityEnabled`. Делает **реальный** запрос к Google и разбирает вердикт; заглушкой оставлено **только получение учётных данных** (`AccessTokenProvider`).

```kotlin
override suspend fun verify(token, expectedNonce, packageName): PlayIntegrityAssessment {
    val accessToken = accessTokenProvider.accessToken()
        ?: return PlayIntegrityAssessment(UNAVAILABLE, note = "no-credentials-configured") // заглушка настройки
    val url = "$apiBaseUrl/v1/$packageName:decodeIntegrityToken"
    val response = httpClient.send(POST(url, {"integrity_token": token}, Bearer accessToken), ...)
    val decoded = AntiBotJson.decodeFromString<DecodeResponse>(response.body())
    return evaluate(decoded, expectedNonce, packageName)
}
```
`evaluate` разбирает вердикт Google и **привязывает его к нашему nonce**:
```kotlin
if (request.nonce != expectedNonce) return FAILED("nonce-mismatch")            // анти-replay
if (request.requestPackageName != packageName) return FAILED("package-mismatch")
val appOk = appVerdict == "PLAY_RECOGNIZED"                                     // приложение из Play
val deviceOk = deviceVerdicts.any { it == "MEETS_DEVICE_INTEGRITY" || "MEETS_STRONG_INTEGRITY" }
status = if (appOk && deviceOk) PASSED else FAILED
```
Почему проверка nonce критична: Google подписывает вердикт и вкладывает в него тот nonce, что мы передали на клиенте. Сверяя `request.nonce == expectedNonce`, сервер убеждается, что вердикт **свежий и наш**, а не переигранный.

- **`AccessTokenProvider`** (заглушка настройки): `StubAccessTokenProvider` возвращает `null` (креды не заданы → gracefully UNAVAILABLE); `StaticAccessTokenProvider` — для теста/ручного запуска можно подставить готовый OAuth-токен. В проде сюда подключают минтер токена сервисного аккаунта Google.
- **`DisabledPlayIntegrityVerifier`** — используется, когда флаг выключен.
- `httpClient` и `apiBaseUrl` — инъекции: в тесте `apiBaseUrl` указывает на MockWebServer, и мы проверяем разбор реального ответа Google без самого Google.

`PlayIntegrityAssessment(status, appVerdict, deviceVerdicts, licensingVerdict, note)` — итог: `PASSED`/`FAILED`/`UNAVAILABLE` плюс детали для наблюдаемости.

---

### Шаг 7. Risk scoring — `RiskEngine.assess`

Файл: `server/RiskEngine.kt`. Превращает сигналы в **число риска**, а число — в решение. Никаких «бот/не бот» напрямую.
```kotlin
fun assess(payload: EnvelopePayload, playIntegrity: PlayIntegrityAssessment?): Assessment {
    var score = 0
    if (integrity.rooted)           { score += 45; reasons += ROOT_DETECTED }
    if (integrity.emulator)         { score += 35; reasons += EMULATOR_DETECTED }
    if (integrity.debuggerAttached) { score += 30; reasons += DEBUGGER_DETECTED }
    if (integrity.hookingDetected)  { score += 55; reasons += HOOKING_DETECTED }
    if (telemetry.debuggable)       { score += 10 }
    when (playIntegrity?.status) {                          // null = фича выключена, не учитываем
        PASSED      -> score -= 20                          // сильный сигнал доверия снижает риск
        FAILED      -> { score += 50; reasons += PLAY_INTEGRITY_FAILED }
        UNAVAILABLE -> { reasons += INTEGRITY_UNAVAILABLE; score += if (requirePlayIntegrity) 40 else 15 }
        null        -> {}
    }
    score = score.coerceIn(0, 100)
    decision = when { score >= 70 -> DENY; score >= 40 -> CHALLENGE; else -> ALLOW }
    if (decision == CHALLENGE && !challengeEnabled) decision = DENY   // если челленджи выключены
    ...
}
```
Почему **веса** такие: hooking (55) опаснее всего — активный перехват; root (45) — среда скомпрометирована; эмулятор (35) и отладчик (30) — сильные, но бывают у легитимных разработчиков; `debuggable` (10) — слабый сигнал. Play Integrity `PASSED` **снижает** риск (−20), потому что это самый надёжный, подписанный Google сигнал.

**Пороги** `RiskConfig`: `< 40` → `ALLOW`, `40..69` → `CHALLENGE`, `>= 70` → `DENY`. `coerceIn(0,100)` держит счёт в диапазоне.

Флаги в `RiskConfig`: `playIntegrityEnabled`, `requirePlayIntegrity` (жёсткость при отсутствии вердикта), `challengeEnabled`, `shadowMode`. **Shadow-режим** (`shadowMode=true`): движок считает решение, но **возвращает ALLOW**, лишь помечая `shadowed=true`. Это для безопасной выкатки: собрать статистику ложных срабатываний, никого не заблокировав.

`Assessment(decision, level, reasons, score, shadowed)` — итог: решение, уровень риска (`LOW/MEDIUM/HIGH`), список reason codes (почему), сам счёт, и был ли это shadow.

---

### Шаг 8. Выдача trust token — `AttestationService.allow` + `TrustToken.issue`

При `ALLOW` сервер выдаёт короткоживущий подписанный «пропуск».
```kotlin
private fun allow(clientIdPublicKey, level, reasons, shadow): AttestationResponse {
    val nowSec = clock() / 1000
    val claims = TrustTokenClaims(
        sub = subjectFor(clientIdPublicKey),   // sha256(pubkey).take(24) — стабильный, но не раскрывает ключ
        iss = "curator-antibot", iat = nowSec, exp = nowSec + tokenTtlSeconds,  // TTL = 300 сек
        lvl = level, jti = UUID.randomUUID().toString(),  // уникальный id токена
    )
    return AttestationResponse(ALLOW, level, reasons,
        trustToken = TrustToken.issue(claims, serverKeys.private), ttlSeconds = tokenTtlSeconds, shadow = shadow)
}
```
Модель **`TrustTokenClaims`** (что «зашито» в токен):

| Поле | Зачем |
|---|---|
| `sub` (subject) | кто владелец: `sha256(clientPubKey).take(24)` — привязка к клиенту без раскрытия ключа |
| `iss` (issuer) | кто выдал (`curator-antibot`) |
| `iat` (issued at) | когда выдан (сек) |
| `exp` (expiry) | когда истекает (сек) — короткий TTL |
| `lvl` | уровень доверия (LOW/MEDIUM/HIGH) |
| `jti` (JWT ID) | уникальный id — помогает учитывать/инвалидировать токены |

**`TrustToken.issue`** — компактный JWT-подобный токен:
```kotlin
fun issue(claims, serverPrivateKey): String {
    val headerB64 = b64Url("""{"alg":"ES256","typ":"CTT"}""")
    val claimsB64 = b64Url(json(claims))
    val signingInput = "$headerB64.$claimsB64"
    val sig = sign(serverPrivateKey, signingInput.toByteArray())
    return "$signingInput.${b64Url(sig)}"          // header.claims.signature
}
```
Формат `header.claims.signature` (как JWT). Подпись покрывает `header.claims`. Так любой с публичным ключом сервера проверит подлинность токена и не сможет его подделать. `alg:ES256` = та же подпись EC-SHA256.

Модель **`AttestationResponse`** — единый ответ на `/v1/attest` (и на `/v1/challenge/verify`):

| Поле | Зачем |
|---|---|
| `decision` | ALLOW / CHALLENGE / DENY |
| `riskLevel` | уровень риска |
| `reasonCodes` | список причин (наблюдаемость/поддержка) |
| `trustToken` | сам токен (при ALLOW), иначе `null` |
| `ttlSeconds` | сколько токен живёт |
| `shadow` | сработал ли shadow-режим |
| `challenge` | объект челленджа (при CHALLENGE), иначе `null` |

---

### Шаг 9. (Ветка) WebView-челлендж — если риск «средний»

Если `decision == CHALLENGE`, сервер вместо токена возвращает `Challenge` и заводит запись в `ChallengeStore`:
```kotlin
Decision.CHALLENGE -> {
    val issued = challengeStore.issue(payload.clientIdPublicKey)   // одноразовый, привязан к клиенту
    val pageUrl = "${PATH_CHALLENGE_PAGE}?cid=${issued.challengeId}&n=${issued.challengeNonce}"
    AttestationResponse(CHALLENGE, ..., challenge = Challenge(issued.challengeId, issued.challengeNonce, pageUrl, issued.expiresAt))
}
```
Модель **`Challenge`**: `challengeId` (id задачи), `challengeNonce` (случайное значение для ответа), `pageUrl` (адрес тестовой страницы), `expiresAt` (срок).

**`ChallengeStore`** (`server/ChallengeStore.kt`) — как `NonceStore`, но привязывает челлендж к `clientIdPublicKey`: `consume(challengeId, clientId)` вернёт `Ok` только если тот же клиент и не истекло/не использовано. Значит чужой не решит твой челлендж.

**Что происходит на клиенте** (`AttestationClient.handleChallenge`):
```kotlin
if (!config.featureFlags.webViewChallenge || challenge == null) return Rejected(CHALLENGE_REQUIRED)
when (val solved = challengeSolver.solve(challenge, config.baseUrl)) {
    is Failed -> Rejected(solved.reason)
    is Solved -> {
        val solution = ChallengeSolution(challenge.challengeId, solved.answer, encodePublicKey(identity.public))
        val verifyResp = postChallengeVerify(solution)     // POST /v1/challenge/verify
        if (verifyResp.decision == ALLOW) Token(verifyResp.trustToken, verifyResp.ttlSeconds) else Rejected(...)
    }
}
```
**`AndroidWebViewChallengeSolver`** (`sdk-android`) — грузит тестовую страницу в WebView и получает ответ через JS-мост:
```kotlin
val webView = WebView(context)
webView.settings.javaScriptEnabled = true                // JS только для нашей доверенной страницы
webView.addJavascriptInterface(object {
    @JavascriptInterface fun onChallengeSolved(answer: String) { deferred.complete(answer) }
}, "AntiBotBridge")
webView.webViewClient = object : WebViewClient() {         // блокируем любую навигацию наружу
    override fun shouldOverrideUrlLoading(...): Boolean = !target.startsWith(baseUrl)
}
webView.loadUrl(url)
val answer = withTimeoutOrNull(timeoutMillis) { deferred.await() }
webView.destroy()                                          // одноразовый WebView, уничтожаем
```
Безопасность WebView (комментарий в коде): JS включён только для загрузки **нашей** страницы; навигация на чужие origin заблокирована — значит JS-мост не достанется недоверенному контенту (классический риск `addJavascriptInterface`). WebView одноразовый и уничтожается.

**Тестовая страница** (`server/ChallengePage.kt`, отдаётся по `GET /v1/challenge/page`): в ней встроенный JS считает `sha256("curator:cid:n")` и возвращает ответ через `AntiBotBridge.onChallengeSolved(...)`. Это **специально воспроизводимая** тестовая задача — её единственная цель проверить связку **натив ↔ WebView ↔ сервер**. Реальный челлендж был бы непрозрачным и собирал бы browser fingerprint.

`ChallengeCrypto.expectedAnswer(cid, cnonce) = sha256Hex("curator:$cid:$cnonce")` — **одна и та же** формула в Kotlin (сервер) и в JS (страница). Сервер на `/v1/challenge/verify` пересчитывает ожидаемый ответ и сравнивает **в постоянном времени** (`constantTimeEquals`, чтобы не утекало по времени сравнения), и при совпадении выдаёт токен (`RiskLevel.MEDIUM`, т.к. клиент прошёл усиленную проверку).

Модель **`ChallengeSolution`**: `challengeId`, `answer`, `clientIdPublicKey` (сервер сверит, что решает тот же клиент).

---

### Шаг 10. Использование токена — `AntiBotInterceptor`

Файл: `sdk-core/AntiBotInterceptor.kt`. Это «одна строчка интеграции»: хост добавляет interceptor в свой OkHttp — и все запросы автоматически несут trust token.
```kotlin
override fun intercept(chain): Response {
    val original = chain.request()
    if (!config.featureFlags.attachTokenHeader) return chain.proceed(original)
    val token = resolveToken()
    val request = if (token != null)
        original.newBuilder().header(TRUST_TOKEN_HEADER, token).header(PROTOCOL_VERSION_HEADER, "1").build()
    else {
        if (config.failureMode == FAIL_CLOSED) return failClosedResponse(chain)  // 428, не пускаем
        original                                                                 // FAIL_OPEN: пускаем без токена
    }
    val response = chain.proceed(request)
    if (response.code == 401 || response.code == 403) {                          // сервер отклонил токен
        tokenManager.invalidate()
        scope.launch(Dispatchers.IO) { tokenManager.forceRefresh() }             // обновим в фоне
    }
    return response
}
private fun resolveToken(): String? {
    tokenManager.cachedTokenOrNull()?.let { return it }        // быстрый путь: готовый токен из кеша
    return runBlocking { withTimeoutOrNull(config.interceptorWaitMillis) {       // холодный старт: ждём чуть-чуть
        (tokenManager.getToken() as? TokenResult.Success)?.token
    } }
}
```
Ключевые решения:
- **Быстрый путь** — `cachedTokenOrNull()` не блокирует: если токен уже есть, просто вешаем его. Тяжёлую работу interceptor **не** делает.
- **Холодный старт** — если токена ещё нет, `runBlocking` с **ограниченным** таймаутом (`interceptorWaitMillis`, 1.5с): либо успеем получить, либо идём дальше. Никакого бесконечного ожидания.
- **FAIL_OPEN / FAIL_CLOSED** — компромисс «не мешать пользователю» vs «строгая безопасность». По умолчанию FAIL_OPEN: наш сбой не должен блокировать легитимных. FAIL_CLOSED возвращает синтетический `428 Precondition Required`, не выпуская запрос.
- **Реакция на 401/403** — сервер сказал «токен не годен» → инвалидируем и обновляем **в фоне** (не блокируя текущий ответ).

Заголовки (`Protocol`): `TRUST_TOKEN_HEADER = "X-AntiBot-Token"`, `PROTOCOL_VERSION_HEADER = "X-AntiBot-Proto"`.

---

### Шаг 11. Хранение и обновление токена — `TokenManager` + `EncryptedTokenStorage`

Файл: `sdk-core/TokenManager.kt`. Управляет жизненным циклом токена.
```kotlin
private val refreshMutex = Mutex()                            // для single-flight

suspend fun getToken(): TokenResult {
    val current = cached()
    if (current != null && current.isFresh(now) && !current.needsProactiveRefresh(now))
        return Success(current.value, current.expiresAtMillis)  // есть свежий — отдаём сразу
    return refreshMutex.withLock {                              // иначе обновляем ПОД замком
        val fresh = cached()                                    // ещё раз проверяем внутри замка
        if (fresh != null && fresh.isFresh(now) && !fresh.needsProactiveRefresh(now))
            return@withLock Success(...)                        // кто-то уже обновил, пока мы ждали
        refreshWithBackoff()
    }
}
```
- **`isFresh`** = `now < expiresAtMillis`; **`needsProactiveRefresh`** = `now >= expiresAtMillis - refreshSkewMillis`. То есть токен обновляют **заранее** (за минуту до истечения), чтобы у запросов всегда был живой токен.
- **Single-flight** через `Mutex`: если 10 запросов одновременно увидели, что токен протух, обновление уйдёт на сервер **один раз**, остальные дождутся результата. Иначе был бы шторм запросов. Двойная проверка `cached()` внутри замка — чтобы не обновлять повторно.

```kotlin
private suspend fun refreshWithBackoff(): TokenResult {
    var attempt = 0
    while (attempt <= config.maxRetries) {
        when (val outcome = client.obtainToken()) {
            is Token   -> { storage.save(StoredToken(value, now + ttl*1000)); return Success(...) }
            is Rejected-> { invalidate(); return Failure(reason, retryable = false) } // вердикт — не повторяем
            is Error   -> { if (!retryable || last) return Failure(...); delay(backoffMillis(attempt)); attempt++ }
        }
    }
}
private fun backoffMillis(attempt: Int): Long {
    val base = (500.0 * 2.0.pow(attempt)).toLong().coerceAtMost(8000)  // 500 → 1000 → 2000 …
    return Random.nextLong(0, base + 1)                                // + jitter (случайная добавка)
}
```
- **Различие Rejected vs Error**: `Rejected` (сервер сказал DENY/CHALLENGE-провал) — это **вердикт**, повторять бессмысленно и вредно (`retryable=false`). `Error` (сеть) — временная беда, повторяем с backoff.
- **Exponential backoff + jitter**: пауза растёт (500→1000→2000мс), плюс случайная добавка (jitter), чтобы тысячи клиентов не долбили сервер синхронно (thundering herd).

**`EncryptedTokenStorage`** (`sdk-android`) — куда сохраняется токен:
```kotlin
val masterKey = MasterKey.Builder(context).setKeyScheme(AES256_GCM).build()
prefs = EncryptedSharedPreferences.create(context, "curator_antibot_secure", masterKey, AES256_SIV, AES256_GCM)
```
Токен хранится **зашифрованным** ключом из Android Keystore. Если создать защищённое хранилище не удалось — падаем на in-memory (`memoryFallback`), но **не крэшим** хост. Модель `StoredToken(value, expiresAtMillis)` — сам токен и когда истекает.

`TokenResult` (что возвращается наружу): `Success(token, expiresAtMillis)` или `Failure(reason, retryable)` — явные варианты, вызывающему всё понятно без «магии».

---

### Шаг 12. Защищённый запрос и проверка токена — `verify`

Когда токен уже висит на запросе, прикладной бэкенд его проверяет. В демо это делает сам сервер (`GET /v1/protected` и `POST /v1/verify`) через `AttestationService.verify`:
```kotlin
fun verify(token: String): VerifyResponse =
    when (val r = TrustToken.verify(token, serverKeys.public, clock()/1000)) {
        is Valid   -> VerifyResponse(true, OK, r.claims)
        is Invalid -> VerifyResponse(false, r.reason)
    }
```
**`TrustToken.verify`**:
```kotlin
fun verify(token, serverPublicKey, nowSeconds): VerifyResult {
    val parts = token.split(".")                              // header.claims.signature
    if (parts.size != 3) return Invalid(ATTESTATION_FAILED)
    if (!verify(serverPublicKey, "${parts[0]}.${parts[1]}".bytes, b64UrlDecode(parts[2]))) return Invalid(BAD_SIGNATURE)
    val claims = decode(parts[1])
    if (nowSeconds >= claims.exp) return Invalid(NONCE_EXPIRED) // истёк
    return Valid(claims)
}
```
Проверяется **подпись** (токен наш, не подделан) и **срок** (`exp`). Всё **stateless** — не нужна база, только публичный ключ. Поэтому проверять токен может любой сервис. Модель `VerifyResponse(valid, reason, claims?)`.

На этом круг замкнулся: клиент собрал доказательства → сервер выдал пропуск → пропуск проверяется на каждом запросе → истекает → обновляется. Всё построено на «клиенту не доверяем, решает сервер, replay закрыт nonce+TTL».

<a id="4"></a>
## 4. Справочник: файл за файлом

Быстрый указатель «где что лежит». Каждая строка — класс/функция и одно предложение назначения.

### Модуль `protocol` (общий: клиент + сервер)

**`CryptoPrimitives.kt`** — низкоуровневые крипто-кубики (объект):
- `b64UrlEncode/b64UrlDecode` — байты ↔ Base64URL-строка.
- `randomBytes(n)` — n криптослучайных байт.
- `generateEcKeyPair()` — новая EC-пара P-256.
- `encodePublicKey/decodePublicKey` — публичный ключ ↔ X.509-строка.
- `encodePrivateKey/decodePrivateKey` — приватный ключ ↔ PKCS#8-строка (для хранения серверного).
- `sign/verify` — подпись ES256 (SHA256withECDSA) и её проверка.
- `ecdh(priv, pub)` — общий секрет по Диффи-Хеллману.
- `hkdfSha256(ikm, salt, info, len)` / `deriveAesKey(...)` — вывод AES-256 ключа из секрета.
- `aesGcmIv()` / `aesGcmEncrypt/aesGcmDecrypt` — AES-256-GCM (шифрование + целостность).
- `sha256/sha256Hex` — хеш и его hex-представление.

**`Models.kt`** — все модели «на проводе» + `Protocol` (константы: `VERSION`, имена заголовков, пути, `ENVELOPE_INFO`) + `ChallengeCrypto.expectedAnswer`. Модели: `NonceRequest/Response`, `Telemetry`, `IntegrityVerdict`, `EnvelopePayload`, `SealedEnvelope`, `Decision`, `RiskLevel`, `ReasonCode`, `AttestationResponse`, `Challenge`, `ChallengeSolution`, `TrustTokenClaims`, `VerifyResponse`, `ErrorResponse`. Все `@Serializable` (kotlinx) — умеют в JSON.

**`EnvelopeCrypto.kt`** — `AntiBotJson` (конфиг JSON: `ignoreUnknownKeys=true` для forward-compat), `seal` (клиент запечатывает), `open` (сервер распечатывает), `OpenResult`, `OpenedEnvelope`.

**`TrustToken.kt`** — `issue` (сервер выпускает токен), `verify` (кто угодно проверяет), `VerifyResult`.

### Модуль `sdk-core` (чистое ядро)

**`Api.kt`** — публичный API и «контракты»: `FailureMode`, `TokenResult`, `AntiBotConfig`(+`Builder`), `FeatureFlags`, интерфейсы провайдеров (`TelemetryProvider`, `IntegrityProvider`, `ClientKeyProvider`, `TokenStorage`, `Clock`), `StoredToken`, `SystemClock`, `InMemoryTokenStorage`, `ChallengeResult`, `WebViewChallengeSolver`, `NoWebViewChallengeSolver`. Провайдеры — это «дырки», которые затыкает Android-слой (или фейки в тестах).

**`AttestationClient.kt`** — исполняет флоу: `obtainToken()` (nonce→телеметрия→конверт→attest→решение), `requestNonce`, `postAttest`, `postChallengeVerify`, `interpret`, `handleChallenge`. Свой OkHttp-клиент (без interceptor) против рекурсии. `Outcome` (Token/Rejected/Error), `Logger` (молчит вне debug), `BuildInfo.SDK_VERSION`.

**`TokenManager.kt`** — кеш, проактивное обновление, single-flight (`Mutex`), backoff+jitter. `getToken`, `forceRefresh`, `cachedTokenOrNull`, `invalidate`.

**`AntiBotInterceptor.kt`** — OkHttp-`Interceptor`: вешает токен, реализует fail-open/closed, реагирует на 401/403.

**`AntiBotClient.kt`** — фасад, собирающий `AttestationClient` + `TokenManager`: `warmUp`, `getToken`, `interceptor`, `invalidateToken`. `JvmClientKeyProvider` (EC-ключ в памяти — для JVM/тестов).

### Модуль `sdk-android` (тонкая обвязка)

**`AntiBot.kt`** — синглтон-точка входа: `config`, `init`, `interceptor`, `getToken`, `invalidateToken`, `isInitialized`.
**`AndroidTelemetryProvider.kt`** — реализует `TelemetryProvider` через `Build`/`PackageManager`.
**`AndroidIntegrityProvider.kt`** — реализует `IntegrityProvider`: детекторы + Play Integrity.
**`Detectors.kt`** — `RootDetector`, `EmulatorDetector`, `DebuggerDetector`, `HookingDetector` (+`DetectionResult`).
**`KeystoreClientKeyProvider.kt`** — identity-ключ в Android Keystore (не покидает TEE).
**`EncryptedTokenStorage.kt`** — токен в EncryptedSharedPreferences (+ in-memory fallback).
**`AndroidWebViewChallengeSolver.kt`** — решает WebView-челлендж через безопасный одноразовый WebView.

### Модуль `server` (Ktor)

**`Application.kt`** — `antiBotModule(context)` описывает роуты (`/health`, `/v1/pubkey`, `/v1/nonce`, `/v1/attest`, `/v1/verify`, `/v1/challenge/page`, `/v1/challenge/verify`, `/v1/protected`) + `main()`.
**`ServerContext.kt`** — держит серверные ключи и собранные сервисы; `fromEnvOrGenerate()` читает env (ключи, флаги, креды Play Integrity).
**`NonceStore.kt`** — выдача и одноразовое «съедание» nonce (replay-защита).
**`ChallengeStore.kt`** — одноразовые челленджи, привязанные к клиенту.
**`RiskEngine.kt`** — risk scoring (веса, пороги, флаги, shadow).
**`PlayIntegrity.kt`** — полная серверная верификация Play Integrity (заглушка только в `AccessTokenProvider`).
**`AttestationService.kt`** — оркестратор: `attest`, `verifyChallenge`, `verify`.
**`ChallengePage.kt`** — локальная тестовая HTML-страница челленджа.

### Модуль `demo-app` (пример хоста)

**`DemoApp.kt`** — `Application`. **`DemoViewModel.kt`** — connect/getToken/callProtected/clearToken + лог. **`MainActivity.kt`** — Compose-экран.

<a id="5"></a>
## 5. Почему так, а не иначе (дизайн-решения)

- **Почему общий модуль `protocol`.** Если бы клиент и сервер описывали формат по отдельности, малейшее расхождение (порядок полей, алгоритм) ломало бы всё молча. Общий код → формат физически один.
- **Почему `sdk-core` отдельно от `sdk-android`.** Чтобы логику (флоу, токены, backoff, single-flight, interceptor) тестировать на обычной JVM за секунды, без эмулятора. Android-слой — тонкий и почти без логики.
- **Почему провайдеры-интерфейсы (`TelemetryProvider` и т.д.).** Инверсия зависимостей: ядро не знает про Android; в проде подставляются Android-реализации, в тестах — фейки. Это и тестируемость, и чистые границы.
- **Почему отдельный OkHttp-клиент в `AttestationClient`.** Иначе запрос SDK за токеном сам бы прошёл через наш interceptor → рекурсия. Разделение клиентов её исключает.
- **Почему конверт шифруется, хотя есть TLS.** Защита в глубину: атакующий на своём устройстве снимает TLS (свой CA + Frida). Шифрование конверта поверх TLS означает, что даже сняв TLS, он видит лишь шифртекст.
- **Почему эфемерный ECDH-ключ на каждый конверт.** Forward secrecy: старые перехваченные конверты нельзя расшифровать задним числом.
- **Почему identity-ключ в Keystore, а эфемерный — в софте.** Identity-ключ долгоживущий и ценный → его нельзя дать вытащить (Keystore/TEE). Эфемерный одноразовый → генерить в софте дешевле и не жалко.
- **Почему подпись покрывает `iv|ciphertext|nonce`, а не payload.** Чтобы сервер аутентифицировал отправителя **до** расшифровки (экономия ресурсов, защита от «расшифруй мусор»); содержимое и так под GCM-tag.
- **Почему решение на сервере, а не на клиенте.** Клиент — враждебная среда. На сервере можно безопасно сверять с Google, менять правила без релиза приложения, применять ML/историю.
- **Почему risk score, а не «бот/не бот».** Сигналы клиента ненадёжны по отдельности; жёсткая блокировка по одному признаку = много ложных срабатываний. Взвешенный счёт + пороги + step-up мягче и точнее.
- **Почему single-flight и backoff+jitter.** Чтобы при массовом истечении токенов не устроить шторм запросов к серверу (thundering herd).
- **Почему FAIL_OPEN по умолчанию.** Наш сбой не должен блокировать реальных пользователей; строгость (FAIL_CLOSED) хост включает осознанно для чувствительных операций.
- **Почему Builder для конфига и `sealed`/`enum` для результатов.** Builder даёт расширяемость без слома совместимости; `sealed`/`enum` делают API самодокументируемым и заставляют обработать все случаи.
- **Почему idempotent `init` и `applicationContext`.** Типовые грабли SDK — двойная инициализация и утечка Activity; и то, и другое здесь закрыто.

<a id="6"></a>
## 6. Глоссарий

- **AEAD** — шифрование с аутентификацией (AES-GCM): секретность + целостность разом.
- **AES-256-GCM** — симметричный шифр, 256-битный ключ, режим GCM (с проверкой целостности).
- **IV (Initialization Vector)** — случайные байты на каждое шифрование, чтобы шифртексты не повторялись.
- **AAD** — данные, которые не шифруются, но «привязываются» к шифртексту (у нас — nonce).
- **GCM-tag** — «печать целостности» в конце шифртекста; при подмене расшифровка падает.
- **EC / P-256 (secp256r1)** — эллиптическая кривая; короткие быстрые ключи.
- **Приватный/публичный ключ** — секретный/открытый ключи асимметричной пары.
- **ECDH** — получение общего секрета из своей приватной и чужой публичной части.
- **Эфемерный ключ** — одноразовая пара ключей (даёт forward secrecy).
- **Forward secrecy** — старые перехваты нельзя расшифровать, даже если ключ утечёт позже.
- **HKDF** — вывод криптоключа нужной длины из «сырого» секрета с привязкой контекста.
- **Подпись / ECDSA / ES256** — доказательство подлинности, проверяемое публичным ключом.
- **MAC/HMAC** — то же на **общем секрете** (в этом проекте не основной путь; используется внутри HKDF).
- **SHA-256** — хеш-функция, «отпечаток» данных.
- **Base64URL** — текстовое представление байтов для JSON/URL.
- **nonce** — одноразовое серверное число; ломает replay.
- **TTL** — срок жизни (nonce/токена).
- **Replay-атака** — повтор перехваченного валидного запроса.
- **Trust token** — короткоживущий подписанный «пропуск» для запросов.
- **Attestation** — процесс: клиент шлёт доказательства, сервер выносит вердикт.
- **Telemetry** — компактные сигналы об устройстве/приложении.
- **Play Integrity** — сервис Google с подписанным вердиктом о подлинности.
- **Detector (root/emulator/debugger/hooking)** — локальная проверка среды; сигнал, не приговор.
- **Risk scoring** — превращение сигналов в число риска и решение.
- **Shadow mode** — режим «считаем, но не блокируем» для безопасной выкатки.
- **Reason code** — машинный код-объяснение решения.
- **Interceptor** — прослойка OkHttp, вешающая токен на каждый запрос.
- **Single-flight** — одно обновление токена на всех ожидающих.
- **Backoff + jitter** — растущая пауза со случайной добавкой при повторах.
- **FAIL_OPEN / FAIL_CLOSED** — при отсутствии токена пропускать / блокировать.
- **Keystore / TEE** — аппаратно-защищённое хранилище ключей Android.
- **Idempotent** — повторный вызов безопасен (наш `init`).
- **JS bridge / `@JavascriptInterface`** — мост Kotlin ↔ JS в WebView (для челленджа).

---

_Этот файл описывает код на момент коммита. Если меняете сигнатуры/поля — обновляйте и его: он часть контракта на понятность SDK._


