# Runtime-целостность — cert-pinning, frida/mitmproxy-детект, anti-CDP

Бьёт по динамическим векторам REA: `capture_browser_scenario` (CDP),
`list_browser_targets` / `list_electron_targets`, `observe_*`, инспекция
mitmproxy/Fiddler/`.saz` (`inspect_web_network_capture`), frida-инструментарий.

## 1. Certificate pinning (затрудняет mitmproxy/Fiddler-перехват)

REA снифает трафик через mitmproxy (`bridge/mitmproxy/capture.py`) и инспектирует
Fiddler `.saz`. Pinning не даёт подменить сертификат — дешифровка не сработает.

### Node.js / Electron

Use a maintained platform integration that validates SPKI hashes, covers every
network stack used by the application, and supports at least one backup pin.
Document certificate rotation and a signed emergency update path. A custom
`https.Agent` does not cover Chromium traffic automatically, and hashing
`cert.raw` is not equivalent to SPKI pinning.

### Android (OkHttp)
```kotlin
val c = CertificatePinner.Builder()
  .add("api.yourapp.com", "sha256/AAAA...")
  .build()
OkHttpClient.Builder().certificatePinner(c).build()
```

### iOS (URLSession)
```swift
// URLSessionDelegate -> didReceive challenge -> сравнить publicKey hash
```

### macOS signed app
- не отдавать `get-task-allow` в релизе (иначе LLDB-attach работает);
- включить Hardened Runtime + Library Validation (сигнатура приложения).

## 2. Frida-детект (сигнализирует о вероятном инструментировании)

REA использует frida (optionalDependency) для runtime-наблюдения. Детект frida:

```c
// Android (JNI, native): сканировать /proc/self/maps на frida-агентов
//   признаки: "frida", "gum-js-loop", "gmain", "linjector"
// iOS/macOS: проверить подключение через dyld info + перебор подозрительных модулей
```

Способы (по возрастанию сложности обхода):
1. **Скан maps/имён модулей** — `frida-agent`, `gum-js-loop`, `libFridaGadget`.
2. **Проверка портов** — frida default port 27042 (`frida-server`).
3. **ptrace-противодействие** — см. native-binaries.md.
4. **Связь с серверной политикой риска**: повышать требования к повторной
   аутентификации, ограничивать привилегированные операции и писать
   диагностическое событие. Не уничтожать данные и не считать один детектор
   доказательством компрометации.

Все перечисленные проверки обходятся переименованием, патчингом или перехватом
самой проверки. Используйте несколько независимых сигналов, но не делайте из
них локальную границу авторизации.

## 3. Anti-CDP (браузер/Electron)

REA подключается к Chromium через CDP (`list_browser_targets`). Контрмеры:

- Electron: `--remote-debugging-port` НЕ включать в проде;
- проверять `app.commandLine.hasSwitch('remote-debugging-port')` / `--inspect`
  и гасить чувствительную логику;
- packaged fuses: `EnableNodeCliInspectArguments` = false (`inspect_electron_fuses`
  в REA прямо проверяет этот fuse — держать выключенным);
- минимизировать `contextBridge`-поверхности и не экспортировать лишние API
  из preload (REA читает их статически через `capture_*`).

## 4. Сеть

- протокол не открытым текстом (TLS + pinning — обязательны);
- критичные payload подписывать HMAC с ключом из нативного слоя (не из JS);
- не логировать чувствительные заголовки/тела (иначе `.saz`/HAR отдаст их REA).

## Проверка через REA

```bash
# MCP: capture_browser_scenario / list_electron_targets / inspect_web_network_capture
#   -> попытка перехватить трафик или подключиться к CDP должна провалиться.
```

Критерий: стандартный proxy-перехват не расшифровывает трафик, production-сборка
не открывает CDP/Node inspector, а тестовое инструментирование либо наблюдается
политикой риска, либо документируется как остаточная возможность. Детект Frida
не доказывает невозможность инъекции.

## 5. Node runtime boundary attack (v0.29)

`scripts/probe-vm-runtime.mjs` устанавливает bounded observers до загрузки exact
artifact и формирует schema-v2 report по одиннадцати границам: base64 decode,
`Buffer.toString`, decipher output, file/cache reads, `MessagePort` IPC,
`JSON.parse`, fetch/Response, stdout/stderr, `structuredClone`, `TextDecoder` и
WebAssembly compile/instantiate input. Для каждой границы сохраняются только
счётчики; canary values в отчёт не попадают, только SHA-256.

Gate требует установки всех observers, фактического исполнения JSON/TextDecoder
decode path и полного списка protected function IDs. Лимит 8192 наблюдений,
32 MiB общего текста и 10 MiB на значение закрывает memory-flood: превышение
делает evidence `invalid`, а не `not-recovered`. Это атакующий harness для Node,
не доказательство против CDP, Frida, LLDB, V8 internals или native memory dump.
