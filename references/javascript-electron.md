# JS / Electron / ASAR — обфускация и упаковка

Бьёт по `analyze_javascript_application` (REA строит AST-граф, читает импорты,
литералы, IPC-каналы, native-binding запросы) и `recover_javascript_sources`.

## External-key VM для ограниченной T1 offline-защиты

Для клиентской логики класса `COST_ONLY` инструмент поддерживает
`--key-mode external --key-slot NAME --key-env ENV_NAME`. В артефакте остаётся
ChaCha20-Poly1305 VM envelope со случайным 96-битным nonce и context AAD, но
отсутствует случайный 256-битный build-key. Ключ следует выдавать только после серверной
авторизации. VM 1.2 требует, чтобы заявленный runtime-slot содержал функцию
`provider(functionId)`, возвращающую свежий 32-byte `Uint8Array`; строковый
hex-key отклоняется. Provider обязан выдавать отдельную копию на каждый новый
protected function ID: VM немедленно зануляет returned buffer, свою рабочую
копию и decrypted payload bytes после decode.

Ключ нельзя сохранять в local storage, preload-коде, конфигурации, обновлении,
логах, crash/support bundle или evidence-пакете. Проверенный публичный
deobfuscator распознаёт envelope, но без ключа не восстанавливает канарейки;
после легитимной выдачи ключа T2 runtime-hook по-прежнему извлекает 3/3.
Следовательно, режим не подходит для `SERVER_REQUIRED` логики и не является
границей доверия.

## 1. Обфускация как базовый cost layer

Инструмент: закреплённый `javascript-obfuscator` через
`scripts/transform-javascript.mjs` и профили из `profiles/`. Не принимайте
конфигурацию из приложения: это downgrade-путь. Профиль
`javascript-vm-balanced` требует хэш-связанный отчёт предыдущего VM-этапа.

Ключевые флаги против REA:
- `stringArray` + `stringArrayEncoding` — ломает извлечение литералов
  (`search_strings` ничего полезного не покажет);
- `controlFlowFlattening` — ломает AST-граф / восстановление структуры;
- `renameGlobals` — убивает читаемые имена экспортов;
- `selfDefending` может повысить стоимость перепаковки, но несовместим с частью
  следующих стадий и не мешает patched runtime или hook до инициализации.

Минус: сильная обфускация тормозит рантайм. Критичные горячие пути держать
в нативном/WASM (см. ниже), а не гонять через `controlFlowFlattening`.

## 1a. Закрытие СТРУКТУРЫ, ЭНДПОИНТОВ и ПРИНЦИПА РАБОТЫ (а не только строк)

REA после анализа выдаёт не просто строки, а **семантический граф**: имена
классов, методов, переменных, модулей (`express`/`axios`/`crypto`), эндпоинты
(`/api/v1/payments/transfer`), роуты, IPC-каналы, native-binding запросы. По
этому графу агент восстанавливает «принцип: сначала подпись, потом HTTP» и
карту API. Закрыть всё три слоя утечки:

1. **Структура (классы/методы/переменные/модули)** — `renameGlobals: true` +
   `identifierNamesGenerator: "hexadecimal"`. Имена превращаются в
   `a0_0x19217b`/`Bkoekr` — REA видит «функции есть», но не что они делают.
2. **Эндпоинты (URL/роуты)** — `stringArray` + `stringArrayEncoding: ["rc4"]`
   + `splitStrings` + `stringArrayWrappersChainedCalls`. URL не лежит ни в
   исходнике, ни в памяти графа читаемым текстом.
3. **Принцип работы (логика вызова)** — `controlFlowFlattening: true` +
   `deadCodeInjection` + `numbersToExpressions` + `transformObjectKeys`.
   Это ухудшает прямое восстановление из AST, но не скрывает наблюдаемое
   поведение от выполнения, трассировки и инструментирования.

Один реальный прогон REA `6.7.0` на fixture уменьшил прямое восстановление
имен и строк, но это не общая гарантия: специализированный unpacker и runtime
hook извлекают текущий VM payload. Любой вывод должен содержать digest артефакта,
версию/digest REA, tier, точную команду и recovery score.

Важно по `stringArrayThreshold`: ставить `1` (все строки). По умолчанию
`0.75` оставляет 25% строк читаемыми — этого хватит REA, чтобы вытащить
пару «богатых» эндпоинтов или имя модуля.

## 2. Bytecode вместо исходного AST (дополнительный cost layer)

REA работает по AST — по байткоду V8 AST не построится. Компилируем `.js` в
bytecode, отдаём только `.jsc`:

```bash
# bytenode: скомпилировать и загрузить
npm i -D bytenode
# build:
node -e "require('bytenode').compileFile({ filename: 'src/app.js', output: 'dist/app.jsc', electron: true })"
# load (main process):
require('bytenode');
const app = require('./dist/app.jsc');
```

Electron-нюансы:
- для main/preload — `electron: true` (нужна совместимость с electron runtime);
- байткод привязан к версии Node/Electron: обновление движка = перекомпиляция;
- держать `bytenode` в runtime-зависимостях.

V8 bytecode распознаётся по loader, привязан к известному V8 и доступен для
дизассемблирования и matching-runtime hooks. Он мешает текущему AST-проходу,
но REA может добавить bytecode provider. Включайте loader hook и V8-наблюдение
в T2 corpus; не назначайте bytecode границей доверия.

## 3. ASAR-шифрование (Electron)

`analyze_javascript_application` работает прямо по ASAR/извлечённому дереву.
Шифруем содержимое ASAR, чтобы статическое чтение было дороже. Код и ключ
должны оказаться в памяти для исполнения, поэтому это не граница доверия.

- заменить стандартный `electron-packager`/`electron-builder` этап упаковки на
  кастомный packer, который шифрует payload и кладёт внутрь мини-загрузчик,
  расшифровывающий в память;
- проверенный способ — хуком в `preload`/`main` расшифровывать модули на лету
  (custom `Module._extensions['.js']`), а на диск класть зашифрованные блобы;
- не оставлять ключ рядом с payload в отдельном файле; встраивание ключа в
  бинарник лишь повышает стоимость извлечения и не делает его секретным.

## 4. Критичная логика — на сервер; native/WASM только повышают стоимость

Логику и решения, которые нельзя раскрывать или локально подменять, выносить на
авторитетный сервер. Native addon и WASM допустимы только для `COST_ONLY`:
- нативный addon (`.node`) со стрипом символов (см. native-binaries.md);
- либо WASM-модуль с обфускацией (см. wasm.md) — `inspect_wasm_artifact` даст
  только WAT, не исходник.

## Проверка через REA

```bash
npx -y rea-agents@6.7.0 analyze-javascript-application /path/to/app \
  --artifact-format directory --format json --full-output
```

Критерий задаётся по каждому leakage ID. Отсутствие plaintext недостаточно:
запустите `probe-vm-runtime.mjs`, browser/CDP или Electron IPC probe согласно
tier. Recovery критичного факта требует server-side migration, а не более
оптимистичной формулировки отчёта.
