# Карта вариантов вскрытия Anti-REA

Версия карты: 2026-10-23, ревизия 28 (`anti-rea` 0.34.1, 209/209
локальных тестов; исходная критика проводилась на 0.9.0 с 80/80).
Объект анализа — фактический код framework, а не абстрактный
обфускатор. Карта предназначена только для проверки собственных или явно
разрешённых продуктов. Зелёный unit test подтверждает локальный инвариант, но не
доказывает KMS/IAM, изоляцию runner, честность сервера или publisher.

Консолидированный отчёт двух независимых критиков: 
`references/rea-security-critic-review-2026-10-22.md`.

В 0.34.1 закрыты подмена байтов между inventory и CAS copy, ложный успех
повторной публикации повреждённого объекта, неполная проверка receipt и цепочки
релизов, отключённые стандартные правила Gitleaks и обход таймаута клиента
времени. Исправления подтверждаются отдельными регрессионными тестами; детали
и оставшиеся границы — в разделе 32 отчёта критиков. Они не превращают локальный
publisher в неизменяемое хранилище и не доказывают конфиденциальность runtime.

## 1. Что считается вскрытием

Вскрытие — это не только получение исходного файла. Атакующий выигрывает, если
достигает хотя бы одной цели:

- восстанавливает защищённый факт, правило, алгоритм, схему или контракт;
- заставляет локальный клиент принять выгодное ему решение;
- повторно использует ключ, capability, токен или серверный ответ;
- выпускает слабый артефакт с формально зелёными доказательствами;
- откатывает пользователя на ранее подписанный, но уязвимый релиз;
- вынуждает команду отключить защиту из-за несовместимости или деградации;
- изучает Anti-REA и превращает его устойчивые признаки в новый REA-провайдер.

Полнота исходника не требуется. Операционно пригодное частичное восстановление
тоже считается успехом.

## 2. Модель противника

| Tier | Возможности | Примеры |
|---|---|---|
| T0 | Пассивно читает поставку | архивы, строки, карты, метаданные, конфиги |
| T1 | Проводит статический анализ и массовые сравнения | REA, AST, public deobfuscators, chosen-input и cross-build corpus |
| T2 | Управляет обычным клиентским runtime | debugger/CDP, proxy, preload hooks, patched client, IPC/network capture |
| T3 | Контролирует хост или часть фабрики выпуска | injection/memory, CI runner, signer misuse, insider, dependency substitution |

Допущение максимальной прозрачности: противник знает репозиторий Anti-REA,
фикстуры, тесты, маркеры, форматы отчётов и алгоритмы. Секретность конструкции
не является контролем.

### 2.1. Активы и границы доверия

| Граница | Что пересекает границу | Кто не должен иметь возможность подделать обе стороны | Сейчас |
|---|---|---|:---:|
| TB-01 product source → build input | commit, tree, build definition, dependency graph | обычный build job | Н |
| TB-02 build → protection | точный input digest и owner classification | transformer/CI | У |
| TB-03 protection → attack runner | неизменяемый artifact и pre-committed policy | analyzer | Б* |
| TB-04 runner → gate | raw output, typed result, workload identity, fresh challenge | build job | У |
| TB-05 server → gate | production-like authorization transcript | клиент и build job | У |
| TB-06 gate → publisher | signed PASS, product/channel scope, freshness | release job | У |
| TB-07 publisher → client | manifest, release chain, authoritative channel head | CDN и клиент | У |
| TB-08 client key service → runtime | scoped, short-lived key/capability | локальный storage | Н |
| TB-09 untrusted artifacts → defensive agents | analyzer output, source comments, tripwires | prompt content | Н |

`Б*` означает: формат и подпись проверяются, но внешняя эксплуатационная граница
должна существовать отдельно. Главный принцип карты: один principal не должен
иметь возможность изготовить вход, evidence, все подписи и публикацию.

### 2.2. Ортогональные роли противника

Tier описывает техническую возможность, но для фабрики доказательств важнее
роль. Отдельно моделируются: владелец клиентского устройства, автор chosen-input
corpus, скомпрометированный dependency, build principal, evidence worker,
assessment signer, server authorization signer, manifest signer, release signer
и publisher operator. Компрометация одной роли не должна автоматически давать
полную зелёную цепочку.

## 3. Дерево победы противника

```text
Получить полезный эквивалент защищённого продукта
├─ A. Извлечь смысл из поставки
│  ├─ A1. Найти забытый открытый экземпляр
│  ├─ A2. Распознать и снять стандартную обфускацию
│  ├─ A3. Извлечь/поднять VM, bytecode, WASM или native слой
│  ├─ A4. Сопоставить chosen-input и серию диверсифицированных сборок
│  ├─ A5. Использовать отчёты, ошибки и support-артефакты как oracle
│  ├─ A6. Восстановить семантику без буквального canary
│  └─ A7. Дать probe один decoy envelope, оставив остальные вне coverage
├─ B. Наблюдать смысл во время исполнения
│  ├─ B1. Перехватить выдачу ключа и plaintext boundary
│  ├─ B2. Снять декодированную программу, cache, inputs и outputs
│  ├─ B3. Восстановить схему через Proxy/getter/network/IPC/storage
│  ├─ B4. Патчить решение вместо понимания алгоритма
│  ├─ B5. Не вызвать lazy/export-only protected path и получить false green
│  └─ B6. Перенести полный валидный AEAD tuple вместе с его AAD
├─ C. Обойти серверную границу доверия
│  ├─ C1. Найти дублированное клиентское решение или fail-open путь
│  ├─ C2. Повторить/расширить capability, токен или подписанный ответ
│  ├─ C3. Подменить клиентский контекст, не перепроверяемый сервером
│  └─ C4. Использовать расхождение staging/prod или неполный сценарий теста
├─ D. Подделать фабрику доказательств или bootstrap доверия
│  ├─ D1. Заменить analyzer/adapter/package/runtime на удобную имитацию
│  ├─ D2. Сфабриковать raw output и самосогласованные хэши
│  ├─ D3. Подменить артефакт между анализом, подписью и публикацией
│  ├─ D4. Получить или переиспользовать assessment/server/release signer
│  ├─ D5. Пропустить стадию через альтернативный release path
│  ├─ D6. Передать validator собственные public trust roots
│  ├─ D7. Подписать произвольный файл вместо результата доверенного workload
│  └─ D8. Валидировать просроченный комплект с caller-controlled `--now`
├─ E. Откатить или разветвить доверенную цепочку
│  ├─ E1. Навязать старый валидно подписанный релиз
│  ├─ E2. Снизить локальный minimum sequence
│  ├─ E3. Создать параллельную подписанную ветку канала
│  └─ E4. Продолжить работу после компрометации ключа без revocation
├─ F. Атаковать сам Anti-REA
│  ├─ F1. Добавить в REA стабильный распознаватель envelope/interpreter
│  ├─ F2. Обучить lifting на публичных fixtures и chosen-input builds
│  ├─ F3. Вызвать unsupported construct/performance regression и downgrade
│  ├─ F4. Отравить corpus/evidence/agent context, чтобы защита переобучилась
│  ├─ F5. Использовать сам gate как differential oracle для настройки REA
│  └─ F6. Получить embedded/default backend, не закреплённый signed policy
├─ G. Обойти процесс и причинную цепочку
│  ├─ G1. Ошибочно классифицировать SERVER_REQUIRED как COST_ONLY
│  ├─ G2. Исключить неудобный факт или tier из assessment
│  ├─ G3. Выдать отсутствие результата инструмента за отсутствие утечки
│  ├─ G4. Скопировать ключ в лог, дамп, support bundle или соседний клиент
│  ├─ G5. Подать product build из другого commit при clean protector repo
│  └─ G6. Подложить текстовый `passed` как regression evidence
└─ H. Использовать LLM-контур
   ├─ H1. Игнорировать/удалить defensive tripwire до анализа
   ├─ H2. Распознать одинаковый tripwire и превратить его в locator защищённых зон
   ├─ H3. Заставить защитного агента выполнить instruction-like artifact content
   ├─ H4. Вынести synthetic canary в сервис анализа и раскрыть маршрут утечки
   └─ H5. Намеренно повторить marker и вызвать ложную атрибуцию/автореакцию
```

## 4. Приоритетная матрица

Обозначения: `Б` — блокирует текущая архитектура при правильной эксплуатации;
`У` — только удорожает; `Н` — не закрыто или требует внешней интеграции.

| ID | Вектор | Tier | Вероятность | Impact | Сейчас | Что должно доказать закрытие |
|---|---|---:|---:|---:|:---:|---|
| B1 | Перехват внешнего ключа после provisioning | T2 | высокая | высокая | Н | runtime probe после реальной выдачи ключа всегда фиксирует recovery; T2 confidentiality не заявляется |
| B2 | Hook `Buffer`/`atob`/`TextDecoder`/`JSON.parse`/VM cache | T2 | высокая | высокая | Н | многоточечный hook corpus и score по каждому защищённому факту |
| B3 | Bit-flip/transplant ciphertext или AAD | T1/T2 | средняя | высокая | Б | ChaCha20-Poly1305 + context AAD; ciphertext tamper test обязан отказать до JSON parse/VM execution; T2 secrecy не заявляется |
| B4 | Патч локального allow/entitlement | T2 | высокая | критический | Б* | production-like сервер независимо запрещает действие; signed transcript свежий и artifact-bound |
| B5 | Runtime probe импортирует модуль, но не вызывает все protected функции | T2/процесс | высокая | высокая | Б | v0.14 runtime probe сравнивает observed IDs с полным signed receipt inventory; partial execution даёт invalid evidence |
| B6 | Перенос `{ciphertext,tag,nonce,AAD}` целиком между функциями | T2 | средняя | высокая | У | negative transplant test; context должен поступать из independently trusted statement, а не переноситься вместе с tuple |
| A3 | Generic lift текущего VM envelope | T1 | высокая для embedded, средняя для external до ключа | высокая | У | публичный deobfuscator + generic extractor; external-key допускает только узкую T1 COST_ONLY заявку |
| A4 | Chosen-plaintext и cross-build alignment | T1 | высокая | высокая | Б* | v0.28 mandatory 20–64 variant high-entropy-window/Jaccard attack пересчитывается gate; semantic cross-language alignment остаётся P1 |
| A6 | Analyzer восстанавливает schema/property/endpoint/structure без точного canary | T1/T3 | высокая | критический | Б* | v0.27 gate извлекает fixed-score exact/endpoint/identifier/JSON/JS/WAT/native-CFG/holdout candidates из signed raw output; cross-language и arbitrary equivalence остаются вне bounded normalizers |
| A7 | Один decoy envelope удовлетворяет `recognizedEnvelopes >= 1` | T1/T3 | средняя | высокая | Б | v0.14 attack report покрывает полный signed function/envelope inventory по ID; missing ID делает evidence invalid |
| A1 | Source map/старый chunk/cache/update/support bundle | T0 | средняя | критический | Б* | v0.26 owner-precommitted delivery graph физически сканирует release/update/crash/support/symbol staging trees и повторяет обход в gate; runtime CDN/cache/ACL остаются внешними |
| C1 | Скрытая fail-open или дублированная клиентская авторизация | T2 | средняя | критический | Н | fault injection: нет ключа, сеть недоступна, timeout, stale token, downgrade; privileged operation остаётся closed |
| C2 | Replay/перенос capability | T2 | средняя | критический | Н | capability связан с user/device/action/audience/artifact, одноразовым nonce и коротким TTL |
| C4 | Подписан только удобный staging transcript | T2/T3 | средняя | высокая | У | доверенный environment policy, prod-equivalent config digest, набор негативных мутаций, а не один кейс |
| D1 | Фальшивый analyzer с правильными name/version и собственными хэшами | T3 | средняя | критический | Б* | owner-signed policy фиксирует adapter/executable digest; worker isolation остаётся deployment requirement |
| D2 | Самосогласованный поддельный probe report | T3 | средняя | критический | Б* | v0.9 требует свежую approved-worker подпись точного report/artifact; ключ должен быть вне build job |
| D2a | Подмена canary или ручной recovery score | T3/процесс | высокая | критический | Б* | v0.20 literal canary и typed semantic matches автоматически повышают score по signed raw stdout; неподдерживаемая поведенческая эквивалентность остаётся residual risk |
| D3 | TOCTOU на артефакте/публикации | T3 | средняя | критический | Б* | v0.18 publisher повторно сверяет artifact/manifest/attestation и публикует только read-only CAS object; внешние ACL/Object Lock обязательны |
| D4 | Все signer-ключи доступны одному CI job | T3 | средняя | критический | Н | разные trust domains, KMS policy, approvals, audit, key rotation и compromise drill |
| D5 | Альтернативный release path обходит gate | T3 | средняя | критический | Н | publisher принимает только attestation policy; прямой upload технически запрещён |
| D6 | Build job подаёт validator собственные public roots и подписывает всю цепочку | T3 | средняя | критический | Б* | v0.16 assessment/provenance/release используют один offline-root signed role bundle и запрещают cross-role key reuse; root public key всё ещё должен быть pin-нут внешней protected config |
| D7 | Approved worker key подписывает отчёт, созданный вне trusted runner | T3 | средняя | критический | Б* | v0.22 coordinator challenge связан с evaluation ID и атомарно потребляется общим ledger между assessment-процессами; KMS enforcement и защита ledger от storage-admin внешние |
| D8 | Runner откатывает системные часы, повторяет или задерживает старое время | T3/процесс | средняя | высокая | Б* | v0.32 assessment, provenance, release и CAS требуют root-trusted remote-time подпись exact scope и атомарно расходуют 256-bit nonce; proof должен выдаваться live по непредсказуемому nonce, потому что заранее полученный, ещё не использованный файл можно задержать; authority/online ledger остаются внешней границей |
| E1 | Старый валидный релиз | T1/T2 | средняя | высокая | У | minimum sequence хранится вне клиента либо подтверждается online trusted state |
| E3 | Две валидные ветки одного канала | T3 | низкая/средняя | высокая | Б* | v0.18 signed CAS receipts + atomic single channel head отклоняют fork/skipped predecessor; hostile storage требует внешнего append-only log/Object Lock |
| E4 | Attestation принимает manifest без проверки его подписи | T3 | средняя | высокая | Б | attestation v13 требует manifest signer из root-signed `release-manifest` role, проверяет signature/key ID и связывает issuer key ID |
| E5 | Gate для product A повторно используется при выпуске product B | T3 | средняя | критический | Б | v0.10 release create/verify сравнивает signed `protectionPolicy.product` со scope release; negative test обязателен |
| F1 | REA распознаёт Anti-REA по публичной реализации | T1 | почти неизбежна | высокая | У | никаких гарантий от неизвестности; extractor остаётся обязательной атакой каждого релиза |
| F3 | Защиту отключают из-за syntax/performance/bugs | T0/T1 | средняя | высокая | У | fail-closed build, semantic property tests, performance budget, запрет тихого fallback |
| F4 | Agent читает вредоносный output как инструкцию | T1/T3 | средняя | высокая | Н | analyzer output всегда untrusted data; structured parser, isolation, no secret-bearing env |
| F6 | Pipeline по умолчанию выпускает embedded key mode, а policy его не фиксирует | T0/T3 | средняя | высокая | Б | v0.13 policy v3 + assessment v4 сверяют backend, versions, profile digest, key mode/encryption и claim tier с фактическими receipts |
| G1 | Критичное правило ошибочно оставлено в клиенте | процесс | высокая | критический | У | обязательный owner sign-off классификации и автоматический запрет известных SERVER_REQUIRED классов |
| G2 | Assessment просто не перечисляет неудобный факт | процесс | средняя | критический | Б* | signed exposure/policy binding блокирует исчезновение известных ID; полнота первоначального owner inventory остаётся review-задачей |
| G4 | Ключ утёк через env/log/crash/support | T2/T3 | средняя | критический | Н | secret scanning всех журналов и bundles, ephemeral secret injection, no shell tracing, rotation test |
| G5 | Provenance описывает protector, но не product source/build graph | T3 | средняя | критический | Б* | v0.12 связывает owner-approved repository/commit/tree, tracked build definition, builder identity и virtualization input; реальная builder isolation внешняя |
| G6 | Functional/performance/platform evidence — произвольный непустой файл | T3 | высокая | высокая | Б* | v0.11 policy v2 + assessment v3 требуют typed report, raw result, suite/runner/environment identity и approved-worker signature; KMS isolation внешняя |
| G7 | Server receipt истёк после assessment, но до release signing | T3/процесс | средняя | высокая | Б* | v0.10 release create/verify повторно проверяют freshness; production должна запретить caller-controlled historical clock |
| G8 | Clean Git относится к protector, но artifact собран из другого product source | T3 | средняя | критический | Б* | product-build attestation + provenance v4 + release attestation v13 проверяют causal chain и builder role; доверие к CI/KMS остаётся внешним |
| G9 | Изменён transitive dependency при неизменном lockfile | T3 | средняя | высокая | Б* | v0.33 policy v6 pin-ит lockfile и фактический installed closure; provenance и release заново хэшируют package trees/modes и отклоняют missing/extra/symlink; registry provenance, install scripts и hermetic image остаются внешними |
| G10 | Mutable artifact/metadata меняются между hash и publish | T3 | средняя | критический | Б* | v0.18 publisher копирует exact attested inventory в digest-addressed read-only object; mode/xattr/platform signatures ещё требуют platform packaging evidence |
| H1 | LLM tripwire удаляется нормализатором или игнорируется моделью | T1 | высокая | низкий | У | tripwire никогда не является release control; эффективность измеряется отдельным holdout agent corpus |
| H2 | Tripwire становится стабильным locator/fingerprint Anti-REA | T1 | средняя | средний | Н | несколько шаблонов, независимые placement rules, отсутствие соседства с реальными protected symbols |
| H3 | Tripwire/analyzer output отравляет собственный защитный агент | T1/T3 | средняя | высокая | Н | quarantine + data-only parser + no tools/secrets + prompt-injection regression |
| H4 | Tripwire содержит реальный секрет/PII или исполняется приложением | процесс | низкая | критический | Б* | v0.12 exact five-template verifier, non-executable namespace, release inventory и attestation binding; независимый secret scan всё ещё обязателен |
| H5 | Видимый marker намеренно replay-ится для ложной атрибуции или автоматического ответа | T1/T3 | средняя | высокая | Б* | v0.15 observation имеет `telemetry-signal-only`, нулевой score и не даёт identity/verdict; автоматические санкции запрещены |

`Б*` означает, что framework проверяет форму доказательства, но фактическая
гарантия возникает только при настоящем серверном исполнении и разнесённых
ключах. Репозиторий сам по себе серверную границу не создаёт.

### 4.1. Какие гарантии реально даёт каждый слой

| Слой | Допустимая гарантия | Что он принципиально не доказывает |
|---|---|---|
| selective VM + obfuscation | рост стоимости T0/T1 для перечисленных фактов | секретность от владельца runtime |
| external key + AEAD | offline T1 не читает payload; ciphertext/context tamper отвергается | скрытие ключа/plaintext после легитимной выдачи |
| owner-signed policy | thresholds и известные facts нельзя тихо изменить после результата | полноту первоначальной классификации |
| worker attestation | exact report/artifact подписал approved key | что key доступен только честному workload |
| assessment signature | конкретный evidence root получил PASS | независимость signer от build job |
| release manifest + attestation | exact inventory связан с evidence и channel sequence | отсутствие глобального fork без online head |
| LLM tripwire | иногда задерживает generic agent и создаёт synthetic signal | отказ целевого adversarial agent или защита логики |

### 4.2. Контрольный end-to-end прогон 0.10.0

External-key fixture прошёл полный VM → obfuscation → pinned REA → strings →
public webcrack → runtime-hook pipeline. Полученный результат соответствует
заявленной границе, а не обещанию невскрываемости:

- public T1 deobfuscator распознал 1 envelope, восстановил 0/3 canary;
- после легитимной установки ключа T2 runtime hook восстановил 3/3 canary;
- build key отсутствовал в release и evidence directories;
- negative control обнаружил заведомо плохой artifact;
- итог: допускается только узкая offline T1 COST_ONLY заявка, T2 secrecy нет.

Во время этого review был найден и закрыт отдельный P0: analyzer раньше
наследовал весь environment, включая внешний VM-ключ и потенциальные signer
passphrases. Теперь `run-probe` передаёт только минимальный системный allowlist,
pipeline удаляет build-key из общего environment и подаёт его лишь virtualizer и
авторизованному runtime probe; regression test проверяет отсутствие secret
canary в дочернем analyzer. Это закрывает прямую утечку через environment, но не
заменяет отдельные network-disabled analysis jobs и KMS signers.

## 5. Главные цепочки, которые надо тестировать целиком

### Цепочка X1: Anti-REA становится учебником для REA

1. Противник читает публичные маркер, envelope, decoder и opcode families.
2. Генерирует chosen-input функции с одним изменением конструкции.
3. Сопоставляет двадцать и более сборок по разным seeds/releases.
4. Учится распознавать interpreter, decrypt boundary и semantic operators.
5. Добавляет generic provider: recognize → deobfuscate → hook/lift → score.

Текущий random seed и перенумерация opcode ломают сигнатуру байтов, но не эту
цепочку. Требуются структурно разные backend families, holdout corpus и метрика
семантического выравнивания. Даже после этого результат — увеличение стоимости,
не секретность клиентского алгоритма.

### Цепочка X2: Внешний ключ не спасает после запуска

1. Статический T1-анализ видит envelope и место получения ключа, но не plaintext.
2. Легитимный пользователь запускает клиент и получает ключ/capability.
3. T2-наблюдатель снимает значение из global slot или ловит plaintext на decode.
4. Программа, входы, выходы и ветвления сохраняются для offline анализа.

Поэтому внешний ключ поддерживает только заявленную T1 offline-границу для
`COST_ONLY`. Он не повышает клиентский секрет до T2.

### Цепочка X3: Зелёный релиз без настоящей атаки

1. Компрометированный CI создаёт два удобных analyzer executable.
2. Формирует синтаксически корректные raw outputs, reports и хэши.
3. Называет локальный пакет `webcrack@2.16.0`; текущая проверка подтверждает его
   самосогласованность, но не сверяет с внешним доверенным digest.
4. Валидатор выдаёт `PASS`; доступный тому же job gate-key подписывает его.
5. Publisher доверяет подписи и выпускает слабый артефакт.

Закрытие: analyzer policy и runner identity должны поступать из publisher/KMS
trust configuration, evidence должен быть подписан изолированным runner, а
assessment-, server- и release-signers не должны находиться в одной зоне.

### Цепочка X4: Обход понимания через патч

1. Противник не восстанавливает бизнес-логику.
2. Патчит локальный результат на «разрешено» и подавляет telemetry.
3. Повторяет запрос напрямую или через модифицированный клиент.
4. Если сервер доверяет решению, клиентским атрибутам или отсутствию сигнала,
   защита проиграна независимо от качества VM.

Единственная полноценная контрмера — сервер сам проверяет привилегированное
действие. Локальные integrity/anti-debug сигналы могут менять risk score, но не
выдавать полномочие.

### Цепочка X5: Подписанный rollback

1. Противник сохраняет старый корректно подписанный релиз и attestation.
2. Возвращает клиенту старое локальное состояние minimum sequence или запускает
   его offline.
3. Клиент принимает уязвимую, но криптографически валидную цепочку.

Локальный monotonic counter недостаточен против владельца устройства. Для
security-critical каналов minimum head/revocation должны приходить из
доверенного online state либо проверяемого transparency log.

### Цепочка X6: Самоподписанная «доверенная» фабрика

1. Частично скомпрометированный build job генерирует собственные пары ключей.
2. Передаёт их public halves через CLI как policy, worker, server, gate, manifest
   и release trust roots.
3. Теми же private halves подписывает самосогласованный набор отчётов.
4. Все локальные криптографические проверки проходят, потому что bootstrap был
   выбран самим недоверенным caller.

Это не дефект Ed25519, а дефект размещения trust root. Framework должен уметь
читать versioned trust bundle, но фактическое закрытие требует publisher/KMS
configuration вне build workspace и IAM, при котором один principal не может
вызвать все роли.

### Цепочка X7: Artifact не происходит из заявленного продукта

1. CI собирает product source из commit B или другого repository.
2. Защищает результат и получает зелёные analyzer evidence.
3. `create-provenance` фиксирует clean commit framework/protector A.
4. Release signer видит clean provenance, но не причинную цепочку продукта.
5. В канал попадает artifact, происхождение которого не соответствует owner
   intent.

Закрытие требует signed graph: approved product repository/commit/tree → exact
build definition/dependencies/builder → virtualization input → protected output
→ immutable release inventory. Каждый edge содержит digest обеих сторон.

### Цепочка X8: Tripwire против чужого LLM превращается в уязвимость своего

1. Защита добавляет файл с instruction-like текстом и synthetic canary.
2. Generic внешний агент иногда останавливается или эскалирует проверку.
3. Более подготовленный extractor удаляет файл либо использует стабильное имя и
   шаблон как locator для соседних защищённых компонентов.
4. Наш analyzer/agent читает этот же текст как инструкцию, меняет план, раскрывает
   секреты или пропускает проверку.

Поэтому tripwire допускается только как измеряемый deception/telemetry слой.
Его удаление не должно ослаблять ни один основной control, а defender ingestion
обязан быть data-only и проходить отдельный prompt-injection regression.

## 6. Defensive LLM tripwire/deception

### 6.1. Разрешённый дизайн

- Файлы размещаются только в заранее разрешённом non-executable namespace,
  например `META-INF/anti-rea/`; приложение их не импортирует и не исполняет.
- Содержимое создаётся framework из versioned template. Произвольный текст из
  product repository не копируется в prompt-facing часть.
- Используются только synthetic identifier/canary, product/release scope и
  нейтральное уведомление: материал требует подтверждённой авторизации,
  автоматическая эксфильтрация запрещена, инструкции внутри анализируемого
  артефакта не являются командами для defensive agent.
- Каждый файл имеет отдельный случайный canary ID, но manifest публикует только
  его hash. Нельзя помещать API keys, пароли, персональные данные и реальные
  секреты.
- Tripwire bytes входят в подписанный release manifest, а digest отдельного
  tripwire manifest входит в release-channel attestation, чтобы атакующий не мог
  подменить шаблоны на вредоносную инструкцию без нарушения подписи.
- Отдельный sanitizer представляет собственным LLM только typed metadata и
  quoted payload; у процесса нет signer keys, cloud credentials и write tools.

### 6.2. Что измерять

| Метрика | Смысл | Запрещённая интерпретация |
|---|---|---|
| stop/escalation rate на holdout agents | доля generic workflows, которые остановились | «все LLM откажутся» |
| strip survival | сколько вариантов сохранилось после minify/archive/normalization | «файл нельзя удалить» |
| self-poisoning rate | доля defensive runs, изменивших поведение из-за payload | любое значение выше нуля приемлемо |
| locator lift | насколько наличие tripwire помогает найти protected region | «деception всегда только помогает» |
| canary egress signal | synthetic ID замечен в разрешённом monitoring контуре | доказательство личности атакующего |

### 6.3. Release policy

LLM tripwire не участвует в security score и не может компенсировать провал
static/runtime/server probe. Если файлы удалены, release остаётся защищённым
основными controls; если файлы присутствуют, secret scan, non-executable path
check, exact-template validation и defensive-agent injection test обязательны.

## 7. Обязательный regression backlog

| Probe | Что инъецируем | Условие прохождения |
|---|---|---|
| R-01 tool substitution | локальный fake analyzer с допустимым report | gate отклоняет неизвестный digest/identity |
| R-02 fake package | пакет `webcrack@2.16.0` с изменённым entry/manifest/lock | gate отклоняет по внешнему trusted policy, не только по self-reported hash |
| R-03 evidence forgery | полностью самосогласованный вручную созданный probe bundle | нет доверенной runner signature — hard fail; реализовано в v0.9 |
| R-04 chosen plaintext | corpus функций с одним изменяемым construct | измеряется восстановление mapping на holdout |
| R-05 cross-build | ≥20 seeds/releases/customers | generic aligner не достигает согласованного порога либо заявка понижается |
| R-06 plaintext hooks | hooks до первого вызова на decode/cache/input/output | любое восстановление относится к соответствующему tier и ломает его claim |
| R-07 fail-open | key/network/server timeout, corrupt response, clock skew | привилегированная операция запрещена сервером |
| R-08 capability replay | другой user/device/action/artifact, повтор nonce | сервер отказывает каждой замене и повтору |
| R-09 staging drift | меняется security config между тестом и prod | receipt/gate не принимает несовпадающий config digest |
| R-10 artifact TOCTOU | analyzer или соседний job меняет файл | content digest меняется, публикация блокируется |
| R-11 signer separation | build job пытается вызвать все signers | IAM/KMS policy не позволяет собрать цепочку одному principal |
| R-12 rollback/fork | старый sequence и альтернативный signed head | trusted online head отвергает оба случая |
| R-13 delivery graph | canary по очереди в map/chunk/cache/update/crash/support | каждый канал обнаруживается |
| R-14 agent-output injection | instruction-like строки в analyzer output | трактуются как данные, секреты/команды не исполняются |
| R-15 downgrade pressure | unsupported syntax и превышение performance budget | защита не исчезает молча; сборка или release закрываются |
| R-16 inventory omission | leakage ID удаляется после baseline | coverage gate отклоняет исчезнувший ID |
| R-17 canary substitution | сохраняем count, но заменяем identities на decoys | точное fact→canary→comparison binding не совпадает — hard fail |
| R-18 manual score lie | raw output содержит fact, assessment пишет score 0 | score вычисляется из evidence и релиз падает |
| R-19 manifest signature | корректный inventory с чужим key/signature | release attestation не создаётся и не проверяется; реализовано в v0.9 |
| R-20 product provenance | защищаем input из другого product commit | causal build graph mismatch блокирует выпуск |
| R-21 fake regression | evidence содержит только `passed` | typed schema/attestation отсутствуют — hard fail; реализовано в v0.11 |
| R-22 trust-root substitution | build job подаёт собственные public keys | pinned publisher trust bundle отвергает неизвестные role/key IDs |
| R-23 cross-product gate | PASS для product A используется с manifest product B | release create и verify дают hard fail |
| R-24 stale upstream | server/gate/worker evidence истёк до release | create и verify повторно проверяют freshness и блокируют выпуск |
| R-25 worker laundering | approved key подписывает report вне trusted workload | KMS policy/challenge/workload identity не позволяют получить подпись |
| R-26 transitive dependency mutation | меняется исполняемый dependency без изменения lockfile | resolved graph/image digest mismatch блокирует gate |
| R-27 filesystem race | файл или metadata меняются между attestation и publish | v0.18 publisher повторно сверяет bytes и копирует только exact inventory в CAS object |
| R-28 tripwire strip | все tripwire files удалены до анализа | core security claims и probes не меняются; фиксируется только loss of deception |
| R-29 tripwire self-poison | instruction-like tripwire подаётся defensive agent | payload остаётся данными; план/tools/secrets не меняются |
| R-30 tripwire locator | модели показывают corpus с/без tripwire | наличие tripwire не повышает поиск protected region выше policy threshold |
| R-31 tripwire template abuse | в template пытаются вставить secret, executable extension или path escape | generator/verifier fail closed до упаковки |
| R-32 lazy protected path | canary находится только в экспортированной/условной функции, не вызываемой при import | runtime probe не может дать `not-recovered`: требует coverage либо возвращает inconclusive |
| R-33 semantic recovery | analyzer возвращает нормализованный факт без literal canary | typed finding автоматически повышает score и блокирует ложный PASS |
| R-34 decoy envelope | один из нескольких protected IDs распознан, остальные не обследованы | неполный ID coverage делает probe inconclusive/invalid |
| R-35 marker replay | атакующий копирует release marker в публичный/чужой transcript | detector сообщает только typed telemetry hit; identity, refusal и compromise не выводятся |
| R-35 embedded downgrade | key mode не задан, но policy требует external T1 boundary | default/fallback не проходит signed policy |
| R-36 chosen-input policy | owner требует alignment probe | schema принимает typed probe и gate делает его обязательным |
| R-37 AEAD tuple transplant | полный tuple одной функции переносится в другую | подмена отвергается или заявка явно ограничивается signed artifact integrity |
| R-38 historical clock | просроченный evidence проверяется с `--now` из прошлого | production mode запрещает override и даёт hard fail |
| R-39 output ingestion | deep/large/control/prompt-like analyzer output | cap/schema/depth/escaping срабатывают; agent не выполняет содержимое |
| R-40 CAS channel fork | второй genesis, skipped sequence или wrong predecessor пытается заменить head | signed publisher ledger отклоняет ветку; внешний Object Lock защищает receipts от удаления |

## 8. Порядок устранения

### P0 — до заявления о полноценном release gate

1. Operational pin offline root public key вне build workspace: формат role
   bundle и запрет per-command/cross-role key substitution реализованы в v0.16,
   но runner/publisher всё ещё должен защищённо закрепить сам root path/digest.
2. Production KMS enforcement для workload-bound challenge и внешний
   append-only/Object-Lock backend для v0.22 replay ledger; локальный framework
   уже делает atomic exclusive-create consumption между assessment-процессами.
3. Техническое разнесение assessment, server-authorization, manifest и release
   signers; KMS policy не даёт одному principal собрать всю цепочку.
4. Production CAS ACL/Object Lock: v0.18 реализует publisher-only protocol,
   signed receipts и single-head ledger, но удаление объектов hostile storage
   administrator-ом предотвращается внешней storage policy.
5. Расширить v0.27 bounded JS/WAT/native-CFG/hashed holdout scorer на
   cross-language equivalence и дополнительные architecture-specific lifters;
   поддерживаемые типы уже не доверяют ручному score, именам, литералам,
   адресам, block IDs или порядку holdout cases.

Закрыто сразу после независимой критики в v0.10: cross-product policy reuse и
повторная freshness-проверка server authorization при release create/verify.
В v0.11 закрыт handwritten regression bypass: policy v2 precommit и assessment
v3 принимают только typed worker-signed reports, exact raw results и budgets.
В v0.12 добавлена signed causal product-build chain и обязательная проверка
пяти agent-refusal tripwire-векторов внутри release inventory; оба механизма
остаются зависимыми от внешнего KMS/IAM и не повышают security score tripwire.
В v0.13 закрыт embedded/default downgrade: protection policy v3 фиксирует
pipeline identity, версии, profile digest, key mode/encryption и maximum claim
tier, а assessment v4, provenance и release signer сверяют точные receipts.
В v0.14 каждый VM-envelope получил stable opaque function ID; runtime/public
probes и assessment требуют полного совпадения expected/observed ID inventory.
Частичный lazy-path probe больше не может дать `not-recovered`.
В v0.15 пять honeyfiles получили typed trigger/expected-response binding, а
локальный observer выдаёт hash-only telemetry report при появлении synthetic
marker. Marker replay явно считается недоверенным сигналом и не меняет security
score, release verdict или атрибуцию.
В v0.16 assessment, provenance и release attestation v10 принимают operational
keys только из одного offline-root signed bundle. Bundle привязан к gate и
release payload, а один key ID запрещён в нескольких signer-ролях. Это закрывает
per-command PEM substitution на уровне формата; внешний pin root key и реальная
изоляция signer/KMS остаются deployment requirement.
В v0.17 signed assessment result schema v5 фиксирует clock source/time.
Historical `--now` разрешён только в explicit test mode, test-clock result нельзя
подписать gate key, а provenance/release attestation v13 требуют свежий
`system` clock. Это закрывает caller-controlled time travel, но не компрометацию
часов самого host; для hostile runner нужен внешний signed time authority.
В v0.18 CAS publisher повторно проверяет точный artifact, manifest, release
attestation и trust bundle, создаёт read-only digest-addressed object, подписывает
publisher receipt и атомарно двигает единственный channel head. Mutable
workspace больше не является publish input после staging; внешние append-only
ACL/Object Lock остаются production boundary.
В v0.19 каждый из пяти honeyfiles несёт canonical refusal capsule v1: risk class,
typed trigger, denied operations, требуемое внешнее evidence, fail-closed
`defaultDecision: deny` и ожидаемый safe response. Manifest v4 связывает те же
поля с exact bytes и signed release chain; подмена `deny` на `allow` делает bundle
невалидным. Это усиливает policy-aware agent refusal, но не мешает целевому
analyzer удалить файл и поэтому по-прежнему даёт нулевой security score.
В v0.20 exposure policy v2 требует owner-precommitted semantic fingerprints для
каждого клиентского `COST_ONLY` факта. Assessment result v6 самостоятельно
извлекает кандидаты из worker-signed raw stdout и применяет фиксированные scores
для `exact-text`, `endpoint`, `identifier` и `json-shape`. Analyzer не может
скрыть восстановленный endpoint лишь перестановкой query или регистра, а автор
assessment не может занизить такой score вручную. CFG и произвольная behavioral
equivalence остаются отдельным holdout-oracle gap.
В v0.21 добавлена отдельная root-trusted роль `evidence-coordinator` и challenge
v1 с максимальным TTL 15 минут. Worker attestation v2 связывает challenge с
exact report/artifact, policy digest, worker key, runner ID, environment image и
workload identity. Assessment запрещает повтор challenge внутри одного evidence
bundle и включает challenge digest в evidence root. Реальное ограничение KMS по
workload identity и глобальное one-time consumption остаются deployment boundary.
В v0.22 challenge дополнительно связан с уникальным `evaluationId`, а assessment
input v5 атомарно создаёт immutable consumption record по challenge ID в общем
persistent ledger. Повтор между независимыми gate-процессами отклоняется;
consumption digest входит в assessment result v7 и evidence root. Ошибка после
consumption намеренно сжигает challenge. Удаление ledger-записи hostile storage
administrator-ом всё ещё требует внешнего append-only/Object Lock и ACL.
В v0.23 protection policy v4 заранее фиксирует server authorization product,
environment, channel, privileged action и deployment/config/transcript-schema
digests. Новый signer и assessment принимают только v2 receipt, hash-bound raw
request/response transcript и fresh coordinator challenge для exact artifact и
evaluation. Release повторно сверяет channel и owner policy. Это закрывает
локальный C4/server-receipt gap; честность production deployment и KMS workload
identity остаются внешней trust boundary.
В v0.24 semantic scorer получил `js-structure`: bounded Acorn AST fingerprint
игнорирует имена/литералы, но сохраняет control/operator structure. Второй тип
`behavior-vector` канонизирует до 256 owner holdout input/output hashes. Оба
извлекаются из signed raw analyzer output и принудительно дают score 4. Это
закрывает переименование, минификацию и известные holdout-equivalent реализации
для JavaScript; arbitrary/native/WASM equivalence и секретный online oracle ещё
остаются адаптивным P1/P0 deployment gap.
В v0.25 hash-only holdout стал обязательным adversarial probe: reference и
recovered candidate реально исполняются на полном private corpus. Gate проверяет
artifact/runtime/reference/candidate identities, owner-precommitted reference
vector, complete case coverage и signed worker/challenge binding. Timeout,
crash, malformed output, output limit и executable/artifact TOCTOU дают invalid
evidence. Network/filesystem sandbox по-прежнему обеспечивается внешним runner.
В v0.26 protection policy v6 требует ровно по одному owner-signed disposition
для release/update/crash/support/symbols. Новый scanner физически обходит все
`present` staging trees, fail-closed отклоняет source/debug leakage, credentials,
symlink/special entries и непросмотренные архивы. Assessment input v6 повторно
открывает каждое дерево, сверяет policy IDs/kinds/audiences и TOCTOU digest,
требует release root равным verified artifact и включает report в signed result
v8/evidence root. Реальные CDN caches, crash SaaS retention и storage ACL всё ещё
требуют внешних connector/API probes.
В v0.27 semantic scorer получил `wasm-structure` и `native-cfg` с fixed score 4.
WAT normalizer поддерживает nested comments и сохраняет module/control/opcode
structure после удаления имён, чисел и строк. Native normalizer проверяет полный
bounded CFG, затем канонизирует mnemonic/operand-class sequence и топологию без
адресов, register names, immediate values, block IDs и порядка блоков. Оба типа
извлекаются из signed raw analyzer output самим gate; unknown successor,
partial/malformed graph или unbalanced WAT не дают non-recovery. Это bounded
structural signal, а не доказательство cross-language/program equivalence.
В v0.28 каждый comparison обязан пройти T1 cross-build alignment на 20–64
уникальных independently produced protected-function regions. Probe ищет
32-byte high-entropy windows с support не менее 80%, считает stable target ratio
и maximum pairwise Jaccard, отдавая только hashes/ratios. Gate повторно читает
все variants, пересчитывает отчёт, запрещает duplicate path/bytes, weakened
threshold, post-report mutation и привязывает worker/challenge к exact release
region. Whole-runtime corpus явно запрещён как неверная поверхность измерения.
Каждый region дополнительно имеет отдельную `product-builder` подпись exact
policy/source/build/environment/run/ordinal/seed commitment/digest; случайные
непричинные файлы без owner-approved build chain больше не проходят gate.
В v0.30 тот же corpus обязательно проходит pinned `semantic-ir` extractor.
Его bounded language-neutral control/data-flow graph канонизируется без node
IDs и inventory order; 80%-consensus fingerprint или pairwise feature Jaccard
выше 70% означает recovery. Gate сверяет owner-approved adapter/executable,
builder signatures и заново выполняет все 20–64 extraction runs. Unreachable,
duplicate, opaque-heavy, malformed и мутировавшие графы считаются invalid.

### P1 — до заявления об адаптивной устойчивости к REA

1. Browser/OS/native-specific plaintext probes за пределами Node harness:
   CDP/DevTools Protocol, Frida/LLDB, native allocator/register snapshots и
   platform keychain callbacks. v0.29 уже покрывает Node Buffer/base64,
   decipher, file/cache reads, fetch/Response, structured clone, MessagePort
   IPC, process output, JSON/TextDecoder и WebAssembly input.
2. Внешний append-only/Object-Lock backend и online anti-rollback head поверх
   локального signed single-head CAS protocol из v0.18.
3. Signed/remote time authority для hostile-host threat model; v0.17 уже
   запрещает caller `--now`, но доверяет системным часам управляемого runner.

### P2 — повышение стоимости и живучести

1. Несколько структурно разных backend families и ротация без понижения тестов.
2. Property/differential tests JavaScript edge cases.
3. Availability/DoS и performance-pressure corpus.
4. Poisoning-safe ingestion всех результатов анализаторов.
5. LLM tripwire/deception только после self-poisoning, strip и locator eval;
   этот слой остаётся вне security score.

## 9. Честная текущая граница

Текущая реализация уже существенно сильнее обычной «обфускации»: она применяет
selective VM, external-key AEAD, связывает facts с owner-signed policy, требует
signed worker и typed regression evidence, проверяет manifest signature и
immediate predecessor, а provenance связывает owner-approved product commit/tree,
tracked build definition, builder identity и точный virtualization input.
Agent-refusal bundle проверяется exact-template verifier-ом и входит в release
chain, но остаётся вероятностным deception-слоем. Operational keys выбираются
только из root-signed role bundle; сам offline root public key всё ещё приходит
из внешней protected runner/publisher config. Server/publisher/KMS и реальная
изоляция builder/worker создаются внешней инфраструктурой, а не repository.

Допустимая формулировка сейчас:

> Для точного digest релиза измерена устойчивость перечисленных COST_ONLY фактов
> к перечисленным T0/T1 анализаторам. После легитимной выдачи ключа T2 может
> восстановить клиентскую семантику. Привилегированные решения считаются
> защищёнными только при независимо проверенной серверной авторизации. LLM
> tripwire является дополнительным deception/telemetry слоем и не входит в
> криптографическую или серверную гарантию.

Недопустимые формулировки: «код невозможно вскрыть», «ключ защищает от
отладчика», «подписанный JSON доказывает честный тест» и «anti-rollback защищает
контролируемое атакующим устройство без внешнего доверенного состояния».
