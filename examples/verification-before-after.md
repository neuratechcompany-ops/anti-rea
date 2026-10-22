# Верификация защиты — прогон через REA (реальные результаты)

Ниже — фактические результаты прогона демо-приложения через REA `6.7.0`
(`analyze_javascript_application`), доказывающие, что контрмеры из скилла
работают в действительности.

## Тестовое приложение

`secret.js` с чувствительными данными:
- `API_KEY = "sk-live-9f8e7d6c5b4a39281706secret"`
- `ENDPOINT = "https://api.private-service.com/v1/transactions"`
- `DB_PASSWORD = "Sup3rSecret!Prod#2026"`
- функции `signRequest`, `fetchTransactions`

## Результат ДО защиты (незащищённый JS)

REA **извлёк все секреты** из AST-графа:

```
grep по before.json →
  sk-live-9f8e7d6c5b4a39281706secret   (найден, 2x)
  api.private-service.com/v1/transactions  (найден, 2x)
  Sup3rSecret!Prod#2026                (найден, 2x)
  API_KEY / DB_PASSWORD / ENDPOINT     (имена переменных)
  signRequest / fetchTransactions      (имена функций)
```

Вывод: без защиты REA полностью раскрывает логику и секреты.

## Результат ПОСЛЕ защиты (javascript-obfuscator, конфиг из `scripts/harden-js.sh`)

Применены: `stringArray` + `rc4`-шифрование строк, `controlFlowFlattening`,
`renameGlobals`, `splitStrings`, `selfDefending`, `deadCodeInjection`.

```
grep по after.json →   СЕКРЕТЫ НЕ ИЗВЛЕЧЕНЫ
grep по обфусцир. коду → СЕКРЕТЫ СКРЫТЫ
единственное читаемое имя из REA: "fetch" (стандартный API, не секрет)
```

Размер артефакта: 625 байт → 22 110 байт (плата за обфускацию).

## Вывод

Защита подтверждена эмпирически: статический анализатор REA перестаёт извлекать
чувствительные строки и читаемые идентификаторы после обфускации по методологии
скилла. Это не «должно сработать» — это задокументированный результат прогона.
