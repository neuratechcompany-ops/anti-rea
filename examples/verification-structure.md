# Верификация закрытия СТРУКТУРЫ / ЭНДПОИНТОВ / ПРИНЦИПА РАБОТЫ

Реальный прогон обфусцированного приложения через REA `6.7.0`
(`analyze_javascript_application`). Доказывает, что после обфускации REA не
извлекает ни структуру классов, ни карту эндпоинтов, ни принцип работы.

## Тестовое приложение (`app.js`)

Богатый пример с бизнес-логикой:
- класс `PaymentProcessor` с методами `sign` (HMAC-подпись) и `transfer`;
- модули `express`, `axios`, `crypto`;
- `INTERNAL_TOKEN = "tok_8f3d2a1b9c7e6secret"`, `BASE_URL`;
- эндпоинты `/api/v1/auth/login`, `/api/v1/payments/transfer`,
  `/api/v1/accounts/{id}/balance`, `/api/v1/reports/export`;
- принцип: «сначала подпись, потом HTTP POST».

## ДО обфускации — REA восстановил всё

| Слой | Что извлёк REA |
|---|---|
| Структура | `PaymentProcessor`, `sign`, `transfer`, `login`, `ROUTES`, `INTERNAL_TOKEN`, `BASE_URL` |
| Модули | `express`, `axios`, `crypto` |
| Значения | `tok_8f3d2a1b9c7e6secret`, `https://gateway.corp.internal` |
| Эндпоинты | в исходных source-ranges (полные строки `/api/v1/...`) |

## ПОСЛЕ обфускации — REA потерял всё

Конфиг (см. `examples/obfuscator.config.example.cjs`): `stringArrayThreshold: 1`,
`rc4`, `controlFlowFlatteningThreshold: 1`, `renameGlobals` + hexadecimal,
`splitStrings` (chunk 6), `deadCodeInjection`, `selfDefending`.

| Слой | Результат после |
|---|---|
| Структура | только `a0_0x19217b`, `Bkoekr`, `HuIVau`… (мусор) |
| Модули | не извлечены |
| Значения | `tok_*` / `https://*` не найдены |
| Эндпоинты | не найдены |
| Осталось осмысленного | только стандартные глобалы `Boolean`/`Date`/`Math`/`String`/`Function`/`RegExp` |

## Вывод

`renameGlobals`+hex закрывает структуру, `stringArray`+rc4+`splitStrings`
закрывает эндпоинты и значения, `controlFlowFlattening`+`deadCodeInjection`
закрывает принцип. REA после этого различает только «есть какие-то функции»,
но не может понять ни что они делают, ни какие API и логику приложение
использует.

Плата: 1196 байт → 32 647 байт (обфускация сильно раздувает объём).
