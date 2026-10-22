# Security Policy

## Supported versions

Security fixes выпускаются для последней опубликованной версии `0.x`. До 1.0
форматы evidence и attestations могут получать несовместимые обновления.

## Reporting a vulnerability

Не публикуйте рабочий обход release gate, утечку ключа или supply-chain
уязвимость в обычном issue. Используйте GitHub **Private vulnerability
reporting** на вкладке Security этого репозитория.

В отчёте укажите:

- затронутую версию и commit;
- attacker tier и необходимые права;
- минимальный сценарий воспроизведения;
- влияние на confidentiality, integrity или authenticity evidence;
- возможное исправление, если оно известно.

Мы постараемся подтвердить получение в течение 72 часов. Срок исправления
зависит от влияния и воспроизводимости. Публикация деталей координируется после
выхода исправления.

## Scope

В scope входят подделка evidence, обход fail-closed gate, signer/key confusion,
rollback/fork release chain, sandbox escape в bundled probes и утечка реальных
секретов. Сам факт возможности наблюдать код, который легитимно выполняется на
полностью контролируемом клиенте, является задокументированной границей, а не
уязвимостью.
