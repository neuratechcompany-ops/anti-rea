# Native-бинарники (Mach-O / ELF / PE) + Go/Rust

Бьёт по `open_binary`, `analyze_function`, `inspect_macho`, `inspect_binary_layout`,
`search_strings`, `procedure_pseudo_code`. REA полагается на: символы, строки,
Objective-C селекторы (Mach-O dispatch metadata), relocation-таблицы, debug DSYM.

## 1. Стрипинг и скрытие символов (базовый рубеж)

### macOS / iOS (Mach-O)
```bash
# стрип символов и debug-инфо
strip -x -S MyApp
# вырезать locale/архитектуры-дубли, если не нужны fat-бинари
lipo -thin arm64 MyApp -output MyApp_arm64

# при компиляции (clang):
clang -O2 -fvisibility=hidden -fvisibility-inlines-hidden \
      -Wl,-dead_strip -Wl,-x \
      -mmacosx-version-min=12.0 -o MyApp src.c
```

Objective-C — главная утечка: `inspect_macho` читает селекторы и dispatch metadata.
Смягчение — не класть чувствительные имена в селекторы, либо уводить логику из
ObjC в чистый C (селекторы остаются только у тонкой обвязки).

### Linux (ELF)
```bash
strip --strip-all --strip-unneeded myapp
# сборка с минимумом символов:
gcc -O2 -fvisibility=hidden -s -Wl,--gc-sections -o myapp src.c
# запретить экспорт лишних символов (version script):
# mylib.map:
#   { global: my_public_api; local: *; };
gcc -Wl,--version-script=mylib.map ...
```

### Windows (PE)
```bash
# MSVC: keep exploit mitigations enabled; omit public PDBs from the artifact.
cl /O2 /GL /GS /Gy /DEBUG:NONE src.c /link /OPT:REF /OPT:ICF /LTCG /DYNAMICBASE /NXCOMPAT
# GNU/MinGW:
strip -s myapp.exe
```

## 2. Шифрование строк

REA `search_strings` / `referenced strings` вытаскивает литералы. Защита:
- не держать чувствительные строки plaintext — расшифровывать в рантайме;
- коммерческие протекторы (VMProtect/Win, Themida) делают это автоматически;
- самодельный вариант: XOR/RC4-обёртка + накопление строк в рантайме, чтобы
  статически в бинаре лежали только зашифрованные блобы.

## 3. Упаковка / VM-протекция

- **Windows**: VMProtect, Themida/WinLicense — виртуализация + packing +
  анти-отладка. После них `analyze_function` покажет распаковочный stub.
- **Cross-platform OLLVM**: обфускация на уровне LLVM IR:
  ```bash
  # Hikari (форк OLLVM) — флаги при сборке Clang:
  -mllvm -enable-bcfobf        # bogus control flow
  -mllvm -enable-strcry        # string encryption
  -mllvm -enable-indibran      # indirect branches
  -mllvm -enable-fco           # function call obfuscation
  ```
- **macOS/iOS**: Hikari (`-fllvm` toolchain) — тот же набор OLLVM-пассов.

Важно: OLLVM-обфускация применяется только к критичным функциям (т.н.
"obfuscation attributes"), иначе сильно растёт размер и тормозит рантайм.

## 4. Анти-отладка (против `observe_native_calls`/LLDB)

REA запускает таргет под LLDB (`observe_native_calls` → breakpoints). Контрмеры:

```c
// macOS: запретить attach (нужны права, обычно в main() до всего)
#include <sys/ptrace.h>
ptrace(PT_DENY_ATTACH, 0, 0, 0);

// macOS: дочерний процесс держит ptrace-блокировку (актуально для новых SDK)
//   fork() -> дочерний ptrace(PT_DENY_ATTACH) -> ждать.

// Windows:
if (IsDebuggerPresent()) exit(-1);
// + CheckRemoteDebuggerPresent, NtQueryInformationProcess(ProcessDebugPort)

// Linux:
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) { /* уже под отладчиком */ }
```

- `get-task-allow` entitlement НЕ выдавать в релизной подписи (иначе LLDB attach
  работает; см. runtime-integrity.md).
- hardened runtime (+ library validation) на macOS.

## 5. Go / Rust — убираем встроенные метаданные (критично)

REA имеет ПРЯМЫЕ инструменты: `inspect_go_binary` (версия компилятора, модули,
`/src/path` строки) и `inspect_rust_binary` (`.dep-v0` список зависимостей).
Обычные release-флаги уменьшают утечку путей и отладочных данных, но не
гарантируют исчезновение всей build metadata.

### Go
```bash
go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/app .
# -s -w        : убрать DWARF и symbol table
# -trimpath    : убрать абсолютные пути /home/user/project/... из бинаря
# -buildvcs=false : не встраивать VCS revision/status; module build info может остаться
```

Проверка, что метаданных нет:
```bash
go version -m bin/app               # зафиксировать, что реально осталось
```

### Rust
```toml
# Cargo.toml — убрать cargo-auditable метаданные (.dep-v0)
#   cargo-auditable внедряется через `cargo auditable build` — просто НЕ использовать его.
[profile.release]
strip = "symbols"          # или = true
debug = false
lto = true
codegen-units = 1
```

```bash
# remap путей (убрать /home/user/... и приватные пути)
RUSTFLAGS="--remap-path-prefix=$HOME=/redacted -C strip=symbols" cargo build --release
```

Критерий: отчёт перечисляет оставшуюся metadata и подтверждает отсутствие
абсолютных путей, VCS revision/status и `.dep-v0`, если она не нужна. Не требуйте
`null` от `inspect_go_binary`: стандартная Go-сборка обычно сохраняет сведения
о toolchain и модулях даже с `-s -w -trimpath -buildvcs=false`.

## Проверка через REA

```bash
# offline, без disasm-движка (ELF only):
#  (через MCP: open_binary -> binary_overview / search_strings / analyze_function)
# быстрый контроль строк/символов вручную:
strings -a MyApp | grep -iE "secret|api_key|endpoint|/home/|/Users/" | head
nm MyApp 2>/dev/null | head        # символов не должно быть (stripped)
otool -l MyApp | grep -A2 LC_SYMTAB  # Mach-O: проверить symtab пуст
```

Критерий: `strings`/`search_strings` не выдают секреты и пути; `nm`/`inspect_macho`
не дают имена функций; декомпиляция критичных функций не восстанавливает логику.

Для критичных `COST_ONLY` функций isolated REA/IDA/Ghidra worker также обязан
сериализовать полный CFG в схему `examples/native-cfg.example.json`. Owner
precommit `native-cfg` сохраняет mnemonic/operand-class sequence и топологию,
но игнорирует адреса, конкретные регистры, immediate values, block IDs и порядок
выдачи блоков. Совпадение в подписанном raw output даёт score 4; неизвестный
successor или частичный/повреждённый graph не принимается как non-recovery.
