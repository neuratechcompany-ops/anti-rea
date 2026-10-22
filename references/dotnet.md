# .NET managed assembly — обфускация IL

Бьёт по `inspect_managed_artifact` и `inspect_managed_members` (REA читает
metadata: types, методы, поля, `member_refs`, `user_strings`, call-граф, MVID).

## Инструменты

| Инструмент | Лицензия | Что даёт против REA |
|---|---|---|
| **ConfuserEx** | open-source (LGPL) | control-flow обфускация IL, шифрование строк, anti-tamper, anti-dump |
| **.NET Reactor** | коммерч. | полная протекция + native-компиляция обвязки |
| **Eazfuscator.NET** | коммерч. | автоматическая обфускация + слияние сборок |
| **Obfuscar** | open-source (MIT) | базовое переименование + string encryption |

## Базовый конфиг (ConfuserEx)

```xml
<!-- ConfuserEx project (.crproj) -->
<project outputDir="dist" baseDir="src">
  <module path="App.dll">
    <rule pattern="true" preset="none">
      <protection id="constants" />        <!-- шифрование констант/строк -->
      <protection id="ctrl flow">
        <argument name="intensity" value="100" />
      </protection>
      <protection id="rename" mode="unicode" />  <!-- переименование идентификаторов -->
      <protection id="anti dump" />        <!-- против дампа памяти -->
      <protection id="anti tamper" />      <!-- анти-тампер подпись -->
      <protection id="anti ildasm" />      <!-- ломает ILDasm -->
      <protection id="resources" />        <!-- шифрование ресурсов -->
    </rule>
  </module>
</project>
```

```bash
Confuser.CLI.exe -n app.crproj
```

## Что именно это ломает в REA

- `constants` + `resources` → `user_strings` и `references` (string-таблица)
  вернут пустоту/мусор;
- `ctrl flow` → декомпиляторы и IL-чтение дают спагетти;
- `rename` → `exported_types`, `methods`, `fields` теряют смысловые имена;
- `anti ildasm` / `anti dump` → затрудняет прямое чтение metadata.

## Дополнительно

- **NativeAOT** (или .NET's ReadyToRun) — компиляция в нативный код полностью
  убирает IL. REA по NativeAOT идёт нативным путём (`open_binary` + Ghidra),
  значит дальше применяются правила native-binaries.md. Свой README REA прямо
  говорит: "NativeAOT binaries contain native machine code, so ordinary CIL
  decompilers cannot recover the original method bodies".
- **Strong name** — идентичность сборки, а не security boundary. Для проверки
  издателя и целостности поставки используйте платформенную подпись пакета/
  исполняемого файла и проверяемую цепочку обновлений; это не препятствует
  анализу кода.

## Проверка через REA

```bash
# MCP: inspect_managed_artifact(detail="summary") -> проверить, что
#   exported_types/methods/user_strings обеднены, string-таблица пуста.
```

Критерий: `inspect_managed_members` не возвращает осмысленные имена методов и
строки; IL не декомпилируется в исходную логику (или вовсе отсутствует при NativeAOT).
