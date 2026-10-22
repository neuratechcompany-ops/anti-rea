# Android APK — R8 / ProGuard / DexGuard + нативный .so

Бьёт по `inspect_android_package` (JADX), `search_android_classes`,
`inspect_android_class`, `inspect_android_method`, `trace_android_references`.
REA декомпилирует dex → Java через JADX. Значит защита = минификация/обфускация
dex + вынос логики в нативный .so.

## 1. R8 / ProGuard (базовый, обязательный)

```proguard
# proguard-rules.pro
-keepattributes Signature,InnerClasses,EnclosingMethod
# обфусцировать имена
-obfuscationdictionary obf_dict.txt
-classobfuscationdictionary obf_dict.txt
-packageobfuscationdictionary obf_dict.txt
# вырезать логи, отладку
-assumenosideeffects class android.util.Log { *; }
```

`build.gradle`:
```gradle
android {
  buildTypes {
    release {
      minifyEnabled true
      shrinkResources true
      proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                  'proguard-rules.pro'
    }
  }
}
```

R8 переименовывает классы/методы и выкидывает мёртвый код — JADX покажет
`a.b.c` вместо `com.yourapp.SecretManager`.

## 2. DexGuard (коммерч., сильнее R8)

DexGuard добавляет: string encryption, control-flow обфускацию dex, class
encryption, anti-tamper, обфускацию native-вызовов (контекстно-связанные имена
JNI становятся динамическими).

## 3. Критичная логика — в нативный .so

JADX не дизассемблирует native-код. Выносим в JNI и применяем правила из
native-binaries.md (стрип + OLLVM + string encryption):

```bash
# ndk-build / cmake с флагами:
-strip-all -fvisibility=hidden
# + OLLVM/Hikari пассы на критичные функции (см. native-binaries.md)
```

JNI-символы (`Java_com_app_SecretManager_decrypt`) — это тоже утечка: REA/обычные
инструменты видят их в `.dynsym`. Смягчение — регистрация нативных методов через
`RegisterNatives` (динамическая привязка) вместо конвенции имён.

## 4. Корневые проверки (обнаружение окружения анализа)

Статический JADX-проход не запускает APK, но REA также поддерживает отдельные
ADB/Frida-сценарии на выбранном устройстве. Root/emulator/Frida-сигналы только
повышают стоимость динамического анализа и обходятся патчингом; не используйте
их как локальную авторизацию — см. runtime-integrity.md.

## Проверка через REA

```bash
# MCP: inspect_android_package(путь) -> inspect_android_class(SecretManager)
#   -> проверить: класс обфусцирован, литералы зашифрованы,
#      логика не читается.
```

Критерий: JADX-вывод даёт классы вида `a.a.a`, чувствительные строки отсутствуют,
критичная логика не в dex (ушла в .so).
