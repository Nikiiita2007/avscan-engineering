# C API AVScan (avscan.h)

Стабильный интерфейс на чистом C поверх C++-ядра (`libs/core`). Нужен, чтобы подключать сканер к другим модулям и языкам (Rust, C#, Python через FFI) без зависимости от ABI компилятора и от `std::span`, `tl::expected` в заголовках.

Версия API: **1** (`AVSCAN_API_VERSION`). Совместимые добавления не меняют номер; ломающее изменение означает новую мажорную версию и новое имя DLL.

## Сборка

Библиотека включается опцией `AV_CAPI` (по умолчанию OFF; в пресете `windows-vcpkg` и в Linux-сборке CI включена):

```powershell
cmake --preset windows-vcpkg
cmake --build build/windows --config Release
ctest --test-dir build/windows -C Release --output-on-failure
```

Результат: `avscan_capi.dll` (и `capi_test.exe`) рядом с остальными EXE. Ядро встроено в DLL статически; DLL сторонних библиотек vcpkg (zlib, libarchive и др.) нужно поставлять вместе с ней.

## Пример

```c
#include "avscan.h"
#include <stdio.h>

int main(void) {
    avscan_engine* e = NULL;
    avscan_result* r = NULL;
    if (avscan_open("db/signatures.db", NULL, &e) != AVSCAN_OK) {
        fprintf(stderr, "open failed: %s\n", avscan_last_error());
        return 1;
    }
    if (avscan_scan_path(e, "C:\\Samples\\file.exe", &r) == AVSCAN_OK) {
        printf("status=%d score=%d detections=%zu\n", (int)avscan_result_status(r),
               avscan_result_score(r), avscan_result_detection_count(r));
        avscan_result_free(r);
    }
    avscan_close(e);
    return 0;
}
```

## Использование из CMake

Внутри этого репозитория (через `add_subdirectory`) цель `avscan::capi`. После `cmake --install` подключается так:

```cmake
find_package(avscan CONFIG REQUIRED)
target_link_libraries(my_module PRIVATE avscan::capi)
```

## Правила

- Все строки — UTF-8. Ошибки возвращаются кодами `AVSCAN_ERR_*`, текст — через `avscan_last_error()` (на поток).
- Проблема сканирования (нет файла, нет доступа) — это статус `AVSCAN_STATUS_ERROR` в результате, а не код возврата. Ошибка никогда не равна `Clean`.
- Объекты освобождаются парными функциями: `avscan_open`/`avscan_close`, `avscan_scan_*`/`avscan_result_free`. `NULL` допустим.
- Строки из `avscan_result_*` принадлежат результату и действительны до `avscan_result_free`.
- Движок можно вызывать из нескольких потоков (вызовы сериализуются). Один результат нельзя читать из нескольких потоков одновременно.
- `avscan_options` всегда инициализируется `avscan_options_init()`; кэш по умолчанию выключен.
- Разбор недоверенных файлов выполняется в процессе вызывающего. Для защиты хоста от сбоев запускайте модуль отдельным процессом.
