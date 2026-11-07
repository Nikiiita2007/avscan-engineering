# Кросс-сборка под Windows x64 из Linux: x86_64-w64-mingw32-g++ (MinGW-w64, GCC 13, POSIX threads).
# zlib и libarchive нужно собрать под MinGW отдельно (статика) и положить в
# /usr/x86_64-w64-mingw32 (libz.a, libarchive.a, zlib.h, archive.h, archive_entry.h).
# Сборка: cmake --preset windows-mingw && cmake --build build/win
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
