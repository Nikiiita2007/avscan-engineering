#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build-local
python3 scripts/make_corpus.py
CXX=${CXX:-g++}
FLAGS="-std=c++20 -O1 -g -Wall -Wextra -Ilibs/core -Ilibs/monitor -Ilibs/quarantine -Ilibs/gui -DAV_HAVE_ZLIB"
if [ "${SANITIZE:-0}" = 1 ]; then FLAGS="$FLAGS -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"; fi
CORE="libs/core/scanner.cpp libs/core/archive.cpp libs/core/report.cpp"
$CXX $FLAGS $CORE apps/main.cpp apps/selftest.cpp -lz -o build-local/avscan
$CXX $FLAGS $CORE libs/quarantine/quarantine.cpp tests/quality.cpp -lz -o build-local/quality
build-local/avscan --selftest
build-local/quality db/signatures.db tests/corpus
for kind in pe archive; do
 $CXX $FLAGS $CORE fuzz/$kind.cpp tests/mutation_driver.cpp -lz -o build-local/mutate-$kind
 build-local/mutate-$kind tests/corpus
done
