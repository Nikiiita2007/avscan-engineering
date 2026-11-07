#pragma once
#include <iosfwd>
#include <string>
#include "types.hpp"

namespace av {
void printResult(std::ostream& os, const ScanResult& r, bool verbose, int indent = 0);
void printJson(std::ostream& os, const ScanResult& r, int indent = 0);
}
