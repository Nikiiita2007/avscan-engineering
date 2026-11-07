#pragma once
#include "engine.hpp"
#include <cstdint>
#include <vector>
namespace av {
struct QuarantineRecord {
 std::string id;          // record directory name (decimal digits)
 std::string source;      // original path (UTF-8), from source.txt
 std::uintmax_t cipherBytes=0; // size of the encrypted sample
};
// Evidence store. copyEvidence keeps the legacy plaintext behavior used by tests.
// store() is the hardened path: AES-256-CBC encryption (key DPAPI-protected),
// deny-execute ACL, restore() and remove() (overwrite + delete).
class Quarantine {
 std::filesystem::path root;
public:
 explicit Quarantine(std::filesystem::path p):root(std::move(p)){}
 Result<std::filesystem::path> copyEvidence(const std::filesystem::path& source);
 Result<std::string> store(const std::filesystem::path& source);            // Windows only
 Result<void> restore(const std::string& id,const std::filesystem::path& dest); // Windows only
 Result<void> remove(const std::string& id);                                  // Windows only
 Result<std::vector<QuarantineRecord>> list() const;
};
}
