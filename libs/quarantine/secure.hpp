#pragma once
// Windows-only secure primitives for the quarantine store.
// AES-256-CBC via CNG (bcrypt), key protected with DPAPI (crypt32),
// NTFS deny-execute ACLs (advapi32). All functions return Result<>.
#include "result.hpp"
#ifdef _WIN32
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace av {
// Encrypt/decrypt bytes with AES-256-CBC; output = IV(16) || ciphertext (PKCS-style block padding).
Result<std::vector<std::uint8_t>> aesEncrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> plain);
Result<std::vector<std::uint8_t>> aesDecrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> ivAndCipher);

// DPAPI-protect a key blob (per-user scope). Reversible only on this machine/account.
Result<std::vector<std::uint8_t>> dpapiProtect(std::span<const std::uint8_t> plain);
Result<std::vector<std::uint8_t>> dpapiUnprotect(std::span<const std::uint8_t> blob);

// Replace the DACL of a file: deny FILE_GENERIC_EXECUTE for Everyone, allow full
// control to the current user (owner), Administrators and SYSTEM. The deny ACE
// overrides the allows, so the sample cannot be executed but stays readable for restore.
// For a directory (sealDirAcl) no deny ACE is used: deny-execute on a directory also
// denies traversal on NTFS, which would make the record unreadable.
Result<void> denyExecuteAcl(const std::filesystem::path& file);
Result<void> sealDirAcl(const std::filesystem::path& dir);

// Overwrite the file content with random bytes (single pass) without resizing.
// Used before deletion so the on-disk ciphertext cannot be carved back cheaply.
Result<void> overwriteWithRandom(const std::filesystem::path& target);
}
#endif
