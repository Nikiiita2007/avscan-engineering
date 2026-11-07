#include "secure.hpp"
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <random>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace av {
namespace {
std::string ntError(std::string what, NTSTATUS s) { return what + " NTSTATUS=" + std::to_string(long(s)); }
std::string winError(std::string what, DWORD e) { return what + " GetLastError=" + std::to_string(e); }
}

Result<std::vector<std::uint8_t>> aesEncrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> plain) {
    if (key.size() != 32) return failure("AES-256 key must be 32 bytes");
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (s != 0) return failure(ntError("BCryptOpenAlgorithmProvider", s));
    struct CloseAlg { BCRYPT_ALG_HANDLE a; ~CloseAlg() { if (a) BCryptCloseAlgorithmProvider(a, 0); } } closeAlg{alg};
    s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (s != 0) return failure(ntError("BCryptSetProperty(CBC)", s));
    BCRYPT_KEY_HANDLE kh = nullptr;
    s = BCryptGenerateSymmetricKey(alg, &kh, nullptr, 0, (PUCHAR)key.data(), ULONG(key.size()), 0);
    if (s != 0) return failure(ntError("BCryptGenerateSymmetricKey", s));
    struct DestroyKey { BCRYPT_KEY_HANDLE k; ~DestroyKey() { if (k) BCryptDestroyKey(k); } } destroyKey{kh};
    std::uint8_t iv[16];
    s = BCryptGenRandom(nullptr, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (s != 0) return failure(ntError("BCryptGenRandom(IV)", s));
    ULONG outLen = 0;
    s = BCryptEncrypt(kh, (PUCHAR)plain.data(), ULONG(plain.size()), nullptr, iv, sizeof(iv),
                      nullptr, 0, &outLen, BCRYPT_BLOCK_PADDING);
    if (s != 0) return failure(ntError("BCryptEncrypt(size)", s));
    std::vector<std::uint8_t> out(16 + outLen);
    std::copy(std::begin(iv), std::end(iv), out.begin());
    ULONG written = 0;
    s = BCryptEncrypt(kh, (PUCHAR)plain.data(), ULONG(plain.size()), nullptr, iv, sizeof(iv),
                      out.data() + 16, ULONG(outLen), &written, BCRYPT_BLOCK_PADDING);
    if (s != 0) return failure(ntError("BCryptEncrypt", s));
    out.resize(16 + written);
    return out;
}

Result<std::vector<std::uint8_t>> aesDecrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> ivAndCipher) {
    if (key.size() != 32) return failure("AES-256 key must be 32 bytes");
    if (ivAndCipher.size() < 16 + 16) return failure("ciphertext too short");
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (s != 0) return failure(ntError("BCryptOpenAlgorithmProvider", s));
    struct CloseAlg { BCRYPT_ALG_HANDLE a; ~CloseAlg() { if (a) BCryptCloseAlgorithmProvider(a, 0); } } closeAlg{alg};
    s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (s != 0) return failure(ntError("BCryptSetProperty(CBC)", s));
    BCRYPT_KEY_HANDLE kh = nullptr;
    s = BCryptGenerateSymmetricKey(alg, &kh, nullptr, 0, (PUCHAR)key.data(), ULONG(key.size()), 0);
    if (s != 0) return failure(ntError("BCryptGenerateSymmetricKey", s));
    struct DestroyKey { BCRYPT_KEY_HANDLE k; ~DestroyKey() { if (k) BCryptDestroyKey(k); } } destroyKey{kh};
    std::uint8_t iv[16];
    std::copy(ivAndCipher.begin(), ivAndCipher.begin() + 16, std::begin(iv));
    ULONG outLen = 0;
    s = BCryptDecrypt(kh, (PUCHAR)ivAndCipher.data() + 16, ULONG(ivAndCipher.size() - 16), nullptr,
                      iv, sizeof(iv), nullptr, 0, &outLen, BCRYPT_BLOCK_PADDING);
    if (s != 0) return failure(ntError("BCryptDecrypt(size)", s));
    std::vector<std::uint8_t> out(outLen);
    ULONG written = 0;
    s = BCryptDecrypt(kh, (PUCHAR)ivAndCipher.data() + 16, ULONG(ivAndCipher.size() - 16), nullptr,
                      iv, sizeof(iv), out.data(), ULONG(outLen), &written, BCRYPT_BLOCK_PADDING);
    if (s != 0) return failure(ntError("BCryptDecrypt", s));
    out.resize(written);
    return out;
}

Result<std::vector<std::uint8_t>> dpapiProtect(std::span<const std::uint8_t> plain) {
    DATA_BLOB in{}, out{};
    in.pbData = (BYTE*)plain.data();
    in.cbData = DWORD(plain.size());
    if (!CryptProtectData(&in, L"AVScan quarantine key", nullptr, nullptr, nullptr, 0, &out))
        return failure(winError("CryptProtectData", GetLastError()));
    std::vector<std::uint8_t> v(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return v;
}

Result<std::vector<std::uint8_t>> dpapiUnprotect(std::span<const std::uint8_t> blob) {
    DATA_BLOB in{}, out{};
    in.pbData = (BYTE*)blob.data();
    in.cbData = DWORD(blob.size());
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out))
        return failure(winError("CryptUnprotectData", GetLastError()));
    std::vector<std::uint8_t> v(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return v;
}

namespace {
// Current process owner SID (for explicit owner allow ACEs).
std::vector<BYTE> ownerSidStorage() {
    std::vector<BYTE> sidBuf;
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return sidBuf;
    struct CloseTok { HANDLE h; ~CloseTok() { CloseHandle(h); } } closeTok{tok};
    DWORD n = 0;
    if (!GetTokenInformation(tok, TokenOwner, nullptr, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) return sidBuf;
    sidBuf.resize(n);
    if (!GetTokenInformation(tok, TokenOwner, sidBuf.data(), n, &n)) sidBuf.clear();
    return sidBuf;
}

Result<void> applyProtectedDacl(const std::filesystem::path& target, EXPLICIT_ACCESSW* ea, ULONG count) {
    PACL acl = nullptr;
    if (SetEntriesInAclW(count, ea, nullptr, &acl) != ERROR_SUCCESS)
        return failure(winError("SetEntriesInAclW", GetLastError()));
    struct FreeAcl { PACL a; ~FreeAcl() { if (a) LocalFree(a); } } freeAcl{acl};
    DWORD rc = SetNamedSecurityInfoW(const_cast<LPWSTR>(target.c_str()), SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                     nullptr, nullptr, acl, nullptr);
    if (rc != ERROR_SUCCESS) return failure(winError("SetNamedSecurityInfoW", rc));
    return {};
}
}

Result<void> denyExecuteAcl(const std::filesystem::path& file) {
    auto sidBuf = ownerSidStorage();
    PSID ownerSid = sidBuf.empty() ? nullptr : reinterpret_cast<TOKEN_OWNER*>(sidBuf.data())->Owner;
    if (!ownerSid || !IsValidSid(ownerSid)) return failure("cannot resolve current user SID");
    EXPLICIT_ACCESSW ea[4]{};
    // Deny execute for Everyone (overrides the allows below); keep read/write/delete for the owner.
    BuildExplicitAccessWithNameW(&ea[0], const_cast<LPWSTR>(L"Everyone"), FILE_GENERIC_EXECUTE, DENY_ACCESS, NO_INHERITANCE);
    BuildExplicitAccessWithNameW(&ea[1], const_cast<LPWSTR>(L"Administrators"), GENERIC_ALL, GRANT_ACCESS, NO_INHERITANCE);
    BuildExplicitAccessWithNameW(&ea[2], const_cast<LPWSTR>(L"SYSTEM"), GENERIC_ALL, GRANT_ACCESS, NO_INHERITANCE);
    BuildTrusteeWithSidW(&ea[3].Trustee, ownerSid);
    ea[3].grfAccessPermissions = GENERIC_ALL;
    ea[3].grfAccessMode = GRANT_ACCESS;
    ea[3].grfInheritance = NO_INHERITANCE;
    return applyProtectedDacl(file, ea, 4);
}

Result<void> sealDirAcl(const std::filesystem::path& dir) {
    // Directory: protected DACL, owner/Admins/SYSTEM full control, NO deny ACE:
    // denying execute on a directory would also deny traversal and break restore/list.
    auto sidBuf = ownerSidStorage();
    PSID ownerSid = sidBuf.empty() ? nullptr : reinterpret_cast<TOKEN_OWNER*>(sidBuf.data())->Owner;
    if (!ownerSid || !IsValidSid(ownerSid)) return failure("cannot resolve current user SID");
    EXPLICIT_ACCESSW ea[3]{};
    BuildExplicitAccessWithNameW(&ea[0], const_cast<LPWSTR>(L"Administrators"), GENERIC_ALL, GRANT_ACCESS, NO_INHERITANCE);
    BuildExplicitAccessWithNameW(&ea[1], const_cast<LPWSTR>(L"SYSTEM"), GENERIC_ALL, GRANT_ACCESS, NO_INHERITANCE);
    BuildTrusteeWithSidW(&ea[2].Trustee, ownerSid);
    ea[2].grfAccessPermissions = GENERIC_ALL;
    ea[2].grfAccessMode = GRANT_ACCESS;
    ea[2].grfInheritance = NO_INHERITANCE;
    return applyProtectedDacl(dir, ea, 3);
}

Result<void> overwriteWithRandom(const std::filesystem::path& target) {
    HANDLE h = CreateFileW(target.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return failure(winError("CreateFileW(overwrite)", GetLastError()));
    struct CloseH { HANDLE h; ~CloseH() { CloseHandle(h); } } closeH{h};
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) return failure(winError("GetFileSizeEx", GetLastError()));
    std::mt19937_64 rng(std::random_device{}());
    std::vector<std::uint8_t> buf(1 << 16);
    for (long long off = 0; off < sz.QuadPart;) {
        for (auto& b : buf) b = std::uint8_t(rng());
        long long chunk = std::min<long long>(buf.size(), sz.QuadPart - off);
        DWORD written = 0;
        if (!WriteFile(h, buf.data(), DWORD(chunk), &written, nullptr) || written != chunk)
            return failure(winError("WriteFile(overwrite)", GetLastError()));
        off += chunk;
    }
    if (!FlushFileBuffers(h)) return failure(winError("FlushFileBuffers", GetLastError()));
    return {};
}
}
#endif
