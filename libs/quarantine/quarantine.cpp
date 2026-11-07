#include "quarantine.hpp"
#ifdef _WIN32
#include "secure.hpp"
#include <windows.h>
#include <bcrypt.h>
#endif
#include <fstream>
#include <chrono>
#include <random>
#include <set>

namespace av {
namespace {
bool validId(const std::string& id) {
    if (id.empty() || id.size() > 20) return false;
    for (char c : id) if (c < '0' || c > '9') return false;
    return true;
}
std::string readFile(const std::filesystem::path& p, bool& ok) {
    std::ifstream f(p, std::ios::binary);
    if (!f) { ok = false; return {}; }
    ok = true;
    return std::string(std::istreambuf_iterator<char>(f), {});
}
}

Result<std::filesystem::path> Quarantine::copyEvidence(const std::filesystem::path& source){
 namespace fs=std::filesystem;std::error_code ec;
 if(!fs::is_regular_file(fs::symlink_status(source,ec))||ec)return failure("Not a regular file");
 fs::create_directories(root,ec);if(ec)return failure(ec.message());
 // Atomic directory creation avoids overwriting an existing record.
 std::mt19937_64 rng(std::random_device{}());fs::path dir;
 bool made=false;for(int i=0;i<16;++i){dir=root/std::to_string(rng());if(fs::create_directory(dir,ec)){made=true;break;}if(ec)return failure(ec.message());}
 if(!made)return failure("Cannot allocate record");
 fs::permissions(dir,fs::perms::owner_all,fs::perm_options::replace,ec);
 ec.clear();fs::copy_file(source,dir/"sample.bin",fs::copy_options::none,ec);
 if(ec){fs::remove_all(dir,ec);return failure("Evidence copy failed");}
 std::ofstream meta(dir/"source.txt",std::ios::binary);meta<<pathUtf8(source)<<'\n';meta.close();
 if(!meta)return failure("Evidence copied but metadata write failed: "+pathUtf8(dir));
 return dir;
}

#ifdef _WIN32
namespace {
// Store-wide AES-256 key, DPAPI-protected on disk (root/store.key).
Result<std::vector<std::uint8_t>> loadOrCreateKey(const std::filesystem::path& root) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) return failure("create store: " + ec.message());
    fs::path keyFile = root / "store.key";
    std::ifstream f(keyFile, std::ios::binary);
    if (f) {
        std::vector<std::uint8_t> blob(std::istreambuf_iterator<char>(f), {});
        auto key = dpapiUnprotect(blob);
        if (!key || key->size() != 32) return failure("store.key unreadable (DPAPI/machine mismatch?)");
        return key;
    }
    // First use: generate the key and seal it with DPAPI.
    std::vector<std::uint8_t> key(32);
    if (NTSTATUS s = BCryptGenRandom(nullptr, key.data(), ULONG(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
        return failure("BCryptGenRandom NTSTATUS=" + std::to_string(long(s)));
    auto sealed = dpapiProtect(key);
    if (!sealed) return failure(sealed.error().message);
    std::ofstream out(keyFile, std::ios::binary);
    out.write(reinterpret_cast<const char*>(sealed->data()), std::streamsize(sealed->size()));
    out.close();
    if (!out) return failure("store.key write failed");
    fs::permissions(keyFile, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
    return key;
}
Result<std::vector<std::uint8_t>> readBinary(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return failure("open " + pathUtf8(p));
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), {});
}
Result<void> writeBinary(const std::filesystem::path& p, std::span<const std::uint8_t> data) {
    std::ofstream f(p, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), std::streamsize(data.size()));
    f.close();
    if (!f) return failure("write " + pathUtf8(p));
    return {};
}
}

Result<std::string> Quarantine::store(const std::filesystem::path& source) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::is_regular_file(fs::symlink_status(source, ec)) || ec) return failure("Not a regular file");
    auto key = loadOrCreateKey(root);
    if (!key) return failure(key.error().message);
    auto plain = readBinary(source);
    if (!plain) return plain.error().message;
    auto sealed = aesEncrypt(*key, *plain);
    if (!sealed) return failure(sealed.error().message);
    // Unique record id; same collision-safe allocation as copyEvidence.
    std::mt19937_64 rng(std::random_device{}());
    fs::path dir;
    bool made = false;
    for (int i = 0; i < 16; ++i) {
        dir = root / std::to_string(rng());
        if (fs::create_directory(dir, ec)) { made = true; break; }
        if (ec) return failure(ec.message());
    }
    if (!made) return failure("Cannot allocate record");
    std::string id = dir.filename().string();
    auto w = writeBinary(dir / "sample.bin.enc", *sealed);
    if (!w) { fs::remove_all(dir, ec); return w.error().message; }
    std::ofstream meta(dir / "source.txt", std::ios::binary);
    meta << pathUtf8(source) << '\n';
    meta.close();
    if (!meta) { fs::remove_all(dir, ec); return failure("metadata write failed"); }
    // Seal the record: deny-execute on the encrypted sample; protected owner-only DACL on the dir.
    auto acl2 = denyExecuteAcl(dir / "sample.bin.enc");
    if (!acl2) return failure("ACL file: " + acl2.error().message);
    auto acl1 = sealDirAcl(dir);
    if (!acl1) return failure("ACL dir: " + acl1.error().message);
    return id;
}

Result<void> Quarantine::restore(const std::string& id, const std::filesystem::path& dest) {
    namespace fs = std::filesystem;
    if (!validId(id)) return failure("Invalid record id");
    fs::path dir = root / id;
    std::error_code ec;
    if (!fs::is_directory(dir, ec) || ec) return failure("Record not found: " + id);
    auto key = loadOrCreateKey(root);
    if (!key) return failure(key.error().message);
    auto sealed = readBinary(dir / "sample.bin.enc");
    if (!sealed) return failure(sealed.error().message);
    auto plain = aesDecrypt(*key, *sealed);
    if (!plain) return failure(plain.error().message);
    auto w = writeBinary(dest, *plain);
    if (!w) return failure(w.error().message);
    return {};
}

Result<void> Quarantine::remove(const std::string& id) {
    namespace fs = std::filesystem;
    if (!validId(id)) return failure("Invalid record id");
    fs::path dir = root / id;
    std::error_code ec;
    if (!fs::is_directory(dir, ec) || ec) return failure("Record not found: " + id);
    fs::path enc = dir / "sample.bin.enc";
    if (fs::is_regular_file(enc, ec)) {
        auto ow = overwriteWithRandom(enc);   // wipe ciphertext before unlink
        if (!ow) return failure(ow.error().message);
    }
    fs::remove_all(dir, ec);
    if (ec) return failure("remove record: " + ec.message());
    return {};
}

Result<std::vector<QuarantineRecord>> Quarantine::list() const {
    namespace fs = std::filesystem;
    std::error_code ec;
    std::vector<QuarantineRecord> out;
    if (!fs::is_directory(root, ec) || ec) return out; // empty store is not an error
    for (fs::directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_directory(ec) || ec) continue;
        std::string id = it->path().filename().string();
        if (!validId(id)) continue;
        QuarantineRecord r;
        r.id = id;
        bool ok = false;
        r.source = readFile(it->path() / "source.txt", ok);
        if (!ok) r.source.clear();
        if (fs::is_regular_file(it->path() / "sample.bin.enc", ec))
            r.cipherBytes = fs::file_size(it->path() / "sample.bin.enc", ec);
        if (ec) ec.clear();
        out.push_back(std::move(r));
    }
    return out;
}
#else
Result<std::string> Quarantine::store(const std::filesystem::path&) {
    return failure("Encrypted quarantine requires Windows (CNG/DPAPI/ACL)");
}
Result<void> Quarantine::restore(const std::string&, const std::filesystem::path&) {
    return failure("Encrypted quarantine requires Windows (CNG/DPAPI/ACL)");
}
Result<void> Quarantine::remove(const std::string&) {
    return failure("Encrypted quarantine requires Windows (CNG/DPAPI/ACL)");
}
Result<std::vector<QuarantineRecord>> Quarantine::list() const {
    namespace fs = std::filesystem;
    std::vector<QuarantineRecord> out;
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec) return out;
    for (fs::directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_directory(ec) || ec) continue;
        std::string id = it->path().filename().string();
        if (!validId(id)) continue;
        QuarantineRecord r; r.id = id;
        bool ok = false;
        r.source = readFile(it->path() / "source.txt", ok);
        out.push_back(std::move(r));
    }
    return out;
}
#endif
}
