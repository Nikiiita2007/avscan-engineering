// Распаковка архивов с лимитами против zip-бомб.
//  ZIP  — встроенный разбор + zlib (AV_HAVE_ZLIB)
//  7z/RAR (и по желанию ZIP) — через libarchive (AV_HAVE_LIBARCHIVE)
#include <algorithm>
#include <cstring>
#include <memory>

#include "scanner.hpp"
#include "source.hpp"

#ifdef AV_HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef AV_HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

namespace av {
namespace {

struct Ctx {
    Scanner& sc;
    ScanResult& parent;
    int depth;
    Budget& b;
    bool aborted = false;

    const Limits& lim() const { return sc.config().limits; }

    void limitHit(const std::string& why) {
        if (!aborted) {
            parent.partial = true;
            parent.notes.push_back("лимит распаковки: " + why);
            parent.indicators.push_back({"ARCHIVE_LIMIT", "Превышен лимит распаковки", 40, 40, true,
                                         why + " — признак zip-бомбы или умышленно «тяжёлого» архива."});
        }
        aborted = true;
    }
    void partialNote(const std::string& why, int pts = 0, const std::string& id = "") {
        parent.partial = true;
        parent.notes.push_back(why);
        if (pts) parent.indicators.push_back({id, why, pts, pts, true, why});
    }
    bool admit(const std::string& name) {
        if (aborted) return false;
        if (++b.entries > lim().maxEntries) { limitHit("больше " + std::to_string(lim().maxEntries) + " файлов в архиве"); return false; }
        if (name.find("../") != std::string::npos || name.find("..\\") != std::string::npos || (!name.empty() && (name[0] == '/' || name[0] == '\\')))
            parent.indicators.push_back({"ARCHIVE_PATH_TRAVERSAL", "Подозрительный путь внутри архива", 20, 20, true,
                                         "Запись «" + name + "» пытается выйти из каталога распаковки (zip-slip)."});
        return true;
    }
    // Сколько байт ещё можно распаковать для текущей записи.
    std::uint64_t allowance() const {
        std::uint64_t byTotal = lim().maxTotalUnpacked > b.unpacked ? lim().maxTotalUnpacked - b.unpacked : 0;
        auto byRatioMax = static_cast<std::uint64_t>(lim().maxRatio * double(b.rootSize));
        std::uint64_t byRatio = byRatioMax > b.unpacked ? byRatioMax - b.unpacked : 0;
        return std::min({lim().maxEntrySize, byTotal, byRatio});
    }
    void scanEntry(const std::string& name, const std::vector<std::uint8_t>& data) {
        b.unpacked += data.size();
        parent.children.push_back(sc.scanMemory(data, parent.path + "!" + name, depth + 1, b));
    }
};

std::uint32_t le32(const std::uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (std::uint32_t(p[3]) << 24); }
std::uint16_t le16(const std::uint8_t* p) { return std::uint16_t(p[0] | (p[1] << 8)); }

#ifdef AV_HAVE_ZLIB
void scanZip(Ctx& cx, Source& src, std::uint64_t size) {
    if (size < 22) { cx.partialNote("ZIP слишком короткий"); return; }
    std::size_t tail = std::size_t(std::min<std::uint64_t>(size, 22 + 65535));
    std::vector<std::uint8_t> t(tail);
    if (!src.readAt(size - tail, t.data(), tail)) { cx.partialNote("не удалось прочитать конец ZIP"); return; }
    std::int64_t eocd = -1;
    for (std::int64_t i = std::int64_t(tail) - 22; i >= 0; --i)
        if (le32(&t[i]) == 0x06054b50u) { eocd = i; break; }
    if (eocd < 0) { cx.partialNote("не найден центральный каталог ZIP (повреждён или не ZIP)"); return; }
    std::uint32_t count = le16(&t[eocd + 10]), cdSize = le32(&t[eocd + 12]), cdOff = le32(&t[eocd + 16]);
    if (count == 0xFFFF || cdSize == 0xFFFFFFFFu || cdOff == 0xFFFFFFFFu) { cx.partialNote("ZIP64 не поддерживается"); return; }
    if (std::uint64_t(cdOff) + cdSize > size || cdSize > (64u << 20)) { cx.partialNote("некорректный центральный каталог"); return; }
    std::vector<std::uint8_t> cd(cdSize);
    if (cdSize && !src.readAt(cdOff, cd.data(), cdSize)) { cx.partialNote("не удалось прочитать центральный каталог"); return; }
    std::size_t p = 0;
    for (std::uint32_t i = 0; i < count && !cx.aborted; ++i) {
        if (p + 46 > cd.size() || le32(&cd[p]) != 0x02014b50u) { cx.partialNote("повреждён центральный каталог"); return; }
        std::uint16_t flags = le16(&cd[p + 8]), method = le16(&cd[p + 10]);
        std::uint32_t csize = le32(&cd[p + 20]), usize = le32(&cd[p + 24]);
        std::uint16_t nl = le16(&cd[p + 28]), el = le16(&cd[p + 30]), cl = le16(&cd[p + 32]);
        std::uint32_t lho = le32(&cd[p + 42]);
        if (p + 46 + nl > cd.size()) { cx.partialNote("повреждено имя записи"); return; }
        std::string name(reinterpret_cast<const char*>(&cd[p + 46]), nl);
        p += 46 + nl + el + cl;
        if (!name.empty() && name.back() == '/') continue;
        if (!cx.admit(name)) break;
        if (flags & 1) { cx.partialNote("зашифрованная запись «" + name + "» не проверена", 10, "ARCHIVE_ENCRYPTED"); continue; }
        std::uint64_t allow = cx.allowance();
        if (usize > allow) { cx.limitHit("запись «" + name + "» заявляет " + std::to_string(usize) + " байт (доступно " + std::to_string(allow) + ")"); break; }
        std::uint8_t lh[30];
        if (!src.readAt(lho, lh, 30) || le32(lh) != 0x04034b50u) { cx.partialNote("битый локальный заголовок «" + name + "»"); continue; }
        std::uint64_t dataOff = std::uint64_t(lho) + 30 + le16(lh + 26) + le16(lh + 28);
        if (dataOff + csize > size || csize > cx.lim().maxEntrySize) { cx.partialNote("запись «" + name + "» выходит за границы"); continue; }
        std::vector<std::uint8_t> comp(csize), out;
        if (csize && !src.readAt(dataOff, comp.data(), csize)) { cx.partialNote("не удалось прочитать «" + name + "»"); continue; }
        if (method == 0) out = std::move(comp);
        else if (method == 8) {
            z_stream zs{};
            if (inflateInit2(&zs, -15) != Z_OK) { cx.partialNote("zlib init"); continue; }
            zs.next_in = comp.data(); zs.avail_in = csize;
            std::vector<std::uint8_t> buf(64 * 1024);
            int rc = Z_OK;
            while (rc == Z_OK) {
                zs.next_out = buf.data(); zs.avail_out = uInt(buf.size());
                rc = inflate(&zs, Z_NO_FLUSH);
                out.insert(out.end(), buf.data(), buf.data() + (buf.size() - zs.avail_out));
                if (out.size() > allow) { cx.limitHit("запись «" + name + "» распаковывается за лимит (zip-бомба)"); break; }
            }
            inflateEnd(&zs);
            if (cx.aborted) break;
            if (rc != Z_STREAM_END) { cx.partialNote("ошибка распаковки «" + name + "»"); continue; }
        } else { cx.partialNote("метод сжатия " + std::to_string(method) + " в «" + name + "» не поддерживается"); continue; }
        cx.scanEntry(name, out);
    }
}
#endif

#ifdef AV_HAVE_LIBARCHIVE
void scanWithLibarchive(Ctx& cx, const std::string* path, std::span<const std::uint8_t> mem) {
    struct archive* a = archive_read_new();
    archive_read_support_format_7zip(a);
    archive_read_support_format_rar(a);
    archive_read_support_format_rar5(a);
    archive_read_support_format_zip(a);
#ifdef _WIN32
    int rc = path ? archive_read_open_filename_w(a, pathFromUtf8(*path).wstring().c_str(), 65536)
                  : archive_read_open_memory(a, mem.data(), mem.size());
#else
    int rc = path ? archive_read_open_filename(a, path->c_str(), 65536)
                  : archive_read_open_memory(a, mem.data(), mem.size());
#endif
    if (rc != ARCHIVE_OK) { cx.partialNote(std::string("libarchive: ") + archive_error_string(a)); archive_read_free(a); return; }
    struct archive_entry* e = nullptr;
    while (!cx.aborted && (rc = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
        if (archive_entry_filetype(e) != AE_IFREG) continue;
        std::string name = archive_entry_pathname(e) ? archive_entry_pathname(e) : "?";
        if (!cx.admit(name)) break;
        if (archive_entry_is_encrypted(e) || archive_entry_is_data_encrypted(e)) {
            cx.partialNote("зашифрованная запись «" + name + "» не проверена", 10, "ARCHIVE_ENCRYPTED"); continue;
        }
        std::uint64_t allow = cx.allowance();
        std::vector<std::uint8_t> out, buf(64 * 1024);
        for (;;) {
            la_ssize_t n = archive_read_data(a, buf.data(), buf.size());
            if (n == 0) break;
            if (n < 0) { cx.partialNote("ошибка чтения «" + name + "»: " + archive_error_string(a)); out.clear(); break; }
            out.insert(out.end(), buf.data(), buf.data() + n);
            if (out.size() > allow) { cx.limitHit("запись «" + name + "» распаковывается за лимит (zip-бомба)"); break; }
        }
        if (cx.aborted) break;
        if (!out.empty() || archive_entry_size(e) == 0) cx.scanEntry(name, out);
    }
    if (!cx.aborted && rc != ARCHIVE_EOF) cx.partialNote(std::string("архив прочитан не до конца: ") + archive_error_string(a));
    archive_read_free(a);
}
#endif

} // namespace

bool archiveSupportFor(FileType t) {
#ifdef AV_HAVE_ZLIB
    if (t == FileType::Zip) return true;
#endif
#ifdef AV_HAVE_LIBARCHIVE
    if (isArchive(t)) return true;
#endif
    (void)t;
    return false;
}

void scanArchive(Scanner& sc, const std::string* path, std::span<const std::uint8_t> mem, FileType t,
                 ScanResult& parent, int depth, Budget& b) {
    Ctx cx{sc, parent, depth, b};
    if (!archiveSupportFor(t)) {
        cx.partialNote(std::string("содержимое ") + toString(t) + " не проверено: формат не поддержан в этой сборке (см. MANUAL.md, libarchive)");
        return;
    }
    try {
#ifdef AV_HAVE_ZLIB
        if (t == FileType::Zip) {
            std::unique_ptr<Source> src;
            if (path) src = std::make_unique<FileSource>(*path); else src = std::make_unique<MemSource>(mem);
            scanZip(cx, *src, parent.size);
            return;
        }
#endif
#ifdef AV_HAVE_LIBARCHIVE
        scanWithLibarchive(cx, path, mem);
#endif
    } catch (const std::exception& e) {
        cx.partialNote(std::string("ошибка при распаковке: ") + e.what());
    }
}

} // namespace av
