#include "scanner.hpp"
#include "modern.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <set>

#include "cache.hpp"
#include "fuzzy.hpp"
#include "pe.hpp"
#include "sha256.hpp"

namespace av {
namespace fs = std::filesystem;

constexpr std::size_t kBlock = 64 * 1024;

Status worst(Status a, Status b) { return static_cast<int>(a) >= static_cast<int>(b) ? a : b; }

double entropyOf(const std::array<std::uint64_t, 256>& h, std::uint64_t total) {
    if (total == 0) return 0.0;
    double e = 0;
    for (auto c : h) if (c) { double p = double(c) / double(total); e -= p * std::log2(p); }
    return e;
}

FileType detectType(std::span<const std::uint8_t> h) {
    auto starts = [&](std::initializer_list<int> m) {
        if (h.size() < m.size()) return false;
        std::size_t i = 0;
        for (int b : m) if (h[i++] != b) return false;
        return true;
    };
    if (starts({'M', 'Z'}) && h.size() >= 0x44) {
        std::uint32_t l = h[0x3C] | (h[0x3D] << 8) | (h[0x3E] << 16) | (std::uint32_t(h[0x3F]) << 24);
        if (l <= h.size() && h.size() - l >= 4 && std::memcmp(h.data() + l, "PE\0\0", 4) == 0) return FileType::PE;
        return FileType::Unknown; // голый MZ без PE — не PE
    }
    if (starts({0x7F, 'E', 'L', 'F'})) return FileType::ELF;
    if (starts({'P', 'K', 3, 4}) || starts({'P', 'K', 5, 6})) return FileType::Zip;
    if (starts({'7', 'z', 0xBC, 0xAF, 0x27, 0x1C})) return FileType::SevenZip;
    if (starts({'R', 'a', 'r', '!', 0x1A, 0x07})) return FileType::Rar;
    if (starts({0xFF, 0xD8, 0xFF})) return FileType::Jpeg;
    if (starts({'#', '!'})) return FileType::Script;
    if (!h.empty()) {
        std::size_t n = std::min<std::size_t>(h.size(), 1024);
        bool text = true;
        for (std::size_t i = 0; i < n; ++i) {
            auto c = h[i];
            if (c < 9 || (c > 13 && c < 32 && c != 27)) { text = false; break; }
        }
        if (text) return FileType::Script;
    }
    return FileType::Unknown;
}

Scanner::Scanner(SigDb db, Config cfg) : db_(std::move(db)), cfg_(std::move(cfg)) {
    if (cfg_.useCache) cache_ = new Cache(cfg_.cachePath);
}
Scanner::~Scanner() { flushCache(); delete cache_; }
void Scanner::flushCache() { if (cache_) cache_->flush(); }

namespace {

void addInd(ScanResult& r, std::string id, std::string title, int max, int pts, bool applicable, std::string expl) {
    r.indicators.push_back({std::move(id), std::move(title), max, applicable ? pts : 0, applicable, std::move(expl)});
}

const std::set<std::string> kPackerSections = {"upx0", "upx1", "upx2", ".upx0", ".upx1", ".aspack", ".adata",
    ".themida", ".vmp0", ".vmp1", ".petite", ".mpress1", ".mpress2", ".nsp0", ".nsp1", ".enigma1", ".enigma2", ".winlice", "pec1", "pec2"};
const std::set<std::string> kSuspApis = {"virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
    "queueuserapc", "setwindowshookexa", "setwindowshookexw", "urldownloadtofilea", "urldownloadtofilew", "getasynckeystate",
    "adjusttokenprivileges", "ntwritevirtualmemory", "readprocessmemory", "createremotethreadex", "rtlcreateuserthread"};

std::string lowerStr(std::string s) { for (auto& c : s) c = char(std::tolower(static_cast<unsigned char>(c))); return s; }

void peIndicators(ScanResult& r, const PeInfo* pe, double fileEntropy) {
    const bool app = pe && pe->valid;
    const std::string na = pe ? ("PE не разобран: " + pe->error) : "не PE-файл — проверка неприменима";
    auto fmt = [](double v) { char b[32]; std::snprintf(b, sizeof b, "%.2f", v); return std::string(b); };

    // 1. Энтропия исполняемых секций
    {
        std::string hit; bool any = false;
        if (app) for (std::size_t i = 0; i < pe->sections.size(); ++i) {
            auto& s = pe->sections[i];
            if ((s.chars & 0x20000000u) && r.sections[i].entropy >= 7.2 && s.rawsize >= 512) { any = true; hit += s.name + "(" + fmt(r.sections[i].entropy) + ") "; }
        }
        addInd(r, "PE_HIGH_ENTROPY_EXEC", "Высокая энтропия исполняемой секции", 25, any ? 25 : 0, app,
               app ? (any ? "Секции " + hit + "имеют энтропию ≥ 7.2 из 8: код выглядит зашифрованным или упакованным."
                          : "Исполняемые секции с энтропией ≥ 7.2 не найдены: обычный код имеет энтропию примерно 5.5–6.8.") : na);
    }
    // 2. Имена секций упаковщиков
    {
        std::string hit;
        if (app) for (auto& s : pe->sections) if (kPackerSections.contains(lowerStr(s.name))) hit += s.name + " ";
        addInd(r, "PE_PACKER_SECTION", "Секции известных упаковщиков (UPX, ASPack, Themida, VMProtect...)", 30, hit.empty() ? 0 : 30, app,
               app ? (hit.empty() ? "Имён секций упаковщиков нет (имена легко подделать, поэтому отсутствие ничего не гарантирует)."
                                  : "Найдены секции: " + hit + "— типичный след упаковщика. Сам по себе UPX легитимен, но скрывает реальный код.") : na);
    }
    // 3. W+X
    {
        std::string hit;
        if (app) for (auto& s : pe->sections) if ((s.chars & 0x20000000u) && (s.chars & 0x80000000u)) hit += s.name + " ";
        addInd(r, "PE_WX_SECTION", "Секция одновременно записываемая и исполняемая", 15, hit.empty() ? 0 : 15, app,
               app ? (hit.empty() ? "W+X секций нет." : "Секции " + hit + "доступны и на запись, и на исполнение: так работает распаковщик/самомодифицирующийся код.") : na);
    }
    // 4. Мало импортов
    {
        bool few = app && (!pe->importsParsed || pe->funcs.size() <= 5);
        addInd(r, "PE_FEW_IMPORTS", "Аномально мало импортов", 15, few ? 15 : 0, app,
               app ? (few ? "Импортировано функций: " + std::to_string(pe->funcs.size()) + " (≤5). Упакованные файлы обычно импортируют только LoadLibrary/GetProcAddress."
                          : "Импортировано функций: " + std::to_string(pe->funcs.size()) + " — таблица импорта нормального размера.") : na);
    }
    // 5. Точка входа
    {
        bool bad = false; std::string why;
        if (app) {
            if (pe->entryRva == 0) why = "точка входа = 0 (DLL/драйвер допустимы), не штрафуется";
            else if (pe->entrySection < 0) { bad = true; why = "точка входа лежит вне любой секции"; }
            else if (pe->entrySection == int(pe->sections.size()) - 1 && pe->sections.size() > 1) { bad = true; why = "точка входа в последней секции «" + pe->sections.back().name + "» (типично для упаковщиков и инфекторов)"; }
            else why = "точка входа в секции «" + pe->sections[pe->entrySection].name + "» — норма";
        }
        addInd(r, "PE_ENTRYPOINT", "Подозрительная точка входа", 15, bad ? 15 : 0, app, app ? why : na);
    }
    // 6. Подозрительные API
    {
        std::set<std::string> found;
        if (app) for (auto& f : pe->funcs) if (kSuspApis.contains(lowerStr(f))) found.insert(f);
        int pts = found.size() >= 3 ? 25 : (found.empty() ? 0 : 8);
        std::string lst; for (auto& f : found) lst += f + " ";
        addInd(r, "PE_SUSPICIOUS_APIS", "API инъекции кода / кейлоггинга / загрузки", 25, pts, app,
               app ? (found.empty() ? "Подозрительных API среди импортов нет." : "Найдено " + std::to_string(found.size()) + ": " + lst + (found.size() >= 3 ? "— связка похожа на инъекцию в чужой процесс (25 баллов)." : "— по отдельности встречаются и в легитимном ПО (8 баллов).")) : na);
    }
    // 7. Заглушка распаковщика
    {
        std::string hit;
        if (app) for (auto& s : pe->sections) if (s.rawsize == 0 && s.vsize >= 64 * 1024) hit += s.name + " ";
        addInd(r, "PE_EMPTY_RAW_BIG_VIRTUAL", "Пустая на диске секция с большим виртуальным размером", 10, hit.empty() ? 0 : 10, app,
               app ? (hit.empty() ? "Таких секций нет." : "Секции " + hit + "пусты в файле, но резервируют ≥64 КБ в памяти — место, куда упаковщик распакует код.") : na);
    }
    // 8. Общая энтропия
    {
        bool hi = app && fileEntropy >= 7.0;
        addInd(r, "PE_FILE_ENTROPY", "Высокая энтропия всего файла", 10, hi ? 10 : 0, app,
               app ? "Энтропия файла " + fmt(fileEntropy) + (hi ? " ≥ 7.0: большая часть файла сжата/зашифрована." : " < 7.0: порог не достигнут.") : na);
    }
}

} // namespace

ScanResult Scanner::scanSource(Source& src, const std::string& name, std::uint64_t size, int depth, Budget& bud,
                               const std::string* realPath, std::span<const std::uint8_t> mem) {
    ScanResult r;
    r.path = name; r.size = size;
    std::vector<std::uint8_t> block(kBlock), win;
    Sha256 sha;
    FuzzyHasher fz(size);
    std::array<std::uint64_t, 256> hist{};
    std::vector<std::array<std::uint64_t, 256>> shist;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> sranges;
    PeInfo pe; bool havePe = false;

    const auto& sigs = db_.sigs;
    std::vector<std::vector<char>> hit(sigs.size());
    for (std::size_t i = 0; i < sigs.size(); ++i) hit[i].assign(sigs[i].patterns.size(), 0);
    struct Pending { std::uint32_t ref; std::uint64_t start; };
    std::vector<Pending> pending;
    std::uint64_t winBase = 0, pos = 0;
    int state = 0;
    bool first = true;

    auto verify = [&](std::uint32_t refId, std::uint64_t start) -> int { // 1 ok, 0 no, -1 нужно больше данных
        auto [si, pi] = db_.refs[refId];
        if (hit[si][pi]) return 0;
        const auto& p = sigs[si].patterns[pi];
        if (p.offset && *p.offset != start) return 0;
        if (start < winBase) return 0;
        if (start + p.bytes.size() > winBase + win.size()) return -1;
        const std::uint8_t* base = win.data() + (start - winBase);
        for (std::size_t k = 0; k < p.bytes.size(); ++k)
            if ((base[k] & p.mask[k]) != p.bytes[k]) return 0;
        hit[si][pi] = 1;
        return 1;
    };

    for (;;) {
        std::size_t n = src.read(block.data(), kBlock); // единственное чтение содержимого
        if (n == 0) break;
        std::span<const std::uint8_t> chunk(block.data(), n);
        if (first) {
            first = false;
            r.type = detectType(chunk);
            if (r.type == FileType::PE) {
                pe = parsePe(src, chunk, size);
                havePe = true;
                if (pe.valid) {
                    shist.assign(pe.sections.size(), {});
                    for (auto& s : pe.sections) {
                        std::uint64_t a = s.rawptr, e = std::min<std::uint64_t>(a + s.rawsize, size);
                        sranges.emplace_back(a, a < size ? e : a);
                    }
                }
            }
        }
        feed(sha, chunk);
        fz.update(chunk);
        for (auto c : chunk) ++hist[c];
        for (std::size_t i = 0; i < sranges.size(); ++i) {
            auto [a, e] = sranges[i];
            if (e <= pos || a >= pos + n) continue;
            for (std::uint64_t k = std::max(a, pos); k < std::min(e, pos + n); ++k) ++shist[i][block[k - pos]];
        }
        win.insert(win.end(), chunk.begin(), chunk.end());
        // отложенные кандидаты
        for (std::size_t i = 0; i < pending.size();) {
            int v = verify(pending[i].ref, pending[i].start);
            if (v < 0) ++i; else pending.erase(pending.begin() + i);
        }
        for (std::size_t i = 0; i < n; ++i) {
            state = db_.ac.next(state, chunk[i]);
            const auto& o = db_.ac.out(state);
            if (o.empty()) continue;
            std::uint64_t endAbs = pos + i + 1;
            for (auto id : o) {
                const auto& p = sigs[db_.refs[id].sig].patterns[db_.refs[id].pat];
                std::uint64_t anchorEnd = p.anchorPos + p.anchorLen;
                if (endAbs < anchorEnd) continue;
                std::uint64_t start = endAbs - anchorEnd;
                if (verify(id, start) < 0) pending.push_back({id, start});
            }
        }
        pos += n;
        if (win.size() > db_.maxPatLen) {
            std::size_t cut = win.size() - db_.maxPatLen;
            win.erase(win.begin(), win.begin() + cut);
            winBase += cut;
        }
    }

    r.sha256 = sha.hexdigest();
    r.fuzzy = fz.digest();
    r.entropy = entropyOf(hist, pos);
    if (pos != size) { r.status = Status::Error; r.message = "прочитано " + std::to_string(pos) + " из " + std::to_string(size) + " байт"; return r; }

    // --- сигнатуры ---
    for (std::size_t i = 0; i < sigs.size(); ++i) {
        const auto& s = sigs[i];
        if (s.type && *s.type != r.type) continue;
        if (!std::all_of(hit[i].begin(), hit[i].end(), [](char c) { return c; })) continue;
        r.detections.push_back({"signature", s.name, std::to_string(s.patterns.size()) + " усл. выполнено, тип " + toString(r.type), s.malware});
    }
    // --- хэш ---
    if (auto it = db_.sha256.find(r.sha256); it != db_.sha256.end())
        r.detections.push_back({"hash", it->second, "SHA-256 " + r.sha256, true});
    // --- нечёткие хэши ---
    int bestSim = 0; std::string bestFam;
    for (auto& [h, fam] : db_.fuzzy) {
        int sim = FuzzyHasher::compare(r.fuzzy, h);
        if (sim > bestSim) { bestSim = sim; bestFam = fam; }
    }
    addInd(r, "FUZZY_FAMILY", "Сходство с известным семейством (нечёткий хэш)", 60, bestSim >= 80 ? 60 : (bestSim >= 50 ? 30 : 0), !db_.fuzzy.empty(),
           db_.fuzzy.empty() ? "в базе нет fuzzy-записей" :
           bestSim == 0 ? "Совпадений с семействами нет." :
           "Лучшее сходство " + std::to_string(bestSim) + "% с «" + bestFam + "» (≥80 → 60 баллов, 50–79 → 30 баллов).");

    // --- PE ---
    if (havePe && pe.valid) {
        for (std::size_t i = 0; i < pe.sections.size(); ++i) {
            SectionInfo si{pe.sections[i].name, pe.sections[i].vsize, pe.sections[i].rawsize, pe.sections[i].chars, 0};
            std::uint64_t tot = sranges[i].second - sranges[i].first;
            si.entropy = entropyOf(shist[i], tot);
            r.sections.push_back(si);
        }
    }
    peIndicators(r, havePe ? &pe : nullptr, r.entropy);
    if (havePe && !pe.valid) r.notes.push_back("PE-заголовок повреждён: " + pe.error);
    if (havePe && pe.valid) {
        r.notes.push_back("импортов: " + std::to_string(pe.funcs.size()) + " из " + std::to_string(pe.dlls.size()) + " DLL");
        std::string dl; for (auto& d : pe.dlls) dl += d + " ";
        if (!dl.empty()) r.notes.push_back("DLL: " + dl);
    }

    // --- архивы ---
    if (isArchive(r.type)) {
        if (depth >= cfg_.limits.maxDepth) {
            r.partial = true;
            r.notes.push_back("превышена глубина вложенности архивов (" + std::to_string(cfg_.limits.maxDepth) + ")");
            addInd(r, "ARCHIVE_LIMIT", "Превышен лимит распаковки", 40, 40, true, "Глубина вложенности больше лимита — типичный приём zip-бомб.");
        } else {
            scanArchive(*this, realPath, mem, r.type, r, depth, bud);
        }
    }
    finalize(r);
    return r;
}

void Scanner::finalize(ScanResult& r) {
    int score = 0;
    bool malware = false;
    for (auto& d : r.detections) {
        if (d.malware) malware = true;
        else {
            addInd(r, "SIG:" + d.name, "Подозрительная сигнатура «" + d.name + "»", 40, 40, true, d.detail);
        }
    }
    for (auto& i : r.indicators) score += i.points;
    r.score = score;
    Status st = Status::Clean;
    if (malware || score >= cfg_.infectedThreshold) st = Status::Infected;
    else if (score >= cfg_.suspiciousThreshold) st = Status::Suspicious;
    for (auto& c : r.children) st = worst(st, c.status);
    if (r.partial) st = worst(st, Status::Skipped);
    r.status = st;
}

ScanResult Scanner::scanMemory(std::span<const std::uint8_t> data, const std::string& name, int depth, Budget& b) {
    MemSource ms(data);
    try { return scanSource(ms, name, data.size(), depth, b, nullptr, data); }
    catch (const std::exception& e) { ScanResult r; r.path = name; r.status = Status::Error; r.message = e.what(); return r; }
}

ScanResult Scanner::scanPath(const std::string& path) {
    ScanResult r; r.path = path;
    std::error_code ec;
    auto st = fs::symlink_status(pathFromUtf8(path), ec);
    if (ec || !fs::exists(st)) { r.status = Status::Error; r.message = "файл не найден или недоступен: " + ec.message(); return r; }
    if (fs::is_symlink(st)) { r.status = Status::Skipped; r.message = "символическая ссылка пропущена"; return r; }
    if (!fs::is_regular_file(st)) { r.status = Status::Skipped; r.message = "не обычный файл"; return r; }
    auto size = fs::file_size(pathFromUtf8(path), ec);
    if (ec) { r.status = Status::Error; r.message = "не удалось определить размер: " + ec.message(); return r; }
    r.size = size;
    if (size > cfg_.limits.maxFileSize) { r.status = Status::Skipped; r.message = "файл больше лимита " + std::to_string(cfg_.limits.maxFileSize >> 20) + " МиБ"; return r; }
    long long mtime = 0;
    auto lw = fs::last_write_time(pathFromUtf8(path), ec);
    if (!ec) mtime = std::chrono::duration_cast<std::chrono::nanoseconds>(lw.time_since_epoch()).count();
    std::string key = Cache::key(pathUtf8(fs::absolute(pathFromUtf8(path))), size, mtime, db_.version);
    if (cache_) { ScanResult c; c.path = path; c.size = size; if (cache_->get(key, c)) return c; }

    try {
        FileSource fsrc(path);
        Budget b; b.rootSize = std::max<std::uint64_t>(size, 1);
        r = scanSource(fsrc, path, size, 0, b, &path, {});
    } catch (const std::exception& e) {
        r = ScanResult{}; r.path = path; r.size = size; r.status = Status::Error; r.message = e.what();
        return r; // ошибки не кэшируем и никогда не считаем «чистыми»
    }
    if (cache_ && !r.partial && (r.status == Status::Clean || r.status == Status::Suspicious || r.status == Status::Infected))
        cache_->put(key, r);
    return r;
}

} // namespace av
