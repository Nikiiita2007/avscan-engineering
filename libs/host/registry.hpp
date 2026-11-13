#pragma once
// Module discovery: every <modules dir>/<id>/module.json is validated; the directory name must equal the module id.
#include "manifest.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace av::host {

struct Discovery {
    std::vector<Manifest> modules;      // valid modules, sorted by id
    std::vector<std::string> errors;    // one line per problem, prefixed with the directory name
};

inline std::string pathToUtf8(const std::filesystem::path& p) {
    const auto u = p.u8string();
    return std::string(u.begin(), u.end());
}

// requireExecutable: also check that entry.exe exists inside the module directory.
inline Discovery discoverModules(const std::filesystem::path& dir, bool requireExecutable = false) {
    namespace fs = std::filesystem;
    Discovery d;
    std::error_code ec;
    std::vector<fs::path> dirs;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code e2;
        if (it->is_directory(e2) && !e2) dirs.push_back(it->path());
    }
    if (ec) { d.errors.push_back("cannot read modules directory: " + ec.message()); return d; }
    std::sort(dirs.begin(), dirs.end());

    for (const auto& sub : dirs) {
        const std::string name = pathToUtf8(sub.filename());
        const fs::path file = sub / "module.json";
        std::error_code e3;
        if (!fs::is_regular_file(file, e3)) continue;  // not a module directory
        const auto size = fs::file_size(file, e3);
        if (e3 || size > 256 * 1024) { d.errors.push_back(name + ": module.json is unreadable or larger than 256 KiB"); continue; }
        std::ifstream f(file, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        ManifestResult r = parseManifest(text);
        if (!r.value) {
            for (const auto& e : r.errors) d.errors.push_back(name + ": " + e);
            continue;
        }
        Manifest& m = *r.value;
        if (m.id != name) { d.errors.push_back(name + ": directory name must equal the module id '" + m.id + "'"); continue; }
        if (std::any_of(d.modules.begin(), d.modules.end(), [&](const Manifest& x) { return x.id == m.id; })) {
            d.errors.push_back(name + ": duplicate module id '" + m.id + "'");
            continue;
        }
        m.root = sub;
        if (requireExecutable) {
            std::error_code e4;
            if (!fs::is_regular_file(sub / fs::path(m.exe), e4)) { d.errors.push_back(name + ": entry.exe '" + m.exe + "' not found"); continue; }
        }
        d.modules.push_back(std::move(m));
    }
    std::sort(d.modules.begin(), d.modules.end(), [](const Manifest& a, const Manifest& b) { return a.id < b.id; });
    return d;
}

} // namespace av::host
