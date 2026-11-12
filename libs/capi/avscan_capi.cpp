// C API wrapper around the C++ core. See libs/capi/avscan.h.
#include "avscan.h"

#include "engine.hpp"
#include "report.hpp"

#include <exception>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <string>
#include <utility>

struct avscan_engine {
    explicit avscan_engine(std::unique_ptr<av::Scanner> s) : scanner(std::move(s)) {}
    std::unique_ptr<av::Scanner> scanner;
    std::mutex mu;
};

struct avscan_result {
    explicit avscan_result(av::ScanResult r_) : r(std::move(r_)) {}
    av::ScanResult r;
    mutable std::string json;
};

namespace {

thread_local std::string g_error;

void setError(const std::string& m) {
    try { g_error = m; } catch (...) {}
}

avscan_status mapStatus(av::Status s) {
    switch (s) {
        case av::Status::Clean: return AVSCAN_STATUS_CLEAN;
        case av::Status::Skipped: return AVSCAN_STATUS_SKIPPED;
        case av::Status::Error: return AVSCAN_STATUS_ERROR;
        case av::Status::Suspicious: return AVSCAN_STATUS_SUSPICIOUS;
        case av::Status::Infected: return AVSCAN_STATUS_INFECTED;
    }
    return AVSCAN_STATUS_ERROR;
}

int finishScan(av::ScanResult&& res, avscan_result** out) {
    auto* r = new (std::nothrow) avscan_result(std::move(res));
    if (!r) {
        setError("out of memory");
        return AVSCAN_ERR_INTERNAL;
    }
    *out = r;
    return AVSCAN_OK;
}

} // namespace

uint32_t avscan_api_version(void) { return AVSCAN_API_VERSION; }

const char* avscan_version_string(void) { return AVSCAN_VERSION_STRING; }

const char* avscan_last_error(void) { return g_error.c_str(); }

void avscan_options_init(avscan_options* o) {
    if (!o) return;
    const av::Config d;
    o->struct_size = static_cast<uint32_t>(sizeof(avscan_options));
    o->use_cache = 0;
    o->suspicious_threshold = d.suspiciousThreshold;
    o->infected_threshold = d.infectedThreshold;
    o->max_file_size = d.limits.maxFileSize;
    o->max_archive_depth = d.limits.maxDepth;
}

int avscan_open(const char* db_path, const avscan_options* o, avscan_engine** out) {
    if (!out) {
        setError("out_engine is NULL");
        return AVSCAN_ERR_ARGUMENT;
    }
    *out = nullptr;
    g_error.clear();
    if (!db_path || !*db_path) {
        setError("db_path is NULL or empty");
        return AVSCAN_ERR_ARGUMENT;
    }
    try {
        av::Config cfg;
        cfg.useCache = false;
        if (o) {
            if (o->struct_size != sizeof(avscan_options)) {
                setError("avscan_options.struct_size mismatch: call avscan_options_init()");
                return AVSCAN_ERR_ARGUMENT;
            }
            if (o->suspicious_threshold <= 0 || o->infected_threshold < o->suspicious_threshold || o->max_archive_depth < 0) {
                setError("invalid thresholds or archive depth");
                return AVSCAN_ERR_ARGUMENT;
            }
            cfg.useCache = o->use_cache != 0;
            cfg.suspiciousThreshold = o->suspicious_threshold;
            cfg.infectedThreshold = o->infected_threshold;
            cfg.limits.maxFileSize = o->max_file_size;
            cfg.limits.maxDepth = o->max_archive_depth;
        }
        auto made = av::makeEngine(av::pathFromUtf8(db_path), cfg);
        if (!made) {
            setError(made.error().message);
            return AVSCAN_ERR_DB;
        }
        auto* e = new (std::nothrow) avscan_engine(std::move(*made));
        if (!e) {
            setError("out of memory");
            return AVSCAN_ERR_INTERNAL;
        }
        *out = e;
        return AVSCAN_OK;
    } catch (const std::exception& ex) {
        setError(ex.what());
        return AVSCAN_ERR_INTERNAL;
    } catch (...) {
        setError("unknown exception");
        return AVSCAN_ERR_INTERNAL;
    }
}

void avscan_close(avscan_engine* e) { delete e; }

int avscan_scan_path(avscan_engine* e, const char* path, avscan_result** out) {
    if (!out) {
        setError("out_result is NULL");
        return AVSCAN_ERR_ARGUMENT;
    }
    *out = nullptr;
    if (!e || !path || !*path) {
        setError("engine or path is NULL");
        return AVSCAN_ERR_ARGUMENT;
    }
    try {
        std::lock_guard<std::mutex> lock(e->mu);
        return finishScan(e->scanner->scanPath(path), out);
    } catch (const std::exception& ex) {
        setError(ex.what());
        return AVSCAN_ERR_INTERNAL;
    } catch (...) {
        setError("unknown exception");
        return AVSCAN_ERR_INTERNAL;
    }
}

int avscan_scan_buffer(avscan_engine* e, const void* data, size_t size, const char* name, avscan_result** out) {
    if (!out) {
        setError("out_result is NULL");
        return AVSCAN_ERR_ARGUMENT;
    }
    *out = nullptr;
    if (!e || (!data && size != 0)) {
        setError("engine is NULL or data is NULL with non-zero size");
        return AVSCAN_ERR_ARGUMENT;
    }
    try {
        std::lock_guard<std::mutex> lock(e->mu);
        av::Budget budget;
        budget.rootSize = size;
        std::span<const std::uint8_t> view(static_cast<const std::uint8_t*>(data), size);
        return finishScan(e->scanner->scanMemory(view, name ? name : "buffer", 0, budget), out);
    } catch (const std::exception& ex) {
        setError(ex.what());
        return AVSCAN_ERR_INTERNAL;
    } catch (...) {
        setError("unknown exception");
        return AVSCAN_ERR_INTERNAL;
    }
}

avscan_status avscan_result_status(const avscan_result* r) { return r ? mapStatus(r->r.status) : AVSCAN_STATUS_ERROR; }
const char* avscan_result_path(const avscan_result* r) { return r ? r->r.path.c_str() : ""; }
const char* avscan_result_message(const avscan_result* r) { return r ? r->r.message.c_str() : ""; }
const char* avscan_result_sha256(const avscan_result* r) { return r ? r->r.sha256.c_str() : ""; }
int avscan_result_score(const avscan_result* r) { return r ? r->r.score : 0; }
int avscan_result_partial(const avscan_result* r) { return r && r->r.partial ? 1 : 0; }
size_t avscan_result_detection_count(const avscan_result* r) { return r ? r->r.detections.size() : 0; }

const char* avscan_result_detection_name(const avscan_result* r, size_t i) {
    return (r && i < r->r.detections.size()) ? r->r.detections[i].name.c_str() : nullptr;
}
const char* avscan_result_detection_kind(const avscan_result* r, size_t i) {
    return (r && i < r->r.detections.size()) ? r->r.detections[i].kind.c_str() : nullptr;
}
int avscan_result_detection_is_malware(const avscan_result* r, size_t i) {
    return (r && i < r->r.detections.size() && r->r.detections[i].malware) ? 1 : 0;
}

const char* avscan_result_json(const avscan_result* r) {
    if (!r) return nullptr;
    try {
        if (r->json.empty()) {
            std::ostringstream os;
            av::printJson(os, r->r);
            r->json = os.str();
        }
        return r->json.c_str();
    } catch (...) {
        return nullptr;
    }
}

void avscan_result_free(avscan_result* r) { delete r; }
