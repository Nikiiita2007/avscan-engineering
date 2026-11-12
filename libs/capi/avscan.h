/*
 * avscan.h - C API of the AVScan engine (API version 1).
 *
 * - Plain C, no C++ types, safe to call from any language with a C FFI.
 * - All strings are UTF-8, NUL-terminated.
 * - An avscan_engine may be used from several threads: calls on one engine are serialized internally.
 *   A single avscan_result must not be used from several threads at the same time.
 * - Every function that returns an object has a matching *_free / *_close function.
 * - avscan_last_error() returns a message for the last failure on the calling thread.
 */
#ifndef AVSCAN_H
#define AVSCAN_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(AVSCAN_BUILD)
#    define AVSCAN_API __declspec(dllexport)
#  elif defined(AVSCAN_SHARED)
#    define AVSCAN_API __declspec(dllimport)
#  else
#    define AVSCAN_API
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define AVSCAN_API __attribute__((visibility("default")))
#else
#  define AVSCAN_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AVSCAN_API_VERSION 1
#define AVSCAN_VERSION_STRING "0.4.0"

typedef struct avscan_engine avscan_engine; /* opaque */
typedef struct avscan_result avscan_result; /* opaque */

typedef enum avscan_error {
    AVSCAN_OK = 0,
    AVSCAN_ERR_ARGUMENT = 1, /* NULL or invalid argument */
    AVSCAN_ERR_DB = 2,       /* signature database cannot be opened or is invalid */
    AVSCAN_ERR_INTERNAL = 3  /* unexpected failure (exception, out of memory) */
} avscan_error;

typedef enum avscan_status {
    AVSCAN_STATUS_CLEAN = 0,
    AVSCAN_STATUS_SKIPPED = 1,
    AVSCAN_STATUS_ERROR = 2,
    AVSCAN_STATUS_SUSPICIOUS = 3,
    AVSCAN_STATUS_INFECTED = 4
} avscan_status;

typedef struct avscan_options {
    uint32_t struct_size;     /* set by avscan_options_init(), must equal sizeof(avscan_options) */
    int use_cache;            /* 0 = off (default for the library), 1 = on */
    int suspicious_threshold; /* score at which a file becomes Suspicious */
    int infected_threshold;   /* score at which a file becomes Infected; must be >= suspicious_threshold */
    uint64_t max_file_size;   /* bytes; larger files are skipped */
    int max_archive_depth;    /* nesting depth of archives */
} avscan_options;

/* Versions */
AVSCAN_API uint32_t avscan_api_version(void);
AVSCAN_API const char* avscan_version_string(void);

/* Last error message of the calling thread ("" when there is none). Never NULL. */
AVSCAN_API const char* avscan_last_error(void);

/* Fills *opts with the engine defaults. */
AVSCAN_API void avscan_options_init(avscan_options* opts);

/* Opens an engine with the signature database at db_path. opts may be NULL (defaults). */
AVSCAN_API int avscan_open(const char* db_path, const avscan_options* opts, avscan_engine** out_engine);
AVSCAN_API void avscan_close(avscan_engine* engine); /* NULL is allowed */

/* Scans a file. A scan problem (missing file, unreadable file) is reported through the result status
   AVSCAN_STATUS_ERROR, not through the return code. */
AVSCAN_API int avscan_scan_path(avscan_engine* engine, const char* path, avscan_result** out_result);

/* Scans a memory buffer. name is used in the report and may be NULL. data may be NULL only if size is 0. */
AVSCAN_API int avscan_scan_buffer(avscan_engine* engine, const void* data, size_t size, const char* name,
                                  avscan_result** out_result);

/* Result access. Returned strings are owned by the result and valid until avscan_result_free(). */
AVSCAN_API avscan_status avscan_result_status(const avscan_result* result);
AVSCAN_API const char* avscan_result_path(const avscan_result* result);
AVSCAN_API const char* avscan_result_message(const avscan_result* result);
AVSCAN_API const char* avscan_result_sha256(const avscan_result* result);
AVSCAN_API int avscan_result_score(const avscan_result* result);
AVSCAN_API int avscan_result_partial(const avscan_result* result); /* 1 if part of the content was not checked */
AVSCAN_API size_t avscan_result_detection_count(const avscan_result* result);
AVSCAN_API const char* avscan_result_detection_name(const avscan_result* result, size_t index); /* NULL if out of range */
AVSCAN_API const char* avscan_result_detection_kind(const avscan_result* result, size_t index);
AVSCAN_API int avscan_result_detection_is_malware(const avscan_result* result, size_t index);
/* Full report as a JSON object (same format as `avscan --json`). NULL on failure. */
AVSCAN_API const char* avscan_result_json(const avscan_result* result);
AVSCAN_API void avscan_result_free(avscan_result* result); /* NULL is allowed */

#ifdef __cplusplus
}
#endif

#endif /* AVSCAN_H */
