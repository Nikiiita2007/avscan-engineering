/* Test of the C API (pure C). Usage: capi_test <signatures.db> <corpus dir> */
#include "avscan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, msg)                         \
    do {                                         \
        if (cond) printf("PASS %s\n", (msg));    \
        else { printf("FAIL %s\n", (msg)); ++fails; } \
    } while (0)

int main(int argc, char** argv) {
    avscan_engine* e = NULL;
    avscan_result* r = NULL;
    avscan_options o;
    char path[1024];
    char eicar[96];
    const char* clean = "hello world";
    /* EICAR is assembled at runtime from two parts and never stored whole. */
    const char* part1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    const char* part2 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t l1, l2;

    if (argc != 3) return 4;
    CHECK(avscan_api_version() == AVSCAN_API_VERSION, "api version");
    CHECK(strlen(avscan_version_string()) > 0, "version string");

    CHECK(avscan_open("_no_such_db_", NULL, &e) == AVSCAN_ERR_DB && e == NULL, "open: missing db -> ERR_DB");
    CHECK(strlen(avscan_last_error()) > 0, "last error is set");
    CHECK(avscan_open(NULL, NULL, &e) == AVSCAN_ERR_ARGUMENT, "open: NULL path -> ERR_ARGUMENT");
    CHECK(avscan_open(argv[1], NULL, NULL) == AVSCAN_ERR_ARGUMENT, "open: NULL out -> ERR_ARGUMENT");

    avscan_options_init(&o);
    CHECK(o.struct_size == sizeof(o) && o.infected_threshold >= o.suspicious_threshold, "options init");
    o.struct_size = 1;
    CHECK(avscan_open(argv[1], &o, &e) == AVSCAN_ERR_ARGUMENT, "open: bad struct_size -> ERR_ARGUMENT");
    avscan_options_init(&o);

    CHECK(avscan_open(argv[1], &o, &e) == AVSCAN_OK && e != NULL, "open: valid db");
    if (!e) return 1;

    CHECK(avscan_scan_buffer(e, clean, strlen(clean), "clean.txt", &r) == AVSCAN_OK && r != NULL, "scan buffer (clean): rc");
    CHECK(avscan_result_status(r) == AVSCAN_STATUS_CLEAN, "clean buffer -> Clean");
    CHECK(avscan_result_detection_count(r) == 0, "clean buffer has no detections");
    CHECK(avscan_result_detection_name(r, 0) == NULL, "detection index out of range -> NULL");
    avscan_result_free(r);
    r = NULL;

    l1 = strlen(part1);
    l2 = strlen(part2);
    CHECK(l1 + l2 == 68 && l1 + l2 < sizeof(eicar), "test string has the expected length");
    memcpy(eicar, part1, l1);
    memcpy(eicar + l1, part2, l2);
    CHECK(avscan_scan_buffer(e, eicar, l1 + l2, "eicar.com", &r) == AVSCAN_OK && r != NULL, "scan buffer (EICAR): rc");
    CHECK(avscan_result_status(r) == AVSCAN_STATUS_INFECTED, "EICAR buffer -> Infected");
    CHECK(avscan_result_detection_count(r) >= 1 && avscan_result_detection_name(r, 0) != NULL, "EICAR has a named detection");
    CHECK(avscan_result_detection_is_malware(r, 0) == 1, "EICAR detection is malware");
    CHECK(strlen(avscan_result_sha256(r)) == 64, "sha256 has 64 hex chars");
    CHECK(avscan_result_json(r) != NULL && strstr(avscan_result_json(r), "Infected") != NULL, "json report mentions Infected");
    avscan_result_free(r);
    r = NULL;

    snprintf(path, sizeof(path), "%s/clean.txt", argv[2]);
    CHECK(avscan_scan_path(e, path, &r) == AVSCAN_OK && r != NULL, "scan path (clean.txt): rc");
    CHECK(avscan_result_status(r) == AVSCAN_STATUS_CLEAN, "clean.txt -> Clean");
    avscan_result_free(r);
    r = NULL;

    snprintf(path, sizeof(path), "%s/definitely_missing.file", argv[2]);
    CHECK(avscan_scan_path(e, path, &r) == AVSCAN_OK && r != NULL, "scan path (missing): rc");
    CHECK(avscan_result_status(r) == AVSCAN_STATUS_ERROR, "missing file -> Error, never Clean");
    avscan_result_free(r);
    r = NULL;

    CHECK(avscan_scan_buffer(NULL, clean, 1, "x", &r) == AVSCAN_ERR_ARGUMENT && r == NULL, "scan buffer: NULL engine");
    CHECK(avscan_scan_buffer(e, NULL, 5, "x", &r) == AVSCAN_ERR_ARGUMENT && r == NULL, "scan buffer: NULL data with size");
    CHECK(avscan_scan_path(e, NULL, &r) == AVSCAN_ERR_ARGUMENT && r == NULL, "scan path: NULL path");
    CHECK(avscan_result_status(NULL) == AVSCAN_STATUS_ERROR, "NULL result -> Error status");

    avscan_result_free(NULL);
    avscan_close(e);
    avscan_close(NULL);
    return fails ? 1 : 0;
}
