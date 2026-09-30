/* SPDX-License-Identifier: Apache-2.0 */
#ifndef KSIGHT_KEYLOG_XREF_H
#define KSIGHT_KEYLOG_XREF_H

#include <stddef.h>
#include <stdint.h>

#define KS_KEYLOG_MAX_LOADS 32u
#define KS_KEYLOG_MAX_LABEL_MATCHES 256u
#define KS_KEYLOG_MAX_XREFS 256u
#define KS_KEYLOG_MAX_CANDIDATES 128u
#define KS_KEYLOG_MAX_BUILD_ID 64u
#define KS_KEYLOG_LABEL_COUNT 8u

struct ks_keylog_load {
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t file_size;
    uint32_t flags;
};

struct ks_keylog_label_match {
    uint64_t file_offset;
    uint64_t virtual_address;
    uint16_t label_index;
};

struct ks_keylog_xref {
    uint64_t instruction_address;
    uint64_t label_address;
    uint64_t call_address;
    uint64_t target_address;
    uint16_t label_index;
    uint8_t materialization_instructions;
};

struct ks_keylog_candidate {
    uint64_t target_address;
    uint64_t label_mask;
    uint32_t references;
    uint16_t distinct_labels;
};

struct ks_keylog_report {
    struct ks_keylog_load loads[KS_KEYLOG_MAX_LOADS];
    struct ks_keylog_label_match labels[KS_KEYLOG_MAX_LABEL_MATCHES];
    struct ks_keylog_xref xrefs[KS_KEYLOG_MAX_XREFS];
    struct ks_keylog_candidate candidates[KS_KEYLOG_MAX_CANDIDATES];
    uint8_t build_id[KS_KEYLOG_MAX_BUILD_ID];
    uint64_t winner_address;
    uint32_t winner_references;
    uint16_t load_count;
    uint16_t label_count;
    uint16_t xref_count;
    uint16_t candidate_count;
    uint16_t winner_distinct_labels;
    uint8_t build_id_size;
    uint8_t winner_unique;
    uint8_t truncated;
};

enum ks_keylog_status {
    KS_KEYLOG_OK = 0,
    KS_KEYLOG_BAD_ARGUMENT,
    KS_KEYLOG_NOT_ELF,
    KS_KEYLOG_UNSUPPORTED,
    KS_KEYLOG_MALFORMED
};

const char *ks_keylog_status_name(enum ks_keylog_status status);
const char *ks_keylog_label_name(unsigned index);
enum ks_keylog_status ks_keylog_scan(const uint8_t *image, size_t image_size,
                                     struct ks_keylog_report *report);

#endif
