/* SPDX-License-Identifier: Apache-2.0
 * Bounded, diagnostic-only AArch64 ELF key-log label xref scanner.
 * Not part of `make device` / ksightd. Do not wire into default attach. */
#include "keylog_xref.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ELF_HEADER_SIZE 64u
#define ELF_PROGRAM_HEADER_SIZE 56u
#define PT_LOAD 1u
#define PT_NOTE 4u
#define PF_X 1u
#define EM_AARCH64 183u
#define NT_GNU_BUILD_ID 3u
#define XREF_LOOKAHEAD 24u

struct label_spec {
    const char *text;
    size_t size;
};

static const struct label_spec label_specs[KS_KEYLOG_LABEL_COUNT] = {
    {"CLIENT_RANDOM", sizeof("CLIENT_RANDOM") - 1u},
    {"CLIENT_EARLY_TRAFFIC_SECRET", sizeof("CLIENT_EARLY_TRAFFIC_SECRET") - 1u},
    {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", sizeof("CLIENT_HANDSHAKE_TRAFFIC_SECRET") - 1u},
    {"SERVER_HANDSHAKE_TRAFFIC_SECRET", sizeof("SERVER_HANDSHAKE_TRAFFIC_SECRET") - 1u},
    {"CLIENT_TRAFFIC_SECRET_0", sizeof("CLIENT_TRAFFIC_SECRET_0") - 1u},
    {"SERVER_TRAFFIC_SECRET_0", sizeof("SERVER_TRAFFIC_SECRET_0") - 1u},
    {"EXPORTER_SECRET", sizeof("EXPORTER_SECRET") - 1u},
    {"EARLY_EXPORTER_SECRET", sizeof("EARLY_EXPORTER_SECRET") - 1u},
};

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t read_u64(const uint8_t *p) {
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8u; ++i) {
        value |= (uint64_t)p[i] << (8u * i);
    }
    return value;
}

static int range_ok(size_t size, uint64_t offset, uint64_t length) {
    return offset <= (uint64_t)size && length <= (uint64_t)size - offset;
}

static int add_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (left > UINT64_MAX - right) {
        return 0;
    }
    *result = left + right;
    return 1;
}

static int file_to_va(const struct ks_keylog_report *report, uint64_t file_offset,
                      uint64_t *virtual_address) {
    unsigned i;
    for (i = 0; i < report->load_count; ++i) {
        const struct ks_keylog_load *load = &report->loads[i];
        uint64_t end;
        if (!add_u64(load->file_offset, load->file_size, &end)) {
            continue;
        }
        if (file_offset >= load->file_offset && file_offset < end) {
            return add_u64(load->virtual_address, file_offset - load->file_offset,
                           virtual_address);
        }
    }
    return 0;
}

static int64_t sign_extend(uint64_t value, unsigned bits) {
    const uint64_t sign = UINT64_C(1) << (bits - 1u);
    return (int64_t)((value ^ sign) - sign);
}

static int decode_adrp(uint32_t insn, uint64_t pc, unsigned *rd, uint64_t *value) {
    uint64_t immediate;
    int64_t signed_immediate;
    if ((insn & UINT32_C(0x9f000000)) != UINT32_C(0x90000000)) {
        return 0;
    }
    immediate = ((uint64_t)((insn >> 5) & UINT32_C(0x7ffff)) << 2) |
                ((insn >> 29) & 3u);
    signed_immediate = sign_extend(immediate, 21u) * 4096;
    *rd = insn & 31u;
    *value = (uint64_t)((int64_t)(pc & ~UINT64_C(0xfff)) + signed_immediate);
    return 1;
}

static int decode_adr(uint32_t insn, uint64_t pc, unsigned *rd, uint64_t *value) {
    uint64_t immediate;
    if ((insn & UINT32_C(0x9f000000)) != UINT32_C(0x10000000)) {
        return 0;
    }
    immediate = ((uint64_t)((insn >> 5) & UINT32_C(0x7ffff)) << 2) |
                ((insn >> 29) & 3u);
    *rd = insn & 31u;
    *value = (uint64_t)((int64_t)pc + sign_extend(immediate, 21u));
    return 1;
}

static int decode_add_immediate(uint32_t insn, unsigned *rd, unsigned *rn,
                                uint64_t *immediate) {
    unsigned shift;
    if ((insn & UINT32_C(0xff800000)) != UINT32_C(0x91000000)) {
        return 0;
    }
    shift = (insn >> 22) & 3u;
    if (shift > 1u) {
        return 0;
    }
    *rd = insn & 31u;
    *rn = (insn >> 5) & 31u;
    *immediate = (uint64_t)((insn >> 10) & UINT32_C(0xfff)) << (shift * 12u);
    return 1;
}

static int decode_bl(uint32_t insn, uint64_t pc, uint64_t *target) {
    int64_t displacement;
    if ((insn & UINT32_C(0xfc000000)) != UINT32_C(0x94000000)) {
        return 0;
    }
    displacement = sign_extend(insn & UINT32_C(0x03ffffff), 26u) * 4;
    *target = (uint64_t)((int64_t)pc + displacement);
    return 1;
}

static int register_written(uint32_t insn, unsigned reg) {
    unsigned rd = insn & 31u;
    if (reg == 31u) {
        return 0;
    }
    if ((insn & UINT32_C(0x1f000000)) == UINT32_C(0x10000000) ||
        (insn & UINT32_C(0x1f000000)) == UINT32_C(0x11000000) ||
        (insn & UINT32_C(0x1f000000)) == UINT32_C(0x0a000000) ||
        (insn & UINT32_C(0x1f000000)) == UINT32_C(0x0b000000) ||
        (insn & UINT32_C(0x1f800000)) == UINT32_C(0x12800000) ||
        (insn & UINT32_C(0x3b000000)) == UINT32_C(0x18000000) ||
        (insn & UINT32_C(0x3b000000)) == UINT32_C(0x39000000) ||
        (insn & UINT32_C(0x1fe00000)) == UINT32_C(0x1ac00000) ||
        (insn & UINT32_C(0x7f800000)) == UINT32_C(0x53000000)) {
        return rd == reg;
    }
    if ((insn & UINT32_C(0xffe0fc00)) == UINT32_C(0xaa0003e0) ||
        (insn & UINT32_C(0xffe0fc00)) == UINT32_C(0x2a0003e0)) {
        return rd == reg;
    }
    if ((insn & UINT32_C(0xffc00000)) == UINT32_C(0xa9400000) ||
        (insn & UINT32_C(0xffc00000)) == UINT32_C(0x29400000)) {
        return rd == reg || ((insn >> 10) & 31u) == reg;
    }
    return 0;
}

static int is_control_flow(uint32_t insn) {
    return (insn & UINT32_C(0x7c000000)) == UINT32_C(0x14000000) ||
           (insn & UINT32_C(0xff000010)) == UINT32_C(0x54000000) ||
           (insn & UINT32_C(0x7e000000)) == UINT32_C(0x34000000) ||
           (insn & UINT32_C(0x7e000000)) == UINT32_C(0x36000000) ||
           (insn & UINT32_C(0xfffffc1f)) == UINT32_C(0xd61f0000) ||
           (insn & UINT32_C(0xfffffc1f)) == UINT32_C(0xd63f0000) ||
           (insn & UINT32_C(0xfffffc1f)) == UINT32_C(0xd65f0000);
}

static int label_index_at(const struct ks_keylog_report *report, uint64_t address) {
    unsigned i;
    for (i = 0; i < report->label_count; ++i) {
        if (report->labels[i].virtual_address == address) {
            return report->labels[i].label_index;
        }
    }
    return -1;
}

static void record_label(struct ks_keylog_report *report, uint64_t file_offset,
                         uint64_t virtual_address, unsigned label_index) {
    struct ks_keylog_label_match *match;
    if (report->label_count >= KS_KEYLOG_MAX_LABEL_MATCHES) {
        report->truncated = 1;
        return;
    }
    match = &report->labels[report->label_count++];
    match->file_offset = file_offset;
    match->virtual_address = virtual_address;
    match->label_index = (uint16_t)label_index;
}

static void record_xref(struct ks_keylog_report *report, uint64_t insn_address,
                        uint64_t label_address, uint64_t call_address,
                        uint64_t target_address, unsigned label_index,
                        unsigned materialization_instructions) {
    struct ks_keylog_xref *xref;
    if (report->xref_count >= KS_KEYLOG_MAX_XREFS) {
        report->truncated = 1;
        return;
    }
    xref = &report->xrefs[report->xref_count++];
    xref->instruction_address = insn_address;
    xref->label_address = label_address;
    xref->call_address = call_address;
    xref->target_address = target_address;
    xref->label_index = (uint16_t)label_index;
    xref->materialization_instructions = (uint8_t)materialization_instructions;
}

static void parse_note_segment(const uint8_t *image, size_t image_size, uint64_t offset,
                               uint64_t length, struct ks_keylog_report *report) {
    uint64_t cursor = offset;
    uint64_t end;
    if (!range_ok(image_size, offset, length) || !add_u64(offset, length, &end)) {
        report->truncated = 1;
        return;
    }
    while (cursor < end) {
        uint32_t namesz;
        uint32_t descsz;
        uint32_t type;
        uint64_t name_offset;
        uint64_t desc_offset;
        uint64_t next;
        if (end - cursor < 12u) {
            report->truncated = 1;
            return;
        }
        namesz = read_u32(image + cursor);
        descsz = read_u32(image + cursor + 4u);
        type = read_u32(image + cursor + 8u);
        name_offset = cursor + 12u;
        if (!add_u64(name_offset, ((uint64_t)namesz + 3u) & ~UINT64_C(3),
                     &desc_offset) ||
            !add_u64(desc_offset, ((uint64_t)descsz + 3u) & ~UINT64_C(3), &next) ||
            next > end) {
            report->truncated = 1;
            return;
        }
        if (type == NT_GNU_BUILD_ID && namesz >= 3u && descsz != 0u &&
            image[name_offset] == 'G' && image[name_offset + 1u] == 'N' &&
            image[name_offset + 2u] == 'U' && report->build_id_size == 0u) {
            size_t copy = descsz;
            if (copy > KS_KEYLOG_MAX_BUILD_ID) {
                copy = KS_KEYLOG_MAX_BUILD_ID;
                report->truncated = 1;
            }
            memcpy(report->build_id, image + desc_offset, copy);
            report->build_id_size = (uint8_t)copy;
        }
        cursor = next;
    }
}

static void find_labels(const uint8_t *image, size_t image_size,
                        struct ks_keylog_report *report) {
    unsigned load_index;
    for (load_index = 0; load_index < report->load_count; ++load_index) {
        const struct ks_keylog_load *load = &report->loads[load_index];
        uint64_t position;
        if (!range_ok(image_size, load->file_offset, load->file_size)) {
            report->truncated = 1;
            continue;
        }
        for (position = 0; position < load->file_size; ++position) {
            unsigned label_index;
            for (label_index = 0; label_index < KS_KEYLOG_LABEL_COUNT; ++label_index) {
                const struct label_spec *spec = &label_specs[label_index];
                uint64_t virtual_address;
                uint64_t file_offset;
                if (spec->size > load->file_size - position ||
                    memcmp(image + load->file_offset + position, spec->text, spec->size) != 0) {
                    continue;
                }
                file_offset = load->file_offset + position;
                if (file_to_va(report, file_offset, &virtual_address)) {
                    record_label(report, file_offset, virtual_address, label_index);
                }
            }
        }
    }
}

static void find_call_after(const uint8_t *image, const struct ks_keylog_load *load,
                            uint64_t instruction_offset, uint64_t materialized_offset,
                            unsigned label_reg, uint64_t label_address,
                            unsigned label_index, unsigned materialization_instructions,
                            struct ks_keylog_report *report) {
    uint64_t step;
    for (step = 1u; step <= XREF_LOOKAHEAD; ++step) {
        uint64_t next_offset;
        uint64_t pc;
        uint64_t target;
        uint32_t insn;
        if (!add_u64(materialized_offset, step * 4u, &next_offset) ||
            next_offset > load->file_size || load->file_size - next_offset < 4u) {
            return;
        }
        insn = read_u32(image + load->file_offset + next_offset);
        pc = load->virtual_address + next_offset;
        if (decode_bl(insn, pc, &target)) {
            record_xref(report, load->virtual_address + instruction_offset, label_address,
                        pc, target, label_index, materialization_instructions);
            return;
        }
        if (is_control_flow(insn) || register_written(insn, label_reg) ||
            register_written(insn, 1u)) {
            return;
        }
    }
}

static void scan_executable_load(const uint8_t *image, const struct ks_keylog_load *load,
                                 struct ks_keylog_report *report) {
    uint64_t offset;
    if ((load->flags & PF_X) == 0u || load->file_size < 4u) {
        return;
    }
    for (offset = 0; offset <= load->file_size - 4u; offset += 4u) {
        uint32_t insn = read_u32(image + load->file_offset + offset);
        uint64_t pc = load->virtual_address + offset;
        uint64_t address;
        uint64_t immediate;
        unsigned rd;
        unsigned rn;
        int label_index;
        if (decode_adr(insn, pc, &rd, &address)) {
            label_index = label_index_at(report, address);
            if (label_index >= 0 && rd == 1u) {
                find_call_after(image, load, offset, offset, rd, address,
                                (unsigned)label_index, 1u, report);
            }
            continue;
        }
        if (decode_adrp(insn, pc, &rd, &address)) {
            uint64_t step;
            for (step = 1u; step <= XREF_LOOKAHEAD; ++step) {
                uint64_t next_offset;
                uint32_t next_insn;
                unsigned add_rd;
                if (!add_u64(offset, step * 4u, &next_offset) ||
                    next_offset > load->file_size || load->file_size - next_offset < 4u) {
                    break;
                }
                next_insn = read_u32(image + load->file_offset + next_offset);
                if (decode_add_immediate(next_insn, &add_rd, &rn, &immediate) && rn == rd) {
                    uint64_t materialized;
                    if (!add_u64(address, immediate, &materialized)) {
                        break;
                    }
                    label_index = label_index_at(report, materialized);
                    if (label_index >= 0 && add_rd == 1u) {
                        find_call_after(image, load, offset, next_offset, add_rd,
                                        materialized, (unsigned)label_index, 2u, report);
                    }
                    if (add_rd == rd) {
                        break;
                    }
                }
                if (is_control_flow(next_insn) || register_written(next_insn, rd) ||
                    register_written(next_insn, 1u)) {
                    break;
                }
            }
        }
    }
}

static unsigned popcount64(uint64_t value) {
    unsigned count = 0;
    while (value != 0u) {
        value &= value - 1u;
        ++count;
    }
    return count;
}

static void build_candidates(struct ks_keylog_report *report) {
    unsigned i;
    for (i = 0; i < report->xref_count; ++i) {
        const struct ks_keylog_xref *xref = &report->xrefs[i];
        unsigned candidate_index;
        struct ks_keylog_candidate *candidate = NULL;
        for (candidate_index = 0; candidate_index < report->candidate_count;
             ++candidate_index) {
            if (report->candidates[candidate_index].target_address ==
                xref->target_address) {
                candidate = &report->candidates[candidate_index];
                break;
            }
        }
        if (candidate == NULL) {
            if (report->candidate_count >= KS_KEYLOG_MAX_CANDIDATES) {
                report->truncated = 1;
                continue;
            }
            candidate = &report->candidates[report->candidate_count++];
            memset(candidate, 0, sizeof(*candidate));
            candidate->target_address = xref->target_address;
        }
        ++candidate->references;
        candidate->label_mask |= UINT64_C(1) << xref->label_index;
        candidate->distinct_labels = (uint16_t)popcount64(candidate->label_mask);
    }
    if (report->candidate_count != 0u) {
        unsigned best = 0;
        int unique = 1;
        for (i = 1u; i < report->candidate_count; ++i) {
            const struct ks_keylog_candidate *left = &report->candidates[i];
            const struct ks_keylog_candidate *right = &report->candidates[best];
            if (left->distinct_labels > right->distinct_labels ||
                (left->distinct_labels == right->distinct_labels &&
                 left->references > right->references)) {
                best = i;
                unique = 1;
            } else if (left->distinct_labels == right->distinct_labels &&
                       left->references == right->references) {
                unique = 0;
            }
        }
        report->winner_address = report->candidates[best].target_address;
        report->winner_distinct_labels = report->candidates[best].distinct_labels;
        report->winner_references = report->candidates[best].references;
        report->winner_unique = (uint8_t)(unique && report->winner_distinct_labels >= 2u);
    }
}

const char *ks_keylog_status_name(enum ks_keylog_status status) {
    switch (status) {
    case KS_KEYLOG_OK:
        return "ok";
    case KS_KEYLOG_BAD_ARGUMENT:
        return "bad-argument";
    case KS_KEYLOG_NOT_ELF:
        return "not-elf";
    case KS_KEYLOG_UNSUPPORTED:
        return "unsupported";
    case KS_KEYLOG_MALFORMED:
        return "malformed";
    }
    return "unknown";
}

const char *ks_keylog_label_name(unsigned index) {
    if (index >= KS_KEYLOG_LABEL_COUNT) {
        return "UNKNOWN";
    }
    return label_specs[index].text;
}

enum ks_keylog_status ks_keylog_scan(const uint8_t *image, size_t image_size,
                                     struct ks_keylog_report *report) {
    uint64_t program_offset;
    uint64_t program_bytes;
    uint16_t program_entry_size;
    uint16_t program_count;
    unsigned i;
    if (image == NULL || report == NULL) {
        return KS_KEYLOG_BAD_ARGUMENT;
    }
    memset(report, 0, sizeof(*report));
    if (image_size < ELF_HEADER_SIZE || image[0] != 0x7f || image[1] != 'E' ||
        image[2] != 'L' || image[3] != 'F') {
        return KS_KEYLOG_NOT_ELF;
    }
    if (image[4] != 2u || image[5] != 1u || image[6] != 1u ||
        read_u16(image + 18u) != EM_AARCH64) {
        return KS_KEYLOG_UNSUPPORTED;
    }
    program_offset = read_u64(image + 32u);
    program_entry_size = read_u16(image + 54u);
    program_count = read_u16(image + 56u);
    if (program_entry_size < ELF_PROGRAM_HEADER_SIZE || program_count == 0u ||
        !add_u64(0u, (uint64_t)program_entry_size * program_count, &program_bytes) ||
        !range_ok(image_size, program_offset, program_bytes)) {
        return KS_KEYLOG_MALFORMED;
    }
    for (i = 0; i < program_count; ++i) {
        const uint8_t *program = image + program_offset + (uint64_t)i * program_entry_size;
        uint32_t type = read_u32(program);
        uint64_t file_offset = read_u64(program + 8u);
        uint64_t file_size = read_u64(program + 32u);
        if (!range_ok(image_size, file_offset, file_size)) {
            return KS_KEYLOG_MALFORMED;
        }
        if (type == PT_LOAD) {
            struct ks_keylog_load *load;
            if (report->load_count >= KS_KEYLOG_MAX_LOADS) {
                report->truncated = 1;
                continue;
            }
            load = &report->loads[report->load_count++];
            load->file_offset = file_offset;
            load->virtual_address = read_u64(program + 16u);
            load->file_size = file_size;
            load->flags = read_u32(program + 4u);
        } else if (type == PT_NOTE) {
            parse_note_segment(image, image_size, file_offset, file_size, report);
        }
    }
    if (report->load_count == 0u) {
        return KS_KEYLOG_MALFORMED;
    }
    find_labels(image, image_size, report);
    for (i = 0; i < report->load_count; ++i) {
        scan_executable_load(image, &report->loads[i], report);
    }
    build_candidates(report);
    return KS_KEYLOG_OK;
}

#ifndef KS_KEYLOG_XREF_NO_MAIN
static void print_hex(const uint8_t *data, size_t size) {
    size_t i;
    if (size == 0u) {
        fputc('-', stdout);
        return;
    }
    for (i = 0; i < size; ++i) {
        printf("%02x", data[i]);
    }
}

static int scan_path(const char *path) {
    FILE *file;
    long length;
    uint8_t *image;
    size_t size;
    struct ks_keylog_report report;
    enum ks_keylog_status status;
    unsigned i;
    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "keylog_xref: open failed: %s\n", path);
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        fprintf(stderr, "keylog_xref: size failed: %s\n", path);
        return 1;
    }
    size = (size_t)length;
    if ((long)size != length || size == 0u) {
        fclose(file);
        fprintf(stderr, "keylog_xref: invalid size: %s\n", path);
        return 1;
    }
    image = (uint8_t *)malloc(size);
    if (image == NULL || fread(image, 1u, size, file) != size) {
        free(image);
        fclose(file);
        fprintf(stderr, "keylog_xref: read failed: %s\n", path);
        return 1;
    }
    fclose(file);
    status = ks_keylog_scan(image, size, &report);
    printf("file=%s status=%s size=%zu build_id=", path, ks_keylog_status_name(status),
           size);
    print_hex(report.build_id, report.build_id_size);
    printf(" loads=%u labels=%u xrefs=%u candidates=%u truncated=%u\n",
           report.load_count, report.label_count, report.xref_count,
           report.candidate_count, report.truncated);
    for (i = 0; i < report.label_count; ++i) {
        printf("label name=%s file=0x%llx va=0x%llx\n",
               ks_keylog_label_name(report.labels[i].label_index),
               (unsigned long long)report.labels[i].file_offset,
               (unsigned long long)report.labels[i].virtual_address);
    }
    for (i = 0; i < report.xref_count; ++i) {
        printf("xref label=%s insn=0x%llx label_va=0x%llx call=0x%llx target=0x%llx materialization=%u\n",
               ks_keylog_label_name(report.xrefs[i].label_index),
               (unsigned long long)report.xrefs[i].instruction_address,
               (unsigned long long)report.xrefs[i].label_address,
               (unsigned long long)report.xrefs[i].call_address,
               (unsigned long long)report.xrefs[i].target_address,
               report.xrefs[i].materialization_instructions);
    }
    for (i = 0; i < report.candidate_count; ++i) {
        printf("candidate target=0x%llx distinct_labels=%u references=%u label_mask=0x%llx\n",
               (unsigned long long)report.candidates[i].target_address,
               report.candidates[i].distinct_labels, report.candidates[i].references,
               (unsigned long long)report.candidates[i].label_mask);
    }
    printf("winner unique=%u target=0x%llx distinct_labels=%u references=%u\n",
           report.winner_unique, (unsigned long long)report.winner_address,
           report.winner_distinct_labels, report.winner_references);
    free(image);
    return status == KS_KEYLOG_OK ? 0 : 1;
}

int main(int argc, char **argv) {
    int result = 0;
    int i;
    if (argc < 2) {
        fprintf(stderr, "usage: keylog-xref ELF...\n");
        return 2;
    }
    for (i = 1; i < argc; ++i) {
        if (scan_path(argv[i]) != 0) {
            result = 1;
        }
    }
    return result;
}
#endif
