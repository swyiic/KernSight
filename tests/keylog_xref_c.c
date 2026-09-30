/* SPDX-License-Identifier: Apache-2.0 */
#include "keylog_xref.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURE_SIZE 0x3000u
#define PH_OFFSET 0x40u
#define TEXT_OFFSET 0x200u
#define TEXT_VA 0x1000u
#define DATA_OFFSET 0x400u
#define DATA_VA 0x9000u
#define NOTE_OFFSET 0x2f00u

static void put16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *p, uint32_t value) {
    unsigned i;
    for (i = 0; i < 4u; ++i) {
        p[i] = (uint8_t)(value >> (8u * i));
    }
}

static void put64(uint8_t *p, uint64_t value) {
    unsigned i;
    for (i = 0; i < 8u; ++i) {
        p[i] = (uint8_t)(value >> (8u * i));
    }
}

static void put_phdr(uint8_t *image, unsigned index, uint32_t type, uint32_t flags,
                     uint64_t offset, uint64_t address, uint64_t size) {
    uint8_t *p = image + PH_OFFSET + index * 56u;
    put32(p, type);
    put32(p + 4u, flags);
    put64(p + 8u, offset);
    put64(p + 16u, address);
    put64(p + 32u, size);
    put64(p + 40u, size);
    put64(p + 48u, 0x1000u);
}

static uint32_t encode_adr(unsigned rd, uint64_t pc, uint64_t target) {
    int64_t displacement = (int64_t)target - (int64_t)pc;
    uint64_t immediate = (uint64_t)displacement & UINT64_C(0x1fffff);
    return UINT32_C(0x10000000) | (uint32_t)((immediate & 3u) << 29) |
           (uint32_t)(((immediate >> 2) & UINT64_C(0x7ffff)) << 5) | rd;
}

static uint32_t encode_adrp(unsigned rd, uint64_t pc, uint64_t target) {
    int64_t pages = ((int64_t)(target & ~UINT64_C(0xfff)) -
                     (int64_t)(pc & ~UINT64_C(0xfff))) /
                    4096;
    uint64_t immediate = (uint64_t)pages & UINT64_C(0x1fffff);
    return UINT32_C(0x90000000) | (uint32_t)((immediate & 3u) << 29) |
           (uint32_t)(((immediate >> 2) & UINT64_C(0x7ffff)) << 5) | rd;
}

static uint32_t encode_add(unsigned rd, unsigned rn, unsigned immediate) {
    return UINT32_C(0x91000000) | ((immediate & UINT32_C(0xfff)) << 10) |
           (rn << 5) | rd;
}

static uint32_t encode_bl(uint64_t pc, uint64_t target) {
    int64_t words = ((int64_t)target - (int64_t)pc) / 4;
    return UINT32_C(0x94000000) | ((uint32_t)words & UINT32_C(0x03ffffff));
}

static uint8_t *make_fixture(void) {
    uint8_t *image = (uint8_t *)calloc(1u, FIXTURE_SIZE);
    static const uint8_t build_id[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    uint8_t *note;
    if (image == NULL) {
        return NULL;
    }
    image[0] = 0x7f;
    image[1] = 'E';
    image[2] = 'L';
    image[3] = 'F';
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    put16(image + 16u, 3u);
    put16(image + 18u, 183u);
    put32(image + 20u, 1u);
    put64(image + 32u, PH_OFFSET);
    put16(image + 52u, 64u);
    put16(image + 54u, 56u);
    put16(image + 56u, 3u);

    put_phdr(image, 0u, 1u, 5u, TEXT_OFFSET, TEXT_VA, 0x100u);
    put_phdr(image, 1u, 1u, 4u, DATA_OFFSET, DATA_VA, 0x2000u);
    put_phdr(image, 2u, 4u, 4u, NOTE_OFFSET, 0xa000u, 24u);

    memcpy(image + DATA_OFFSET + 0x20u, "CLIENT_RANDOM", sizeof("CLIENT_RANDOM"));
    memcpy(image + DATA_OFFSET + 0x60u, "CLIENT_TRAFFIC_SECRET_0",
           sizeof("CLIENT_TRAFFIC_SECRET_0"));
    memcpy(image + DATA_OFFSET + 0xa0u, "SERVER_TRAFFIC_SECRET_0",
           sizeof("SERVER_TRAFFIC_SECRET_0"));
    memcpy(image + DATA_OFFSET + 0xe0u, "EXPORTER_SECRET", sizeof("EXPORTER_SECRET"));

    put32(image + TEXT_OFFSET, encode_adrp(1u, TEXT_VA, DATA_VA + 0x20u));
    put32(image + TEXT_OFFSET + 4u, encode_add(1u, 1u, 0x20u));
    put32(image + TEXT_OFFSET + 8u, UINT32_C(0xd503201f));
    put32(image + TEXT_OFFSET + 12u, encode_bl(TEXT_VA + 12u, 0x1800u));

    put32(image + TEXT_OFFSET + 0x20u,
          encode_adr(1u, TEXT_VA + 0x20u, DATA_VA + 0x60u));
    put32(image + TEXT_OFFSET + 0x24u, UINT32_C(0xd503201f));
    put32(image + TEXT_OFFSET + 0x28u, encode_bl(TEXT_VA + 0x28u, 0x1800u));

    put32(image + TEXT_OFFSET + 0x40u,
          encode_adr(1u, TEXT_VA + 0x40u, DATA_VA + 0xa0u));
    put32(image + TEXT_OFFSET + 0x44u, encode_bl(TEXT_VA + 0x44u, 0x1900u));

    put32(image + TEXT_OFFSET + 0x60u,
          encode_adr(1u, TEXT_VA + 0x60u, DATA_VA + 0xe0u));
    put32(image + TEXT_OFFSET + 0x64u, encode_add(1u, 1u, 1u));
    put32(image + TEXT_OFFSET + 0x68u, encode_bl(TEXT_VA + 0x68u, 0x1800u));

    note = image + NOTE_OFFSET;
    put32(note, 4u);
    put32(note + 4u, (uint32_t)sizeof(build_id));
    put32(note + 8u, 3u);
    memcpy(note + 12u, "GNU\0", 4u);
    memcpy(note + 16u, build_id, sizeof(build_id));
    return image;
}

static int expect(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL %s\n", message);
        return 0;
    }
    return 1;
}

static int test_fixture(void) {
    uint8_t *image = make_fixture();
    struct ks_keylog_report report;
    enum ks_keylog_status status;
    int ok = expect(image != NULL, "allocate fixture");
    if (image == NULL) {
        return 0;
    }
    status = ks_keylog_scan(image, FIXTURE_SIZE, &report);
    ok &= expect(status == KS_KEYLOG_OK, "fixture status");
    ok &= expect(report.load_count == 2u, "multiple PT_LOAD count");
    ok &= expect(report.build_id_size == 5u && report.build_id[4] == 0x50u,
                 "PT_NOTE build id");
    ok &= expect(report.label_count == 4u, "all fixture labels");
    ok &= expect(report.xref_count == 3u, "xref and x1 clobber handling");
    ok &= expect(report.candidate_count == 2u, "candidate count");
    ok &= expect(report.winner_unique == 1u, "unique winner");
    ok &= expect(report.winner_address == 0x1800u, "winner address");
    ok &= expect(report.winner_distinct_labels == 2u, "distinct-label score");
    ok &= expect(report.winner_references == 2u, "winner references");
    ok &= expect(report.truncated == 0u, "fixture not truncated");
    free(image);
    return ok;
}

static int test_truncated_inputs(void) {
    uint8_t *image = make_fixture();
    struct ks_keylog_report report;
    size_t size;
    int ok = expect(image != NULL, "allocate truncation fixture");
    if (image == NULL) {
        return 0;
    }
    for (size = 0u; size < NOTE_OFFSET + 24u; ++size) {
        enum ks_keylog_status status = ks_keylog_scan(image, size, &report);
        ok &= expect(status != KS_KEYLOG_OK, "truncated image rejected");
        if (!ok) {
            break;
        }
    }
    free(image);
    return ok;
}

static int test_capacity_flag(void) {
    uint8_t *image = make_fixture();
    struct ks_keylog_report report;
    enum ks_keylog_status status;
    size_t position;
    int ok = expect(image != NULL, "allocate capacity fixture");
    if (image == NULL) {
        return 0;
    }
    memset(image + DATA_OFFSET, 'X', 0x2000u);
    for (position = 0u; position + sizeof("CLIENT_RANDOM") <= 0x2000u;
         position += sizeof("CLIENT_RANDOM")) {
        memcpy(image + DATA_OFFSET + position, "CLIENT_RANDOM", sizeof("CLIENT_RANDOM"));
    }
    status = ks_keylog_scan(image, FIXTURE_SIZE, &report);
    ok &= expect(status == KS_KEYLOG_OK, "capacity status");
    ok &= expect(report.label_count == KS_KEYLOG_MAX_LABEL_MATCHES,
                 "fixed label capacity");
    ok &= expect(report.truncated == 1u, "capacity truncation flag");
    free(image);
    return ok;
}

static int test_invalid_headers(void) {
    uint8_t *image = make_fixture();
    struct ks_keylog_report report;
    int ok = expect(image != NULL, "allocate invalid fixture");
    if (image == NULL) {
        return 0;
    }
    image[5] = 2u;
    ok &= expect(ks_keylog_scan(image, FIXTURE_SIZE, &report) == KS_KEYLOG_UNSUPPORTED,
                 "reject big endian");
    image[5] = 1u;
    put64(image + 32u, UINT64_MAX - 8u);
    ok &= expect(ks_keylog_scan(image, FIXTURE_SIZE, &report) == KS_KEYLOG_MALFORMED,
                 "reject overflowing phdr range");
    free(image);
    return ok;
}

int main(void) {
    int ok = test_fixture();
    ok &= test_truncated_inputs();
    ok &= test_capacity_flag();
    ok &= test_invalid_headers();
    printf("keylog_xref_c status=%s cases=4\n", ok ? "ok" : "failed");
    return ok ? 0 : 1;
}
