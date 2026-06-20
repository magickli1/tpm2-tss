/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../helper/cmocka_all.h"
#include "tss2_common.h"
#include "tss2_mu.h"
#include "tss2_tpm2_types.h"

static void
fill_buffer(BYTE *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (BYTE)(seed + i);
}

static void
assert_tpm2b_eq(TPM2B_PUBLIC_KEY_MLKEM const *a, TPM2B_PUBLIC_KEY_MLKEM const *b) {
    assert_int_equal(a->size, b->size);
    assert_memory_equal(a->buffer, b->buffer, a->size);
}

static void
mu_mlkem_pub_key_sizes(void **state) {
    const UINT16 sizes[] = { 800, 1184, 1568 };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        TPM2B_PUBLIC_KEY_MLKEM src = { 0 };
        TPM2B_PUBLIC_KEY_MLKEM out = { 0 };
        uint8_t                buffer[sizeof(TPM2B_PUBLIC_KEY_MLKEM)] = { 0 };
        size_t                 offset = 0;
        TSS2_RC                rc;

        src.size = sizes[i];
        fill_buffer(src.buffer, src.size, (uint8_t)i);

        rc = Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Marshal(&src, buffer, sizeof(buffer), &offset);
        assert_int_equal(rc, TSS2_RC_SUCCESS);
        assert_int_equal(offset, 2 + src.size);

        offset = 0;
        rc = Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Unmarshal(buffer, sizeof(buffer), &offset, &out);
        assert_int_equal(rc, TSS2_RC_SUCCESS);
        assert_tpm2b_eq(&src, &out);
    }
}

static void
mu_mlkem_priv_seed(void **state) {
    TPM2B_PRIVATE_KEY_MLKEM src = { .size = MAX_MLKEM_PRIV_SEED_SIZE };
    TPM2B_PRIVATE_KEY_MLKEM out = { 0 };
    uint8_t                 buffer[sizeof(TPM2B_PRIVATE_KEY_MLKEM)] = { 0 };
    size_t                  offset = 0;
    TSS2_RC                 rc;

    fill_buffer(src.buffer, src.size, 0x42);

    rc = Tss2_MU_TPM2B_PRIVATE_KEY_MLKEM_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_KEY_MLKEM_Unmarshal(buffer, sizeof(buffer), &offset, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.size, MAX_MLKEM_PRIV_SEED_SIZE);
    assert_memory_equal(out.buffer, src.buffer, src.size);
}

static void
mu_mlkem_parms(void **state) {
    TPMS_MLKEM_PARMS src = {
        .symmetric = {
            .algorithm = TPM2_ALG_AES,
            .keyBits = { .aes = 128 },
            .mode = { .aes = TPM2_ALG_CFB },
        },
        .parameterSet = TPM2_MLKEM_768,
    };
    TPMS_MLKEM_PARMS out = { 0 };
    uint8_t          buffer[256] = { 0 };
    size_t           offset = 0;
    TSS2_RC          rc;

    rc = Tss2_MU_TPMS_MLKEM_PARMS_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_MLKEM_PARMS_Unmarshal(buffer, sizeof(buffer), &offset, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.parameterSet, TPM2_MLKEM_768);
}

static void
mu_mlkem_public_parms_union(void **state) {
    TPMU_PUBLIC_PARMS src = {
        .mlkemDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits = { .aes = 256 },
                .mode = { .aes = TPM2_ALG_CFB },
            },
            .parameterSet = TPM2_MLKEM_1024,
        },
    };
    TPMU_PUBLIC_PARMS out = { 0 };
    uint8_t           buffer[512] = { 0 };
    size_t            offset = 0;
    TSS2_RC           rc;

    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Marshal(&src, TPM2_ALG_MLKEM, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Unmarshal(buffer, sizeof(buffer), &offset, TPM2_ALG_MLKEM, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.mlkemDetail.parameterSet, TPM2_MLKEM_1024);
}

static void
mu_mlkem_public_id_union(void **state) {
    TPMU_PUBLIC_ID src = { .mlkem = { .size = 1184 } };
    TPMU_PUBLIC_ID out = { 0 };
    uint8_t        buffer[sizeof(TPM2B_PUBLIC_KEY_MLKEM)] = { 0 };
    size_t         offset = 0;
    TSS2_RC        rc;

    fill_buffer(src.mlkem.buffer, src.mlkem.size, 0x11);

    rc = Tss2_MU_TPMU_PUBLIC_ID_Marshal(&src, TPM2_ALG_MLKEM, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_ID_Unmarshal(buffer, sizeof(buffer), &offset, TPM2_ALG_MLKEM, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.mlkem.size, 1184);
}

static void
mu_mlkem_sensitive_composite(void **state) {
    TPMU_SENSITIVE_COMPOSITE src = { .mlkem = { .size = MAX_MLKEM_PRIV_SEED_SIZE } };
    TPMU_SENSITIVE_COMPOSITE out = { 0 };
    uint8_t                  buffer[128] = { 0 };
    size_t                   offset = 0;
    TSS2_RC                  rc;

    fill_buffer(src.mlkem.buffer, src.mlkem.size, 0x55);

    rc = Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Marshal(&src, TPM2_ALG_MLKEM, buffer, sizeof(buffer),
                                                  &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Unmarshal(buffer, sizeof(buffer), &offset,
                                                    TPM2_ALG_MLKEM, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.mlkem.size, MAX_MLKEM_PRIV_SEED_SIZE);
}

static void
mu_mlkem_encap_outputs(void **state) {
    TPM2B_SHARED_SECRET secret = { .size = 32 };
    TPM2B_KEM_CIPHERTEXT ct = { .size = 1088 };
    TPM2B_SHARED_SECRET secret_out = { 0 };
    TPM2B_KEM_CIPHERTEXT ct_out = { 0 };
    uint8_t             buffer[4096] = { 0 };
    size_t              offset = 0;
    TSS2_RC             rc;

    fill_buffer(secret.buffer, secret.size, 0x01);
    fill_buffer(ct.buffer, ct.size, 0x02);

    rc = Tss2_MU_TPM2B_SHARED_SECRET_Marshal(&secret, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    rc = Tss2_MU_TPM2B_KEM_CIPHERTEXT_Marshal(&ct, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPM2B_SHARED_SECRET_Unmarshal(buffer, sizeof(buffer), &offset, &secret_out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(secret_out.size, 32);

    rc = Tss2_MU_TPM2B_KEM_CIPHERTEXT_Unmarshal(buffer, sizeof(buffer), &offset, &ct_out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(ct_out.size, 1088);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(mu_mlkem_pub_key_sizes),
        cmocka_unit_test(mu_mlkem_priv_seed),
        cmocka_unit_test(mu_mlkem_parms),
        cmocka_unit_test(mu_mlkem_public_parms_union),
        cmocka_unit_test(mu_mlkem_public_id_union),
        cmocka_unit_test(mu_mlkem_sensitive_composite),
        cmocka_unit_test(mu_mlkem_encap_outputs),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
