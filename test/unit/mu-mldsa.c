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
mu_mldsa_pub_key_sizes(void **state) {
    const UINT16 sizes[] = { 1312, 1952, 2592 };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        TPM2B_PUBLIC_KEY_MLDSA src = { 0 };
        TPM2B_PUBLIC_KEY_MLDSA out = { 0 };
        uint8_t                buffer[sizeof(TPM2B_PUBLIC_KEY_MLDSA)] = { 0 };
        size_t                 offset = 0;
        TSS2_RC                rc;

        src.size = sizes[i];
        fill_buffer(src.buffer, src.size, (uint8_t)(0x10 + i));

        rc = Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Marshal(&src, buffer, sizeof(buffer), &offset);
        assert_int_equal(rc, TSS2_RC_SUCCESS);

        offset = 0;
        rc = Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Unmarshal(buffer, sizeof(buffer), &offset, &out);
        assert_int_equal(rc, TSS2_RC_SUCCESS);
        assert_int_equal(out.size, sizes[i]);
        assert_memory_equal(out.buffer, src.buffer, src.size);
    }
}

static void
mu_mldsa_priv_seed(void **state) {
    TPM2B_PRIVATE_KEY_MLDSA src = { .size = MAX_MLDSA_PRIV_SEED_SIZE };
    TPM2B_PRIVATE_KEY_MLDSA out = { 0 };
    uint8_t                 buffer[64] = { 0 };
    size_t                  offset = 0;
    TSS2_RC                 rc;

    fill_buffer(src.buffer, src.size, 0x33);

    rc = Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Unmarshal(buffer, sizeof(buffer), &offset, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.size, 32);
}

static void
mu_mldsa_signature_max(void **state) {
    TPM2B_SIGNATURE_MLDSA src = { .size = MAX_MLDSA_SIG_SIZE };
    TPM2B_SIGNATURE_MLDSA out = { 0 };
    uint8_t               buffer[sizeof(TPM2B_SIGNATURE_MLDSA)] = { 0 };
    size_t                offset = 0;
    TSS2_RC               rc;

    fill_buffer(src.buffer, src.size, 0x77);

    rc = Tss2_MU_TPM2B_SIGNATURE_MLDSA_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, 2 + MAX_MLDSA_SIG_SIZE);

    offset = 0;
    rc = Tss2_MU_TPM2B_SIGNATURE_MLDSA_Unmarshal(buffer, sizeof(buffer), &offset, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.size, MAX_MLDSA_SIG_SIZE);
    assert_memory_equal(out.buffer, src.buffer, src.size);
}

static void
mu_mldsa_signature_ctx_hint(void **state) {
    TPM2B_SIGNATURE_CTX ctx = { .size = MAX_SIGNATURE_CTX_SIZE };
    TPM2B_SIGNATURE_HINT hint = { .size = 0 };
    TPM2B_SIGNATURE_CTX ctx_out = { 0 };
    TPM2B_SIGNATURE_HINT hint_out = { 0 };
    uint8_t             buffer[512] = { 0 };
    size_t              offset = 0;
    TSS2_RC             rc;

    fill_buffer(ctx.buffer, ctx.size, 0xCC);

    rc = Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(&ctx, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    rc = Tss2_MU_TPM2B_SIGNATURE_HINT_Marshal(&hint, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPM2B_SIGNATURE_CTX_Unmarshal(buffer, sizeof(buffer), &offset, &ctx_out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(ctx_out.size, MAX_SIGNATURE_CTX_SIZE);

    rc = Tss2_MU_TPM2B_SIGNATURE_HINT_Unmarshal(buffer, sizeof(buffer), &offset, &hint_out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(hint_out.size, 0);
}

static void
mu_mldsa_hash_signature(void **state) {
    TPMS_SIGNATURE_HASH_MLDSA src = {
        .hash = TPM2_ALG_SHA256,
        .signature = { .size = 3309 },
    };
    TPMS_SIGNATURE_HASH_MLDSA out = { 0 };
    uint8_t                   buffer[4096] = { 0 };
    size_t                    offset = 0;
    TSS2_RC                   rc;

    fill_buffer(src.signature.buffer, src.signature.size, 0xAB);

    rc = Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Unmarshal(buffer, sizeof(buffer), &offset, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.hash, TPM2_ALG_SHA256);
    assert_int_equal(out.signature.size, 3309);
}

static void
mu_mldsa_parms(void **state) {
    TPMS_MLDSA_PARMS src = {
        .parameterSet = TPM2_MLDSA_65,
        .allowExternalMu = TPM2_YES,
    };
    TPMS_HASH_MLDSA_PARMS hash_src = {
        .parameterSet = TPM2_MLDSA_87,
        .hashAlg = TPM2_ALG_SHA256,
    };
    TPMS_MLDSA_PARMS out = { 0 };
    TPMS_HASH_MLDSA_PARMS hash_out = { 0 };
    uint8_t            buffer[64] = { 0 };
    size_t             offset = 0;
    TSS2_RC            rc;

    rc = Tss2_MU_TPMS_MLDSA_PARMS_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_MLDSA_PARMS_Unmarshal(buffer, sizeof(buffer), &offset, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.parameterSet, TPM2_MLDSA_65);
    assert_int_equal(out.allowExternalMu, TPM2_YES);

    offset = 0;
    rc = Tss2_MU_TPMS_HASH_MLDSA_PARMS_Marshal(&hash_src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_HASH_MLDSA_PARMS_Unmarshal(buffer, sizeof(buffer), &offset, &hash_out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(hash_out.parameterSet, TPM2_MLDSA_87);
    assert_int_equal(hash_out.hashAlg, TPM2_ALG_SHA256);
}

static void
mu_mldsa_signature_union(void **state) {
    TPMU_SIGNATURE pure = { .mldsa = { .size = 2420 } };
    TPMU_SIGNATURE hash = {
        .hash_mldsa = {
            .hash = TPM2_ALG_SHA256,
            .signature = { .size = 2420 },
        },
    };
    TPMU_SIGNATURE pure_out = { 0 };
    TPMU_SIGNATURE hash_out = { 0 };
    uint8_t        buffer[4096] = { 0 };
    size_t         offset = 0;
    TSS2_RC        rc;

    fill_buffer(pure.mldsa.buffer, pure.mldsa.size, 0x01);
    fill_buffer(hash.hash_mldsa.signature.buffer, hash.hash_mldsa.signature.size, 0x02);

    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&pure, TPM2_ALG_MLDSA, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(buffer, sizeof(buffer), &offset, TPM2_ALG_MLDSA, &pure_out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(pure_out.mldsa.size, 2420);

    offset = 0;
    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&hash, TPM2_ALG_HASH_MLDSA, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(buffer, sizeof(buffer), &offset, TPM2_ALG_HASH_MLDSA,
                                          &hash_out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(hash_out.hash_mldsa.hash, TPM2_ALG_SHA256);
}

static void
mu_mldsa_public_parms_union(void **state) {
    TPMU_PUBLIC_PARMS mldsa = {
        .mldsaDetail = { .parameterSet = TPM2_MLDSA_44, .allowExternalMu = TPM2_NO },
    };
    TPMU_PUBLIC_PARMS hash = {
        .hash_mldsaDetail = { .parameterSet = TPM2_MLDSA_65, .hashAlg = TPM2_ALG_SHA384 },
    };
    TPMU_PUBLIC_PARMS out = { 0 };
    uint8_t           buffer[128] = { 0 };
    size_t            offset = 0;
    TSS2_RC           rc;

    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Marshal(&mldsa, TPM2_ALG_MLDSA, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Unmarshal(buffer, sizeof(buffer), &offset, TPM2_ALG_MLDSA,
                                               &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.mldsaDetail.parameterSet, TPM2_MLDSA_44);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Marshal(&hash, TPM2_ALG_HASH_MLDSA, buffer, sizeof(buffer),
                                           &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Unmarshal(buffer, sizeof(buffer), &offset, TPM2_ALG_HASH_MLDSA,
                                             &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.hash_mldsaDetail.hashAlg, TPM2_ALG_SHA384);
}

static void
mu_mldsa_public_id_shared_arm(void **state) {
    TPMU_PUBLIC_ID src = { .mldsa = { .size = 1312 } };
    TPMU_PUBLIC_ID out = { 0 };
    uint8_t        buffer[sizeof(TPM2B_PUBLIC_KEY_MLDSA)] = { 0 };
    size_t         offset = 0;
    TSS2_RC        rc;

    fill_buffer(src.mldsa.buffer, src.mldsa.size, 0x44);

    rc = Tss2_MU_TPMU_PUBLIC_ID_Marshal(&src, TPM2_ALG_HASH_MLDSA, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_ID_Unmarshal(buffer, sizeof(buffer), &offset, TPM2_ALG_MLDSA, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.mldsa.size, 1312);
}

static void
mu_mldsa_sig_scheme_empty(void **state) {
    TPMT_SIG_SCHEME src = { .scheme = TPM2_ALG_MLDSA };
    TPMT_SIG_SCHEME out = { 0 };
    uint8_t         buffer[16] = { 0 };
    size_t          offset = 0;
    TSS2_RC         rc;

    rc = Tss2_MU_TPMT_SIG_SCHEME_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, 2);

    offset = 0;
    rc = Tss2_MU_TPMT_SIG_SCHEME_Unmarshal(buffer, sizeof(buffer), &offset, &out);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(out.scheme, TPM2_ALG_MLDSA);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(mu_mldsa_pub_key_sizes),
        cmocka_unit_test(mu_mldsa_priv_seed),
        cmocka_unit_test(mu_mldsa_signature_max),
        cmocka_unit_test(mu_mldsa_signature_ctx_hint),
        cmocka_unit_test(mu_mldsa_hash_signature),
        cmocka_unit_test(mu_mldsa_parms),
        cmocka_unit_test(mu_mldsa_signature_union),
        cmocka_unit_test(mu_mldsa_public_parms_union),
        cmocka_unit_test(mu_mldsa_public_id_shared_arm),
        cmocka_unit_test(mu_mldsa_sig_scheme_empty),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
