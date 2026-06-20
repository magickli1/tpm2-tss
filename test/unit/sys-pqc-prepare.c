/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>

#include "../helper/cmocka_all.h"
#include "sysapi_util.h"
#include "tss2_common.h"
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

#define MAX_SIZE_CTX 8192

static TSS2_SYS_CONTEXT *
alloc_sys_ctx(void) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx;
    UINT32                 size_ctx = Tss2_Sys_GetContextSize(MAX_SIZE_CTX);

    sys_ctx = calloc(1, size_ctx);
    if (sys_ctx == NULL)
        return NULL;
    InitSysContextFields(sys_ctx);
    InitSysContextPtrs(sys_ctx, size_ctx);
    sys_ctx->previousStage = CMD_STAGE_INITIALIZE;
    return (TSS2_SYS_CONTEXT *)sys_ctx;
}

static void
encapsulate_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = alloc_sys_ctx();
    TSS2_RC             rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_Encapsulate_Prepare(sys_ctx, 0x81010001);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

static void
decapsulate_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT    *sys_ctx = alloc_sys_ctx();
    TPM2B_KEM_CIPHERTEXT ct = { .size = 4, .buffer = { 1, 2, 3, 4 } };
    TSS2_RC               rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_Decapsulate_Prepare(sys_ctx, 0x81010001, &ct);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

static void
sign_digest_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = alloc_sys_ctx();
    TPM2B_DIGEST      digest = { .size = 32 };
    TPMT_TK_HASHCHECK validation = { 0 };
    TSS2_RC           rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_SignDigest_Prepare(sys_ctx, 0x81010002, NULL, &digest, &validation);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

static void
sign_sequence_start_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = alloc_sys_ctx();
    TSS2_RC           rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_SignSequenceStart_Prepare(sys_ctx, 0x81010002, NULL, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

static void
verify_sequence_start_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = alloc_sys_ctx();
    TSS2_RC           rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_VerifySequenceStart_Prepare(sys_ctx, 0x81010002, NULL, NULL, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

static void
sign_sequence_complete_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = alloc_sys_ctx();
    TPM2B_MAX_BUFFER   buffer = { .size = 8, .buffer = { 'm', 'e', 's', 's', 'a', 'g', 'e', 0 } };
    TSS2_RC            rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_SignSequenceComplete_Prepare(sys_ctx, 0x81000001, 0x81010002, &buffer);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

static void
verify_digest_signature_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = alloc_sys_ctx();
    TPM2B_DIGEST      digest = { .size = 32 };
    TPMT_SIGNATURE    signature = { .sigAlg = TPM2_ALG_NULL };
    TSS2_RC           rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_VerifyDigestSignature_Prepare(sys_ctx, 0x81010002, NULL, &digest, &signature);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

static void
verify_sequence_complete_prepare_unit(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = alloc_sys_ctx();
    TPMT_SIGNATURE    signature = { .sigAlg = TPM2_ALG_NULL };
    TSS2_RC           rc;

    (void)state;
    assert_non_null(sys_ctx);
    rc = Tss2_Sys_VerifySequenceComplete_Prepare(sys_ctx, 0x81000001, 0x81010002, &signature);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    free(sys_ctx);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(encapsulate_prepare_unit),
        cmocka_unit_test(decapsulate_prepare_unit),
        cmocka_unit_test(sign_digest_prepare_unit),
        cmocka_unit_test(sign_sequence_start_prepare_unit),
        cmocka_unit_test(verify_sequence_start_prepare_unit),
        cmocka_unit_test(sign_sequence_complete_prepare_unit),
        cmocka_unit_test(verify_digest_signature_prepare_unit),
        cmocka_unit_test(verify_sequence_complete_prepare_unit),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
