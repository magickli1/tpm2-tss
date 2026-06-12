/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026
 *
 * Unit tests for PQC Sys API Prepare helpers (no TPM simulator).
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for calloc, free
#include <string.h> // for memset

#include "../helper/cmocka_all.h" // for assert_int_equal, cmocka_unit_test_setup_teardown
#include "sysapi_util.h"          // for _TSS2_SYS_CONTEXT_BLOB, InitSysContextFields
#include "tss2_common.h"          // for TSS2_RC_SUCCESS
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

#define MAX_SIZE_CTX 8192

/* Link-time stubs: Prepare tests never invoke CommonOneCall. */
TSS2_RC
Tss2_Sys_SetCmdAuths(TSS2_SYS_CONTEXT *sysContext, TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray) {
    (void)sysContext;
    (void)cmdAuthsArray;
    return TSS2_SYS_RC_BAD_SEQUENCE;
}

TSS2_RC
Tss2_Sys_Execute(TSS2_SYS_CONTEXT *sysContext) {
    (void)sysContext;
    return TSS2_SYS_RC_BAD_SEQUENCE;
}

TSS2_RC
Tss2_Sys_GetRspAuths(TSS2_SYS_CONTEXT *sysContext, TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {
    (void)sysContext;
    (void)rspAuthsArray;
    return TSS2_SYS_RC_BAD_SEQUENCE;
}

static int
sys_pqc_setup(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx;
    UINT32                 size_ctx;

    size_ctx = Tss2_Sys_GetContextSize(MAX_SIZE_CTX);
    sys_ctx = calloc(1, size_ctx);
    assert_non_null(sys_ctx);

    sys_ctx->cmdBuffer = (UINT8 *)(sys_ctx + sizeof(TSS2_SYS_CONTEXT_BLOB));
    InitSysContextFields(sys_ctx);
    InitSysContextPtrs(sys_ctx, size_ctx);

    *state = sys_ctx;
    return 0;
}

static int
sys_pqc_teardown(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = (TSS2_SYS_CONTEXT *)*state;

    if (sys_ctx)
        free(sys_ctx);

    return 0;
}

static void
sys_encapsulate_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_Encapsulate_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010001);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_Encapsulate);
    assert_int_equal(sys_ctx->decryptAllowed, 0);
    assert_int_equal(sys_ctx->encryptAllowed, 1);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_decapsulate_prepare_null_ciphertext(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_Decapsulate_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010001, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->decryptNull, 1);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
}

static void
sys_sign_digest_prepare_null_context(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_DIGEST           digest = { .size = 32 };
    TPMT_TK_HASHCHECK      validation = { .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL };
    TSS2_RC                rc;

    rc = Tss2_Sys_SignDigest_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, NULL, &digest,
                                   &validation);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_SignDigest);
    assert_int_equal(sys_ctx->decryptNull, 1);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->encryptAllowed, 0);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_sign_digest_prepare_bad_ref(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_DIGEST           digest = { .size = 32 };
    TSS2_RC                rc;

    rc = Tss2_Sys_SignDigest_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, NULL, &digest,
                                   NULL);
    assert_int_equal(rc, TSS2_SYS_RC_BAD_REFERENCE);
}

static void
sys_sign_sequence_start_prepare_null_auth(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_SignSequenceStart_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, NULL, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_SignSequenceStart);
    assert_int_equal(sys_ctx->decryptNull, 1);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->encryptAllowed, 0);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_verify_sequence_start_prepare_null_auth(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_VerifySequenceStart_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, NULL, NULL,
                                            NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_VerifySequenceStart);
    assert_int_equal(sys_ctx->decryptNull, 1);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->encryptAllowed, 0);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_sign_sequence_complete_prepare_null_buffer(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_SignSequenceComplete_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010003,
                                             0x81010002, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_SignSequenceComplete);
    assert_int_equal(sys_ctx->decryptNull, 1);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->encryptAllowed, 1);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_verify_digest_signature_prepare_null_context(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_DIGEST           digest = { .size = 32 };
    TPMT_SIGNATURE         signature = { .sigAlg = TPM2_ALG_MLDSA };
    TSS2_RC                rc;

    signature.signature.mldsa.size = TPM2_MLDSA_44_SIG_SIZE;
    memset(signature.signature.mldsa.buffer, 0xab, signature.signature.mldsa.size);

    rc = Tss2_Sys_VerifyDigestSignature_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, NULL,
                                              &digest, &signature);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_VerifyDigestSignature);
    assert_int_equal(sys_ctx->decryptNull, 1);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->encryptAllowed, 0);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_verify_digest_signature_prepare_bad_ref(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_DIGEST           digest = { .size = 32 };
    TSS2_RC                rc;

    rc = Tss2_Sys_VerifyDigestSignature_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, NULL,
                                              &digest, NULL);
    assert_int_equal(rc, TSS2_SYS_RC_BAD_REFERENCE);
}

static void
sys_verify_sequence_complete_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPMT_SIGNATURE         signature = { .sigAlg = TPM2_ALG_EDDSA };
    TSS2_RC                rc;

    signature.signature.eddsa.size = 64;
    memset(signature.signature.eddsa.buffer, 0xcd, signature.signature.eddsa.size);

    rc = Tss2_Sys_VerifySequenceComplete_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010003,
                                               0x81010002, &signature);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_VerifySequenceComplete);
    assert_int_equal(sys_ctx->decryptAllowed, 0);
    assert_int_equal(sys_ctx->encryptAllowed, 0);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_sign_digest_prepare_empty_context_size_zero(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_SIGNATURE_CTX      empty_ctx = { .size = 0 };
    TPM2B_DIGEST             digest = { .size = 32 };
    TPMT_TK_HASHCHECK        validation = { .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL };
    TSS2_RC                  rc;

    rc = Tss2_Sys_SignDigest_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, &empty_ctx, &digest,
                                     &validation);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->decryptNull, 1);
}

static void
sys_decapsulate_prepare_empty_ciphertext_size_zero(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_KEM_CIPHERTEXT     empty_ct = { .size = 0 };
    TSS2_RC                  rc;

    rc = Tss2_Sys_Decapsulate_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010001, &empty_ct);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->decryptNull, 1);
}

static void
sys_sign_sequence_start_nonempty_auth_null_context(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_AUTH               auth = { .size = 4, .buffer = { 1, 2, 3, 4 } };
    TSS2_RC                  rc;

    rc = Tss2_Sys_SignSequenceStart_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010002, &auth, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->decryptNull, 0);
}

static void
sys_verify_sequence_complete_prepare_bad_ref(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_VerifySequenceComplete_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010003,
                                                 0x81010002, NULL);
    assert_int_equal(rc, TSS2_SYS_RC_BAD_REFERENCE);
}

static void
sys_decapsulate_prepare_command_code(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_Decapsulate_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x81010001, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_Decapsulate);
    assert_int_equal(sys_ctx->decryptNull, 1);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->encryptAllowed, 1);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(sys_encapsulate_prepare_flags, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_decapsulate_prepare_null_ciphertext, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_decapsulate_prepare_command_code, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_sign_digest_prepare_null_context, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_sign_digest_prepare_bad_ref, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_sign_sequence_start_prepare_null_auth, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_verify_sequence_start_prepare_null_auth, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_sign_sequence_complete_prepare_null_buffer,
                                        sys_pqc_setup, sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_verify_digest_signature_prepare_null_context,
                                        sys_pqc_setup, sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_verify_digest_signature_prepare_bad_ref, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_verify_sequence_complete_prepare_flags, sys_pqc_setup,
                                        sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_sign_digest_prepare_empty_context_size_zero,
                                        sys_pqc_setup, sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_decapsulate_prepare_empty_ciphertext_size_zero,
                                        sys_pqc_setup, sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_sign_sequence_start_nonempty_auth_null_context,
                                        sys_pqc_setup, sys_pqc_teardown),
        cmocka_unit_test_setup_teardown(sys_verify_sequence_complete_prepare_bad_ref, sys_pqc_setup,
                                        sys_pqc_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
