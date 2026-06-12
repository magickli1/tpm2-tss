/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026
 *
 * Unit tests for v1.83 / v184 Sys API Prepare helpers (no TPM simulator).
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>
#include <string.h>

#include "../helper/cmocka_all.h"
#include "sysapi_util.h"
#include "tss2_common.h"
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

#define MAX_SIZE_CTX 8192

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
sys_v183_setup(void **state) {
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
sys_v183_teardown(void **state) {
    TSS2_SYS_CONTEXT *sys_ctx = (TSS2_SYS_CONTEXT *)*state;

    if (sys_ctx)
        free(sys_ctx);

    return 0;
}

static void
sys_policy_capability_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_OPERAND          operand = { .size = 4, .buffer = { 1, 2, 3, 4 } };
    TSS2_RC                rc;

    rc = Tss2_Sys_PolicyCapability_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x03000001, &operand, 0,
                                           TPM2_EO_EQ, TPM2_CAP_TPM_PROPERTIES,
                                           TPM2_PT_MANUFACTURER);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_PolicyCapability);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->authAllowed, 1);
}

static void
sys_policy_parameters_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_DIGEST           phash = { .size = TPM2_SHA256_DIGEST_SIZE };
    TSS2_RC                rc;

    rc = Tss2_Sys_PolicyParameters_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x03000001, &phash);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_PolicyParameters);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
}

static void
sys_nv_define_space2_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_NV_PUBLIC_2      pub = { 0 };
    TSS2_RC                rc;

    pub.nvPublic.handleType = TPM2_HT_NV_INDEX;
    pub.nvPublic.publicArea.nvIndex.nvIndex = 0x01800001;
    pub.nvPublic.publicArea.nvIndex.nameAlg = TPM2_ALG_SHA256;
    pub.nvPublic.publicArea.nvIndex.dataSize = 32;

    rc = Tss2_Sys_NV_DefineSpace2_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, TPM2_RH_OWNER, NULL, &pub);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_NV_DefineSpace2);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
    assert_int_equal(sys_ctx->decryptNull, 1);
}

static void
sys_nv_read_public2_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_NV_ReadPublic2_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x01800001);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_NV_ReadPublic2);
    assert_int_equal(sys_ctx->encryptAllowed, 1);
}

static void
sys_set_capability_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB    *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TPM2B_SET_CAPABILITY_DATA cap = { 0 };
    TSS2_RC                   rc;

    cap.setCapabilityData.setCapability = 0x80000006;
    cap.setCapabilityData.data.tpmProperty.property = TPM2_PT_MANUFACTURER;
    cap.setCapabilityData.data.tpmProperty.value = 0x49465800;

    rc = Tss2_Sys_SetCapability_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, TPM2_RH_OWNER, &cap);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_SetCapability);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
}

static void
sys_read_only_control_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_ReadOnlyControl_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, TPM2_RH_PLATFORM,
                                          TPM2_YES);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_ReadOnlyControl);
    assert_int_equal(sys_ctx->decryptAllowed, 0);
}

static void
sys_policy_transport_spdm_prepare_flags(void **state) {
    TSS2_SYS_CONTEXT_BLOB *sys_ctx = (TSS2_SYS_CONTEXT_BLOB *)*state;
    TSS2_RC                rc;

    rc = Tss2_Sys_PolicyTransportSPDM_Prepare((TSS2_SYS_CONTEXT *)sys_ctx, 0x03000001, NULL,
                                              NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(sys_ctx->commandCode, TPM2_CC_PolicyTransportSPDM);
    assert_int_equal(sys_ctx->decryptAllowed, 1);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(sys_policy_capability_prepare_flags, sys_v183_setup,
                                        sys_v183_teardown),
        cmocka_unit_test_setup_teardown(sys_policy_parameters_prepare_flags, sys_v183_setup,
                                        sys_v183_teardown),
        cmocka_unit_test_setup_teardown(sys_nv_define_space2_prepare_flags, sys_v183_setup,
                                        sys_v183_teardown),
        cmocka_unit_test_setup_teardown(sys_nv_read_public2_prepare_flags, sys_v183_setup,
                                        sys_v183_teardown),
        cmocka_unit_test_setup_teardown(sys_set_capability_prepare_flags, sys_v183_setup,
                                        sys_v183_teardown),
        cmocka_unit_test_setup_teardown(sys_read_only_control_prepare_flags, sys_v183_setup,
                                        sys_v183_teardown),
        cmocka_unit_test_setup_teardown(sys_policy_transport_spdm_prepare_flags, sys_v183_setup,
                                        sys_v183_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
