/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026
 *
 * Unit tests for v1.83 / v184 marshal-unmarshal round-trips.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../helper/cmocka_all.h"
#include "tss2_common.h"
#include "tss2_mu.h"
#include "tss2_tpm2_types.h"

#define V183_BUF_SIZE 8192

static void
v183_spdm_session_info_roundtrip(void **state) {
    (void)state;
    TPMS_SPDM_SESSION_INFO src = { 0 };
    TPMS_SPDM_SESSION_INFO dest = { 0 };
    uint8_t              buf1[V183_BUF_SIZE] = { 0 };
    uint8_t              buf2[V183_BUF_SIZE] = { 0 };
    size_t               offset = 0;
    TSS2_RC              rc;

    src.reqKeyName.size = 4;
    memcpy(src.reqKeyName.name, "reqk", 4);
    src.tpmKeyName.size = 4;
    memcpy(src.tpmKeyName.name, "tpmk", 4);

    rc = Tss2_MU_TPMS_SPDM_SESSION_INFO_Marshal(&src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_SPDM_SESSION_INFO_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(dest.reqKeyName.size, src.reqKeyName.size);
    assert_memory_equal(dest.reqKeyName.name, src.reqKeyName.name, src.reqKeyName.size);
    assert_int_equal(dest.tpmKeyName.size, src.tpmKeyName.size);
    assert_memory_equal(dest.tpmKeyName.name, src.tpmKeyName.name, src.tpmKeyName.size);

    offset = 0;
    rc = Tss2_MU_TPMS_SPDM_SESSION_INFO_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
v183_nv_public_2_legacy_roundtrip(void **state) {
    (void)state;
    TPM2B_NV_PUBLIC_2 src = { 0 };
    TPM2B_NV_PUBLIC_2 dest = { 0 };
    uint8_t           buf1[V183_BUF_SIZE] = { 0 };
    uint8_t           buf2[V183_BUF_SIZE] = { 0 };
    size_t            offset = 0;
    TSS2_RC           rc;

    src.nvPublic.handleType = TPM2_HT_NV_INDEX;
    src.nvPublic.publicArea.nvIndex.nvIndex = 0x01800001;
    src.nvPublic.publicArea.nvIndex.nameAlg = TPM2_ALG_SHA256;
    src.nvPublic.publicArea.nvIndex.attributes = TPMA_NV_PPWRITE;
    src.nvPublic.publicArea.nvIndex.dataSize = 64;

    rc = Tss2_MU_TPM2B_NV_PUBLIC_2_Marshal(&src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPM2B_NV_PUBLIC_2_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(dest.nvPublic.handleType, TPM2_HT_NV_INDEX);
    assert_int_equal(dest.nvPublic.publicArea.nvIndex.nvIndex, src.nvPublic.publicArea.nvIndex.nvIndex);
    assert_int_equal(dest.nvPublic.publicArea.nvIndex.dataSize, 64);

    offset = 0;
    rc = Tss2_MU_TPM2B_NV_PUBLIC_2_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
v183_set_capability_data_roundtrip(void **state) {
    (void)state;
    TPM2B_SET_CAPABILITY_DATA src = { 0 };
    TPM2B_SET_CAPABILITY_DATA dest = { 0 };
    uint8_t                   buf1[V183_BUF_SIZE] = { 0 };
    uint8_t                   buf2[V183_BUF_SIZE] = { 0 };
    size_t                    offset = 0;
    TSS2_RC                   rc;

    src.setCapabilityData.setCapability = TPM2_CAP_TPM_PROPERTIES | 0x80000000;
    src.setCapabilityData.data.tpmProperty.property = TPM2_PT_MANUFACTURER;
    src.setCapabilityData.data.tpmProperty.value = 0x49465800;

    rc = Tss2_MU_TPM2B_SET_CAPABILITY_DATA_Marshal(&src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPM2B_SET_CAPABILITY_DATA_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(dest.setCapabilityData.setCapability, src.setCapabilityData.setCapability);
    assert_int_equal(dest.setCapabilityData.data.tpmProperty.property,
                     src.setCapabilityData.data.tpmProperty.property);
    assert_int_equal(dest.setCapabilityData.data.tpmProperty.value,
                     src.setCapabilityData.data.tpmProperty.value);

    offset = 0;
    rc = Tss2_MU_TPM2B_SET_CAPABILITY_DATA_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
v184_tpmu_capabilities_pubkeys_roundtrip(void **state) {
    (void)state;
    TPMU_CAPABILITIES src = { 0 };
    TPMU_CAPABILITIES dest = { 0 };
    uint8_t           buf1[V183_BUF_SIZE] = { 0 };
    uint8_t           buf2[V183_BUF_SIZE] = { 0 };
    size_t            offset = 0;
    TSS2_RC           rc;

    src.pubKeys.count = 0;

    rc = Tss2_MU_TPMU_CAPABILITIES_Marshal(&src, TPM2_CAP_PUB_KEYS, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_CAPABILITIES_Unmarshal(buf1, sizeof(buf1), &offset, TPM2_CAP_PUB_KEYS, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(dest.pubKeys.count, 0);

    offset = 0;
    rc = Tss2_MU_TPMU_CAPABILITIES_Marshal(&dest, TPM2_CAP_PUB_KEYS, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(v183_spdm_session_info_roundtrip),
        cmocka_unit_test(v183_nv_public_2_legacy_roundtrip),
        cmocka_unit_test(v183_set_capability_data_roundtrip),
        cmocka_unit_test(v184_tpmu_capabilities_pubkeys_roundtrip),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
