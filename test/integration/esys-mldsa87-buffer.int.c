/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "pqc-fwtpm-helpers.h"
#include "tss2_esys.h"

#define LOGMODULE test
#include "test-esys.h"
#include "util/log.h"

int
test_esys_mldsa87_buffer(ESYS_CONTEXT *esys_context) {
    TPMS_CAPABILITY_DATA *cap = NULL;
    TPMI_YES_NO           moreData = 0;
    TSS2_RC               r;
    UINT32                ml_sets = 0;
    int                   i;

    if (!pqc_esys_tpm_supports_alg(esys_context, TPM2_ALG_MLDSA)) {
        LOG_INFO("SKIP: ML-DSA-87 buffer test requires v185 TPM (fwTPM with TSS2_TEST_TCTI=mssim)");
        return EXIT_SKIP;
    }

    r = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_TPM_PROPERTIES, TPM2_PT_ML_PARAMETER_SETS, 1, &moreData,
                           &cap);
    if (r != TSS2_RC_SUCCESS || cap == NULL) {
        LOG_INFO("SKIP: TPM2_PT_ML_PARAMETER_SETS unavailable");
        Esys_Free(cap);
        return EXIT_SKIP;
    }

    for (i = 0; i < (int)cap->data.tpmProperties.count; i++) {
        if (cap->data.tpmProperties.tpmProperty[i].property == TPM2_PT_ML_PARAMETER_SETS) {
            ml_sets = cap->data.tpmProperties.tpmProperty[i].value;
            break;
        }
    }
    Esys_Free(cap);

    if (!(ml_sets & TPMA_ML_PARAMETER_SET_MLDSA_87)) {
        LOG_INFO("SKIP: TPM does not advertise ML-DSA-87 parameter set");
        return EXIT_SKIP;
    }

    return pqc_esys_mldsa87_buffer_roundtrip(esys_context);
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_mldsa87_buffer(esys_context);
}
