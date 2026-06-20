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
test_esys_sign_sequence(ESYS_CONTEXT *esys_context) {
    if (!pqc_esys_tpm_supports_alg(esys_context, TPM2_ALG_MLDSA)) {
        LOG_INFO("SKIP: SignSequence* requires v185 TPM (fwTPM with TSS2_TEST_TCTI=mssim)");
        return EXIT_SKIP;
    }

    return pqc_esys_mldsa_sequence_roundtrip(esys_context);
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_sign_sequence(esys_context);
}
