/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "pqc-fwtpm-helpers.h"
#include "test.h"
#include "tss2_sys.h"

#define LOGMODULE test
#include "util/log.h"

int
test_invoke(TSS2_SYS_CONTEXT *sys_context) {
    if (!pqc_sys_tpm_supports_alg(sys_context, TPM2_ALG_HASH_MLDSA)) {
        LOG_INFO("SKIP: SignDigest requires v185 TPM (fwTPM with TSS2_TEST_TCTI=mssim)");
        return PQC_EXIT_SKIP;
    }

    return pqc_sys_hash_mldsa_digest_roundtrip(sys_context);
}
