/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 * All rights reserved.
 ******************************************************************************/

#ifndef PQC_FWTPM_HELPERS_H
#define PQC_FWTPM_HELPERS_H

#include "tss2_common.h"
#include "tss2_esys.h"
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

#define PQC_EXIT_SKIP 77

#define PQC_MLKEM768_CT_SIZE   1088
#define PQC_MLKEM768_SS_SIZE   32
#define PQC_MLDSA65_SIG_SIZE   3309
#define PQC_MLDSA87_SIG_SIZE   4627

#define PQC_OBJECT_ATTRS_COMMON                                                                  \
    (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |                 \
     TPMA_OBJECT_SENSITIVEDATAORIGIN)

#define PQC_EXPECTED_ML_PARAM_SETS                                                                 \
    (TPMA_ML_PARAMETER_SET_MLKEM_768 | TPMA_ML_PARAMETER_SET_MLDSA_65)

int pqc_esys_tpm_supports_alg(ESYS_CONTEXT *esys_context, TPM2_ALG_ID alg);
int pqc_esys_tpm_supports_v185(ESYS_CONTEXT *esys_context);
int pqc_esys_getcap_ml_parameter_sets(ESYS_CONTEXT *esys_context);
int pqc_esys_deprecated_sign_roundtrip(ESYS_CONTEXT *esys_context);
int pqc_sys_tpm_supports_alg(TSS2_SYS_CONTEXT *sys_context, TPM2_ALG_ID alg);

int pqc_esys_mlkem_roundtrip(ESYS_CONTEXT *esys_context);
int pqc_esys_hash_mldsa_digest_roundtrip(ESYS_CONTEXT *esys_context);
int pqc_esys_mldsa_sequence_roundtrip(ESYS_CONTEXT *esys_context);
int pqc_sys_mlkem_roundtrip(TSS2_SYS_CONTEXT *sys_context);
int pqc_sys_hash_mldsa_digest_roundtrip(TSS2_SYS_CONTEXT *sys_context);
int pqc_sys_mldsa_sequence_roundtrip(TSS2_SYS_CONTEXT *sys_context);
int pqc_esys_mldsa87_buffer_roundtrip(ESYS_CONTEXT *esys_context);
int pqc_esys_mldsa_quote_roundtrip(ESYS_CONTEXT *esys_context);
int pqc_esys_mlkem_session_roundtrip(ESYS_CONTEXT *esys_context);

#endif /* PQC_FWTPM_HELPERS_H */
