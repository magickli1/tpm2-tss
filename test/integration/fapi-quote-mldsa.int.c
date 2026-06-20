/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 *
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fapi_int.h"
#include "ifapi_macros.h"
#include "pqc-fwtpm-helpers.h"
#include "test-fapi.h"
#include "tss2_common.h"
#include "tss2_fapi.h"
#include "tss2_tpm2_types.h"

#define LOGMODULE test
#include "util/log.h"

#define PASSWORD      "abc"
#define SIGN_TEMPLATE "sign,noDa"

static TSS2_RC
auth_callback(char const *objectPath, char const *description, const char **auth, void *userData)
{
    UNUSED(objectPath);
    UNUSED(description);
    UNUSED(userData);

    *auth = PASSWORD;
    return TSS2_RC_SUCCESS;
}

static int
test_fapi_quote_mldsa(FAPI_CONTEXT *context)
{
    TSS2_RC  r;
    uint8_t *signature = NULL;
    size_t   signatureSize = 0;
    char    *quoteInfo = NULL;
    char    *pcrEventLog = NULL;
    char    *certificate = NULL;
    uint8_t  data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    uint32_t pcrList[1] = { 16 };
    uint8_t  qualifyingData[32] = { 0 };

    memset(qualifyingData, 0x11, sizeof(qualifyingData));

    r = Fapi_Provision(context, NULL, PASSWORD, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_SetAuthCB(context, auth_callback, NULL);
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    r = Fapi_CreateKey(context, "HS/SRK/myMldsaQuoteKey", SIGN_TEMPLATE, "", PASSWORD);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_PcrExtend(context, 16, data, sizeof(data), "{ \"test\": \"mldsa-quote\" }");
    goto_if_error(r, "Error Fapi_PcrExtend", error);

    r = Fapi_Quote(context, pcrList, 1, "HS/SRK/myMldsaQuoteKey", "TPM-Quote", qualifyingData,
                   sizeof(qualifyingData), &quoteInfo, &signature, &signatureSize, &pcrEventLog,
                   &certificate);
    goto_if_error(r, "Error Fapi_Quote", error);

    ASSERT(signature != NULL);
    ASSERT(quoteInfo != NULL);
    ASSERT(signatureSize == PQC_MLDSA65_SIG_SIZE);

    r = Fapi_VerifyQuote(context, "HS/SRK/myMldsaQuoteKey", qualifyingData, sizeof(qualifyingData),
                         quoteInfo, signature, signatureSize, pcrEventLog);
    goto_if_error(r, "Error Fapi_VerifyQuote", error);

    r = Fapi_Delete(context, "HS/SRK/myMldsaQuoteKey");
    goto_if_error(r, "Error Fapi_Delete", error);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    SAFE_FREE(signature);
    SAFE_FREE(quoteInfo);
    SAFE_FREE(pcrEventLog);
    SAFE_FREE(certificate);
    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    SAFE_FREE(signature);
    SAFE_FREE(quoteInfo);
    SAFE_FREE(pcrEventLog);
    SAFE_FREE(certificate);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    if (!pqc_esys_tpm_supports_alg(fapi_context->esys, TPM2_ALG_MLDSA)) {
        LOG_INFO("SKIP: ML-DSA Quote FAPI test requires v185 TPM (fwTPM)");
        return EXIT_SKIP;
    }

    return test_fapi_quote_mldsa(fapi_context);
}
