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

#define PASSWORD       "abc"
#define KEM_TEMPLATE   "decrypt,noDa"

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
test_fapi_key_create_mlkem(FAPI_CONTEXT *context)
{
    TSS2_RC  r;
    uint8_t *sharedSecret1 = NULL;
    uint8_t *sharedSecret2 = NULL;
    uint8_t *ciphertext = NULL;
    size_t   sharedSecret1Size = 0;
    size_t   sharedSecret2Size = 0;
    size_t   ciphertextSize = 0;

    r = Fapi_Provision(context, NULL, PASSWORD, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_SetAuthCB(context, auth_callback, NULL);
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    r = Fapi_CreateKey(context, "HS/SRK/myMlkemKey", KEM_TEMPLATE, "", PASSWORD);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_Encapsulate(context, "HS/SRK/myMlkemKey", &sharedSecret1, &sharedSecret1Size,
                         &ciphertext, &ciphertextSize);
    goto_if_error(r, "Error Fapi_Encapsulate", error);
    ASSERT(sharedSecret1 != NULL);
    ASSERT(ciphertext != NULL);
    ASSERT(sharedSecret1Size == PQC_MLKEM768_SS_SIZE);
    ASSERT(ciphertextSize == PQC_MLKEM768_CT_SIZE);

    r = Fapi_Decapsulate(context, "HS/SRK/myMlkemKey", ciphertext, ciphertextSize, &sharedSecret2,
                         &sharedSecret2Size);
    goto_if_error(r, "Error Fapi_Decapsulate", error);
    ASSERT(sharedSecret2 != NULL);
    ASSERT(sharedSecret2Size == PQC_MLKEM768_SS_SIZE);
    ASSERT(memcmp(sharedSecret1, sharedSecret2, sharedSecret1Size) == 0);

    r = Fapi_Delete(context, "HS/SRK/myMlkemKey");
    goto_if_error(r, "Error Fapi_Delete", error);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    SAFE_FREE(sharedSecret1);
    SAFE_FREE(sharedSecret2);
    SAFE_FREE(ciphertext);
    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    SAFE_FREE(sharedSecret1);
    SAFE_FREE(sharedSecret2);
    SAFE_FREE(ciphertext);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    if (!pqc_esys_tpm_supports_alg(fapi_context->esys, TPM2_ALG_MLKEM)) {
        LOG_INFO("SKIP: ML-KEM FAPI test requires v185 TPM (fwTPM)");
        return EXIT_SKIP;
    }

    return test_fapi_key_create_mlkem(fapi_context);
}
