/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 *
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/sha.h>
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
test_fapi_key_create_mldsa(FAPI_CONTEXT *context)
{
    TSS2_RC  r;
    uint8_t *signature = NULL;
    size_t   signatureSize = 0;
    uint8_t  message[32];
    uint8_t  digest[TPM2_SHA256_DIGEST_SIZE];

    memset(message, 0x42, sizeof(message));
    SHA256(message, sizeof(message), digest);

    r = Fapi_Provision(context, NULL, PASSWORD, NULL);
    goto_if_error(r, "Error Fapi_Provision", error);

    r = Fapi_SetAuthCB(context, auth_callback, NULL);
    goto_if_error(r, "Error SetPolicyAuthCallback", error);

    r = Fapi_CreateKey(context, "HS/SRK/myMldsaSignKey", SIGN_TEMPLATE, "", PASSWORD);
    goto_if_error(r, "Error Fapi_CreateKey", error);

    r = Fapi_DigestAndSign(context, "HS/SRK/myMldsaSignKey", NULL, message, sizeof(message),
                           &signature, &signatureSize, NULL, NULL);
    goto_if_error(r, "Error Fapi_DigestAndSign", error);
    ASSERT(signature != NULL);
    ASSERT(signatureSize == PQC_MLDSA65_SIG_SIZE);

    r = Fapi_VerifySignature(context, "HS/SRK/myMldsaSignKey", digest, sizeof(digest), signature,
                             signatureSize);
    goto_if_error(r, "Error Fapi_VerifySignature", error);

    r = Fapi_Delete(context, "HS/SRK/myMldsaSignKey");
    goto_if_error(r, "Error Fapi_Delete", error);

    r = Fapi_Delete(context, "/");
    goto_if_error(r, "Error Fapi_Delete", error);

    SAFE_FREE(signature);
    return EXIT_SUCCESS;

error:
    Fapi_Delete(context, "/");
    SAFE_FREE(signature);
    return EXIT_FAILURE;
}

int
test_invoke_fapi(FAPI_CONTEXT *fapi_context)
{
    if (!pqc_esys_tpm_supports_alg(fapi_context->esys, TPM2_ALG_HASH_MLDSA)) {
        LOG_INFO("SKIP: HashML-DSA FAPI test requires v185 TPM (fwTPM)");
        return EXIT_SKIP;
    }

    return test_fapi_key_create_mldsa(fapi_context);
}
