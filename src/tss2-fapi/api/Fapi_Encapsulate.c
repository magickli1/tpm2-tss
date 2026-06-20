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
#include <string.h>

#include <openssl/crypto.h> // for OPENSSL_cleanse

#include "fapi_int.h"
#include "fapi_util.h"
#include "ifapi_io.h"
#include "ifapi_macros.h"
#include "ifapi_profiles.h"
#include "tss2_common.h"
#include "tss2_esys.h"
#include "tss2_fapi.h"
#include "tss2_tcti.h"
#include "tss2_tpm2_types.h"

#define LOGMODULE fapi
#include "util/log.h"

#ifndef MAX_KEM_CIPHERTEXT_SIZE
#define MAX_KEM_CIPHERTEXT_SIZE 2048
#endif

static TSS2_RC
fapi_kem_async(FAPI_CONTEXT  *context,
               char const    *keyPath,
               uint8_t const *cipherText,
               size_t         cipherTextSize,
               bool           decapsulate)
{
    TSS2_RC    r;
    IFAPI_Kem *command = &context->kem;

    check_not_null(context);
    check_not_null(keyPath);
    if (decapsulate) {
        check_not_null(cipherText);
        check_in_bounds(cipherTextSize, MAX_KEM_CIPHERTEXT_SIZE);
    }

    memset(&context->cmd, 0, sizeof(IFAPI_CMD_STATE));
    memset(command, 0, sizeof(*command));

    r = ifapi_session_init(context);
    return_if_error(r, "Initialize KEM");

    command->decapsulate = decapsulate;
    command->key_handle = ESYS_TR_NONE;
    strdup_check(command->keyPath, keyPath, r, error_cleanup);

    if (decapsulate) {
        uint8_t *inData = malloc(cipherTextSize);

        goto_if_null2(inData, "Out of memory", r, TSS2_FAPI_RC_MEMORY, error_cleanup);
        memcpy(inData, cipherText, cipherTextSize);
        command->ciphertext = inData;
        command->ciphertextSize = cipherTextSize;
    }

    context->state = KEM_WAIT_FOR_PROFILE;
    return TSS2_RC_SUCCESS;

error_cleanup:
    SAFE_FREE(command->keyPath);
    SAFE_FREE(command->ciphertext);
    return r;
}

static TSS2_RC
fapi_kem_finish(FAPI_CONTEXT *context,
                uint8_t     **sharedSecret,
                size_t       *sharedSecretSize,
                uint8_t     **cipherText,
                size_t       *cipherTextSize)
{
    TSS2_RC                 r;
    IFAPI_Kem              *command = &context->kem;
    TPM2B_SHARED_SECRET    *tpm_shared_secret = NULL;
    TPM2B_KEM_CIPHERTEXT   *tpm_ciphertext = NULL;
    TPM2B_KEM_CIPHERTEXT    kem_input = { 0 };

    check_not_null(context);
    check_not_null(sharedSecret);

    switch (context->state) {
    statecase(context->state, KEM_WAIT_FOR_PROFILE);
        r = ifapi_profiles_get(&context->profiles, command->keyPath, &command->profile);
        return_try_again(r);
        goto_if_error_reset_state(r, "Get profile", error_cleanup);

        r = ifapi_get_sessions_async(context, IFAPI_SESSION_GEN_SRK | IFAPI_SESSION1, 0, 0);
        goto_if_error_reset_state(r, "Create sessions", error_cleanup);
        fallthrough;

    statecase(context->state, KEM_WAIT_FOR_SESSION);
        r = ifapi_get_sessions_finish(context, &context->profiles.default_profile,
                                      context->profiles.default_profile.nameAlg);
        return_try_again(r);
        goto_if_error_reset_state(r, "Create session", error_cleanup);

        r = ifapi_load_keys_async(context, command->keyPath);
        goto_if_error(r, "Load keys", error_cleanup);
        fallthrough;

    statecase(context->state, KEM_WAIT_FOR_KEY);
        r = ifapi_load_keys_finish(context, IFAPI_FLUSH_PARENT, &command->key_handle,
                                   &command->key_object);
        return_try_again(r);
        goto_if_error_reset_state(r, "Load key", error_cleanup);

        if (command->key_object->misc.key.public.publicArea.type != TPM2_ALG_MLKEM) {
            goto_error(r, TSS2_FAPI_RC_BAD_VALUE, "Key is not an ML-KEM key", error_cleanup);
        }
        fallthrough;

    statecase(context->state, KEM_AUTHORIZE_KEY);
        r = ifapi_authorize_object(context, command->key_object, &command->auth_session);
        return_try_again(r);
        goto_if_error(r, "Authorize key", error_cleanup);

        if (command->decapsulate) {
            kem_input.size = command->ciphertextSize;
            memcpy(kem_input.buffer, command->ciphertext, command->ciphertextSize);
            r = Esys_Decapsulate_Async(context->esys, command->key_handle, command->auth_session,
                                       ENC_SESSION_IF_POLICY(command->auth_session), ESYS_TR_NONE,
                                       &kem_input);
            goto_if_error(r, "Decapsulate async", error_cleanup);
            context->state = KEM_WAIT_FOR_DECAPSULATE;
        } else {
            r = Esys_Encapsulate_Async(context->esys, command->key_handle, command->auth_session,
                                       ENC_SESSION_IF_POLICY(command->auth_session),
                                       ESYS_TR_NONE);
            goto_if_error(r, "Encapsulate async", error_cleanup);
            context->state = KEM_WAIT_FOR_ENCAPSULATE;
        }
        return TSS2_FAPI_RC_TRY_AGAIN;

    statecase(context->state, KEM_WAIT_FOR_ENCAPSULATE);
        r = Esys_Encapsulate_Finish(context->esys, &tpm_shared_secret, &tpm_ciphertext);
        return_try_again(r);
        goto_if_error_reset_state(r, "Encapsulate finish", error_cleanup);
        goto kem_store_output;

    statecase(context->state, KEM_WAIT_FOR_DECAPSULATE);
        r = Esys_Decapsulate_Finish(context->esys, &tpm_shared_secret);
        return_try_again(r);
        goto_if_error_reset_state(r, "Decapsulate finish", error_cleanup);

    kem_store_output:
        command->sharedSecret = malloc(tpm_shared_secret->size);
        goto_if_null2(command->sharedSecret, "Out of memory", r, TSS2_FAPI_RC_MEMORY, error_cleanup);
        command->sharedSecretSize = tpm_shared_secret->size;
        memcpy(command->sharedSecret, tpm_shared_secret->buffer, tpm_shared_secret->size);
        OPENSSL_cleanse(tpm_shared_secret->buffer, sizeof(tpm_shared_secret->buffer));
        Esys_Free(tpm_shared_secret);
        tpm_shared_secret = NULL;

        if (tpm_ciphertext) {
            command->out_ciphertext = malloc(tpm_ciphertext->size);
            goto_if_null2(command->out_ciphertext, "Out of memory", r, TSS2_FAPI_RC_MEMORY,
                          error_cleanup);
            command->out_ciphertextSize = tpm_ciphertext->size;
            memcpy(command->out_ciphertext, tpm_ciphertext->buffer, tpm_ciphertext->size);
            Esys_Free(tpm_ciphertext);
            tpm_ciphertext = NULL;
        }

        if (!command->key_object->misc.key.persistent_handle) {
            r = Esys_FlushContext_Async(context->esys, command->key_handle);
            goto_if_error(r, "FlushContext", error_cleanup);
        }
        context->state = KEM_WAIT_FOR_FLUSH;
        return TSS2_FAPI_RC_TRY_AGAIN;

    statecase(context->state, KEM_WAIT_FOR_FLUSH);
        if (!command->key_object->misc.key.persistent_handle) {
            r = Esys_FlushContext_Finish(context->esys);
            return_try_again(r);
            goto_if_error(r, "FlushContext", error_cleanup);
        }
        command->key_handle = ESYS_TR_NONE;
        fallthrough;

    statecase(context->state, KEM_CLEANUP);
        r = ifapi_cleanup_session(context);
        try_again_or_error_goto(r, "Cleanup", error_cleanup);

        *sharedSecret = command->sharedSecret;
        if (sharedSecretSize)
            *sharedSecretSize = command->sharedSecretSize;
        if (cipherText)
            *cipherText = command->out_ciphertext;
        if (cipherTextSize)
            *cipherTextSize = command->out_ciphertextSize;
        command->sharedSecret = NULL;
        command->out_ciphertext = NULL;
        break;

    statecasedefault(context->state);
    }

    context->state = FAPI_STATE_INIT;
    return TSS2_RC_SUCCESS;

error_cleanup:
    Esys_Free(tpm_shared_secret);
    Esys_Free(tpm_ciphertext);
    if (command->key_handle != ESYS_TR_NONE && command->key_object
        && !command->key_object->misc.key.persistent_handle)
        Esys_FlushContext(context->esys, command->key_handle);
    if (command->sharedSecret)
        OPENSSL_cleanse(command->sharedSecret, command->sharedSecretSize);
    SAFE_FREE(command->sharedSecret);
    SAFE_FREE(command->out_ciphertext);
    SAFE_FREE(command->ciphertext);
    SAFE_FREE(command->keyPath);
    ifapi_session_clean(context);
    ifapi_cleanup_ifapi_object(&context->loadKey.auth_object);
    ifapi_cleanup_ifapi_object(context->loadKey.key_object);
    ifapi_cleanup_ifapi_object(&context->createPrimary.pkey_object);
    ifapi_cleanup_ifapi_object(command->key_object);
    context->state = FAPI_STATE_INIT;
    return r;
}

TSS2_RC
Fapi_Encapsulate(FAPI_CONTEXT  *context,
                 char const    *keyPath,
                 uint8_t      **sharedSecret,
                 size_t        *sharedSecretSize,
                 uint8_t      **cipherText,
                 size_t        *cipherTextSize)
{
    TSS2_RC r, r2;

    check_not_null(context);
    check_not_null(sharedSecret);
    check_not_null(cipherText);
    return_if_null(context->esys, "Command can't be executed in none TPM mode.",
                   TSS2_FAPI_RC_NO_TPM);

#ifndef TEST_FAPI_ASYNC
    r = Esys_SetTimeout(context->esys, TSS2_TCTI_TIMEOUT_BLOCK);
    return_if_error_reset_state(r, "Set Timeout to blocking");
#endif

    r = Fapi_Encapsulate_Async(context, keyPath);
    return_if_error_reset_state(r, "Encapsulate");

    do {
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");
        r = Fapi_Encapsulate_Finish(context, sharedSecret, sharedSecretSize, cipherText,
                                    cipherTextSize);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    return_if_error(r, "Encapsulate");

    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return TSS2_RC_SUCCESS;
}

TSS2_RC
Fapi_Encapsulate_Async(FAPI_CONTEXT *context, char const *keyPath)
{
    return fapi_kem_async(context, keyPath, NULL, 0, false);
}

TSS2_RC
Fapi_Encapsulate_Finish(FAPI_CONTEXT *context,
                        uint8_t     **sharedSecret,
                        size_t       *sharedSecretSize,
                        uint8_t     **cipherText,
                        size_t       *cipherTextSize)
{
    return fapi_kem_finish(context, sharedSecret, sharedSecretSize, cipherText, cipherTextSize);
}

TSS2_RC
Fapi_Decapsulate(FAPI_CONTEXT  *context,
                 char const    *keyPath,
                 uint8_t const *cipherText,
                 size_t         cipherTextSize,
                 uint8_t      **sharedSecret,
                 size_t        *sharedSecretSize)
{
    TSS2_RC r, r2;

    check_not_null(context);
    check_not_null(sharedSecret);
    return_if_null(context->esys, "Command can't be executed in none TPM mode.",
                   TSS2_FAPI_RC_NO_TPM);

#ifndef TEST_FAPI_ASYNC
    r = Esys_SetTimeout(context->esys, TSS2_TCTI_TIMEOUT_BLOCK);
    return_if_error_reset_state(r, "Set Timeout to blocking");
#endif

    r = Fapi_Decapsulate_Async(context, keyPath, cipherText, cipherTextSize);
    return_if_error_reset_state(r, "Decapsulate");

    do {
        r = ifapi_io_poll(&context->io);
        return_if_error(r, "Something went wrong with IO polling");
        r = Fapi_Decapsulate_Finish(context, sharedSecret, sharedSecretSize);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    return_if_error(r, "Decapsulate");

    r2 = Esys_SetTimeout(context->esys, 0);
    return_if_error(r2, "Set Timeout to non-blocking");

    return TSS2_RC_SUCCESS;
}

TSS2_RC
Fapi_Decapsulate_Async(FAPI_CONTEXT  *context,
                       char const    *keyPath,
                       uint8_t const *cipherText,
                       size_t         cipherTextSize)
{
    return fapi_kem_async(context, keyPath, cipherText, cipherTextSize, true);
}

TSS2_RC
Fapi_Decapsulate_Finish(FAPI_CONTEXT *context,
                        uint8_t     **sharedSecret,
                        size_t       *sharedSecretSize)
{
    return fapi_kem_finish(context, sharedSecret, sharedSecretSize, NULL, NULL);
}
