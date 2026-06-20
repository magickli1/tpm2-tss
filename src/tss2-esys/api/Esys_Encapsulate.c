/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>
#include <stdlib.h>

#include "esys_int.h"
#include "esys_iutil.h"
#include "esys_types.h"
#include "tss2_common.h"
#include "tss2_esys.h"
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

#define LOGMODULE esys
#include "util/log.h"

TSS2_RC
Esys_Encapsulate(ESYS_CONTEXT            *esysContext,
                 ESYS_TR                  keyHandle,
                 ESYS_TR                  shandle1,
                 ESYS_TR                  shandle2,
                 ESYS_TR                  shandle3,
                 TPM2B_SHARED_SECRET     **sharedSecret,
                 TPM2B_KEM_CIPHERTEXT    **ciphertext) {
    TSS2_RC r;

    r = Esys_Encapsulate_Async(esysContext, keyHandle, shandle1, shandle2, shandle3);
    return_if_error(r, "Error in async function");

    int32_t timeouttmp = esysContext->timeout;
    esysContext->timeout = -1;
    do {
        r = Esys_Encapsulate_Finish(esysContext, sharedSecret, ciphertext);
        if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN)
            LOG_DEBUG("A layer below returned TRY_AGAIN: %" PRIx32 " => resubmitting command", r);
    } while (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN);

    esysContext->timeout = timeouttmp;
    return_if_error(r, "Esys Finish");

    return TSS2_RC_SUCCESS;
}

TSS2_RC
Esys_Encapsulate_Async(ESYS_CONTEXT *esysContext,
                       ESYS_TR       keyHandle,
                       ESYS_TR       shandle1,
                       ESYS_TR       shandle2,
                       ESYS_TR       shandle3) {
    TSS2_RC                r;
    TSS2L_SYS_AUTH_COMMAND auths;
    RSRC_NODE_T           *keyHandleNode;

    if (esysContext == NULL)
        return TSS2_ESYS_RC_BAD_REFERENCE;
    r = iesys_check_sequence_async(esysContext);
    if (r != TSS2_RC_SUCCESS)
        return r;
    esysContext->state = ESYS_STATE_INTERNALERROR;

    r = check_session_feasibility(shandle1, shandle2, shandle3, 0);
    return_state_if_error(r, ESYS_STATE_INIT, "Check session usage");

    r = esys_GetResourceObject(esysContext, keyHandle, &keyHandleNode);
    return_state_if_error(r, ESYS_STATE_INIT, "keyHandle unknown.");

    r = Tss2_Sys_Encapsulate_Prepare(esysContext->sys,
                                     (keyHandleNode == NULL) ? TPM2_RH_NULL : keyHandleNode->rsrc.handle);
    return_state_if_error(r, ESYS_STATE_INIT, "SAPI Prepare returned error.");

    r = init_session_tab(esysContext, shandle1, shandle2, shandle3);
    return_state_if_error(r, ESYS_STATE_INIT, "Initialize session resources");
    if (keyHandleNode != NULL)
        iesys_compute_session_value(esysContext->session_tab[0], &keyHandleNode->rsrc.name,
                                    &keyHandleNode->auth);
    else
        iesys_compute_session_value(esysContext->session_tab[0], NULL, NULL);

    iesys_compute_session_value(esysContext->session_tab[1], NULL, NULL);
    iesys_compute_session_value(esysContext->session_tab[2], NULL, NULL);

    r = iesys_gen_auths(esysContext, keyHandleNode, NULL, NULL, &auths);
    return_state_if_error(r, ESYS_STATE_INIT, "Error in computation of auth values");

    esysContext->authsCount = auths.count;
    if (auths.count > 0) {
        r = Tss2_Sys_SetCmdAuths(esysContext->sys, &auths);
        return_state_if_error(r, ESYS_STATE_INIT, "SAPI error on SetCmdAuths");
    }

    r = Tss2_Sys_ExecuteAsync(esysContext->sys);
    return_state_if_error(r, ESYS_STATE_INTERNALERROR, "Finish (Execute Async)");

    esysContext->state = ESYS_STATE_SENT;
    return r;
}

TSS2_RC
Esys_Encapsulate_Finish(ESYS_CONTEXT         *esysContext,
                        TPM2B_SHARED_SECRET **sharedSecret,
                        TPM2B_KEM_CIPHERTEXT **ciphertext) {
    TSS2_RC r;

    if (esysContext == NULL)
        return TSS2_ESYS_RC_BAD_REFERENCE;

    if (esysContext->state != ESYS_STATE_SENT && esysContext->state != ESYS_STATE_RESUBMISSION) {
        LOG_ERROR("Esys called in bad sequence.");
        return TSS2_ESYS_RC_BAD_SEQUENCE;
    }
    esysContext->state = ESYS_STATE_INTERNALERROR;

    if (sharedSecret != NULL) {
        *sharedSecret = calloc(1, sizeof(TPM2B_SHARED_SECRET));
        if (*sharedSecret == NULL)
            return_error(TSS2_ESYS_RC_MEMORY, "Out of memory");
    }
    if (ciphertext != NULL) {
        *ciphertext = calloc(1, sizeof(TPM2B_KEM_CIPHERTEXT));
        if (*ciphertext == NULL) {
            if (sharedSecret != NULL)
                SAFE_FREE(*sharedSecret);
            return_error(TSS2_ESYS_RC_MEMORY, "Out of memory");
        }
    }

    r = Tss2_Sys_ExecuteFinish(esysContext->sys, esysContext->timeout);
    if (base_rc(r) == TSS2_BASE_RC_TRY_AGAIN) {
        esysContext->state = ESYS_STATE_SENT;
        goto error_cleanup;
    }
    if (r == TPM2_RC_RETRY || r == TPM2_RC_TESTING || r == TPM2_RC_YIELDED) {
        if (esysContext->submissionCount++ >= ESYS_MAX_SUBMISSIONS) {
            esysContext->state = ESYS_STATE_INIT;
            goto error_cleanup;
        }
        esysContext->state = ESYS_STATE_RESUBMISSION;
        r = Tss2_Sys_ExecuteAsync(esysContext->sys);
        if (r != TSS2_RC_SUCCESS)
            goto error_cleanup;
        r = TSS2_ESYS_RC_TRY_AGAIN;
        goto error_cleanup;
    }
    if (iesys_tpm_error(r)) {
        esysContext->state = ESYS_STATE_INIT;
        goto error_cleanup;
    } else if (r != TSS2_RC_SUCCESS) {
        esysContext->state = ESYS_STATE_INTERNALERROR;
        goto error_cleanup;
    }

    r = iesys_check_response(esysContext);
    goto_state_if_error(r, ESYS_STATE_INTERNALERROR, "Error: check response", error_cleanup);

    r = Tss2_Sys_Encapsulate_Complete(esysContext->sys,
                                      (sharedSecret != NULL) ? *sharedSecret : NULL,
                                      (ciphertext != NULL) ? *ciphertext : NULL);
    goto_state_if_error(r, ESYS_STATE_INTERNALERROR, "Received error from SAPI unmarshaling",
                        error_cleanup);

    esysContext->state = ESYS_STATE_INIT;
    return TSS2_RC_SUCCESS;

error_cleanup:
    if (sharedSecret != NULL)
        SAFE_FREE(*sharedSecret);
    if (ciphertext != NULL)
        SAFE_FREE(*ciphertext);
    return r;
}
