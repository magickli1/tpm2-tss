/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"     // for _TSS2_SYS_CONTEXT_BLOB, syscontext_cast
#include "tss2_common.h"     // for TSS2_RC, TSS2_SYS_RC_BAD_REFERENCE
#include "tss2_mu.h"         // for Tss2_MU_TPM2B_DIGEST_Marshal, Tss2_MU_T...
#include "tss2_sys.h"        // for TSS2_SYS_CONTEXT, TSS2L_SYS_AUTH_COMMAND
#include "tss2_tpm2_types.h" // for TPM2B_DIGEST, TPM2B_SIGNATURE_CTX, TPMI...

TSS2_RC
Tss2_Sys_SignDigest_Prepare(TSS2_SYS_CONTEXT          *sysContext,
                            TPMI_DH_OBJECT             keyHandle,
                            const TPM2B_SIGNATURE_CTX *context,
                            const TPM2B_DIGEST        *digest,
                            const TPMT_TK_HASHCHECK   *validation) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx || !validation)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_SignDigest);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    TPM2B_SIGNATURE_CTX empty_ctx = { .size = 0 };
    const TPM2B_SIGNATURE_CTX *context_in = context ? context : &empty_ctx;

    if (!context || context->size == 0)
        ctx->decryptNull = 1;

    rval = Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(context_in, ctx->cmdBuffer, ctx->maxCmdSize,
                                               &ctx->nextData);
    if (rval)
        return rval;

    TPM2B_DIGEST empty_digest = { .size = 0 };
    const TPM2B_DIGEST *digest_in = digest ? digest : &empty_digest;

    rval = Tss2_MU_TPM2B_DIGEST_Marshal(digest_in, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);

    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_TK_HASHCHECK_Marshal(validation, ctx->cmdBuffer, ctx->maxCmdSize,
                                             &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_SignDigest_Complete(TSS2_SYS_CONTEXT *sysContext, TPMT_SIGNATURE *signature) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_TPMT_SIGNATURE_Unmarshal(ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData,
                                            signature);
}

TSS2_RC
Tss2_Sys_SignDigest(TSS2_SYS_CONTEXT             *sysContext,
                    TPMI_DH_OBJECT                keyHandle,
                    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                    const TPM2B_SIGNATURE_CTX    *context,
                    const TPM2B_DIGEST           *digest,
                    const TPMT_TK_HASHCHECK      *validation,
                    TPMT_SIGNATURE               *signature,
                    TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!validation)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = Tss2_Sys_SignDigest_Prepare(sysContext, keyHandle, context, digest, validation);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_SignDigest_Complete(sysContext, signature);
}
