/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"
#include "tss2_common.h"
#include "tss2_mu.h"
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

TSS2_RC
Tss2_Sys_ReadOnlyControl_Prepare(TSS2_SYS_CONTEXT *sysContext,
                                 TPMI_RH_PLATFORM  authHandle,
                                 TPMI_YES_NO       state) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_ReadOnlyControl);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(authHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT8_Marshal(state, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_ReadOnlyControl_Complete(TSS2_SYS_CONTEXT *sysContext) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    return CommonComplete(ctx);
}

TSS2_RC
Tss2_Sys_ReadOnlyControl(TSS2_SYS_CONTEXT             *sysContext,
                         TPMI_RH_PLATFORM              authHandle,
                         TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                         TPMI_YES_NO                   state,
                         TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    rval = Tss2_Sys_ReadOnlyControl_Prepare(sysContext, authHandle, state);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_ReadOnlyControl_Complete(sysContext);
}
