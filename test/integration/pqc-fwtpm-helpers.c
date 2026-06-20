/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright (c) 2026, tpm2-tss contributors
 * All rights reserved.
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "pqc-fwtpm-helpers.h"

#define LOGMODULE test
#include "util/log.h"

static TPM2B_PUBLIC
pqc_mlkem768_template(void)
{
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_MLKEM,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = PQC_OBJECT_ATTRS_COMMON | TPMA_OBJECT_DECRYPT,
            .authPolicy = { .size = 0 },
            .parameters.mlkemDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .parameterSet = TPM2_MLKEM_768,
            },
            .unique.mlkem = { .size = 0 },
        },
    };
    return inPublic;
}

static TPM2B_PUBLIC
pqc_hash_mldsa65_template(void)
{
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_HASH_MLDSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = PQC_OBJECT_ATTRS_COMMON | TPMA_OBJECT_SIGN_ENCRYPT,
            .authPolicy = { .size = 0 },
            .parameters.hash_mldsaDetail = {
                .parameterSet = TPM2_MLDSA_65,
                .hashAlg = TPM2_ALG_SHA256,
            },
            .unique.mldsa = { .size = 0 },
        },
    };
    return inPublic;
}

static TPM2B_PUBLIC
pqc_mldsa65_template(void)
{
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_MLDSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = PQC_OBJECT_ATTRS_COMMON | TPMA_OBJECT_SIGN_ENCRYPT,
            .authPolicy = { .size = 0 },
            .parameters.mldsaDetail = {
                .parameterSet = TPM2_MLDSA_65,
                .allowExternalMu = TPM2_NO,
            },
            .unique.mldsa = { .size = 0 },
        },
    };
    return inPublic;
}

static TPM2B_PUBLIC
pqc_mldsa87_template(void)
{
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_MLDSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = PQC_OBJECT_ATTRS_COMMON | TPMA_OBJECT_SIGN_ENCRYPT,
            .authPolicy = { .size = 0 },
            .parameters.mldsaDetail = {
                .parameterSet = TPM2_MLDSA_87,
                .allowExternalMu = TPM2_NO,
            },
            .unique.mldsa = { .size = 0 },
        },
    };
    return inPublic;
}

int
pqc_esys_tpm_supports_alg(ESYS_CONTEXT *esys_context, TPM2_ALG_ID alg)
{
    TSS2_RC              r;
    TPMS_CAPABILITY_DATA *cap = NULL;
    TPMI_YES_NO           moreData = 0;

    r = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_ALGS,
                           alg, 1, &moreData, &cap);
    if (r == TPM2_RC_COMMAND_CODE || r == TPM2_RC_VALUE) {
        Esys_Free(cap);
        return 0;
    }
    if (r != TSS2_RC_SUCCESS) {
        Esys_Free(cap);
        return 0;
    }
    if (cap == NULL || cap->data.algorithms.count == 0) {
        Esys_Free(cap);
        return 0;
    }
    r = (cap->data.algorithms.algProperties[0].alg == alg);
    Esys_Free(cap);
    return r;
}

static UINT32
pqc_esys_get_ml_parameter_sets(ESYS_CONTEXT *esys_context, int *supported)
{
    TSS2_RC               r;
    TPMS_CAPABILITY_DATA *cap = NULL;
    TPMI_YES_NO           moreData = 0;
    UINT32                i;

    *supported = 0;

    r = Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_TPM_PROPERTIES, TPM2_PT_ML_PARAMETER_SETS, 1, &moreData,
                           &cap);
    if (r == TPM2_RC_VALUE || r == TPM2_RC_COMMAND_CODE) {
        Esys_Free(cap);
        return 0;
    }
    if (r != TSS2_RC_SUCCESS || cap == NULL) {
        Esys_Free(cap);
        return 0;
    }

    for (i = 0; i < cap->data.tpmProperties.count; i++) {
        if (cap->data.tpmProperties.tpmProperty[i].property == TPM2_PT_ML_PARAMETER_SETS) {
            UINT32 value = cap->data.tpmProperties.tpmProperty[i].value;
            Esys_Free(cap);
            *supported = 1;
            return value;
        }
    }

    Esys_Free(cap);
    return 0;
}

int
pqc_esys_tpm_supports_v185(ESYS_CONTEXT *esys_context)
{
    int supported = 0;

    (void)pqc_esys_get_ml_parameter_sets(esys_context, &supported);
    return supported;
}

int
pqc_esys_getcap_ml_parameter_sets(ESYS_CONTEXT *esys_context)
{
    int    supported = 0;
    UINT32 value = pqc_esys_get_ml_parameter_sets(esys_context, &supported);

    if (!supported) {
        LOG_ERROR("TPM2_PT_ML_PARAMETER_SETS not supported");
        return EXIT_FAILURE;
    }

    if ((value & PQC_EXPECTED_ML_PARAM_SETS) != PQC_EXPECTED_ML_PARAM_SETS) {
        LOG_ERROR("ML_PARAMETER_SETS=0x%08x missing required bits (expected 0x%08x)", value,
                  (unsigned)PQC_EXPECTED_ML_PARAM_SETS);
        return EXIT_FAILURE;
    }

    LOG_INFO("ML_PARAMETER_SETS=0x%08x (MLKEM_768 + MLDSA_65 present)", value);
    return EXIT_SUCCESS;
}

int
pqc_esys_deprecated_sign_roundtrip(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;
    TPMT_SIGNATURE      *signature = NULL;
    TPMT_TK_VERIFIED    *validation = NULL;

    TPM2B_AUTH authValuePrimary = { .size = 5, .buffer = { 1, 2, 3, 4, 5 } };
    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = authValuePrimary,
            .data = { .size = 0, .buffer = { 0 } },
        },
    };
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = PQC_OBJECT_ATTRS_COMMON | TPMA_OBJECT_SIGN_ENCRYPT,
            .authPolicy = { .size = 0 },
            .parameters.eccDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme = {
                    .scheme = TPM2_ALG_ECDSA,
                    .details = { .ecdsa = { .hashAlg = TPM2_ALG_SHA256 } },
                },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf = { .scheme = TPM2_ALG_NULL },
            },
            .unique.ecc = { .x = { .size = 0 }, .y = { .size = 0 } },
        },
    };
    TPM2B_DATA outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };
    TPM2B_AUTH authValue = { .size = 0 };

    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details = { .ecdsa = { .hashAlg = TPM2_ALG_SHA256 } },
    };
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = { .size = 0 },
    };
    TPM2B_DIGEST digest = { .size = 32, .buffer = { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                                    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                                    23, 24, 25, 26, 27, 28, 29, 30, 31, 32 } };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("TR_SetAuth failed: 0x%x", r);
        return EXIT_FAILURE;
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitivePrimary, &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(ECC P-256) failed: 0x%x", r);
        return EXIT_FAILURE;
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_Sign(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  &digest, &inScheme, &hash_validation, &signature);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_Sign (deprecated) failed: 0x%x", r);
        goto error;
    }

    r = Esys_VerifySignature(esys_context, primaryHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             &digest, signature, &validation);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Esys_VerifySignature (deprecated) failed: 0x%x", r);
        goto error;
    }

    LOG_INFO("Deprecated Esys_Sign/Esys_VerifySignature ECDSA P-256 roundtrip OK");

    Esys_Free(signature);
    Esys_Free(validation);
    Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Esys_Free(signature);
    Esys_Free(validation);
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_FAILURE;
}

int
pqc_sys_tpm_supports_alg(TSS2_SYS_CONTEXT *sys_context, TPM2_ALG_ID alg)
{
    TSS2_RC            rc;
    TPMS_CAPABILITY_DATA cap;
    TPMI_YES_NO        moreData = 0;

    rc = Tss2_Sys_GetCapability(sys_context, NULL, TPM2_CAP_ALGS, alg, 1, &moreData, &cap, NULL);
    if (rc == TPM2_RC_COMMAND_CODE || rc == TPM2_RC_VALUE)
        return 0;
    if (rc != TSS2_RC_SUCCESS)
        return 0;
    if (cap.data.algorithms.count == 0)
        return 0;
    return cap.data.algorithms.algProperties[0].alg == alg;
}

int
pqc_esys_mlkem_roundtrip(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_mlkem768_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };
    TPM2B_AUTH             authValue = { .size = 0 };

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_SHARED_SECRET  *sharedSecret1 = NULL;
    TPM2B_KEM_CIPHERTEXT *ciphertext = NULL;
    TPM2B_SHARED_SECRET  *sharedSecret2 = NULL;

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("TR_SetAuth failed: 0x%x", r);
        return EXIT_FAILURE;
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(ML-KEM-768) failed: 0x%x", r);
        return EXIT_FAILURE;
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_Encapsulate(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                         ESYS_TR_NONE, &sharedSecret1, &ciphertext);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Encapsulate failed: 0x%x", r);
        goto error;
    }
    if (ciphertext->size != PQC_MLKEM768_CT_SIZE || sharedSecret1->size != PQC_MLKEM768_SS_SIZE) {
        LOG_ERROR("ML-KEM-768 size mismatch: ct=%u (expected %d) ss=%u (expected %d)",
                  ciphertext->size, PQC_MLKEM768_CT_SIZE, sharedSecret1->size, PQC_MLKEM768_SS_SIZE);
        goto error;
    }

    r = Esys_Decapsulate(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         ciphertext, &sharedSecret2);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Decapsulate failed: 0x%x", r);
        goto error;
    }
    if (sharedSecret2->size != PQC_MLKEM768_SS_SIZE
        || memcmp(sharedSecret1->buffer, sharedSecret2->buffer, PQC_MLKEM768_SS_SIZE) != 0) {
        LOG_ERROR("ML-KEM shared-secret mismatch");
        goto error;
    }

    LOG_INFO("ML-KEM-768 Encap/Decap: ct=%u bytes, shared secrets match", ciphertext->size);

    Esys_Free(sharedSecret1);
    Esys_Free(sharedSecret2);
    Esys_Free(ciphertext);
    Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Esys_Free(sharedSecret1);
    Esys_Free(sharedSecret2);
    Esys_Free(ciphertext);
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_FAILURE;
}

int
pqc_esys_hash_mldsa_digest_roundtrip(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_hash_mldsa65_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };
    TPM2B_AUTH             authValue = { .size = 0 };

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_DIGEST      digest = { .size = TPM2_SHA256_DIGEST_SIZE };
    TPMT_TK_HASHCHECK validation = { .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_OWNER };
    TPMT_SIGNATURE   *signature = NULL;
    TPMT_TK_VERIFIED *ticket = NULL;

    memset(digest.buffer, 0xAA, digest.size);

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("TR_SetAuth failed: 0x%x", r);
        return EXIT_FAILURE;
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(HashMLDSA-65) failed: 0x%x", r);
        return EXIT_FAILURE;
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_SignDigest(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        NULL, &digest, &validation, &signature);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("SignDigest failed: 0x%x", r);
        goto error;
    }
    if (signature->signature.hash_mldsa.signature.size != PQC_MLDSA65_SIG_SIZE) {
        LOG_ERROR("HashMLDSA-65 sig size=%u (expected %d)",
                  signature->signature.hash_mldsa.signature.size, PQC_MLDSA65_SIG_SIZE);
        goto error;
    }

    r = Esys_VerifyDigestSignature(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                   ESYS_TR_NONE, NULL, &digest, signature, &ticket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("VerifyDigestSignature failed: 0x%x", r);
        goto error;
    }
    if (ticket->tag != TPM2_ST_DIGEST_VERIFIED) {
        LOG_ERROR("Ticket tag=0x%x (expected TPM2_ST_DIGEST_VERIFIED)", ticket->tag);
        goto error;
    }

    LOG_INFO("HashMLDSA-65 SignDigest/Verify: sig=%u bytes, ticket=DIGEST_VERIFIED",
             signature->signature.hash_mldsa.signature.size);

    Esys_Free(signature);
    Esys_Free(ticket);
    Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Esys_Free(signature);
    Esys_Free(ticket);
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_FAILURE;
}

int
pqc_esys_mldsa_sequence_roundtrip(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR signSequence = ESYS_TR_NONE;
    ESYS_TR verifySequence = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_mldsa65_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };
    TPM2B_AUTH             authValue = { .size = 0 };
    TPM2B_AUTH             sequenceAuth = { .size = 0 };

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_MAX_BUFFER message = { .size = 32 };
    TPM2B_MAX_BUFFER chunk1 = { .size = 16 };
    TPM2B_MAX_BUFFER chunk2 = { .size = 16 };
    TPMT_SIGNATURE   *signature = NULL;
    TPMT_TK_VERIFIED *ticket = NULL;

    memset(message.buffer, 0xBB, message.size);
    memcpy(chunk1.buffer, message.buffer, chunk1.size);
    memcpy(chunk2.buffer, message.buffer + chunk1.size, chunk2.size);

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("TR_SetAuth failed: 0x%x", r);
        return EXIT_FAILURE;
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(MLDSA-65) failed: 0x%x", r);
        return EXIT_FAILURE;
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_SignSequenceStart(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                               ESYS_TR_NONE, &sequenceAuth, NULL, &signSequence);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("SignSequenceStart failed: 0x%x", r);
        goto error;
    }

    r = Esys_SignSequenceComplete(esys_context, signSequence, primaryHandle, ESYS_TR_PASSWORD,
                                  ESYS_TR_NONE, ESYS_TR_NONE, &message, &signature);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("SignSequenceComplete failed: 0x%x", r);
        goto error;
    }
    if (signature->signature.mldsa.size != PQC_MLDSA65_SIG_SIZE) {
        LOG_ERROR("MLDSA-65 sig size=%u (expected %d)", signature->signature.mldsa.size,
                  PQC_MLDSA65_SIG_SIZE);
        goto error;
    }

    r = Esys_FlushContext(esys_context, signSequence);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("FlushContext(signSequence) failed: 0x%x", r);
        goto error;
    }
    signSequence = ESYS_TR_NONE;

    r = Esys_VerifySequenceStart(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                 ESYS_TR_NONE, &sequenceAuth, NULL, NULL, &verifySequence);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("VerifySequenceStart failed: 0x%x", r);
        goto error;
    }

    r = Esys_SequenceUpdate(esys_context, verifySequence, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                            ESYS_TR_NONE, &chunk1);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("SequenceUpdate(chunk1) failed: 0x%x", r);
        goto error;
    }

    r = Esys_SequenceUpdate(esys_context, verifySequence, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                            ESYS_TR_NONE, &chunk2);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("SequenceUpdate(chunk2) failed: 0x%x", r);
        goto error;
    }

    r = Esys_VerifySequenceComplete(esys_context, verifySequence, primaryHandle, ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE, ESYS_TR_NONE, signature, &ticket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("VerifySequenceComplete failed: 0x%x", r);
        goto error;
    }
    if (ticket->tag != TPM2_ST_MESSAGE_VERIFIED) {
        LOG_ERROR("Ticket tag=0x%x (expected TPM2_ST_MESSAGE_VERIFIED)", ticket->tag);
        goto error;
    }

    LOG_INFO("MLDSA-65 SignSequence/VerifySequence: sig=%u bytes, ticket=MESSAGE_VERIFIED",
             signature->signature.mldsa.size);

    Esys_Free(signature);
    Esys_Free(ticket);
    if (verifySequence != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, verifySequence);
    Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Esys_Free(signature);
    Esys_Free(ticket);
    if (signSequence != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, signSequence);
    if (verifySequence != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, verifySequence);
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_FAILURE;
}

int
pqc_sys_mlkem_roundtrip(TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    TPM2_HANDLE primaryHandle = 0;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_mlkem768_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };

    TPM2B_PUBLIC        outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST        creationHash = { .size = sizeof(creationHash.buffer) };
    TPMT_TK_CREATION    creationTicket = { 0 };
    TPM2B_NAME          name = { .size = sizeof(name.name) };

    TPM2B_SHARED_SECRET  sharedSecret1 = { .size = sizeof(sharedSecret1.buffer) };
    TPM2B_KEM_CIPHERTEXT ciphertext = { .size = sizeof(ciphertext.buffer) };
    TPM2B_SHARED_SECRET  sharedSecret2 = { .size = sizeof(sharedSecret2.buffer) };

    TSS2L_SYS_AUTH_COMMAND  sessions_cmd
        = { .auths = { { .sessionHandle = TPM2_RH_PW } }, .count = 1 };
    TSS2L_SYS_AUTH_RESPONSE sessions_rsp = { .auths = { 0 }, .count = 0 };

    rc = Tss2_Sys_CreatePrimary(sys_context, TPM2_RH_OWNER, &sessions_cmd, &inSensitive, &inPublic,
                                &outsideInfo, &creationPCR, &primaryHandle, &outPublic,
                                &creationData, &creationHash, &creationTicket, &name,
                                &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(ML-KEM-768) failed: 0x%x", rc);
        return EXIT_FAILURE;
    }

    rc = Tss2_Sys_Encapsulate(sys_context, primaryHandle, &sessions_cmd, &sharedSecret1,
                              &ciphertext, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("Encapsulate failed: 0x%x", rc);
        goto error;
    }
    if (ciphertext.size != PQC_MLKEM768_CT_SIZE || sharedSecret1.size != PQC_MLKEM768_SS_SIZE) {
        LOG_ERROR("ML-KEM-768 size mismatch: ct=%u (expected %d) ss=%u (expected %d)",
                  ciphertext.size, PQC_MLKEM768_CT_SIZE, sharedSecret1.size, PQC_MLKEM768_SS_SIZE);
        goto error;
    }

    rc = Tss2_Sys_Decapsulate(sys_context, primaryHandle, &sessions_cmd, &ciphertext,
                              &sharedSecret2, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("Decapsulate failed: 0x%x", rc);
        goto error;
    }
    if (sharedSecret2.size != PQC_MLKEM768_SS_SIZE
        || memcmp(sharedSecret1.buffer, sharedSecret2.buffer, PQC_MLKEM768_SS_SIZE) != 0) {
        LOG_ERROR("ML-KEM shared-secret mismatch");
        goto error;
    }

    LOG_INFO("SYS ML-KEM-768 Encap/Decap: ct=%u bytes, shared secrets match", ciphertext.size);

    Tss2_Sys_FlushContext(sys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Tss2_Sys_FlushContext(sys_context, primaryHandle);
    return EXIT_FAILURE;
}

int
pqc_sys_hash_mldsa_digest_roundtrip(TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    TPM2_HANDLE primaryHandle = 0;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_hash_mldsa65_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };

    TPM2B_PUBLIC        outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST        creationHash = { .size = sizeof(creationHash.buffer) };
    TPMT_TK_CREATION    creationTicket = { 0 };
    TPM2B_NAME          name = { .size = sizeof(name.name) };

    TPM2B_DIGEST      digest = { .size = TPM2_SHA256_DIGEST_SIZE };
    TPMT_TK_HASHCHECK validation = { .tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_OWNER };
    TPMT_SIGNATURE    signature = { 0 };
    TPMT_TK_VERIFIED  ticket = { 0 };

    TSS2L_SYS_AUTH_COMMAND  sessions_cmd
        = { .auths = { { .sessionHandle = TPM2_RH_PW } }, .count = 1 };
    TSS2L_SYS_AUTH_RESPONSE sessions_rsp = { .auths = { 0 }, .count = 0 };

    memset(digest.buffer, 0xAA, digest.size);

    rc = Tss2_Sys_CreatePrimary(sys_context, TPM2_RH_OWNER, &sessions_cmd, &inSensitive, &inPublic,
                                &outsideInfo, &creationPCR, &primaryHandle, &outPublic,
                                &creationData, &creationHash, &creationTicket, &name,
                                &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(HashMLDSA-65) failed: 0x%x", rc);
        return EXIT_FAILURE;
    }

    rc = Tss2_Sys_SignDigest(sys_context, primaryHandle, &sessions_cmd, NULL, &digest,
                             &validation, &signature, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("SignDigest failed: 0x%x", rc);
        goto error;
    }
    if (signature.signature.hash_mldsa.signature.size != PQC_MLDSA65_SIG_SIZE) {
        LOG_ERROR("HashMLDSA-65 sig size=%u (expected %d)",
                  signature.signature.hash_mldsa.signature.size, PQC_MLDSA65_SIG_SIZE);
        goto error;
    }

    rc = Tss2_Sys_VerifyDigestSignature(sys_context, primaryHandle, &sessions_cmd, NULL, &digest,
                                        &signature, &ticket, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("VerifyDigestSignature failed: 0x%x", rc);
        goto error;
    }
    if (ticket.tag != TPM2_ST_DIGEST_VERIFIED) {
        LOG_ERROR("Ticket tag=0x%x (expected TPM2_ST_DIGEST_VERIFIED)", ticket.tag);
        goto error;
    }

    LOG_INFO("SYS HashMLDSA-65 SignDigest/Verify: sig=%u bytes, ticket=DIGEST_VERIFIED",
             signature.signature.hash_mldsa.signature.size);

    Tss2_Sys_FlushContext(sys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Tss2_Sys_FlushContext(sys_context, primaryHandle);
    return EXIT_FAILURE;
}

int
pqc_sys_mldsa_sequence_roundtrip(TSS2_SYS_CONTEXT *sys_context)
{
    TSS2_RC rc;
    TPM2_HANDLE primaryHandle = 0;
    TPM2_HANDLE signSequence = 0;
    TPM2_HANDLE verifySequence = 0;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_mldsa65_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };
    TPM2B_AUTH             sequenceAuth = { .size = 0 };

    TPM2B_PUBLIC        outPublic = { .size = 0 };
    TPM2B_CREATION_DATA creationData = { .size = 0 };
    TPM2B_DIGEST        creationHash = { .size = sizeof(creationHash.buffer) };
    TPMT_TK_CREATION    creationTicket = { 0 };
    TPM2B_NAME          name = { .size = sizeof(name.name) };

    TPM2B_MAX_BUFFER message = { .size = 32 };
    TPM2B_MAX_BUFFER chunk1 = { .size = 16 };
    TPM2B_MAX_BUFFER chunk2 = { .size = 16 };
    TPMT_SIGNATURE   signature = { 0 };
    TPMT_TK_VERIFIED ticket = { 0 };

    TSS2L_SYS_AUTH_COMMAND  sessions_cmd
        = { .auths = { { .sessionHandle = TPM2_RH_PW } }, .count = 1 };
    TSS2L_SYS_AUTH_RESPONSE sessions_rsp = { .auths = { 0 }, .count = 0 };

    memset(message.buffer, 0xBB, message.size);
    memcpy(chunk1.buffer, message.buffer, chunk1.size);
    memcpy(chunk2.buffer, message.buffer + chunk1.size, chunk2.size);

    rc = Tss2_Sys_CreatePrimary(sys_context, TPM2_RH_OWNER, &sessions_cmd, &inSensitive, &inPublic,
                                &outsideInfo, &creationPCR, &primaryHandle, &outPublic,
                                &creationData, &creationHash, &creationTicket, &name,
                                &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(MLDSA-65) failed: 0x%x", rc);
        return EXIT_FAILURE;
    }

    rc = Tss2_Sys_SignSequenceStart(sys_context, primaryHandle, &sessions_cmd, &sequenceAuth, NULL,
                                    &signSequence, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("SignSequenceStart failed: 0x%x", rc);
        goto error;
    }

    rc = Tss2_Sys_SignSequenceComplete(sys_context, signSequence, primaryHandle, &sessions_cmd,
                                       &message, &signature, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("SignSequenceComplete failed: 0x%x", rc);
        goto error;
    }
    if (signature.signature.mldsa.size != PQC_MLDSA65_SIG_SIZE) {
        LOG_ERROR("MLDSA-65 sig size=%u (expected %d)", signature.signature.mldsa.size,
                  PQC_MLDSA65_SIG_SIZE);
        goto error;
    }

    Tss2_Sys_FlushContext(sys_context, signSequence);
    signSequence = 0;

    rc = Tss2_Sys_VerifySequenceStart(sys_context, primaryHandle, &sessions_cmd, &sequenceAuth,
                                      NULL, NULL, &verifySequence, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("VerifySequenceStart failed: 0x%x", rc);
        goto error;
    }

    rc = Tss2_Sys_SequenceUpdate(sys_context, verifySequence, &sessions_cmd, &chunk1,
                                 &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("SequenceUpdate(chunk1) failed: 0x%x", rc);
        goto error;
    }

    rc = Tss2_Sys_SequenceUpdate(sys_context, verifySequence, &sessions_cmd, &chunk2,
                                 &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("SequenceUpdate(chunk2) failed: 0x%x", rc);
        goto error;
    }

    rc = Tss2_Sys_VerifySequenceComplete(sys_context, verifySequence, primaryHandle,
                                         &sessions_cmd, &signature, &ticket, &sessions_rsp);
    if (rc != TPM2_RC_SUCCESS) {
        LOG_ERROR("VerifySequenceComplete failed: 0x%x", rc);
        goto error;
    }
    if (ticket.tag != TPM2_ST_MESSAGE_VERIFIED) {
        LOG_ERROR("Ticket tag=0x%x (expected TPM2_ST_MESSAGE_VERIFIED)", ticket.tag);
        goto error;
    }

    LOG_INFO("SYS MLDSA-65 SignSequence/VerifySequence: sig=%u bytes, ticket=MESSAGE_VERIFIED",
             signature.signature.mldsa.size);

    Tss2_Sys_FlushContext(sys_context, verifySequence);
    Tss2_Sys_FlushContext(sys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    if (signSequence)
        Tss2_Sys_FlushContext(sys_context, signSequence);
    if (verifySequence)
        Tss2_Sys_FlushContext(sys_context, verifySequence);
    if (primaryHandle)
        Tss2_Sys_FlushContext(sys_context, primaryHandle);
    return EXIT_FAILURE;
}

int
pqc_esys_mldsa87_buffer_roundtrip(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR signSequence = ESYS_TR_NONE;
    ESYS_TR verifySequence = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_mldsa87_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };
    TPM2B_AUTH             authValue = { .size = 0 };
    TPM2B_AUTH             sequenceAuth = { .size = 0 };

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_MAX_BUFFER message = { .size = 32 };
    TPMT_SIGNATURE   *signature = NULL;
    TPMT_TK_VERIFIED *ticket = NULL;

    memset(message.buffer, 0xCC, message.size);

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("TR_SetAuth failed: 0x%x", r);
        return EXIT_FAILURE;
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(MLDSA-87) failed: 0x%x", r);
        return EXIT_FAILURE;
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_SignSequenceStart(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                               ESYS_TR_NONE, &sequenceAuth, NULL, &signSequence);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("SignSequenceStart failed: 0x%x", r);
        goto error;
    }

    r = Esys_SignSequenceComplete(esys_context, signSequence, primaryHandle, ESYS_TR_PASSWORD,
                                  ESYS_TR_NONE, ESYS_TR_NONE, &message, &signature);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("SignSequenceComplete failed: 0x%x", r);
        goto error;
    }
    if (signature->signature.mldsa.size != PQC_MLDSA87_SIG_SIZE) {
        LOG_ERROR("MLDSA-87 sig size=%u (expected %d)", signature->signature.mldsa.size,
                  PQC_MLDSA87_SIG_SIZE);
        goto error;
    }

    r = Esys_FlushContext(esys_context, signSequence);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("FlushContext(signSequence) failed: 0x%x", r);
        goto error;
    }
    signSequence = ESYS_TR_NONE;

    r = Esys_VerifySequenceStart(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                 ESYS_TR_NONE, &sequenceAuth, NULL, NULL, &verifySequence);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("VerifySequenceStart failed: 0x%x", r);
        goto error;
    }

    r = Esys_VerifySequenceComplete(esys_context, verifySequence, primaryHandle, ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE, ESYS_TR_NONE, signature, &ticket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("VerifySequenceComplete failed: 0x%x", r);
        goto error;
    }
    if (ticket->tag != TPM2_ST_MESSAGE_VERIFIED) {
        LOG_ERROR("Ticket tag=0x%x (expected TPM2_ST_MESSAGE_VERIFIED)", ticket->tag);
        goto error;
    }

    LOG_INFO("MLDSA-87 buffer roundtrip: sig=%u bytes", signature->signature.mldsa.size);

    Esys_Free(signature);
    Esys_Free(ticket);
    if (verifySequence != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, verifySequence);
    Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Esys_Free(signature);
    Esys_Free(ticket);
    if (signSequence != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, signSequence);
    if (verifySequence != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, verifySequence);
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_FAILURE;
}

static TPM2B_PUBLIC
pqc_mldsa65_restricted_sign_template(void)
{
    TPM2B_PUBLIC inPublic = pqc_mldsa65_template();

    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
    return inPublic;
}

int
pqc_esys_mldsa_quote_roundtrip(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_mldsa65_restricted_sign_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };
    TPM2B_AUTH             authValue = { .size = 0 };

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_DATA         qualifyingData = { .size = 0 };
    TPMT_SIG_SCHEME    sig_scheme = {
        .scheme = TPM2_ALG_MLDSA,
        .details = { .any = { .hashAlg = TPM2_ALG_SHA256 } },
    };
    TPML_PCR_SELECTION pcr_selection = {
        .count = 1,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA256, .sizeofSelect = 3, .pcrSelect = { 0, 4, 0 } },
        },
    };
    TPM2B_ATTEST     *attest = NULL;
    TPMT_SIGNATURE   *signature = NULL;
    TPM2B_DIGEST     *digest = NULL;
    TPMT_TK_VERIFIED *ticket = NULL;

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("TR_SetAuth failed: 0x%x", r);
        return EXIT_FAILURE;
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(MLDSA-65 quote) failed: 0x%x", r);
        return EXIT_FAILURE;
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_Quote(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &qualifyingData, &sig_scheme, &pcr_selection, &attest, &signature);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Quote(MLDSA-65) failed: 0x%x", r);
        goto error;
    }
    if (signature->signature.mldsa.size != PQC_MLDSA65_SIG_SIZE) {
        LOG_ERROR("MLDSA-65 quote sig size=%u (expected %d)", signature->signature.mldsa.size,
                  PQC_MLDSA65_SIG_SIZE);
        goto error;
    }

    {
        TPM2B_MAX_BUFFER attest_buf = { .size = attest->size };

        memcpy(attest_buf.buffer, attest->attestationData, attest->size);
        r = Esys_Hash(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &attest_buf,
                      TPM2_ALG_SHA256, ESYS_TR_RH_OWNER, &digest, NULL);
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("Hash(attest) failed: 0x%x", r);
        goto error;
    }

    r = Esys_VerifySignature(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                             ESYS_TR_NONE, digest, signature, &ticket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("VerifySignature(quote) failed: 0x%x", r);
        goto error;
    }
    if (ticket->tag != TPM2_ST_VERIFIED) {
        LOG_ERROR("Ticket tag=0x%x (expected TPM2_ST_VERIFIED)", ticket->tag);
        goto error;
    }

    LOG_INFO("MLDSA-65 Quote/Verify: sig=%u bytes, nameAlg digest (Errata 2.6)",
             signature->signature.mldsa.size);

    Esys_Free(attest);
    Esys_Free(signature);
    Esys_Free(digest);
    Esys_Free(ticket);
    Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Esys_Free(attest);
    Esys_Free(signature);
    Esys_Free(digest);
    Esys_Free(ticket);
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_FAILURE;
}

static TPM2B_PUBLIC
pqc_mlkem768_restricted_template(void)
{
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_MLKEM,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = PQC_OBJECT_ATTRS_COMMON | TPMA_OBJECT_DECRYPT
                              | TPMA_OBJECT_RESTRICTED,
            .authPolicy = { .size = 0 },
            .parameters.mlkemDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.sym = TPM2_ALG_CFB,
                },
                .parameterSet = TPM2_MLKEM_768,
            },
            .unique.mlkem = { .size = 0 },
        },
    };
    return inPublic;
}

int
pqc_esys_mlkem_session_roundtrip(ESYS_CONTEXT *esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    ESYS_TR sessionHandle = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE inSensitive = { .size = 0 };
    TPM2B_PUBLIC           inPublic = pqc_mlkem768_restricted_template();
    TPM2B_DATA             outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION     creationPCR = { .count = 0 };
    TPM2B_AUTH             authValue = { .size = 0 };

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_DIGEST *random = NULL;
    TPMT_SYM_DEF  session_sym = {
        .algorithm = TPM2_ALG_AES,
        .keyBits.aes = 128,
        .mode.sym = TPM2_ALG_CFB,
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("TR_SetAuth failed: 0x%x", r);
        return EXIT_FAILURE;
    }

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                           &primaryHandle, &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("CreatePrimary(ML-KEM restricted) failed: 0x%x", r);
        return EXIT_FAILURE;
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_StartAuthSession(esys_context, primaryHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &session_sym, TPM2_ALG_SHA256,
                              &sessionHandle);
    if (r != TSS2_RC_SUCCESS) {
        if ((r & 0xFF) == TPM2_RC_KEY || (r & 0xFF) == TPM2_RC_VALUE) {
            LOG_INFO("SKIP: ML-KEM StartAuthSession not supported by TPM (0x%x)", r);
            goto error;
        }
        LOG_ERROR("StartAuthSession(ML-KEM tpmKey) failed: 0x%x", r);
        goto error;
    }

    r = Esys_GetRandom(esys_context, sessionHandle, ESYS_TR_NONE, ESYS_TR_NONE, 32, &random);
    if (r != TSS2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with ML-KEM session failed: 0x%x", r);
        goto error;
    }
    if (random == NULL || random->size != 32) {
        LOG_ERROR("GetRandom returned invalid buffer");
        goto error;
    }

    LOG_INFO("ML-KEM-768 StartAuthSession + GetRandom succeeded");

    Esys_Free(random);
    Esys_FlushContext(esys_context, sessionHandle);
    Esys_FlushContext(esys_context, primaryHandle);
    return EXIT_SUCCESS;

error:
    Esys_Free(random);
    if (sessionHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, sessionHandle);
    if (primaryHandle != ESYS_TR_NONE)
        Esys_FlushContext(esys_context, primaryHandle);
    if ((r & 0xFF) == TPM2_RC_KEY || (r & 0xFF) == TPM2_RC_VALUE)
        return PQC_EXIT_SKIP;
    return EXIT_FAILURE;
}
