/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Sys API integration tests for TPM 2.0 v1.85 PQC commands against wolfTPM
 * fwTPM over the mssim socket transport (tcti-mssim).
 *
 * Prerequisites:
 *   - wolfTPM built with --enable-fwtpm --enable-pqc (or --enable-v185)
 *   - fwtpm_server running OR use script/int-log-compiler-wolftpm.sh (make check)
 *
 * Manual run:
 *   FWTPM_NV_FILE=/tmp/nv.bin /path/to/wolfTPM/src/fwtpm/fwtpm_server \
 *       --port 2321 --platform-port 2322 --clear &
 *   TPM20TEST_TCTI=mssim:host=127.0.0.1,port=2321 \
 *       ./test/integration/sys-pqc-wolftpm.int
 *
 * Expects wolfTPM fwTPM with v1.85 PQC (ML-KEM, Hash-ML-DSA, ML-DSA).
 */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h>
#include <string.h>

#include "tss2_common.h"
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

#define LOGMODULE test
#include "sys-util.h"
#include "test.h"
#include "util/log.h"

#define PQC_OBJECT_ATTRS                                                                           \
    (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |            \
     TPMA_OBJECT_USERWITHAUTH)

static TSS2L_SYS_AUTH_COMMAND  sessions_cmd
    = { .auths = { { .sessionHandle = TPM2_RH_PW } }, .count = 1 };
static TSS2L_SYS_AUTH_RESPONSE sessions_rsp = { .count = 0 };

static TPM2B_DATA outside_info = { .size = 0 };
static TPML_PCR_SELECTION      creation_pcr = { .count = 0 };

static void
fail_test(const char *msg, TSS2_RC rc) {
    LOG_ERROR("%s: 0x%08x", msg, rc);
    exit(EXIT_FAILURE);
}

static void
flush_handle(TSS2_SYS_CONTEXT *sys, TPM2_HANDLE handle) {
    TSS2_RC rc = Tss2_Sys_FlushContext(sys, handle);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("FlushContext", rc);
    }
}

static void
require_pqc_algorithms(TSS2_SYS_CONTEXT *sys) {
    TSS2_RC              rc;
    TPMI_YES_NO          more = 0;
    TPMS_CAPABILITY_DATA cap = { 0 };
    UINT32               i;
    int                  mlkem = 0;
    int                  mldsa = 0;
    int                  hash_mldsa = 0;

    rc = Tss2_Sys_GetCapability(sys, NULL, TPM2_CAP_ALGS, TPM2_ALG_MLKEM, 64, &more, &cap, NULL);
    if (rc != TSS2_RC_SUCCESS || cap.capability != TPM2_CAP_ALGS) {
        fail_test("GetCapability(ALGS)", rc);
    }

    for (i = 0; i < cap.data.algorithms.count; i++) {
        if (cap.data.algorithms.algProperties[i].alg == TPM2_ALG_MLKEM) {
            mlkem = 1;
        }
        if (cap.data.algorithms.algProperties[i].alg == TPM2_ALG_MLDSA) {
            mldsa = 1;
        }
        if (cap.data.algorithms.algProperties[i].alg == TPM2_ALG_HASH_MLDSA) {
            hash_mldsa = 1;
        }
    }

    LOG_INFO("PQC probe: MLKEM=%d MLDSA=%d HashMLDSA=%d", mlkem, mldsa, hash_mldsa);
    if (!mlkem || !mldsa || !hash_mldsa) {
        LOG_ERROR("TPM does not advertise required PQC algorithms");
        exit(EXIT_FAILURE);
    }
}

static TSS2_RC
create_primary(TSS2_SYS_CONTEXT       *sys,
             const TPM2B_PUBLIC     *in_public,
             TPM2_HANDLE            *handle,
             TPM2B_PUBLIC           *out_public) {
    TPM2B_SENSITIVE_CREATE  in_sensitive = { 0 };
    TPM2B_CREATION_DATA     creation_data = { 0 };
    TPM2B_DIGEST            creation_hash = { 0 };
    TPMT_TK_CREATION        creation_ticket = { 0 };
    TPM2B_NAME              name = TPM2B_NAME_INIT;

    return Tss2_Sys_CreatePrimary(sys, TPM2_RH_OWNER, &sessions_cmd, &in_sensitive, in_public,
                                  &outside_info, &creation_pcr, handle, out_public, &creation_data,
                                  &creation_hash, &creation_ticket, &name, &sessions_rsp);
}

static void
fill_mlkem_public(TPM2B_PUBLIC *in_public, TPMI_MLKEM_PARMS set) {
    memset(in_public, 0, sizeof(*in_public));
    in_public->publicArea.type = TPM2_ALG_MLKEM;
    in_public->publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public->publicArea.objectAttributes = PQC_OBJECT_ATTRS | TPMA_OBJECT_DECRYPT;
    in_public->publicArea.parameters.mlkemDetail.parameterSet = set;
    in_public->publicArea.parameters.mlkemDetail.symmetric.algorithm = TPM2_ALG_NULL;
}

static void
fill_hash_mldsa_public(TPM2B_PUBLIC *in_public, TPMI_MLDSA_PARMS set, TPMI_ALG_HASH hash) {
    memset(in_public, 0, sizeof(*in_public));
    in_public->publicArea.type = TPM2_ALG_HASH_MLDSA;
    in_public->publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public->publicArea.objectAttributes = PQC_OBJECT_ATTRS | TPMA_OBJECT_SIGN_ENCRYPT;
    in_public->publicArea.parameters.hash_mldsaDetail.parameterSet = set;
    in_public->publicArea.parameters.hash_mldsaDetail.hashAlg = hash;
}

static void
fill_mldsa_public(TPM2B_PUBLIC *in_public, TPMI_MLDSA_PARMS set) {
    memset(in_public, 0, sizeof(*in_public));
    in_public->publicArea.type = TPM2_ALG_MLDSA;
    in_public->publicArea.nameAlg = TPM2_ALG_SHA256;
    in_public->publicArea.objectAttributes = PQC_OBJECT_ATTRS | TPMA_OBJECT_SIGN_ENCRYPT;
    in_public->publicArea.parameters.mldsaDetail.parameterSet = set;
    /* Sequence sign/verify hashes inside the TPM; external mu is not used. */
    in_public->publicArea.parameters.mldsaDetail.allowExternalMu = 0;
}

static int
test_mlkem_encap_decap(TSS2_SYS_CONTEXT *sys) {
    TSS2_RC                rc;
    TPM2_HANDLE            handle = 0;
    TPM2B_PUBLIC           in_public = { 0 };
    TPM2B_PUBLIC           out_public = { 0 };
    TPM2B_SHARED_SECRET    ss_enc = { 0 };
    TPM2B_SHARED_SECRET    ss_dec = { 0 };
    TPM2B_KEM_CIPHERTEXT   ciphertext = { 0 };

    LOG_INFO("ML-KEM Encapsulate/Decapsulate test");
    fill_mlkem_public(&in_public, TPM2_MLKEM_PARMS_768);

    rc = create_primary(sys, &in_public, &handle, &out_public);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("CreatePrimary(MLKEM)", rc);
    }

    rc = Tss2_Sys_Encapsulate(sys, handle, &sessions_cmd, &ss_enc, &ciphertext, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("Encapsulate", rc);
    }
    if (ciphertext.size != TPM2_MLKEM_768_CT_SIZE || ss_enc.size != TPM2_MLKEM_SHARED_SECRET_SIZE) {
        LOG_ERROR("Unexpected MLKEM-768 sizes: ct=%u ss=%u", ciphertext.size, ss_enc.size);
        exit(EXIT_FAILURE);
    }

    rc = Tss2_Sys_Decapsulate(sys, handle, &sessions_cmd, &ciphertext, &ss_dec, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("Decapsulate", rc);
    }
    if (ss_dec.size != TPM2_MLKEM_SHARED_SECRET_SIZE ||
        memcmp(ss_enc.buffer, ss_dec.buffer, ss_enc.size) != 0) {
        LOG_ERROR("ML-KEM shared secrets do not match");
        exit(EXIT_FAILURE);
    }

    flush_handle(sys, handle);
    LOG_INFO("ML-KEM Encapsulate/Decapsulate passed");
    return 0;
}

static int
test_hash_mldsa_digest(TSS2_SYS_CONTEXT *sys) {
    TSS2_RC             rc;
    TPM2_HANDLE         handle = 0;
    TPM2B_PUBLIC        in_public = { 0 };
    TPM2B_PUBLIC        out_public = { 0 };
    TPM2B_DIGEST        digest = { .size = 32 };
    TPMT_TK_HASHCHECK   validation = { .tag = TPM2_ST_HASHCHECK,
                                       .hierarchy = TPM2_RH_NULL,
                                       .digest = { .size = 0 } };
    TPMT_SIGNATURE      signature = { 0 };
    TPMT_TK_VERIFIED    ticket = { 0 };

    LOG_INFO("Hash-MLDSA SignDigest/VerifyDigestSignature test");
    memset(digest.buffer, 0xAA, digest.size);
    fill_hash_mldsa_public(&in_public, TPM2_MLDSA_PARMS_65, TPM2_ALG_SHA256);

    rc = create_primary(sys, &in_public, &handle, &out_public);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("CreatePrimary(HashMLDSA)", rc);
    }

    rc = Tss2_Sys_SignDigest(sys, handle, &sessions_cmd, NULL, &digest, &validation, &signature,
                             &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("SignDigest", rc);
    }
    if (signature.sigAlg != TPM2_ALG_HASH_MLDSA ||
        signature.signature.hash_mldsa.signature.size != TPM2_MLDSA_65_SIG_SIZE) {
        LOG_ERROR("Unexpected HashMLDSA-65 signature size/alg");
        exit(EXIT_FAILURE);
    }

    rc = Tss2_Sys_VerifyDigestSignature(sys, handle, &sessions_cmd, NULL, &digest, &signature,
                                      &ticket, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("VerifyDigestSignature", rc);
    }
    if (ticket.tag != TPM2_ST_DIGEST_VERIFIED) {
        LOG_ERROR("Expected TPM2_ST_DIGEST_VERIFIED ticket, got 0x%04x", ticket.tag);
        exit(EXIT_FAILURE);
    }

    flush_handle(sys, handle);
    LOG_INFO("Hash-MLDSA SignDigest/VerifyDigestSignature passed");
    return 0;
}

static int
test_mldsa_sequence(TSS2_SYS_CONTEXT *sys) {
    TSS2_RC            rc;
    TPM2_HANDLE        key_handle = 0;
    TPM2_HANDLE        seq_handle = 0;
    TPM2B_PUBLIC       in_public = { 0 };
    TPM2B_PUBLIC       out_public = { 0 };
    TPM2B_MAX_BUFFER   message = { 0 };
    TPM2B_MAX_BUFFER   chunk1 = { 0 };
    TPM2B_MAX_BUFFER   chunk2 = { 0 };
    TPMT_SIGNATURE     signature = { 0 };
    TPMT_TK_VERIFIED   ticket = { 0 };
    static const char  msg[] = "tpm2-tss PQC Sys API ML-DSA sequence test";
    size_t             split;

    LOG_INFO("ML-DSA SignSequence/VerifySequence test");
    fill_mldsa_public(&in_public, TPM2_MLDSA_PARMS_44);

    rc = create_primary(sys, &in_public, &key_handle, &out_public);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("CreatePrimary(MLDSA)", rc);
    }

    rc = Tss2_Sys_SignSequenceStart(sys, key_handle, &sessions_cmd, NULL, NULL, &seq_handle,
                                    &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("SignSequenceStart", rc);
    }

    message.size = sizeof(msg) - 1;
    memcpy(message.buffer, msg, message.size);
    split = message.size / 2;
    chunk1.size = (UINT16)split;
    memcpy(chunk1.buffer, message.buffer, chunk1.size);
    chunk2.size = message.size - chunk1.size;
    memcpy(chunk2.buffer, message.buffer + chunk1.size, chunk2.size);

    rc = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sys, seq_handle, &sessions_cmd, &chunk1,
                                                &sessions_rsp));
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("SequenceUpdate(sign)", rc);
    }

    rc = Tss2_Sys_SignSequenceComplete(sys, seq_handle, key_handle, &sessions_cmd, &chunk2,
                                       &signature, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("SignSequenceComplete", rc);
    }
    if (signature.sigAlg != TPM2_ALG_MLDSA ||
        signature.signature.mldsa.size != TPM2_MLDSA_44_SIG_SIZE) {
        LOG_ERROR("Unexpected MLDSA-44 signature");
        exit(EXIT_FAILURE);
    }

    rc = Tss2_Sys_VerifySequenceStart(sys, key_handle, &sessions_cmd, NULL, NULL, NULL,
                                      &seq_handle, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("VerifySequenceStart", rc);
    }

    rc = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sys, seq_handle, &sessions_cmd, &chunk1,
                                                &sessions_rsp));
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("SequenceUpdate(verify)", rc);
    }

    rc = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sys, seq_handle, &sessions_cmd, &chunk2,
                                                &sessions_rsp));
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("SequenceUpdate(verify)", rc);
    }

    rc = Tss2_Sys_VerifySequenceComplete(sys, seq_handle, key_handle, &sessions_cmd, &signature,
                                         &ticket, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fail_test("VerifySequenceComplete", rc);
    }
    if (ticket.tag != TPM2_ST_MESSAGE_VERIFIED) {
        LOG_ERROR("Expected TPM2_ST_MESSAGE_VERIFIED ticket, got 0x%04x", ticket.tag);
        exit(EXIT_FAILURE);
    }

    flush_handle(sys, key_handle);
    LOG_INFO("ML-DSA sequence sign/verify passed");
    return 0;
}

int
test_invoke(TSS2_SYS_CONTEXT *sys_context) {
    int ret;

    if (sys_context == NULL) {
        return TSS2_RC_LAYER_MASK | TSS2_BASE_RC_BAD_REFERENCE;
    }

    LOG_INFO("PQC wolfTPM Sys API integration tests started");

    require_pqc_algorithms(sys_context);

    ret = test_mlkem_encap_decap(sys_context);
    if (ret != 0) {
        return ret;
    }

    ret = test_hash_mldsa_digest(sys_context);
    if (ret != 0) {
        return ret;
    }

    ret = test_mldsa_sequence(sys_context);
    if (ret != 0) {
        return ret;
    }

    LOG_INFO("All PQC wolfTPM Sys API integration tests passed");
    return 0;
}
