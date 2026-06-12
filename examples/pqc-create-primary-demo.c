/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Sys API demo: all TPM 2.0 v1.85 PQC commands against wolfTPM fwTPM.
 *
 * Covered APIs (7):
 *   Encapsulate, Decapsulate,
 *   SignDigest, VerifyDigestSignature,
 *   SignSequenceStart, VerifySequenceStart,
 *   SignSequenceComplete, VerifySequenceComplete
 *   (SequenceUpdate is shared with traditional TPM2 hash sequences)
 *
 * Build:
 *   ./configure && make && make -C examples
 *
 * Run:
 *   FWTPM_NV_FILE=/tmp/nv.bin fwtpm_server --port 2321 --platform-port 2322 --clear &
 *   TPM20TEST_TCTI=mssim:host=127.0.0.1,port=2321 ./examples/pqc-create-primary-demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tss2_common.h"
#include "tss2_sys.h"
#include "tss2_tctildr.h"
#include "tss2_tpm2_types.h"

#define PQC_OBJECT_ATTRS                                                                           \
    (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |            \
     TPMA_OBJECT_USERWITHAUTH)

#define TSS2_RETRY_EXP(expression)                                                                 \
    ({                                                                                             \
        TSS2_RC __result = 0;                                                                      \
        do {                                                                                       \
            __result = (expression);                                                               \
        } while ((__result & 0x0000ffff) == TPM2_RC_RETRY);                                        \
        __result;                                                                                  \
    })

static TSS2L_SYS_AUTH_COMMAND  sessions_cmd
    = { .auths = { { .sessionHandle = TPM2_RH_PW } }, .count = 1 };
static TSS2L_SYS_AUTH_RESPONSE sessions_rsp = { .count = 0 };

static TPM2B_DATA         outside_info = { .size = 0 };
static TPML_PCR_SELECTION creation_pcr = { .count = 0 };

static int
flush_handle(TSS2_SYS_CONTEXT *sys, TPM2_HANDLE handle, const char *label) {
    TSS2_RC rc = Tss2_Sys_FlushContext(sys, handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "%s: FlushContext failed 0x%08x\n", label, rc);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static TSS2_RC
create_primary(TSS2_SYS_CONTEXT   *sys,
             const TPM2B_PUBLIC *in_public,
             TPM2_HANDLE        *handle,
             TPM2B_PUBLIC       *out_public) {
    TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
    TPM2B_CREATION_DATA   creation_data = { 0 };
    TPM2B_DIGEST          creation_hash = { 0 };
    TPMT_TK_CREATION      creation_ticket = { 0 };
    TPM2B_NAME            name = { .size = sizeof(TPM2B_NAME) - 2, .name = { 0 } };

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
    in_public->publicArea.parameters.mldsaDetail.allowExternalMu = 0;
}

static int
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
        fprintf(stderr, "GetCapability(ALGS) failed 0x%08x\n", rc);
        return EXIT_FAILURE;
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

    printf("PQC algorithms: MLKEM=%d MLDSA=%d HashMLDSA=%d\n", mlkem, mldsa, hash_mldsa);
    if (!mlkem || !mldsa || !hash_mldsa) {
        fprintf(stderr, "TPM does not advertise required PQC algorithms\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/* ML-KEM-768: CreatePrimary → Encapsulate → Decapsulate */
static int
demo_mlkem_encap_decap(TSS2_SYS_CONTEXT *sys) {
    TSS2_RC              rc;
    int                  ret = EXIT_FAILURE;
    TPM2_HANDLE          handle = 0;
    TPM2B_PUBLIC         in_public = { 0 };
    TPM2B_PUBLIC         out_public = { 0 };
    TPM2B_SHARED_SECRET  ss_enc = { 0 };
    TPM2B_SHARED_SECRET  ss_dec = { 0 };
    TPM2B_KEM_CIPHERTEXT ciphertext = { 0 };

    fill_mlkem_public(&in_public, TPM2_MLKEM_PARMS_768);

    rc = create_primary(sys, &in_public, &handle, &out_public);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-KEM-768: CreatePrimary failed 0x%08x\n", rc);
        return EXIT_FAILURE;
    }
    printf("ML-KEM-768: CreatePrimary handle=0x%08x\n", handle);

    rc = Tss2_Sys_Encapsulate(sys, handle, &sessions_cmd, &ss_enc, &ciphertext, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-KEM-768: Encapsulate failed 0x%08x\n", rc);
        goto flush;
    }
    if (ciphertext.size != TPM2_MLKEM_768_CT_SIZE || ss_enc.size != TPM2_MLKEM_SHARED_SECRET_SIZE) {
        fprintf(stderr, "ML-KEM-768: unexpected sizes ct=%u ss=%u\n", ciphertext.size, ss_enc.size);
        goto flush;
    }
    printf("ML-KEM-768: Encapsulate ok ct.size=%u ss.size=%u\n", ciphertext.size, ss_enc.size);

    rc = Tss2_Sys_Decapsulate(sys, handle, &sessions_cmd, &ciphertext, &ss_dec, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-KEM-768: Decapsulate failed 0x%08x\n", rc);
        goto flush;
    }
    if (ss_dec.size != TPM2_MLKEM_SHARED_SECRET_SIZE ||
        memcmp(ss_enc.buffer, ss_dec.buffer, ss_enc.size) != 0) {
        fprintf(stderr, "ML-KEM-768: shared secrets do not match\n");
        goto flush;
    }
    printf("ML-KEM-768: Decapsulate ok (shared secret matches)\n");
    ret = EXIT_SUCCESS;

flush:
    if (flush_handle(sys, handle, "ML-KEM-768") != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return ret;
}

/* Hash-ML-DSA-65: CreatePrimary → SignDigest → VerifyDigestSignature */
static int
demo_hash_mldsa_digest(TSS2_SYS_CONTEXT *sys) {
    TSS2_RC           rc;
    int               ret = EXIT_FAILURE;
    TPM2_HANDLE       handle = 0;
    TPM2B_PUBLIC      in_public = { 0 };
    TPM2B_PUBLIC      out_public = { 0 };
    TPM2B_DIGEST      digest = { .size = 32 };
    TPMT_TK_HASHCHECK validation = { .tag = TPM2_ST_HASHCHECK,
                                       .hierarchy = TPM2_RH_NULL,
                                       .digest = { .size = 0 } };
    TPMT_SIGNATURE    signature = { 0 };
    TPMT_TK_VERIFIED  ticket = { 0 };

    memset(digest.buffer, 0xAA, digest.size);
    fill_hash_mldsa_public(&in_public, TPM2_MLDSA_PARMS_65, TPM2_ALG_SHA256);

    rc = create_primary(sys, &in_public, &handle, &out_public);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Hash-ML-DSA-65: CreatePrimary failed 0x%08x\n", rc);
        return EXIT_FAILURE;
    }
    printf("Hash-ML-DSA-65: CreatePrimary handle=0x%08x\n", handle);

    rc = Tss2_Sys_SignDigest(sys, handle, &sessions_cmd, NULL, &digest, &validation, &signature,
                             &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Hash-ML-DSA-65: SignDigest failed 0x%08x\n", rc);
        goto flush;
    }
    if (signature.sigAlg != TPM2_ALG_HASH_MLDSA ||
        signature.signature.hash_mldsa.signature.size != TPM2_MLDSA_65_SIG_SIZE) {
        fprintf(stderr, "Hash-ML-DSA-65: unexpected signature alg=0x%04x size=%u\n",
                signature.sigAlg, signature.signature.hash_mldsa.signature.size);
        goto flush;
    }
    printf("Hash-ML-DSA-65: SignDigest ok sig.size=%u\n",
           signature.signature.hash_mldsa.signature.size);

    rc = Tss2_Sys_VerifyDigestSignature(sys, handle, &sessions_cmd, NULL, &digest, &signature,
                                        &ticket, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Hash-ML-DSA-65: VerifyDigestSignature failed 0x%08x\n", rc);
        goto flush;
    }
    if (ticket.tag != TPM2_ST_DIGEST_VERIFIED) {
        fprintf(stderr, "Hash-ML-DSA-65: expected TPM2_ST_DIGEST_VERIFIED, got 0x%04x\n",
                ticket.tag);
        goto flush;
    }
    printf("Hash-ML-DSA-65: VerifyDigestSignature ok ticket=0x%04x\n", ticket.tag);
    ret = EXIT_SUCCESS;

flush:
    if (flush_handle(sys, handle, "Hash-ML-DSA-65") != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return ret;
}

/* ML-DSA-44: SignSequence* / VerifySequence* with chunked SequenceUpdate */
static int
demo_mldsa_sequence(TSS2_SYS_CONTEXT *sys) {
    TSS2_RC           rc;
    int               ret = EXIT_FAILURE;
    TPM2_HANDLE       key_handle = 0;
    TPM2_HANDLE       seq_handle = 0;
    TPM2B_PUBLIC      in_public = { 0 };
    TPM2B_PUBLIC      out_public = { 0 };
    TPM2B_MAX_BUFFER   chunk1 = { 0 };
    TPM2B_MAX_BUFFER   chunk2 = { 0 };
    TPMT_SIGNATURE    signature = { 0 };
    TPMT_TK_VERIFIED  ticket = { 0 };
    static const char msg[] = "tpm2-tss PQC Sys API ML-DSA sequence test";
    size_t            split;
    size_t            msg_len = sizeof(msg) - 1;

    fill_mldsa_public(&in_public, TPM2_MLDSA_PARMS_44);

    rc = create_primary(sys, &in_public, &key_handle, &out_public);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: CreatePrimary failed 0x%08x\n", rc);
        return EXIT_FAILURE;
    }
    printf("ML-DSA-44: CreatePrimary handle=0x%08x\n", key_handle);

    rc = Tss2_Sys_SignSequenceStart(sys, key_handle, &sessions_cmd, NULL, NULL, &seq_handle,
                                    &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: SignSequenceStart failed 0x%08x\n", rc);
        goto flush;
    }
    printf("ML-DSA-44: SignSequenceStart seq_handle=0x%08x\n", seq_handle);

    split = msg_len / 2;
    chunk1.size = (UINT16)split;
    memcpy(chunk1.buffer, msg, chunk1.size);
    chunk2.size = (UINT16)(msg_len - split);
    memcpy(chunk2.buffer, msg + chunk1.size, chunk2.size);

    rc = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sys, seq_handle, &sessions_cmd, &chunk1,
                                                &sessions_rsp));
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: SequenceUpdate(sign) failed 0x%08x\n", rc);
        goto flush;
    }

    rc = Tss2_Sys_SignSequenceComplete(sys, seq_handle, key_handle, &sessions_cmd, &chunk2,
                                        &signature, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: SignSequenceComplete failed 0x%08x\n", rc);
        goto flush;
    }
    if (signature.sigAlg != TPM2_ALG_MLDSA ||
        signature.signature.mldsa.size != TPM2_MLDSA_44_SIG_SIZE) {
        fprintf(stderr, "ML-DSA-44: unexpected signature alg=0x%04x size=%u\n", signature.sigAlg,
                signature.signature.mldsa.size);
        goto flush;
    }
    printf("ML-DSA-44: SignSequenceComplete ok sig.size=%u\n", signature.signature.mldsa.size);

    rc = Tss2_Sys_VerifySequenceStart(sys, key_handle, &sessions_cmd, NULL, NULL, NULL,
                                      &seq_handle, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: VerifySequenceStart failed 0x%08x\n", rc);
        goto flush;
    }
    printf("ML-DSA-44: VerifySequenceStart seq_handle=0x%08x\n", seq_handle);

    rc = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sys, seq_handle, &sessions_cmd, &chunk1,
                                                &sessions_rsp));
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: SequenceUpdate(verify) failed 0x%08x\n", rc);
        goto flush;
    }

    rc = TSS2_RETRY_EXP(Tss2_Sys_SequenceUpdate(sys, seq_handle, &sessions_cmd, &chunk2,
                                                &sessions_rsp));
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: SequenceUpdate(verify) failed 0x%08x\n", rc);
        goto flush;
    }

    rc = Tss2_Sys_VerifySequenceComplete(sys, seq_handle, key_handle, &sessions_cmd, &signature,
                                         &ticket, &sessions_rsp);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ML-DSA-44: VerifySequenceComplete failed 0x%08x\n", rc);
        goto flush;
    }
    if (ticket.tag != TPM2_ST_MESSAGE_VERIFIED) {
        fprintf(stderr, "ML-DSA-44: expected TPM2_ST_MESSAGE_VERIFIED, got 0x%04x\n", ticket.tag);
        goto flush;
    }
    printf("ML-DSA-44: VerifySequenceComplete ok ticket=0x%04x\n", ticket.tag);
    ret = EXIT_SUCCESS;

flush:
    if (flush_handle(sys, key_handle, "ML-DSA-44") != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return ret;
}

int
main(void) {
    TSS2_RC             rc;
    TSS2_TCTI_CONTEXT  *tcti = NULL;
    TSS2_SYS_CONTEXT   *sys = NULL;
    const char         *tcti_name;
    TSS2_ABI_VERSION    abi_version = {
        .tssCreator = 1,
        .tssFamily = 2,
        .tssLevel = 1,
        .tssVersion = 108,
    };
    size_t size;

    tcti_name = getenv("TPM20TEST_TCTI");
    if (tcti_name == NULL) {
        tcti_name = "mssim:host=127.0.0.1,port=2321";
    }

    rc = Tss2_TctiLdr_Initialize(tcti_name, &tcti);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "TctiLdr_Initialize(%s) failed 0x%08x\n", tcti_name, rc);
        return EXIT_FAILURE;
    }

    size = Tss2_Sys_GetContextSize(0);
    sys = calloc(1, size);
    if (sys == NULL) {
        fprintf(stderr, "calloc sys context failed\n");
        Tss2_TctiLdr_Finalize(&tcti);
        return EXIT_FAILURE;
    }

    rc = Tss2_Sys_Initialize(sys, size, tcti, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Sys_Initialize failed 0x%08x\n", rc);
        goto out;
    }

    rc = Tss2_Sys_Startup(sys, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        fprintf(stderr, "Startup failed 0x%08x\n", rc);
        goto out;
    }

    if (require_pqc_algorithms(sys) != EXIT_SUCCESS) {
        goto out;
    }

    if (demo_mlkem_encap_decap(sys) != EXIT_SUCCESS) {
        goto out;
    }

    if (demo_hash_mldsa_digest(sys) != EXIT_SUCCESS) {
        goto out;
    }

    if (demo_mldsa_sequence(sys) != EXIT_SUCCESS) {
        goto out;
    }

    printf("All v1.85 PQC Sys API demos passed.\n");
    rc = TSS2_RC_SUCCESS;

out:
    if (sys != NULL) {
        Tss2_Sys_Finalize(sys);
        free(sys);
    }
    Tss2_TctiLdr_Finalize(&tcti);
    return (rc == TSS2_RC_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
