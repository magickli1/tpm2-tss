/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2026
 *
 * Unit tests for PQC / EdDSA v1.85 marshal-unmarshal round-trips.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stddef.h> // for NULL, size_t
#include <stdint.h> // for uint8_t
#include <string.h> // for memcmp, memset

#include "../helper/cmocka_all.h" // for assert_int_equal, cmocka_unit_test
#include "tss2_common.h"          // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_MU_RC_BAD_SIZE
#include "tss2_mu.h"
#include "tss2_tpm2_types.h"

#define PQC_BUF_SIZE 8192

typedef struct {
    UINT16 size;
    BYTE   buffer[1];
} TPM2B_HDR;

static void
fill_pattern(BYTE *buf, size_t size, BYTE seed) {
    for (size_t i = 0; i < size; i++)
        buf[i] = (BYTE)(seed + (BYTE)i);
}

static void
assert_tpm2b_roundtrip(size_t expected_wire_size,
                       TSS2_RC (*marshal_fn)(const void *src,
                                             uint8_t buffer[],
                                             size_t buffer_size,
                                             size_t *offset),
                       TSS2_RC (*unmarshal_fn)(uint8_t const buffer[],
                                               size_t buffer_size,
                                               size_t *offset,
                                               void *dest),
                       const void *src,
                       void *dest) {
    uint8_t buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t buf2[PQC_BUF_SIZE] = { 0 };
    size_t  offset = 0;
    TSS2_RC rc;

    rc = marshal_fn(src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, expected_wire_size);

    offset = 0;
    rc = unmarshal_fn(buf1, sizeof(buf1), &offset, dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, expected_wire_size);
    assert_int_equal(((TPM2B_HDR *)dest)->size, ((TPM2B_HDR *)src)->size);
    assert_memory_equal(((TPM2B_HDR *)dest)->buffer, ((TPM2B_HDR *)src)->buffer,
                        ((TPM2B_HDR *)src)->size);

    offset = 0;
    rc = marshal_fn(dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, expected_wire_size);
}

static void
pqc_tpm2b_public_key_mlkem_roundtrip(void **state) {
    (void)state;
    static const UINT16 sizes[] = { TPM2_MLKEM_512_PUB_SIZE, TPM2_MLKEM_768_PUB_SIZE,
                                    TPM2_MLKEM_1024_PUB_SIZE };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        TPM2B_PUBLIC_KEY_MLKEM src = { 0 };
        TPM2B_PUBLIC_KEY_MLKEM dest = { 0 };

        src.size = sizes[i];
        fill_pattern(src.buffer, src.size, (BYTE)(0x10 + i));

        assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                               (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                                   Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Marshal,
                               (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                                   Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Unmarshal,
                               &src, &dest);
    }
}

static void
pqc_tpm2b_kem_ciphertext_roundtrip(void **state) {
    (void)state;
    static const UINT16 sizes[] = { TPM2_MLKEM_512_CT_SIZE, TPM2_MLKEM_768_CT_SIZE,
                                    TPM2_MLKEM_1024_CT_SIZE };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        TPM2B_KEM_CIPHERTEXT src = { 0 };
        TPM2B_KEM_CIPHERTEXT dest = { 0 };

        src.size = sizes[i];
        fill_pattern(src.buffer, src.size, (BYTE)(0x20 + i));

        assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                               (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                                   Tss2_MU_TPM2B_KEM_CIPHERTEXT_Marshal,
                               (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                                   Tss2_MU_TPM2B_KEM_CIPHERTEXT_Unmarshal,
                               &src, &dest);
    }
}

static void
pqc_tpm2b_shared_secret_roundtrip(void **state) {
    (void)state;
    TPM2B_SHARED_SECRET src = { 0 };
    TPM2B_SHARED_SECRET dest = { 0 };

    src.size = TPM2_MLKEM_SHARED_SECRET_SIZE;
    fill_pattern(src.buffer, src.size, 0x30);

    assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                           (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                               Tss2_MU_TPM2B_SHARED_SECRET_Marshal,
                           (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                               Tss2_MU_TPM2B_SHARED_SECRET_Unmarshal,
                           &src, &dest);
}

static void
pqc_tpm2b_public_key_mldsa_roundtrip(void **state) {
    (void)state;
    static const UINT16 sizes[] = { TPM2_MLDSA_44_PUB_SIZE, TPM2_MLDSA_65_PUB_SIZE,
                                    TPM2_MLDSA_87_PUB_SIZE };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        TPM2B_PUBLIC_KEY_MLDSA src = { 0 };
        TPM2B_PUBLIC_KEY_MLDSA dest = { 0 };

        src.size = sizes[i];
        fill_pattern(src.buffer, src.size, (BYTE)(0x40 + i));

        assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                               (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                                   Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Marshal,
                               (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                                   Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Unmarshal,
                               &src, &dest);
    }
}

static void
pqc_tpm2b_private_key_mldsa_roundtrip(void **state) {
    (void)state;
    TPM2B_PRIVATE_KEY_MLDSA src = { 0 };
    TPM2B_PRIVATE_KEY_MLDSA dest = { 0 };

    src.size = TPM2_MLDSA_PRIVATE_KEY_SEED_SIZE;
    fill_pattern(src.buffer, src.size, 0x50);

    assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                           (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                               Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Marshal,
                           (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                               Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Unmarshal,
                           &src, &dest);
}

static void
pqc_tpm2b_private_key_mlkem_roundtrip(void **state) {
    (void)state;
    TPM2B_PRIVATE_KEY_MLKEM src = { 0 };
    TPM2B_PRIVATE_KEY_MLKEM dest = { 0 };

    src.size = TPM2_MLKEM_PRIVATE_KEY_SEED_SIZE;
    fill_pattern(src.buffer, src.size, 0x55);

    assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                           (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                               Tss2_MU_TPM2B_PRIVATE_KEY_MLKEM_Marshal,
                           (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                               Tss2_MU_TPM2B_PRIVATE_KEY_MLKEM_Unmarshal,
                           &src, &dest);
}

static void
pqc_tpm2b_signature_eddsa_roundtrip(void **state) {
    (void)state;
    TPM2B_SIGNATURE_EDDSA src = { 0 };
    TPM2B_SIGNATURE_EDDSA dest = { 0 };

    src.size = 64;
    fill_pattern(src.buffer, src.size, 0x60);

    assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                           (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                               Tss2_MU_TPM2B_SIGNATURE_EDDSA_Marshal,
                           (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                               Tss2_MU_TPM2B_SIGNATURE_EDDSA_Unmarshal,
                           &src, &dest);
}

static void
pqc_tpm2b_signature_mldsa_roundtrip(void **state) {
    (void)state;
    TPM2B_SIGNATURE_MLDSA src = { 0 };
    TPM2B_SIGNATURE_MLDSA dest = { 0 };

    src.size = TPM2_MLDSA_44_SIG_SIZE;
    fill_pattern(src.buffer, src.size, 0x70);

    assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                           (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                               Tss2_MU_TPM2B_SIGNATURE_MLDSA_Marshal,
                           (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                               Tss2_MU_TPM2B_SIGNATURE_MLDSA_Unmarshal,
                           &src, &dest);
}

static void
pqc_tpm2b_signature_mldsa_bad_size(void **state) {
    (void)state;
    TPM2B_SIGNATURE_MLDSA src = { 0 };
    uint8_t               buffer[PQC_BUF_SIZE] = { 0 };
    size_t                offset = 0;
    TSS2_RC               rc;

    /* Marshal rejects sizes beyond the TPM2B wire limit (struct size minus UINT16). */
    src.size = (UINT16)(sizeof(src) - sizeof(src.size) + 1);
    fill_pattern(src.buffer, TPM2_MAX_MLDSA_SIG_SIZE, 0x71);

    rc = Tss2_MU_TPM2B_SIGNATURE_MLDSA_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_MU_RC_BAD_SIZE);
    assert_int_equal(offset, 0);
}

static void
pqc_tpm2b_signature_ctx_roundtrip(void **state) {
    (void)state;
    TPM2B_SIGNATURE_CTX src = { 0 };
    TPM2B_SIGNATURE_CTX dest = { 0 };

    src.size = 32;
    fill_pattern(src.buffer, src.size, 0x80);

    assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                           (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                               Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal,
                           (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                               Tss2_MU_TPM2B_SIGNATURE_CTX_Unmarshal,
                           &src, &dest);
}

static void
pqc_tpm2b_signature_hint_roundtrip(void **state) {
    (void)state;
    TPM2B_SIGNATURE_HINT src = { 0 };
    TPM2B_SIGNATURE_HINT dest = { 0 };

    src.size = 48;
    fill_pattern(src.buffer, src.size, 0x90);

    assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                           (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                               Tss2_MU_TPM2B_SIGNATURE_HINT_Marshal,
                           (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                               Tss2_MU_TPM2B_SIGNATURE_HINT_Unmarshal,
                           &src, &dest);
}

static void
assert_tpmu_signature_eq(TPMI_ALG_SIG_SCHEME selector,
                         const TPMU_SIGNATURE *a,
                         const TPMU_SIGNATURE *b) {
    switch (selector) {
    case TPM2_ALG_MLDSA:
        assert_int_equal(a->mldsa.size, b->mldsa.size);
        assert_memory_equal(a->mldsa.buffer, b->mldsa.buffer, a->mldsa.size);
        break;
    case TPM2_ALG_HASH_MLDSA:
        assert_int_equal(a->hash_mldsa.hash, b->hash_mldsa.hash);
        assert_int_equal(a->hash_mldsa.signature.size, b->hash_mldsa.signature.size);
        assert_memory_equal(a->hash_mldsa.signature.buffer, b->hash_mldsa.signature.buffer,
                            a->hash_mldsa.signature.size);
        break;
    case TPM2_ALG_EDDSA:
        assert_int_equal(a->eddsa.size, b->eddsa.size);
        assert_memory_equal(a->eddsa.buffer, b->eddsa.buffer, a->eddsa.size);
        break;
    case TPM2_ALG_HASH_EDDSA:
        assert_int_equal(a->hash_eddsa.size, b->hash_eddsa.size);
        assert_memory_equal(a->hash_eddsa.buffer, b->hash_eddsa.buffer, a->hash_eddsa.size);
        break;
    default:
        assert_true(0);
    }
}

static void
assert_tpmu_signature_roundtrip(TPMI_ALG_SIG_SCHEME selector, TPMU_SIGNATURE *src) {
    uint8_t        buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t        buf2[PQC_BUF_SIZE] = { 0 };
    TPMU_SIGNATURE dest = { 0 };
    size_t         offset = 0;
    TSS2_RC        rc;

    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(src, selector, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_SIGNATURE_Unmarshal(buf1, sizeof(buf1), &offset, selector, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_tpmu_signature_eq(selector, src, &dest);

    offset = 0;
    rc = Tss2_MU_TPMU_SIGNATURE_Marshal(&dest, selector, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpmu_signature_roundtrip(void **state) {
    (void)state;
    TPMU_SIGNATURE sig = { 0 };

    sig.mldsa.size = TPM2_MLDSA_44_SIG_SIZE;
    fill_pattern(sig.mldsa.buffer, sig.mldsa.size, 0xa0);
    assert_tpmu_signature_roundtrip(TPM2_ALG_MLDSA, &sig);

    memset(&sig, 0, sizeof(sig));
    sig.hash_mldsa.hash = TPM2_ALG_SHA256;
    sig.hash_mldsa.signature.size = TPM2_MLDSA_44_SIG_SIZE;
    fill_pattern(sig.hash_mldsa.signature.buffer, sig.hash_mldsa.signature.size, 0xa1);
    assert_tpmu_signature_roundtrip(TPM2_ALG_HASH_MLDSA, &sig);

    memset(&sig, 0, sizeof(sig));
    sig.eddsa.size = 64;
    fill_pattern(sig.eddsa.buffer, sig.eddsa.size, 0xa2);
    assert_tpmu_signature_roundtrip(TPM2_ALG_EDDSA, &sig);

    memset(&sig, 0, sizeof(sig));
    sig.hash_eddsa.size = 64;
    fill_pattern(sig.hash_eddsa.buffer, sig.hash_eddsa.size, 0xa3);
    assert_tpmu_signature_roundtrip(TPM2_ALG_HASH_EDDSA, &sig);
}

static void
assert_tpmt_signature_roundtrip(TPMT_SIGNATURE *src) {
    uint8_t         buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t         buf2[PQC_BUF_SIZE] = { 0 };
    TPMT_SIGNATURE  dest = { 0 };
    size_t          offset = 0;
    TSS2_RC         rc;

    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(src, &dest, sizeof(TPMT_SIGNATURE));

    offset = 0;
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpmt_signature_mldsa_roundtrip(void **state) {
    (void)state;
    TPMT_SIGNATURE sig = { 0 };

    sig.sigAlg = TPM2_ALG_MLDSA;
    sig.signature.mldsa.size = TPM2_MLDSA_44_SIG_SIZE;
    fill_pattern(sig.signature.mldsa.buffer, sig.signature.mldsa.size, 0xb0);
    assert_tpmt_signature_roundtrip(&sig);
}

static void
pqc_tpmt_signature_eddsa_roundtrip(void **state) {
    (void)state;
    TPMT_SIGNATURE sig = { 0 };

    sig.sigAlg = TPM2_ALG_EDDSA;
    sig.signature.eddsa.size = 64;
    fill_pattern(sig.signature.eddsa.buffer, sig.signature.eddsa.size, 0xb1);
    assert_tpmt_signature_roundtrip(&sig);
}

static void
pqc_tpms_mlkem_parms_roundtrip(void **state) {
    (void)state;
    TPMS_MLKEM_PARMS src = { 0 };
    TPMS_MLKEM_PARMS dest = { 0 };
    size_t           offset = 0;
    uint8_t          buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t          buf2[PQC_BUF_SIZE] = { 0 };
    TSS2_RC          rc;

    src.symmetric.algorithm = TPM2_ALG_AES;
    src.symmetric.keyBits.aes = 128;
    src.symmetric.mode.aes = TPM2_ALG_CFB;
    src.parameterSet = TPM2_MLKEM_PARMS_768;

    rc = Tss2_MU_TPMS_MLKEM_PARMS_Marshal(&src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_MLKEM_PARMS_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(&src, &dest, sizeof(src));

    offset = 0;
    rc = Tss2_MU_TPMS_MLKEM_PARMS_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpms_mldsa_parms_roundtrip(void **state) {
    (void)state;
    TPMS_MLDSA_PARMS src = { 0 };
    TPMS_MLDSA_PARMS dest = { 0 };
    size_t           offset = 0;
    uint8_t          buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t          buf2[PQC_BUF_SIZE] = { 0 };
    TSS2_RC          rc;

    src.parameterSet = TPM2_MLDSA_PARMS_65;
    src.allowExternalMu = 1;

    rc = Tss2_MU_TPMS_MLDSA_PARMS_Marshal(&src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_MLDSA_PARMS_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(&src, &dest, sizeof(src));

    offset = 0;
    rc = Tss2_MU_TPMS_MLDSA_PARMS_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpms_hash_mldsa_parms_roundtrip(void **state) {
    (void)state;
    TPMS_HASH_MLDSA_PARMS src = { 0 };
    TPMS_HASH_MLDSA_PARMS dest = { 0 };
    size_t                offset = 0;
    uint8_t               buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t               buf2[PQC_BUF_SIZE] = { 0 };
    TSS2_RC               rc;

    src.parameterSet = TPM2_MLDSA_PARMS_44;
    src.hashAlg = TPM2_ALG_SHA512;

    rc = Tss2_MU_TPMS_HASH_MLDSA_PARMS_Marshal(&src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_HASH_MLDSA_PARMS_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(&src, &dest, sizeof(src));

    offset = 0;
    rc = Tss2_MU_TPMS_HASH_MLDSA_PARMS_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
assert_tpmu_public_parms_roundtrip(TPMI_ALG_PUBLIC selector, TPMU_PUBLIC_PARMS *src) {
    uint8_t          buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t          buf2[PQC_BUF_SIZE] = { 0 };
    TPMU_PUBLIC_PARMS dest = { 0 };
    size_t           offset = 0;
    TSS2_RC          rc;

    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Marshal(src, selector, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Unmarshal(buf1, sizeof(buf1), &offset, selector, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(src, &dest, sizeof(*src));

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_PARMS_Marshal(&dest, selector, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpmu_public_parms_roundtrip(void **state) {
    (void)state;
    TPMU_PUBLIC_PARMS parms = { 0 };

    parms.mlkemDetail.symmetric.algorithm = TPM2_ALG_AES;
    parms.mlkemDetail.symmetric.keyBits.aes = 128;
    parms.mlkemDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    parms.mlkemDetail.parameterSet = TPM2_MLKEM_PARMS_512;
    assert_tpmu_public_parms_roundtrip(TPM2_ALG_MLKEM, &parms);

    memset(&parms, 0, sizeof(parms));
    parms.mldsaDetail.parameterSet = TPM2_MLDSA_PARMS_44;
    parms.mldsaDetail.allowExternalMu = 0;
    assert_tpmu_public_parms_roundtrip(TPM2_ALG_MLDSA, &parms);

    memset(&parms, 0, sizeof(parms));
    parms.hash_mldsaDetail.parameterSet = TPM2_MLDSA_PARMS_87;
    parms.hash_mldsaDetail.hashAlg = TPM2_ALG_SHA384;
    assert_tpmu_public_parms_roundtrip(TPM2_ALG_HASH_MLDSA, &parms);
}

static void
assert_tpmu_public_id_roundtrip(TPMI_ALG_PUBLIC selector, TPMU_PUBLIC_ID *src) {
    uint8_t        buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t        buf2[PQC_BUF_SIZE] = { 0 };
    TPMU_PUBLIC_ID dest = { 0 };
    size_t         offset = 0;
    TSS2_RC        rc;

    rc = Tss2_MU_TPMU_PUBLIC_ID_Marshal(src, selector, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_ID_Unmarshal(buf1, sizeof(buf1), &offset, selector, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(src, &dest, sizeof(*src));

    offset = 0;
    rc = Tss2_MU_TPMU_PUBLIC_ID_Marshal(&dest, selector, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpmu_public_id_roundtrip(void **state) {
    (void)state;
    TPMU_PUBLIC_ID id = { 0 };

    id.mlkem.size = TPM2_MLKEM_768_PUB_SIZE;
    fill_pattern(id.mlkem.buffer, id.mlkem.size, 0xd0);
    assert_tpmu_public_id_roundtrip(TPM2_ALG_MLKEM, &id);

    memset(&id, 0, sizeof(id));
    id.mldsa.size = TPM2_MLDSA_65_PUB_SIZE;
    fill_pattern(id.mldsa.buffer, id.mldsa.size, 0xd1);
    assert_tpmu_public_id_roundtrip(TPM2_ALG_MLDSA, &id);

    memset(&id, 0, sizeof(id));
    id.mldsa.size = TPM2_MLDSA_87_PUB_SIZE;
    fill_pattern(id.mldsa.buffer, id.mldsa.size, 0xd2);
    assert_tpmu_public_id_roundtrip(TPM2_ALG_HASH_MLDSA, &id);
}

static void
assert_tpmu_sensitive_composite_roundtrip(TPMI_ALG_PUBLIC selector,
                                            TPMU_SENSITIVE_COMPOSITE *src) {
    uint8_t                  buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t                  buf2[PQC_BUF_SIZE] = { 0 };
    TPMU_SENSITIVE_COMPOSITE dest = { 0 };
    size_t                   offset = 0;
    TSS2_RC                  rc;

    rc = Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Marshal(src, selector, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Unmarshal(buf1, sizeof(buf1), &offset, selector,
                                                    &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(src, &dest, sizeof(*src));

    offset = 0;
    rc = Tss2_MU_TPMU_SENSITIVE_COMPOSITE_Marshal(&dest, selector, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpmu_sensitive_composite_roundtrip(void **state) {
    (void)state;
    TPMU_SENSITIVE_COMPOSITE sens = { 0 };

    sens.mlkem.size = TPM2_MLKEM_PRIVATE_KEY_SEED_SIZE;
    fill_pattern(sens.mlkem.buffer, sens.mlkem.size, 0xe0);
    assert_tpmu_sensitive_composite_roundtrip(TPM2_ALG_MLKEM, &sens);

    memset(&sens, 0, sizeof(sens));
    sens.mldsa.size = TPM2_MLDSA_PRIVATE_KEY_SEED_SIZE;
    fill_pattern(sens.mldsa.buffer, sens.mldsa.size, 0xe1);
    assert_tpmu_sensitive_composite_roundtrip(TPM2_ALG_MLDSA, &sens);

    memset(&sens, 0, sizeof(sens));
    sens.mldsa.size = TPM2_MLDSA_PRIVATE_KEY_SEED_SIZE;
    fill_pattern(sens.mldsa.buffer, sens.mldsa.size, 0xe2);
    assert_tpmu_sensitive_composite_roundtrip(TPM2_ALG_HASH_MLDSA, &sens);
}

static void
pqc_tpmu_encrypted_secret_mlkem_roundtrip(void **state) {
    (void)state;
    TPMU_ENCRYPTED_SECRET src = { 0 };
    TPMU_ENCRYPTED_SECRET dest = { 0 };
    size_t                offset = 0;
    uint8_t               buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t               buf2[PQC_BUF_SIZE] = { 0 };
    TSS2_RC               rc;

    fill_pattern(src.mlkem, TPM2_MAX_MLKEM_CT_SIZE, 0xf0);

    rc = Tss2_MU_TPMU_ENCRYPTED_SECRET_Marshal(&src, TPM2_ALG_MLKEM, buf1, sizeof(buf1),
                                               &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, TPM2_MAX_MLKEM_CT_SIZE);

    offset = 0;
    rc = Tss2_MU_TPMU_ENCRYPTED_SECRET_Unmarshal(buf1, sizeof(buf1), &offset, TPM2_ALG_MLKEM,
                                                 &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, TPM2_MAX_MLKEM_CT_SIZE);
    assert_memory_equal(&src, &dest, sizeof(src));

    offset = 0;
    rc = Tss2_MU_TPMU_ENCRYPTED_SECRET_Marshal(&dest, TPM2_ALG_MLKEM, buf2, sizeof(buf2),
                                               &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

static void
pqc_tpmi_mlkem_parms_roundtrip(void **state) {
    (void)state;
    static const TPMI_MLKEM_PARMS sets[] = { TPM2_MLKEM_PARMS_512, TPM2_MLKEM_PARMS_768,
                                             TPM2_MLKEM_PARMS_1024 };
    size_t offset = 0;
    uint8_t buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t buf2[PQC_BUF_SIZE] = { 0 };
    TPMI_MLKEM_PARMS dest = 0;
    TSS2_RC rc;

    for (size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++) {
        offset = 0;
        rc = Tss2_MU_TPMI_MLKEM_PARMS_Marshal(sets[i], buf1, sizeof(buf1), &offset);
        assert_int_equal(rc, TSS2_RC_SUCCESS);

        offset = 0;
        rc = Tss2_MU_TPMI_MLKEM_PARMS_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
        assert_int_equal(rc, TSS2_RC_SUCCESS);
        assert_int_equal(dest, sets[i]);

        offset = 0;
        rc = Tss2_MU_TPMI_MLKEM_PARMS_Marshal(dest, buf2, sizeof(buf2), &offset);
        assert_int_equal(rc, TSS2_RC_SUCCESS);
        assert_memory_equal(buf1, buf2, offset);
    }
}

static void
pqc_tpmi_mldsa_parms_roundtrip(void **state) {
    (void)state;
    static const TPMI_MLDSA_PARMS sets[] = { TPM2_MLDSA_PARMS_44, TPM2_MLDSA_PARMS_65,
                                             TPM2_MLDSA_PARMS_87 };
    size_t offset = 0;
    uint8_t buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t buf2[PQC_BUF_SIZE] = { 0 };
    TPMI_MLDSA_PARMS dest = 0;
    TSS2_RC rc;

    for (size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++) {
        offset = 0;
        rc = Tss2_MU_TPMI_MLDSA_PARMS_Marshal(sets[i], buf1, sizeof(buf1), &offset);
        assert_int_equal(rc, TSS2_RC_SUCCESS);

        offset = 0;
        rc = Tss2_MU_TPMI_MLDSA_PARMS_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
        assert_int_equal(rc, TSS2_RC_SUCCESS);
        assert_int_equal(dest, sets[i]);

        offset = 0;
        rc = Tss2_MU_TPMI_MLDSA_PARMS_Marshal(dest, buf2, sizeof(buf2), &offset);
        assert_int_equal(rc, TSS2_RC_SUCCESS);
        assert_memory_equal(buf1, buf2, offset);
    }
}

static void
pqc_tpm2b_signature_mldsa_all_sizes(void **state) {
    (void)state;
    static const UINT16 sizes[] = { TPM2_MLDSA_44_SIG_SIZE, TPM2_MLDSA_65_SIG_SIZE,
                                    TPM2_MLDSA_87_SIG_SIZE };

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        TPM2B_SIGNATURE_MLDSA src = { 0 };
        TPM2B_SIGNATURE_MLDSA dest = { 0 };

        src.size = sizes[i];
        fill_pattern(src.buffer, src.size, (BYTE)(0x72 + i));

        assert_tpm2b_roundtrip(sizeof(UINT16) + src.size,
                               (TSS2_RC(*)(const void *, uint8_t[], size_t, size_t *))
                                   Tss2_MU_TPM2B_SIGNATURE_MLDSA_Marshal,
                               (TSS2_RC(*)(uint8_t const[], size_t, size_t *, void *))
                                   Tss2_MU_TPM2B_SIGNATURE_MLDSA_Unmarshal,
                               &src, &dest);
    }
}

static void
pqc_tpmt_signature_hash_mldsa_roundtrip(void **state) {
    (void)state;
    TPMT_SIGNATURE sig = { 0 };

    sig.sigAlg = TPM2_ALG_HASH_MLDSA;
    sig.signature.hash_mldsa.hash = TPM2_ALG_SHA256;
    sig.signature.hash_mldsa.signature.size = TPM2_MLDSA_65_SIG_SIZE;
    fill_pattern(sig.signature.hash_mldsa.signature.buffer,
                 sig.signature.hash_mldsa.signature.size, 0xb2);
    assert_tpmt_signature_roundtrip(&sig);
}

static void
pqc_tpmt_signature_hash_eddsa_roundtrip(void **state) {
    (void)state;
    TPMT_SIGNATURE sig = { 0 };

    sig.sigAlg = TPM2_ALG_HASH_EDDSA;
    sig.signature.hash_eddsa.size = 64;
    fill_pattern(sig.signature.hash_eddsa.buffer, sig.signature.hash_eddsa.size, 0xb3);
    assert_tpmt_signature_roundtrip(&sig);
}

static void
pqc_tpms_signature_hash_mldsa_roundtrip(void **state) {
    (void)state;
    TPMS_SIGNATURE_HASH_MLDSA src = { 0 };
    TPMS_SIGNATURE_HASH_MLDSA dest = { 0 };
    size_t                  offset = 0;
    uint8_t                 buf1[PQC_BUF_SIZE] = { 0 };
    uint8_t                 buf2[PQC_BUF_SIZE] = { 0 };
    TSS2_RC                 rc;

    src.hash = TPM2_ALG_SHA256;
    src.signature.size = TPM2_MLDSA_44_SIG_SIZE;
    fill_pattern(src.signature.buffer, src.signature.size, 0xc0);

    rc = Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Marshal(&src, buf1, sizeof(buf1), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    offset = 0;
    rc = Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Unmarshal(buf1, sizeof(buf1), &offset, &dest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(&src, &dest, sizeof(src));

    offset = 0;
    rc = Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Marshal(&dest, buf2, sizeof(buf2), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_memory_equal(buf1, buf2, offset);
}

int
main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(pqc_tpm2b_public_key_mlkem_roundtrip),
        cmocka_unit_test(pqc_tpm2b_kem_ciphertext_roundtrip),
        cmocka_unit_test(pqc_tpm2b_shared_secret_roundtrip),
        cmocka_unit_test(pqc_tpm2b_public_key_mldsa_roundtrip),
        cmocka_unit_test(pqc_tpm2b_private_key_mldsa_roundtrip),
        cmocka_unit_test(pqc_tpm2b_private_key_mlkem_roundtrip),
        cmocka_unit_test(pqc_tpm2b_signature_eddsa_roundtrip),
        cmocka_unit_test(pqc_tpm2b_signature_mldsa_roundtrip),
        cmocka_unit_test(pqc_tpm2b_signature_mldsa_all_sizes),
        cmocka_unit_test(pqc_tpm2b_signature_mldsa_bad_size),
        cmocka_unit_test(pqc_tpm2b_signature_ctx_roundtrip),
        cmocka_unit_test(pqc_tpm2b_signature_hint_roundtrip),
        cmocka_unit_test(pqc_tpmu_signature_roundtrip),
        cmocka_unit_test(pqc_tpmt_signature_mldsa_roundtrip),
        cmocka_unit_test(pqc_tpmt_signature_eddsa_roundtrip),
        cmocka_unit_test(pqc_tpmt_signature_hash_mldsa_roundtrip),
        cmocka_unit_test(pqc_tpmt_signature_hash_eddsa_roundtrip),
        cmocka_unit_test(pqc_tpmu_public_parms_roundtrip),
        cmocka_unit_test(pqc_tpmu_public_id_roundtrip),
        cmocka_unit_test(pqc_tpmu_sensitive_composite_roundtrip),
        cmocka_unit_test(pqc_tpmu_encrypted_secret_mlkem_roundtrip),
        cmocka_unit_test(pqc_tpmi_mlkem_parms_roundtrip),
        cmocka_unit_test(pqc_tpmi_mldsa_parms_roundtrip),
        cmocka_unit_test(pqc_tpms_mlkem_parms_roundtrip),
        cmocka_unit_test(pqc_tpms_mldsa_parms_roundtrip),
        cmocka_unit_test(pqc_tpms_hash_mldsa_parms_roundtrip),
        cmocka_unit_test(pqc_tpms_signature_hash_mldsa_roundtrip),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
