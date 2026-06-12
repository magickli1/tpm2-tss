# TPM2-TSS Interface Inventory (PQC Fork)

Standalone index of **tss2-sys**, **tss2-mu**, **tss2-esys**, and **types** coverage in this repository, cross-referenced against the TCG TPM 2.0 Library (Part 2 v185 rc4 command-code table). For per-command parameters, handle counts, and coding patterns, see [PQC API Reference](pqc-api-reference.md).

**Repository:** `/home/magickli/tpm/tpm2-tss_pqc`  
**Verified:** headers, `src/tss2-sys/api/`, and `lib/*.def` / `lib/*.map` export lists.

---

## 1. Scope and layers

| Layer | Header | Role in this fork |
|-------|--------|-------------------|
| **Types** | `include/tss2/tss2_tpm2_types.h` | Algorithm IDs, PQC structures, command codes (CCs) |
| **MU** (Marshal/Unmarshal) | `include/tss2/tss2_mu.h` | Wire-format encode/decode for TPM types |
| **Sys** (SAPI) | `include/tss2/tss2_sys.h` | Low-level `_Prepare` / `_Complete` / one-shot command wrappers |
| **ESYS** | `include/tss2/tss2_esys.h` | High-level resource/session API — **not extended for PQC** |

**Fork focus:** v1.83 ECC encrypt/decrypt (`0x199`–`0x19A`) and v1.85 PQC/KEM/sequence-sign commands (`0x1A3`–`0x1AA`), plus supporting types and MU.

---

## 2. Spec command map (TCG SSOT): 0x198–0x1AA

Authoritative assignment from **TCG TPM 2.0 Library Part 2** (v185 rc4). Version column reflects Part 0 changelog.

| CC | Spec command | Introduced | Repo Sys API | Repo CC macro |
|----|--------------|------------|--------------|---------------|
| `0x198` | `TPM2_ACT_SetTimeout` | ≪1.83 | ✓ | `TPM2_CC_ACT_SetTimeout` |
| `0x199` | `TPM2_ECC_Encrypt` | **1.83** | ✓ | `TPM2_CC_ECC_Encrypt` |
| `0x19A` | `TPM2_ECC_Decrypt` | **1.83** | ✓ | `TPM2_CC_ECC_Decrypt` |
| `0x19B` | `TPM2_PolicyCapability` | **1.83** | ✗ | — |
| `0x19C` | `TPM2_PolicyParameters` | **1.83** | ✗ | — |
| `0x19D` | `TPM2_NV_DefineSpace2` | **1.83** | ✗ | — |
| `0x19E` | `TPM2_NV_ReadPublic2` | **1.83** | ✗ | — |
| `0x19F` | `TPM2_SetCapability` | **1.83** | ✗ | — |
| `0x1A0` | `TPM2_ReadOnlyControl` | **184** | ✗ | — |
| `0x1A1` | `TPM2_PolicyTransportSPDM` | **184** | ✗ | — |
| `0x1A2` | **Reserved** | — | — (legacy macro only) | `TPM2_CC_SignVerifySequenceStart`* |
| `0x1A3` | `TPM2_VerifySequenceComplete` | **185** | ✓ | `TPM2_CC_VerifySequenceComplete` |
| `0x1A4` | `TPM2_SignSequenceComplete` | **185** | ✓ | `TPM2_CC_SignSequenceComplete` |
| `0x1A5` | `TPM2_VerifyDigestSignature` | **185** | ✓ | `TPM2_CC_VerifyDigestSignature` |
| `0x1A6` | `TPM2_SignDigest` | **185** | ✓ | `TPM2_CC_SignDigest` |
| `0x1A7` | `TPM2_Encapsulate` | **185** | ✓ | `TPM2_CC_Encapsulate` |
| `0x1A8` | `TPM2_Decapsulate` | **185** | ✓ | `TPM2_CC_Decapsulate` |
| `0x1A9` | `TPM2_VerifySequenceStart` | **185** | ✓ | `TPM2_CC_VerifySequenceStart` |
| `0x1AA` | `TPM2_SignSequenceStart` | **185** | ✓ | `TPM2_CC_SignSequenceStart` |
| — | **`TPM_CC_LAST`** | — | — | `TPM2_CC_LAST = 0x1AA` |

\* Legacy merged CC — see [§9 Known implementation deviations](#9-known-implementation-deviations).

---

## 3. Sys API inventory

### 3.1 Global Sys infrastructure

Shared by all TPM commands (not tied to a single CC):

| Function | Source | Exported (`.def`) | Exported (`.map`) |
|----------|--------|-------------------|-------------------|
| `Tss2_Sys_GetContextSize` | `src/tss2-sys/api/Tss2_Sys_GetContextSize.c` | ✓ | ✓ |
| `Tss2_Sys_Initialize` | `Tss2_Sys_Initialize.c` | ✓ | ✓ |
| `Tss2_Sys_Finalize` | `Tss2_Sys_Finalize.c` | ✓ | ✓ |
| `Tss2_Sys_GetTctiContext` | `Tss2_Sys_GetTctiContext.c` | ✓ | ✓ |
| `Tss2_Sys_GetDecryptParam` / `SetDecryptParam` | respective `.c` | ✓ | ✓ |
| `Tss2_Sys_GetEncryptParam` / `SetEncryptParam` | respective `.c` | ✓ | ✓ |
| `Tss2_Sys_GetCpBuffer` / `GetRpBuffer` | respective `.c` | ✓ | ✓ |
| `Tss2_Sys_SetCmdAuths` / `GetRspAuths` | respective `.c` | ✓ | ✓ |
| `Tss2_Sys_GetCommandCode` | `Tss2_Sys_GetCommandCode.c` | ✓ | ✓ |
| `Tss2_Sys_ExecuteAsync` / `ExecuteFinish` | respective `.c` | ✓ | ✓ |
| `Tss2_Sys_Execute` | `Tss2_Sys_Execute.c` | ✗ | ✓ |
| `Tss2_Sys_Abort` | `Tss2_Sys_Abort.c` | ✓ | ✓ |

All TPM command families share `ExecuteAsync` / `ExecuteFinish` (exported once).

### 3.2 Baseline commands (summary count)

| Metric | Count |
|--------|------:|
| Implementation files in `src/tss2-sys/api/` | **145** |
| TPM command families (`*_Prepare` in header) | **130** |
| Upstream baseline commands (excluding fork additions) | **~120** |
| `TSS2_RC Tss2_Sys_*` declarations in `tss2_sys.h` | **402** |

Each command family typically exposes three symbols: `_Prepare`, `_Complete`, and a one-shot wrapper (e.g. `Tss2_Sys_Startup`).

### 3.3 Fork additions: v1.83 ECC + v1.85 PQC

Each row: CC, Sys functions (Prepare / Complete / one-shot), and source file.

#### v1.83 — ECC encrypt/decrypt (2 commands, 6 Sys functions)

| CC | Command | Sys functions | Source file |
|----|---------|---------------|-------------|
| `0x199` | `ECC_Encrypt` | `Tss2_Sys_ECC_Encrypt_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_ECC_Encrypt.c` |
| `0x19A` | `ECC_Decrypt` | `Tss2_Sys_ECC_Decrypt_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_ECC_Decrypt.c` |

#### v1.85 — PQC / KEM / sequence sign (8 commands, 24 Sys functions)

| CC | Command | Sys functions | Source file |
|----|---------|---------------|-------------|
| `0x1A7` | `Encapsulate` | `Tss2_Sys_Encapsulate_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_Encapsulate.c` |
| `0x1A8` | `Decapsulate` | `Tss2_Sys_Decapsulate_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_Decapsulate.c` |
| `0x1A6` | `SignDigest` | `Tss2_Sys_SignDigest_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_SignDigest.c` |
| `0x1A5` | `VerifyDigestSignature` | `Tss2_Sys_VerifyDigestSignature_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_VerifyDigestSignature.c` |
| `0x1AA` | `SignSequenceStart` | `Tss2_Sys_SignSequenceStart_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_SignSequenceStart.c` |
| `0x1A9` | `VerifySequenceStart` | `Tss2_Sys_VerifySequenceStart_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_VerifySequenceStart.c` |
| `0x1A4` | `SignSequenceComplete` | `Tss2_Sys_SignSequenceComplete_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_SignSequenceComplete.c` |
| `0x1A3` | `VerifySequenceComplete` | `Tss2_Sys_VerifySequenceComplete_{Prepare,Complete,}` | `src/tss2-sys/api/Tss2_Sys_VerifySequenceComplete.c` |

`SequenceUpdate` for in-flight sign/verify sequences continues to use the existing `TPM2_CC_SequenceUpdate` (`0x15C`).

See [PQC API Reference](pqc-api-reference.md) for implementation details.

---

## 4. MU API inventory (PQC / EdDSA types)

PQC-related marshal/unmarshal pairs exported in `lib/tss2-mu.def`.

### TPM2B (10 types × 2 = 20 pairs)

| Type | Marshal | Unmarshal |
|------|---------|-----------|
| `TPM2B_PUBLIC_KEY_MLKEM` | `Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Marshal` | `_Unmarshal` |
| `TPM2B_PRIVATE_KEY_MLKEM` | ✓ | ✓ |
| `TPM2B_KEM_CIPHERTEXT` | ✓ | ✓ |
| `TPM2B_SHARED_SECRET` | ✓ | ✓ |
| `TPM2B_PUBLIC_KEY_MLDSA` | ✓ | ✓ |
| `TPM2B_PRIVATE_KEY_MLDSA` | ✓ | ✓ |
| `TPM2B_SIGNATURE_EDDSA` | ✓ | ✓ |
| `TPM2B_SIGNATURE_MLDSA` | ✓ | ✓ |
| `TPM2B_SIGNATURE_CTX` | ✓ | ✓ |
| `TPM2B_SIGNATURE_HINT` | ✓ | ✓ |

### TPMS (4 types × 2 = 8 pairs)

| Type | Notes |
|------|-------|
| `TPMS_MLKEM_PARMS` | ML-KEM public-key parameters |
| `TPMS_MLDSA_PARMS` | ML-DSA parameters |
| `TPMS_HASH_MLDSA_PARMS` | Hash-ML-DSA parameters |
| `TPMS_SIGNATURE_HASH_MLDSA` | Hash + ML-DSA signature body |

EdDSA scheme bodies (`TPMS_SIG_SCHEME_EDDSA`, `TPMS_SIG_SCHEME_HASH_EDDSA`) are empty (`TPMS_EMPTY`) and encoded via `TPMU_SIG_SCHEME`.

### TPMI (2 types × 2 = 4 pairs)

| Type | Values |
|------|--------|
| `TPMI_MLKEM_PARMS` | 512 / 768 / 1024 |
| `TPMI_MLDSA_PARMS` | 44 / 65 / 87 |

### TPMU / TPMT (extended via existing selectors)

| Union / template | PQC / EdDSA members |
|------------------|---------------------|
| `TPMU_SIGNATURE` | `eddsa`, `hash_eddsa`, `mldsa`, `hash_mldsa` |
| `TPMU_SIG_SCHEME` / `TPMU_ASYM_SCHEME` | `eddsa`, `hash_eddsa` |
| `TPMU_PUBLIC_PARMS` | `mlkemDetail`, `mldsaDetail`, `hash_mldsaDetail` |
| `TPMU_PUBLIC_ID` | `mlkem`, `mldsa` |
| `TPMU_SENSITIVE_COMPOSITE` | `mldsa`, `mlkem` private-key seeds |
| `TPMU_ENCRYPTED_SECRET` | `mlkem` ciphertext slot |
| `TPMT_SIGNATURE` | Selector covers EdDSA / Hash-EdDSA / ML-DSA / Hash-ML-DSA |
| `TPMT_PUBLIC` / `TPMT_PUBLIC_PARMS` / `TPMT_SENSITIVE` | Carry PQC key material via extended `TPMU_*` |

**Dedicated PQC MU export total:** 32 marshal/unmarshal pairs (20 + 8 + 4).  
**Full MU library:** 316 exported `Tss2_MU_*` symbols (158 type families × Marshal + Unmarshal).

---

## 5. Types header (`tss2_tpm2_types.h`) — algorithms, structures, CCs

### Algorithms added for PQC / EdDSA

| Macro | Value | Purpose |
|-------|-------|---------|
| `TPM2_ALG_EDDSA` | `0x0060` | EdDSA signatures |
| `TPM2_ALG_HASH_EDDSA` | `0x0061` | Pre-hash EdDSA |
| `TPM2_ALG_MLKEM` | `0x00A0` | ML-KEM (KEM) |
| `TPM2_ALG_MLDSA` | `0x00A1` | ML-DSA signatures |
| `TPM2_ALG_HASH_MLDSA` | `0x00A2` | Pre-hash ML-DSA |
| `TPM2_ALG_LAST` | `0x00A2` | — |

### ECC curves (EdDSA support)

| Macro | Value |
|-------|-------|
| `TPM2_ECC_CURVE_25519` | `0x0040` |
| `TPM2_ECC_CURVE_448` | `0x0041` |

### Parameter-set enums

| Type | Sets |
|------|------|
| `TPMI_MLKEM_PARMS` | NONE, 512, 768, 1024 |
| `TPMI_MLDSA_PARMS` | NONE, 44, 65, 87 |

### Command codes (fork-relevant block)

Defined from `TPM2_CC_ECC_Encrypt` through `TPM2_CC_LAST` — see [§2](#2-spec-command-map-tcg-ssot-0198–0x1aa).

### Structures (representative)

| Category | Examples |
|----------|----------|
| ML-KEM keys / KEM | `TPM2B_PUBLIC_KEY_MLKEM`, `TPM2B_KEM_CIPHERTEXT`, `TPM2B_SHARED_SECRET`, `TPMS_MLKEM_PARMS` |
| ML-DSA keys / sigs | `TPM2B_PUBLIC_KEY_MLDSA`, `TPM2B_SIGNATURE_MLDSA`, `TPMS_MLDSA_PARMS`, `TPMS_HASH_MLDSA_PARMS` |
| EdDSA | `TPM2B_SIGNATURE_EDDSA`, `TPM2B_SIGNATURE_CTX`, `TPM2B_SIGNATURE_HINT` |
| Size limits | ML-KEM / ML-DSA public key, ciphertext, signature, seed, and context buffer macros |

---

## 6. Export symbol statistics (`.def` / `.map`)

Counts from `grep -c` on export lists (verified in repo):

| Library | File | Lines | Exported symbols | Notes |
|---------|------|------:|-----------------:|-------|
| **tss2-sys** | `lib/tss2-sys.def` | 405 | **403** `Tss2_Sys_*` | Windows/DLL export list |
| | `lib/tss2-sys.map` | — | **407** | +4 vs `.def`: `Tss2_Sys_Execute`, `CreateLoaded`, `PolicyAuthorizeNV`, `PolicyTemplate` one-shots |
| **tss2-mu** | `lib/tss2-mu.def` | 318 | **316** `Tss2_MU_*` | `.map` matches (316) |
| **tss2-esys** | `lib/tss2-esys.def` | 389 | **387** `Esys_*` | `.map`: 390 |

---

## 7. ESYS — not extended

**`tss2-esys` was intentionally not modified for PQC.** `lib/tss2-esys.def` (387 `Esys_*` symbols) and `include/tss2/tss2_esys.h` stop at the upstream command set.

**Missing ESYS wrappers for fork Sys commands:**

| Missing `Esys_*` | CC |
|------------------|-----|
| `Encapsulate` | `0x1A7` |
| `Decapsulate` | `0x1A8` |
| `SignDigest` | `0x1A6` |
| `VerifyDigestSignature` | `0x1A5` |
| `SignSequenceStart` | `0x1AA` |
| `VerifySequenceStart` | `0x1A9` |
| `SignSequenceComplete` | `0x1A4` |
| `VerifySequenceComplete` | `0x1A3` |

Also missing: v1.83 gap commands (`0x19B`–`0x19F`) and v184 commands (`ReadOnlyControl`, `PolicyTransportSPDM`).

**Present in ESYS (upstream, not fork-specific):** `Esys_ECC_Encrypt` / `Esys_ECC_Decrypt` (with Async/Finish variants).

Applications using ESYS must call PQC Sys APIs via `Esys_GetSysContext()` + `Tss2_Sys_*`, or add local wrappers.

---

## 8. Spec gaps (1.83 / 184 / 185)

Separate **spec truth** (TCG Part 2) from **repo implementation**.

### Spec defines; repo has no Sys API / types

| Version | CC range | Commands | Repo status |
|---------|----------|----------|---------------|
| **1.83** | `0x19B`–`0x19F` | `PolicyCapability`, `PolicyParameters`, `NV_DefineSpace2`, `NV_ReadPublic2`, `SetCapability` | ✗ No `Tss2_Sys_*`, no CC macros, no supporting structures (`NV_PUBLIC_2`, etc.) |
| **184** | `0x1A0`–`0x1A1` | `ReadOnlyControl`, `PolicyTransportSPDM` | ✗ No Sys / ESYS |
| **184** | Capabilities | `TPM_CAP_PUB_KEYS` (`0x0B`), `TPM_CAP_SPDM_SESSION_INFO` (`0x0C`) | ✗ Not in types header |
| **184** | Return codes | `TPM_RC_CHANNEL`, `TPM_RC_CHANNEL_KEY`, `TPM_RC_READ_ONLY` | ✗ Not in types header |

### Spec defines; repo implements (v1.85 PQC block)

| CC range | Commands | Repo status |
|----------|----------|-------------|
| `0x1A3`–`0x1A8` | Complete / digest / KEM commands | ✓ Sys + types + MU |
| `0x1A9`–`0x1AA` | Sequence Start commands | ✓ Sys uses spec CCs in Prepare |

### Spec defines; repo partially covers (v1.83 ECC)

| CC | Command | Repo status |
|----|---------|-------------|
| `0x199`–`0x19A` | `ECC_Encrypt`, `ECC_Decrypt` | ✓ Sys (also ESYS for ECC) |

---

## 9. Known implementation deviations

### 9.1 Legacy `TPM2_CC_SignVerifySequenceStart` (`0x1A2`)

| Item | Spec (Part 2 v185) | Current repo |
|------|-------------------|--------------|
| `0x1A2` | **Reserved** | `TPM2_CC_SignVerifySequenceStart` still defined in `tss2_tpm2_types.h` |
| Start commands | Separate CCs `0x1A9` / `0x1AA` | **Prepare paths use spec CCs** (`SignSequenceStart.c` → `0x1AA`; `VerifySequenceStart.c` → `0x1A9`) |
| Handle metadata | — | `sysapi_util.c` still registers `{ TPM2_CC_SignVerifySequenceStart, 1, 1 }` |

**Action for integrators:** Prefer `TPM2_CC_SignSequenceStart` / `TPM2_CC_VerifySequenceStart` on the wire. Treat `TPM2_CC_SignVerifySequenceStart` as a deprecated alias; remove when cleaning up `sysapi_util.c` and docs.

### 9.2 `TPM2_CC_LAST`

| Spec | Repo (current) |
|------|----------------|
| `0x1AA` | `TPM2_CC_LAST = 0x1AA` ✓ (aligned) |

### 9.3 Export list vs linker map

Four Sys one-shot symbols are in `tss2-sys.map` but absent from `tss2-sys.def`: `Tss2_Sys_Execute`, `Tss2_Sys_CreateLoaded`, `Tss2_Sys_PolicyAuthorizeNV`, `Tss2_Sys_PolicyTemplate`. Unix linkers use `.map`; Windows DLL builds rely on `.def`.

### 9.4 Documentation drift

`doc/pqc-api-reference.md` still references merged `0x1A2` Prepare examples in places; source files have moved to spec CCs. Prefer this inventory and live headers over stale doc snippets.

---

## 10. Related docs

| Document | Content |
|----------|---------|
| [PQC API Reference](pqc-api-reference.md) | Command parameters, handle counts, coding patterns, integration notes |
| TCG TPM 2.0 Library Part 2 §6.5 | Authoritative command-code table |
| TCG TPM 2.0 Library Part 0 | Version changelog (1.83 / 184 / 185 attribution) |

---

## Quick coverage summary

| Layer | v1.85 PQC (8 commands) | v1.83 ECC | v1.83/184 gaps |
|-------|------------------------|-----------|----------------|
| **Types** | ✓ CCs through `0x1AA`, algorithms, structures | ✓ | ✗ `0x19B`–`0x19F`, v184 caps/RCs |
| **MU** | ✓ 32 dedicated PQC pairs + extended TPMU/TPMT | — | — |
| **Sys** | ✓ 8 × 3 functions, exported | ✓ 2 × 3 functions | ✗ 7 commands |
| **ESYS** | ✗ | ✓ ECC only (upstream) | ✗ |
