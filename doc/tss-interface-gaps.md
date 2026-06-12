# TPM2-TSS Missing Interfaces (vs TCG Spec)

This document lists **only gaps** between this repository and the TCG TPM 2.0 Library Specification **Part 2 v1.85** (structures / command codes) and **Part 3** (command behavior). The spec is the single source of truth — not local header comments or older fork docs.

**Repository:** `/home/magickli/tpm/tpm2-tss_pqc`  
**Verified:** `grep` / header and `src/` inspection (2025-06-11).

For implemented v1.83 ECC and v1.85 PQC interfaces, see [PQC API Reference](pqc-api-reference.md).

---

## 1. Missing Sys commands (by spec version)

Columns **Missing in** use ✗ per layer: **Types** (`TPM2_CC_*` macro), **Sys** (`Tss2_Sys_*`), **MU** (marshal/unmarshal), **ESYS** (`Esys_*`).

### 1.83 (`0x19B`–`0x19F`)

| CC | Command | Spec version | Missing in |
|----|---------|--------------|------------|
| `0x19B` | `TPM2_PolicyCapability` | 1.83 | Types / Sys / ESYS |
| `0x19C` | `TPM2_PolicyParameters` | 1.83 | Types / Sys / ESYS |
| `0x19D` | `TPM2_NV_DefineSpace2` | 1.83 | Types / Sys / MU / ESYS |
| `0x19E` | `TPM2_NV_ReadPublic2` | 1.83 | Types / Sys / MU / ESYS |
| `0x19F` | `TPM2_SetCapability` | 1.83 | Types / Sys / MU / ESYS |

**Evidence:** `include/tss2/tss2_tpm2_types.h` jumps from `TPM2_CC_ECC_Decrypt` (`0x19A`) to `TPM2_CC_SignVerifySequenceStart` (`0x1A2`). No `Tss2_Sys_PolicyCapability`, `Tss2_Sys_NV_DefineSpace2`, etc. in `tss2_sys.h` or `src/tss2-sys/api/`. `sysapi_util.c` `commandArray[]` has no entries for `0x19B`–`0x19F`.

### 1.84 / 184 (`0x1A0`–`0x1A1`, capabilities `0x0B` / `0x0C`)

| CC | Command | Spec version | Missing in |
|----|---------|--------------|------------|
| `0x1A0` | `TPM2_ReadOnlyControl` | 184 | Types / Sys / ESYS |
| `0x1A1` | `TPM2_PolicyTransportSPDM` | 184 | Types / Sys / ESYS |

| Capability | Value | Spec version | Missing in |
|------------|-------|--------------|------------|
| `TPM2_CAP_PUB_KEYS` | `0x0B` | 184 | Types / MU |
| `TPM2_CAP_SPDM_SESSION_INFO` | `0x0C` | 184 | Types / MU |

**Evidence:** `grep` over `include/` and `src/` finds no `SPDM`, `ReadOnlyControl`, `PolicyTransportSPDM`, or `TPM2_CAP_PUB_KEYS`. `TPM2_CAP_LAST` remains `0x0A` (`TPM2_CAP_ACT`); spec v184 sets last standard cap to `0x0C`.

### 1.85 partial (`0x1A3`–`0x1AA`; `0x1A2` deviation)

**No missing Sys APIs** for the v1.85 PQC / digest-sign command block `0x1A3`–`0x1AA`. All eight families are present in `tss2_sys.h` and `src/tss2-sys/api/`.

| CC | Command | Spec version | Status |
|----|---------|--------------|--------|
| `0x1A3` | `TPM2_VerifySequenceComplete` | 1.85 | ✓ Sys |
| `0x1A4` | `TPM2_SignSequenceComplete` | 1.85 | ✓ Sys |
| `0x1A5` | `TPM2_VerifyDigestSignature` | 1.85 | ✓ Sys |
| `0x1A6` | `TPM2_SignDigest` | 1.85 | ✓ Sys |
| `0x1A7` | `TPM2_Encapsulate` | 1.85 | ✓ Sys |
| `0x1A8` | `TPM2_Decapsulate` | 1.85 | ✓ Sys |
| `0x1A9` | `TPM2_VerifySequenceStart` | 1.85 | ✓ Sys (Prepare uses `TPM2_CC_VerifySequenceStart`) |
| `0x1AA` | `TPM2_SignSequenceStart` | 1.85 | ✓ Sys (Prepare uses `TPM2_CC_SignSequenceStart`) |

**Remaining 1.85 gap (deviation, not absent API):** spec reserves `0x1A2`; this repo still defines legacy `TPM2_CC_SignVerifySequenceStart` and registers it in `sysapi_util.c`. Wire-format Prepare paths for Start commands correctly use `0x1A9` / `0x1AA` — see [§5](#5-implementation-deviations-not-missing-but-wrong-vs-spec).

**ESYS:** all eight v1.85 commands above lack `Esys_*` wrappers (see [§4](#4-esys-wrappers-all-pqc--184-commands--none)).

---

## 2. Missing types / RC / capability constants

### Command codes (`0x19B`–`0x1A1`)

All seven macros absent from `tss2_tpm2_types.h`:

- `TPM2_CC_PolicyCapability`, `TPM2_CC_PolicyParameters`
- `TPM2_CC_NV_DefineSpace2`, `TPM2_CC_NV_ReadPublic2`
- `TPM2_CC_SetCapability`
- `TPM2_CC_ReadOnlyControl`, `TPM2_CC_PolicyTransportSPDM`

### Capability constants (v184)

| Missing | Spec value | Notes |
|---------|------------|-------|
| `TPM2_CAP_PUB_KEYS` | `0x0000000B` | `GetCapability` returns `TPML_PUB_KEY` |
| `TPM2_CAP_SPDM_SESSION_INFO` | `0x0000000C` | `GetCapability` returns `TPML_SPDM_SESSION_INFO` |
| `TPM2_CAP_LAST` update | `0x0C` (not `0x0A`) | Header still ends at `TPM2_CAP_ACT` |

### Return codes (v184)

| Missing | Spec encoding | When returned |
|---------|---------------|---------------|
| `TPM2_RC_READ_ONLY` | `TPM2_RC_VER1 + 0x056` | TPM in read-only mode |
| `TPM2_RC_CHANNEL` | `TPM2_RC_FMT1 + 0x030` | Command needs secure-channel protection |
| `TPM2_RC_CHANNEL_KEY` | `TPM2_RC_FMT1 + 0x031` | Secure channel not established |

**Evidence:** `grep TPM2_RC_READ_ONLY|TPM2_RC_CHANNEL` → no matches in repo.

### SPDM / public-key structures (v184)

| Missing structure | Used by |
|-------------------|---------|
| `TPMS_SPDM_SESSION_INFO` | `TPM2_CAP_SPDM_SESSION_INFO`, `TPML_SPDM_SESSION_INFO` |
| `TPML_SPDM_SESSION_INFO` | `GetCapability`, `TPMU_CAPABILITIES` |
| `TPML_PUB_KEY` | `TPM2_CAP_PUB_KEYS`, `TPMU_CAPABILITIES` |
| `TPM_PUB_KEY_*` property constants (`TPM_PUB_KEY_TPM_SPDM_00` … `FF`) | `PolicyCapability` / `GetCapability` property selector |

### NV index v2 structures (v1.83)

| Missing structure | Used by |
|-------------------|---------|
| `TPMU_NV_PUBLIC_2` | `TPMT_NV_PUBLIC_2` selector |
| `TPMT_NV_PUBLIC_2` | `TPM2_NV_DefineSpace2`, `TPM2_NV_ReadPublic2` |
| `TPM2B_NV_PUBLIC_2` | command parameters |

Repo only has legacy `TPMS_NV_PUBLIC` / `TPM2B_NV_PUBLIC`.

### SetCapability structures (v1.83)

| Missing structure | Used by |
|-------------------|---------|
| `TPMU_SET_CAPABILITIES` | `TPMS_SET_CAPABILITY_DATA` |
| `TPMS_SET_CAPABILITY_DATA` | `TPM2_SetCapability` |
| `TPM2B_SET_CAPABILITY_DATA` | `TPM2_SetCapability` input |

### `TPMU_CAPABILITIES` union extension (v184)

`TPMU_CAPABILITIES` in `tss2_tpm2_types.h` ends at `actData` / `vendor`. Spec v184 adds:

- `pubKeys` → `TPML_PUB_KEY`
- `spdmSessionInfo` → `TPML_SPDM_SESSION_INFO`

Without these members, `Tss2_Sys_GetCapability_Complete` / `Tss2_MU_TPMU_CAPABILITIES_*` cannot decode v184 capability responses.

---

## 3. Missing MU (marshal/unmarshal for v1.83 / v184 types)

No `Tss2_MU_*` symbols exist for:

| Type family | Pairs needed | Blocks |
|-------------|-------------|--------|
| `TPMS_SPDM_SESSION_INFO` | Marshal + Unmarshal | v184 `GetCapability` |
| `TPML_SPDM_SESSION_INFO` | Marshal + Unmarshal | v184 `GetCapability` |
| `TPML_PUB_KEY` | Marshal + Unmarshal | v184 `GetCapability` |
| `TPMU_NV_PUBLIC_2` | Marshal + Unmarshal | v1.83 NV2 commands |
| `TPMT_NV_PUBLIC_2` | Marshal + Unmarshal | v1.83 NV2 commands |
| `TPM2B_NV_PUBLIC_2` | Marshal + Unmarshal | v1.83 NV2 commands |
| `TPMS_SET_CAPABILITY_DATA` | Marshal + Unmarshal | v1.83 `SetCapability` |
| `TPM2B_SET_CAPABILITY_DATA` | Marshal + Unmarshal | v1.83 `SetCapability` |
| `TPMU_SET_CAPABILITIES` | Marshal + Unmarshal | v1.83 `SetCapability` (if registry-defined) |

**Existing MU gap:** `Tss2_MU_TPMU_CAPABILITIES_{Marshal,Unmarshal}` (`src/tss2-mu/tpmu-types.c`) has no `TPM2_CAP_PUB_KEYS` or `TPM2_CAP_SPDM_SESSION_INFO` selector branches.

**Note:** v1.85 PQC types (ML-KEM, ML-DSA, EdDSA buffers) **are** implemented in MU — out of scope here; see [pqc-api-reference.md](pqc-api-reference.md).

---

## 4. ESYS wrappers (all PQC + 184 commands — none)

`tss2-esys` was not extended for fork Sys commands. `grep Esys_Encapsulate|Esys_ReadOnlyControl` → no matches.

### Missing v1.85 PQC / digest-sign (8 commands × 3 symbols each)

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

Each family normally exposes `_Async` and `_Finish` variants in addition to the one-shot call.

### Missing v1.83 gap commands (5)

`PolicyCapability`, `PolicyParameters`, `NV_DefineSpace2`, `NV_ReadPublic2`, `SetCapability` — no `Esys_*` symbols.

### Missing v184 commands (2)

`ReadOnlyControl`, `PolicyTransportSPDM` — no `Esys_*` symbols.

**Present (not a gap):** `Esys_ECC_Encrypt` / `Esys_ECC_Decrypt` (upstream ESYS, `0x199`–`0x19A`).

**Workaround:** `Esys_GetSysContext()` + direct `Tss2_Sys_*` for PQC and gap commands.

---

## 5. Implementation deviations (not "missing" but wrong vs spec)

### 5.1 `0x1A2` — merged `SignVerifySequenceStart` vs spec Reserved + `0x1A9` / `0x1AA`

| Item | Spec (Part 2 v1.85) | Current repo |
|------|---------------------|--------------|
| `0x1A2` | **Reserved** | `TPM2_CC_SignVerifySequenceStart` defined in `tss2_tpm2_types.h` |
| Start commands | Separate CCs `0x1A9` / `0x1AA` | **Prepare paths correct** (`SignSequenceStart.c` → `0x1AA`; `VerifySequenceStart.c` → `0x1A9`) |
| Handle metadata | — | `sysapi_util.c` still has `{ TPM2_CC_SignVerifySequenceStart, 1, 1 }` |
| Sys one-shot API | — | No `Tss2_Sys_SignVerifySequenceStart_*` (only legacy CC macro + metadata) |

**Integrator guidance:** use `TPM2_CC_SignSequenceStart` / `TPM2_CC_VerifySequenceStart` on the wire. Treat `TPM2_CC_SignVerifySequenceStart` as a deprecated fork artifact.

### 5.2 `TPM2_CC_LAST`

| Spec | Repo header (`tss2_tpm2_types.h`) | Stale doc |
|------|-----------------------------------|-----------|
| `0x1AA` | `TPM2_CC_LAST = 0x1AA` ✓ aligned | `doc/pqc-api-reference.md` still shows `0x1A8` in places — **doc drift**, not a types gap |

### 5.3 `TPM2_CAP_LAST`

| Spec v184 | Repo |
|-----------|------|
| `0x0C` (`TPM2_CAP_SPDM_SESSION_INFO`) | `0x0A` (`TPM2_CAP_ACT`) — **not updated** |

---

## 6. Summary count table

| Layer | Missing items count | Notes |
|-------|--------------------:|-------|
| **Types** | **~24** | 7 CC macros; 2 cap constants + `TPM2_CAP_LAST`; 3 RCs; ~11 structures/unions (`NV_PUBLIC_2`, SetCapability, SPDM, `TPMU_CAPABILITIES` members) |
| **Sys** | **7 commands** (21 API functions) | `0x19B`–`0x1A1`; no Prepare/Complete/one-shot |
| **MU** | **~18 symbol pairs** | 9 type families × (Marshal + Unmarshal); plus `TPMU_CAPABILITIES` selector extension |
| **ESYS** | **15 command families** | 8 PQC v1.85 + 5 v1.83 gaps + 2 v184 (~45 symbols with Async/Finish) |
| **Deviations** | **2** | Legacy `0x1A2` macro/metadata; stale `TPM2_CAP_LAST` |

**v1.85 PQC Sys block (`0x1A3`–`0x1AA`):** 0 missing Sys commands; 8 missing ESYS families.

---

## Related docs

| Document | Role |
|----------|------|
| [pqc-api-reference.md](pqc-api-reference.md) | Implemented v1.83 ECC + v1.85 PQC (what **is** in the repo) |
| [tpm-v183-v184-gap-reference.md](tpm-v183-v184-gap-reference.md) | Deeper v1.83/v184 command-parameter notes (Chinese) |
| TCG Part 2 §6.5 | Authoritative command-code table |
| TCG Part 0 | Version changelog (1.83 / 184 / 185 attribution) |
