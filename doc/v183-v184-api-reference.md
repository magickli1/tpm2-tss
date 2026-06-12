# TPM 2.0 v1.83 / v184 头文件与实现设计摘录

按 **TCG TPM 2.0 Library Specification**（Part 0/2/3，v185 rc4 交叉核对）整理 **tpm2-tss_pqc** 的 **v1.83 策略/NV2/SetCapability** 与 **v184 ReadOnlyControl/SPDM 策略** 类型与 Sys/MU API。**Sys/MU 与单元测试已实现**（见 [tpm-v183-v184-gap-reference.md](tpm-v183-v184-gap-reference.md)）；行号随源码更新。

规范：**TPM 2.0 Library Specification v1.83（`0x19B`–`0x19F`）+ v184（`0x1A0`–`0x1A1`）**

**相关文档：**

- [tpm-v183-v184-gap-reference.md](tpm-v183-v184-gap-reference.md) — 缺口清单与实现阶段
- [pqc-api-reference.md](pqc-api-reference.md) — v1.85 PQC（已实现部分）

**实现范围：** 本文档描述 **TSS2-Sys** 与 **TSS2-MU**。**ESYS** / **FAPI** / Policy 工具链不在首阶段实现范围内。

---

## TSS Sys API 约定（nullable 参数与 session 解密）

与 upstream tpm2-tss / 本 fork [pqc-api-reference.md](pqc-api-reference.md) 一致：

| 规则 | 说明 |
|------|------|
| **可空 TPM2B** | `Prepare` 时指针为 `NULL` → 栈上 `{ .size = 0 }` 占位，经 `Tss2_MU_TPM2B_*_Marshal`（wire 上为 `UINT16(0)`） |
| **`decryptNull`** | **仅**在该命令的**第一个** session-decrypt 目标 TPM2B 为 `NULL` **或** `size==0` 时置 `ctx->decryptNull = 1` |
| **`SetDecryptParam`** | 通过 `Tss2_Sys_GetDecryptParam` 只能取得**第一个** decrypt 参数 |
| **auth 标志** | `decryptAllowed` / `encryptAllowed` / `authAllowed` 在 `Prepare` 末尾、`CommonPrepareEpilogue` 之前设置 |

v1.83 / v184 命令的第一个 decrypt 目标与 auth 标志：

| 命令 | CC | 第一个 decrypt 参数 | 其他可空 TPM2B | `decrypt` | `encrypt` | `auth` |
|------|-----|---------------------|----------------|-----------|-----------|--------|
| `PolicyCapability` | `0x19B` | `operandB` | — | 1 | 0 | 1 |
| `PolicyParameters` | `0x19C` | `pHash` | — | 1 | 0 | 1 |
| `NV_DefineSpace2` | `0x19D` | `auth` | `publicInfo` | 1 | 0 | 1 |
| `NV_ReadPublic2` | `0x19E` | 无 | — | 0 | 1 | 1 |
| `SetCapability` | `0x19F` | `setCapabilityData` | — | 1 | 0 | 1 |
| `ReadOnlyControl` | `0x1A0` | 无 | — | 0 | 0 | 1 |
| `PolicyTransportSPDM` | `0x1A1` | `reqKeyName` | `tpmKeyName` | 1 | 0 | 1 |

### 必填 / 可选参数（Prepare 与一体式）

| API | 必填 | 可选（`NULL` → `UINT16(0)`） |
|-----|------|-------------------------------|
| `PolicyCapability` | `sysContext`, `policySession`, `offset`, `operation`, `capability`, `property` | `operandB`（`NULL`/`size==0` → `decryptNull`） |
| `PolicyParameters` | `sysContext`, `policySession` | `pHash`（`NULL`/`size==0` → `decryptNull`） |
| `NV_DefineSpace2` | `sysContext`, `authHandle` | `auth`（`NULL`/`size==0` → `decryptNull`）, `publicInfo` |
| `NV_ReadPublic2` | `sysContext`, `nvIndex` | — |
| `SetCapability` | `sysContext`, `authHandle` | `setCapabilityData`（`NULL`/`size==0` → `decryptNull`） |
| `ReadOnlyControl` | `sysContext`, `authHandle`, `state` | — |
| `PolicyTransportSPDM` | `sysContext`, `policySession` | `reqKeyName`（`NULL`/`size==0` → `decryptNull`）, `tpmKeyName` |

### 参数边界矩阵（Prepare）

| API | 参数 | `NULL` | `size==0` | 有效值 | 超大 `size` |
|-----|------|--------|-----------|--------|-------------|
| `PolicyCapability` | `operandB` | `decryptNull` + empty TPM2B | 同左 | marshal `TPM2B_OPERAND` | MU `BAD_SIZE` |
| `PolicyParameters` | `pHash` | `decryptNull` + empty TPM2B | 同左 | marshal `TPM2B_DIGEST` | MU `BAD_SIZE` |
| `NV_DefineSpace2` | `auth` | `decryptNull` + empty TPM2B | 同左 | marshal `TPM2B_AUTH` | MU `BAD_SIZE` |
| `NV_DefineSpace2` | `publicInfo` | marshal `UINT16(0)` | marshal NV2 | marshal `TPM2B_NV_PUBLIC_2` | MU / `ValidateNV_Public2` |
| `NV_ReadPublic2` | `nvIndex` | — | — | marshal `UINT32` | — |
| `SetCapability` | `setCapabilityData` | `decryptNull` + empty TPM2B | 同左 | marshal `TPM2B_SET_CAPABILITY_DATA` | MU `BAD_SIZE` |
| `ReadOnlyControl` | `state` | — | — | marshal `UINT8` (`TPMI_YES_NO`) | — |
| `PolicyTransportSPDM` | `reqKeyName` | `decryptNull` + empty TPM2B | 同左 | marshal `TPM2B_NAME` | MU `BAD_SIZE` |
| `PolicyTransportSPDM` | `tpmKeyName` | marshal empty TPM2B | marshal（size 0） | marshal `TPM2B_NAME` | MU `BAD_SIZE` |

**`NV_DefineSpace2` 校验：** 在 `Prepare` 前调用 `ValidateNV_Public2(publicInfo)`（泛化自 `ValidateNV_Public`，按 `handleType` 分支校验 `nameAlg` 与 `TPMA_NV` / `TPMA_NV_EXP`）。

**`ReadOnlyControl` 与全局只读：** TPM 处于只读模式时，`NV_DefineSpace2` / `SetCapability` 等写命令返回 `TPM2_RC_READ_ONLY`；`NV_ReadPublic2` / `PolicyTransportSPDM` 等仍允许（Part 3 Table 207）。

---

## `include/tss2/tss2_tpm2_types.h`（待添加）

**插入位置：** `TPM2_CC_ECC_Decrypt`（`0x19A`）之后、`TPM2_CC_SignVerifySequenceStart`（`0x1A2`，本 fork PQC）之前。实现时需评估 CC 布局冲突（见文末 Known gaps）。

### 命令码

```c
#define TPM2_CC_PolicyCapability    ((TPM2_CC)0x0000019b)
#define TPM2_CC_PolicyParameters    ((TPM2_CC)0x0000019c)
#define TPM2_CC_NV_DefineSpace2     ((TPM2_CC)0x0000019d)
#define TPM2_CC_NV_ReadPublic2      ((TPM2_CC)0x0000019e)
#define TPM2_CC_SetCapability       ((TPM2_CC)0x0000019f)
#define TPM2_CC_ReadOnlyControl     ((TPM2_CC)0x000001a0)
#define TPM2_CC_PolicyTransportSPDM ((TPM2_CC)0x000001a1)
/* TPM2_CC_LAST 保持本 fork 末命令（当前 0x1AA）或按发布策略单独 bump */
```

当前仓库在 `0x19A` 与 `0x1A2` 之间 **无** 上述宏（证据：`tss2_tpm2_types.h` `L304`–`L305`）。

### 句柄类型（NV2，Part 2 Table 29）

本仓库已有 `TPM2_HT_NV_INDEX`（`0x01`）。待添加：

```c
#define TPM2_HT_EXTERNAL_NV  ((TPM2_HT)0x11) /* External NV Index — v1.72+ */
#define TPM2_HT_PERMANENT_NV ((TPM2_HT)0x12) /* Permanent NV Index — v1.73+ */
```

### Capability 常量（v184，Part 2 §6.16）

```c
#define TPM2_CAP_PUB_KEYS          ((TPM2_CAP)0x0000000b) /* TPML_PUB_KEY */
#define TPM2_CAP_SPDM_SESSION_INFO ((TPM2_CAP)0x0000000c) /* TPML_SPDM_SESSION_INFO */
#define TPM2_CAP_LAST              ((TPM2_CAP)0x0000000c) /* 替换当前 0x0A */
```

当前 `TPM2_CAP_LAST` 止于 `TPM2_CAP_ACT`（`0x0A`，`tss2_tpm2_types.h` `L734`）。

### 返回码（v184）

```c
#define TPM2_RC_READ_ONLY   ((TPM2_RC)(TPM2_RC_VER1 + 0x056)) /* TPM 全局只读模式 */
#define TPM2_RC_CHANNEL     ((TPM2_RC)(TPM2_RC_FMT1 + 0x030)) /* 需要安全信道 */
#define TPM2_RC_CHANNEL_KEY ((TPM2_RC)(TPM2_RC_FMT1 + 0x031)) /* 安全信道密钥不匹配 */
```

### NV2 类型链（Part 2 §13.5–13.11）

**`TPMA_NV_EXP`：** `UINT64` 扩展属性；低 32 位与 `TPMA_NV` 语义一致，高 32 位含 External NV 专有属性（Part 2 Table 226）：

```c
typedef UINT64 TPMA_NV_EXP;

#define TPMA_NV_EXP_EXTERNAL_NV_ENCRYPTION   ((TPMA_NV_EXP)0x0000000100000000ULL)
#define TPMA_NV_EXP_EXTERNAL_NV_INTEGRITY    ((TPMA_NV_EXP)0x0000000200000000ULL)
#define TPMA_NV_EXP_EXTERNAL_NV_ANTIROLLBACK ((TPMA_NV_EXP)0x0000000400000000ULL)
/* 低 32 位复用 TPMA_NV 常量（TPMA_NV_PPWRITE 等） */
```

**`TPMI_RH_NV_EXP_INDEX`：** 扩展 NV 句柄（legacy `TPMI_RH_NV_INDEX` + External NV 范围）。

```c
typedef TPMI_RH_NV_INDEX TPMI_RH_NV_EXP_INDEX;
```

**`TPMS_NV_PUBLIC_EXP_ATTR`（Table 229）：**

```c
typedef struct TPMS_NV_PUBLIC_EXP_ATTR TPMS_NV_PUBLIC_EXP_ATTR;
struct TPMS_NV_PUBLIC_EXP_ATTR {
    TPMI_RH_NV_EXP_INDEX nvIndex;
    TPMI_ALG_HASH        nameAlg;
    TPMA_NV_EXP          attributes;
    TPM2B_DIGEST         authPolicy;
    UINT16               dataSize;
};
```

**`TPMU_NV_PUBLIC_2` / `TPMT_NV_PUBLIC_2` / `TPM2B_NV_PUBLIC_2`（Table 230–232）：**

```c
typedef union TPMU_NV_PUBLIC_2 TPMU_NV_PUBLIC_2;
union TPMU_NV_PUBLIC_2 {
    TPMS_NV_PUBLIC          nvIndex;      /* selector: TPM_HT_NV_INDEX */
    TPMS_NV_PUBLIC_EXP_ATTR externalNV;   /* selector: TPM_HT_EXTERNAL_NV */
    TPMS_NV_PUBLIC          permanentNV;  /* selector: TPM_HT_PERMANENT_NV */
};

typedef struct TPMT_NV_PUBLIC_2 TPMT_NV_PUBLIC_2;
struct TPMT_NV_PUBLIC_2 {
    TPM_HT             handleType;
    TPMU_NV_PUBLIC_2   publicArea;
};

typedef struct TPM2B_NV_PUBLIC_2 TPM2B_NV_PUBLIC_2;
struct TPM2B_NV_PUBLIC_2 {
    UINT16           size;
    TPMT_NV_PUBLIC_2 nvPublic;
};
```

| `handleType` | `publicArea` 成员 | `attributes` 类型 | 说明 |
|--------------|-------------------|-------------------|------|
| `TPM_HT_NV_INDEX` | `nvIndex` | `TPMA_NV`（32 位） | 与 `TPM2_NV_DefineSpace` 遗留格式等价 |
| `TPM_HT_EXTERNAL_NV` | `externalNV` | `TPMA_NV_EXP`（64 位） | 外部存储 NV 元数据 |
| `TPM_HT_PERMANENT_NV` | `permanentNV` | `TPMA_NV` | 永久 NV 索引 |

**Name 计算：** `NV_ReadPublic2` 对 `TPM_HT_NV_INDEX` 与 `NV_ReadPublic` 一致；marshal `TPMU_NV_PUBLIC_2` 时 **不含** `handleType` 标签（Part 3 §31.18）。

本仓库已有遗留 NV 类型（可复用）：`TPMS_NV_PUBLIC`、`TPM2B_NV_PUBLIC`（`tss2_tpm2_types.h` `L3035`–`L3055`）。

### SetCapability 类型（Part 2 §10.10.3–10.10.4）

```c
typedef union TPMU_SET_CAPABILITIES TPMU_SET_CAPABILITIES;
union TPMU_SET_CAPABILITIES {
    /* 成员由 TCG Registry 定义；实现时按 registry 逐步填充 */
};

typedef struct TPMS_SET_CAPABILITY_DATA TPMS_SET_CAPABILITY_DATA;
struct TPMS_SET_CAPABILITY_DATA {
    TPM2_CAP                  setCapability;
    TPMU_SET_CAPABILITIES     data;
};

typedef struct TPM2B_SET_CAPABILITY_DATA TPM2B_SET_CAPABILITY_DATA;
struct TPM2B_SET_CAPABILITY_DATA {
    UINT16                    size;
    TPMS_SET_CAPABILITY_DATA  setCapabilityData;
};
```

### SPDM / PubKeys 能力类型（v184，Part 2 §10.7.6）

```c
/* TPM_PUB_KEY property 常量（节选） */
typedef UINT32 TPM_PUB_KEY;
#define TPM_PUB_KEY_TPM_SPDM_00 ((TPM_PUB_KEY)0x00000000)
/* ... TPM_PUB_KEY_TPM_SPDM_01 .. TPM_PUB_KEY_TPM_SPDM_FF */

typedef struct TPMS_SPDM_SESSION_INFO TPMS_SPDM_SESSION_INFO;
struct TPMS_SPDM_SESSION_INFO {
    TPM2B_NAME reqKeyName;
    TPM2B_NAME tpmKeyName;
};

typedef struct TPML_SPDM_SESSION_INFO TPML_SPDM_SESSION_INFO;
struct TPML_SPDM_SESSION_INFO {
    UINT32                   count;
    TPMS_SPDM_SESSION_INFO   spdmSessionInfo[1]; /* 规范实现相关上限 */
};

typedef struct TPML_PUB_KEY TPML_PUB_KEY;
struct TPML_PUB_KEY {
    UINT32        count;
    TPM2B_PUBLIC  pubKey[1]; /* SPDM 认证公钥列表，非 TPM Object */
};
```

### `TPMU_CAPABILITIES` 扩展（v184）

当前 union 止于 `actData` / `vendor`（`tss2_tpm2_types.h` `L2020`–`L2033`）。待添加：

```c
union TPMU_CAPABILITIES {
    /* ... 既有成员 ... */
    TPML_PUB_KEY             pubKeys;          /* TPM2_CAP_PUB_KEYS */
    TPML_SPDM_SESSION_INFO   spdmSessionInfo;  /* TPM2_CAP_SPDM_SESSION_INFO */
};
```

### 本仓库已有、可复用（v1.83 非 NV2）

| 类型 / 常量 | 位置 | 用于 |
|-------------|------|------|
| `TPM2B_OPERAND`（`typedef TPM2B_DIGEST`） | `tss2_tpm2_types.h` `L1780` | `PolicyCapability.operandB` |
| `TPM2_EO_*` | `tss2_tpm2_types.h` `L625`+ | `PolicyCapability.operation` |
| `TPM2B_DIGEST` + MU | 既有 | `PolicyParameters.pHash` |
| `TPM2B_NAME` + MU | 既有 | `PolicyTransportSPDM`、SPDM session info |
| `Tss2_Sys_GetCapability` | 既有 | 扩展 `Complete` 解码新 cap 分支 |

---

## `include/tss2/tss2_sys.h`（待添加）

七组 Sys API（每组 `Prepare` / `Complete` / 一体式），模式对齐既有策略/NV/平台命令。

### `PolicyCapability`（`0x19B`）

参考：`Tss2_Sys_PolicyCommandCode` + `PolicyCpHash` 的可空 TPM2B 处理。

```c
TSS2_RC Tss2_Sys_PolicyCapability_Prepare(TSS2_SYS_CONTEXT      *sysContext,
                                          TPMI_SH_POLICY         policySession,
                                          const TPM2B_OPERAND   *operandB,
                                          UINT16                 offset,
                                          TPM2_EO                operation,
                                          TPM2_CAP               capability,
                                          UINT32                 property);

TSS2_RC Tss2_Sys_PolicyCapability_Complete(TSS2_SYS_CONTEXT *sysContext);

TSS2_RC Tss2_Sys_PolicyCapability(TSS2_SYS_CONTEXT             *sysContext,
                                  TPMI_SH_POLICY                policySession,
                                  TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                  const TPM2B_OPERAND           *operandB,
                                  UINT16                         offset,
                                  TPM2_EO                        operation,
                                  TPM2_CAP                       capability,
                                  UINT32                         property,
                                  TSS2L_SYS_AUTH_RESPONSE       *rspAuthsArray);
```

### `PolicyParameters`（`0x19C`）

参考：`Tss2_Sys_PolicyCpHash`（仅 CC 与语义不同）。

```c
TSS2_RC Tss2_Sys_PolicyParameters_Prepare(TSS2_SYS_CONTEXT   *sysContext,
                                          TPMI_SH_POLICY      policySession,
                                          const TPM2B_DIGEST *pHash);

TSS2_RC Tss2_Sys_PolicyParameters_Complete(TSS2_SYS_CONTEXT *sysContext);

TSS2_RC Tss2_Sys_PolicyParameters(TSS2_SYS_CONTEXT             *sysContext,
                                  TPMI_SH_POLICY                policySession,
                                  TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                  const TPM2B_DIGEST           *pHash,
                                  TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);
```

### `NV_DefineSpace2`（`0x19D`）

参考：`Tss2_Sys_NV_DefineSpace`（`publicInfo` 换为 `TPM2B_NV_PUBLIC_2`）。

```c
TSS2_RC Tss2_Sys_NV_DefineSpace2_Prepare(TSS2_SYS_CONTEXT         *sysContext,
                                         TPMI_RH_PROVISION         authHandle,
                                         const TPM2B_AUTH         *auth,
                                         const TPM2B_NV_PUBLIC_2  *publicInfo);

TSS2_RC Tss2_Sys_NV_DefineSpace2_Complete(TSS2_SYS_CONTEXT *sysContext);

TSS2_RC Tss2_Sys_NV_DefineSpace2(TSS2_SYS_CONTEXT             *sysContext,
                                TPMI_RH_PROVISION             authHandle,
                                TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                const TPM2B_AUTH             *auth,
                                const TPM2B_NV_PUBLIC_2      *publicInfo,
                                TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);
```

### `NV_ReadPublic2`（`0x19E`）

参考：`Tss2_Sys_NV_ReadPublic`（响应为 `TPM2B_NV_PUBLIC_2`）。

```c
TSS2_RC Tss2_Sys_NV_ReadPublic2_Prepare(TSS2_SYS_CONTEXT *sysContext,
                                      TPMI_RH_NV_INDEX  nvIndex);

TSS2_RC Tss2_Sys_NV_ReadPublic2_Complete(TSS2_SYS_CONTEXT   *sysContext,
                                          TPM2B_NV_PUBLIC_2  *nvPublic,
                                          TPM2B_NAME         *nvName);

TSS2_RC Tss2_Sys_NV_ReadPublic2(TSS2_SYS_CONTEXT             *sysContext,
                               TPMI_RH_NV_INDEX              nvIndex,
                               TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                               TPM2B_NV_PUBLIC_2            *nvPublic,
                               TPM2B_NAME                   *nvName,
                               TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);
```

### `SetCapability`（`0x19F`）

参考：`Tss2_Sys_GetCapability`（反向写入）；`authHandle` 类型为 `TPMI_RH_HIERARCHY_AUTH+`。

```c
TSS2_RC Tss2_Sys_SetCapability_Prepare(TSS2_SYS_CONTEXT                  *sysContext,
                                       TPMI_RH_HIERARCHY_AUTH             authHandle,
                                       const TPM2B_SET_CAPABILITY_DATA   *setCapabilityData);

TSS2_RC Tss2_Sys_SetCapability_Complete(TSS2_SYS_CONTEXT *sysContext);

TSS2_RC Tss2_Sys_SetCapability(TSS2_SYS_CONTEXT                    *sysContext,
                               TPMI_RH_HIERARCHY_AUTH               authHandle,
                               TSS2L_SYS_AUTH_COMMAND const        *cmdAuthsArray,
                               const TPM2B_SET_CAPABILITY_DATA     *setCapabilityData,
                               TSS2L_SYS_AUTH_RESPONSE             *rspAuthsArray);
```

### `ReadOnlyControl`（`0x1A0`）

参考：`Tss2_Sys_ClearControl`（平台授权 + `TPMI_YES_NO`）。

```c
TSS2_RC Tss2_Sys_ReadOnlyControl_Prepare(TSS2_SYS_CONTEXT *sysContext,
                                         TPMI_RH_PLATFORM  authHandle,
                                         TPMI_YES_NO       state);

TSS2_RC Tss2_Sys_ReadOnlyControl_Complete(TSS2_SYS_CONTEXT *sysContext);

TSS2_RC Tss2_Sys_ReadOnlyControl(TSS2_SYS_CONTEXT             *sysContext,
                                TPMI_RH_PLATFORM              authHandle,
                                TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                TPMI_YES_NO                   state,
                                TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);
```

### `PolicyTransportSPDM`（`0x1A1`）

参考：`Tss2_Sys_PolicySecret`（双可空 `TPM2B`；第一个 `reqKeyName` 置 `decryptNull`）。

```c
TSS2_RC Tss2_Sys_PolicyTransportSPDM_Prepare(TSS2_SYS_CONTEXT *sysContext,
                                             TPMI_SH_POLICY    policySession,
                                             const TPM2B_NAME *reqKeyName,
                                             const TPM2B_NAME *tpmKeyName);

TSS2_RC Tss2_Sys_PolicyTransportSPDM_Complete(TSS2_SYS_CONTEXT *sysContext);

TSS2_RC Tss2_Sys_PolicyTransportSPDM(TSS2_SYS_CONTEXT             *sysContext,
                                    TPMI_SH_POLICY                policySession,
                                    TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                    const TPM2B_NAME             *reqKeyName,
                                    const TPM2B_NAME             *tpmKeyName,
                                    TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);
```

---

## `include/tss2/tss2_mu.h`（待添加）

### NV2

```c
TSS2_RC Tss2_MU_TPMA_NV_EXP_Marshal(TPMA_NV_EXP src, uint8_t buffer[], size_t buffer_size,
                                    size_t *offset);
TSS2_RC Tss2_MU_TPMA_NV_EXP_Unmarshal(uint8_t const buffer[], size_t buffer_size,
                                      size_t *offset, TPMA_NV_EXP *dest);

TSS2_RC Tss2_MU_TPMS_NV_PUBLIC_EXP_ATTR_Marshal(TPMS_NV_PUBLIC_EXP_ATTR const *src,
                                                uint8_t buffer[], size_t buffer_size,
                                                size_t *offset);
TSS2_RC Tss2_MU_TPMS_NV_PUBLIC_EXP_ATTR_Unmarshal(uint8_t const buffer[], size_t buffer_size,
                                                  size_t *offset,
                                                  TPMS_NV_PUBLIC_EXP_ATTR *dest);

TSS2_RC Tss2_MU_TPMU_NV_PUBLIC_2_Marshal(TPMU_NV_PUBLIC_2 const *src, TPM_HT selector,
                                         uint8_t buffer[], size_t buffer_size, size_t *offset);
TSS2_RC Tss2_MU_TPMU_NV_PUBLIC_2_Unmarshal(uint8_t const buffer[], size_t buffer_size,
                                           size_t *offset, TPM_HT selector,
                                           TPMU_NV_PUBLIC_2 *dest);

TSS2_RC Tss2_MU_TPMT_NV_PUBLIC_2_Marshal(TPMT_NV_PUBLIC_2 const *src, uint8_t buffer[],
                                         size_t buffer_size, size_t *offset);
TSS2_RC Tss2_MU_TPMT_NV_PUBLIC_2_Unmarshal(uint8_t const buffer[], size_t buffer_size,
                                           size_t *offset, TPMT_NV_PUBLIC_2 *dest);

TSS2_RC Tss2_MU_TPM2B_NV_PUBLIC_2_Marshal(TPM2B_NV_PUBLIC_2 const *src, uint8_t buffer[],
                                          size_t buffer_size, size_t *offset);
TSS2_RC Tss2_MU_TPM2B_NV_PUBLIC_2_Unmarshal(uint8_t const buffer[], size_t buffer_size,
                                            size_t *offset, TPM2B_NV_PUBLIC_2 *dest);
```

`TPMU_NV_PUBLIC_2` selector 映射（`src/tss2-mu/tpmu-types.c`）：

| selector (`TPM_HT`) | 成员 | Marshal 函数 |
|---------------------|------|--------------|
| `TPM_HT_NV_INDEX` | `nvIndex` | `Tss2_MU_TPMS_NV_PUBLIC_Marshal`（既有） |
| `TPM_HT_EXTERNAL_NV` | `externalNV` | `Tss2_MU_TPMS_NV_PUBLIC_EXP_ATTR_Marshal` |
| `TPM_HT_PERMANENT_NV` | `permanentNV` | `Tss2_MU_TPMS_NV_PUBLIC_Marshal` |

`TPMT_NV_PUBLIC_2`：先 marshal `handleType`（`TPM_HT` / `UINT8`），再按 selector marshal `publicArea`。

### SetCapability

```c
TSS2_RC Tss2_MU_TPMS_SET_CAPABILITY_DATA_Marshal(TPMS_SET_CAPABILITY_DATA const *src, ...);
TSS2_RC Tss2_MU_TPMS_SET_CAPABILITY_DATA_Unmarshal(...);
TSS2_RC Tss2_MU_TPM2B_SET_CAPABILITY_DATA_Marshal(TPM2B_SET_CAPABILITY_DATA const *src, ...);
TSS2_RC Tss2_MU_TPM2B_SET_CAPABILITY_DATA_Unmarshal(...);
TSS2_RC Tss2_MU_TPMU_SET_CAPABILITIES_Marshal(TPMU_SET_CAPABILITIES const *src,
                                              TPM2_CAP selector, ...);
TSS2_RC Tss2_MU_TPMU_SET_CAPABILITIES_Unmarshal(..., TPM2_CAP selector, ...);
```

### SPDM capability

```c
TSS2_RC Tss2_MU_TPMS_SPDM_SESSION_INFO_Marshal(TPMS_SPDM_SESSION_INFO const *src, ...);
TSS2_RC Tss2_MU_TPMS_SPDM_SESSION_INFO_Unmarshal(...);
TSS2_RC Tss2_MU_TPML_SPDM_SESSION_INFO_Marshal(TPML_SPDM_SESSION_INFO const *src, ...);
TSS2_RC Tss2_MU_TPML_SPDM_SESSION_INFO_Unmarshal(...);
TSS2_RC Tss2_MU_TPML_PUB_KEY_Marshal(TPML_PUB_KEY const *src, ...);
TSS2_RC Tss2_MU_TPML_PUB_KEY_Unmarshal(...);
```

扩展 `Tss2_MU_TPMU_CAPABILITIES_{Marshal,Unmarshal}`：

| selector | 成员 |
|----------|------|
| `TPM2_CAP_PUB_KEYS` | `pubKeys` |
| `TPM2_CAP_SPDM_SESSION_INFO` | `spdmSessionInfo` |

---

## 实现代码（`.c`）设计摘录

以下为实现蓝图（**非当前源码**）；模板文件均存在于本仓库。

### `src/tss2-sys/sysapi_util.c` — `commandArray` 扩展

在 `TPM2_CC_ECC_Decrypt` 与 PQC 命令之间插入：

```c
{ TPM2_CC_PolicyCapability,    1, 0 },
{ TPM2_CC_PolicyParameters,    1, 0 },
{ TPM2_CC_NV_DefineSpace2,       1, 0 },
{ TPM2_CC_NV_ReadPublic2,        1, 0 },
{ TPM2_CC_SetCapability,         1, 0 },
{ TPM2_CC_ReadOnlyControl,       1, 0 },
{ TPM2_CC_PolicyTransportSPDM,   1, 0 },
```

参考现有条目：`NV_DefineSpace` `{1,0}`、`NV_ReadPublic` `{1,0}`、`ClearControl` `{1,0}`（`sysapi_util.c` `L258`–`L280`）。

### `ValidateNV_Public2`（`sysapi_util.c` / `sysapi_util.h`）

```c
TSS2_RC
ValidateNV_Public2(const TPM2B_NV_PUBLIC_2 *nv_public_info) {
    if (!nv_public_info || nv_public_info->size == 0)
        return TSS2_RC_SUCCESS;

    const TPMT_NV_PUBLIC_2 *nv2 = &nv_public_info->nvPublic;
    switch (nv2->handleType) {
    case TPM2_HT_NV_INDEX:
        return ValidateNV_Public(
            (const TPM2B_NV_PUBLIC *)&(TPM2B_NV_PUBLIC){
                .size = sizeof(TPMS_NV_PUBLIC),
                .nvPublic = nv2->publicArea.nvIndex });
    case TPM2_HT_EXTERNAL_NV:
        if (IsAlgorithmWeak(nv2->publicArea.externalNV.nameAlg, 0))
            return TSS2_SYS_RC_BAD_VALUE;
        return TSS2_RC_SUCCESS;
    case TPM2_HT_PERMANENT_NV:
        if (IsAlgorithmWeak(nv2->publicArea.permanentNV.nameAlg, 0))
            return TSS2_SYS_RC_BAD_VALUE;
        return TSS2_RC_SUCCESS;
    default:
        return TSS2_SYS_RC_BAD_VALUE;
    }
}
```

### `Tss2_Sys_NV_DefineSpace2.c`

参考 `Tss2_Sys_NV_DefineSpace.c`（`L17`–`L100`）：

```c
TSS2_RC
Tss2_Sys_NV_DefineSpace2_Prepare(TSS2_SYS_CONTEXT         *sysContext,
                                 TPMI_RH_PROVISION         authHandle,
                                 const TPM2B_AUTH         *auth,
                                 const TPM2B_NV_PUBLIC_2  *publicInfo) {
    /* ValidateNV_Public2(publicInfo) */
    /* CommonPreparePrologue(ctx, TPM2_CC_NV_DefineSpace2) */
    /* Marshal authHandle */
    /* auth: NULL/size==0 → decryptNull + UINT16(0) else TPM2B_AUTH */
    /* publicInfo: NULL → UINT16(0) else TPM2B_NV_PUBLIC_2 */
    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;
    return CommonPrepareEpilogue(ctx);
}
```

### `Tss2_Sys_NV_ReadPublic2.c`

参考 `Tss2_Sys_NV_ReadPublic.c`（`L17`–`L81`）：

```c
TSS2_RC
Tss2_Sys_NV_ReadPublic2_Complete(TSS2_SYS_CONTEXT  *sysContext,
                                TPM2B_NV_PUBLIC_2 *nvPublic,
                                TPM2B_NAME        *nvName) {
    /* CommonComplete */
    rval = Tss2_MU_TPM2B_NV_PUBLIC_2_Unmarshal(..., nvPublic);
    return Tss2_MU_TPM2B_NAME_Unmarshal(..., nvName);
}
```

### `Tss2_Sys_PolicyCapability.c`

参考 `Tss2_Sys_PolicyCommandCode.c` + 可空 `operandB`（同 `PolicyCpHash`）：

```c
/* Marshal: policySession, operandB, offset (UINT16), operation (TPM2_EO),
            capability (TPM2_CAP), property (UINT32) */
ctx->decryptAllowed = 1;
ctx->encryptAllowed = 0;
ctx->authAllowed = 1;
```

### `Tss2_Sys_PolicyParameters.c`

与 `Tss2_Sys_PolicyCpHash.c`（`L17`–`L82`）结构相同，仅 `TPM2_CC_PolicyParameters`。

### `Tss2_Sys_ReadOnlyControl.c`

与 `Tss2_Sys_ClearControl.c`（`L17`–`L74`）相同模式：`authHandle` + `state`（`TPMI_YES_NO` / `UINT8`）。

### `Tss2_Sys_PolicyTransportSPDM.c`

与 `Tss2_Sys_PolicySecret.c` 前两个 TPM2B 模式：`reqKeyName` → `decryptNull`；`tpmKeyName` 仅 empty marshal。

### `Tss2_Sys_SetCapability.c`

```c
/* Marshal authHandle, setCapabilityData (decryptNull if NULL/size==0) */
ctx->decryptAllowed = 1;
ctx->authAllowed = 1;
```

### `Tss2_Sys_GetCapability_Complete` 扩展

在 `cap != TPM2_CAP_VENDOR_PROPERTY` 分支中，为 `TPM2_CAP_PUB_KEYS` / `TPM2_CAP_SPDM_SESSION_INFO` 增加 `Tss2_MU_TPMU_CAPABILITIES_Unmarshal` selector 路径（参考 `GetCapability.c` `L72`–`L80` 现有 peak-and-decode 逻辑）。

### `src/tss2-mu/` 文件分工

| 文件 | 新增内容 |
|------|----------|
| `base-types.c` | `TPMA_NV_EXP`（`BASE_MARSHAL` UINT64） |
| `tpms-types.c` | `TPMS_NV_PUBLIC_EXP_ATTR`、`TPMS_SET_CAPABILITY_DATA`、`TPMS_SPDM_SESSION_INFO` |
| `tpm2b-types.c` | `TPM2B_NV_PUBLIC_2`、`TPM2B_SET_CAPABILITY_DATA`；`TPML_PUB_KEY`、`TPML_SPDM_SESSION_INFO` |
| `tpmu-types.c` | `TPMU_NV_PUBLIC_2`、`TPMU_SET_CAPABILITIES`；扩展 `TPMU_CAPABILITIES` |

链接导出：`lib/tss2-sys.map` / `lib/tss2-sys.def`、`lib/tss2-mu.map` / `lib/tss2-mu.def`。

---

## 命令与类型布局速查

### 命令码对照（`0x198` 之后）

| CC | Part 3 命令 | 本仓库 | 设计模板 |
|----|-------------|--------|----------|
| `0x199` | `ECC_Encrypt` | ✓ | — |
| `0x19A` | `ECC_Decrypt` | ✓ | — |
| `0x19B` | `PolicyCapability` | ✗ | `PolicyCommandCode` + `operandB` nullable |
| `0x19C` | `PolicyParameters` | ✗ | `PolicyCpHash` |
| `0x19D` | `NV_DefineSpace2` | ✗ | `NV_DefineSpace` + NV2 |
| `0x19E` | `NV_ReadPublic2` | ✗ | `NV_ReadPublic` + NV2 |
| `0x19F` | `SetCapability` | ✗ | `GetCapability`（写） |
| `0x1A0` | `ReadOnlyControl` | ✗ | `ClearControl` |
| `0x1A1` | `PolicyTransportSPDM` | ✗ | `PolicySecret`（双 Name） |
| `0x1A2` | **Reserved** | ⚠ fork PQC | `SignVerifySequenceStart` |
| `0x1A3`–`0x1AA` | v1.85 PQC | ✓ | 见 [pqc-api-reference.md](pqc-api-reference.md) |

### NV2 public 区选择器

| `TPMT_NV_PUBLIC_2.handleType` | `TPMU_NV_PUBLIC_2` | 属性宽度 | 典型用途 |
|-------------------------------|--------------------|---------|----------|
| `TPM_HT_NV_INDEX` (`0x01`) | `nvIndex` | 32-bit `TPMA_NV` | 传统 NV 索引 |
| `TPM_HT_EXTERNAL_NV` (`0x11`) | `externalNV` | 64-bit `TPMA_NV_EXP` | 外部 NV 存储元数据 |
| `TPM_HT_PERMANENT_NV` (`0x12`) | `permanentNV` | 32-bit `TPMA_NV` | 永久 NV 索引 |

### 策略命令语义对照

| 命令 | 断言时机 | digest 更新 | 与同类命令差异 |
|------|----------|-------------|----------------|
| `PolicyCapability` | **立即** | 式 10（Part 3 §23.23） | 比较 TPM capability 与 `operandB` |
| `PolicyParameters` | **延迟** | `H(old ∥ CC ∥ pHash)` | 绑定命令 **参数摘要**；与 `PolicyCpHash` 互斥 |
| `PolicyTransportSPDM` | **延迟** | Part 3 §23.25 | 要求 SPDM 安全信道；可绑定双方密钥 Name |

### SPDM 生态（184，非独立 CC）

| 组件 | 类型 / 命令 | 作用 |
|------|-------------|------|
| 能力查询 | `GetCapability` + `TPM2_CAP_PUB_KEYS` | 读取 TPM SPDM 认证公钥 |
| 能力查询 | `GetCapability` + `TPM2_CAP_SPDM_SESSION_INFO` | 当前 SPDM 会话密钥 Name |
| 策略门控 | `PolicyTransportSPDM` | 授权时校验安全信道 |
| 策略断言 | `PolicyCapability` + `TPM2_CAP_SPDM_SESSION_INFO` | 立即断言会话状态 |

**注意：** SPDM 握手与传输在 TPM Library **规范范围之外**；Library 仅定义能力查询与策略门控。

### 规范索引

| 命令 | Part 3 |
|------|--------|
| `PolicyCapability` | §23.23 |
| `PolicyParameters` | §23.24 |
| `PolicyTransportSPDM` | §23.25 |
| `ReadOnlyControl` | §24.9 |
| `SetCapability` | §30.4 |
| `NV_DefineSpace2` | §31.17 |
| `NV_ReadPublic2` | §31.18 |

| 结构 | Part 2 |
|------|--------|
| `TPM2B_NV_PUBLIC_2` 族 | §13.8–13.11 |
| `TPM2B_SET_CAPABILITY_DATA` | §10.9.3–10.9.4 |
| `TPMS_SPDM_SESSION_INFO` | §10.7.6 |
| `TPM_HT_EXTERNAL_NV` | §7.2 Table 29 |

---

## 实现状态与 Known gaps

**当前状态：Sys/MU 已实现；ESYS/FAPI 与集成测试未覆盖**（详见 [tpm-v183-v184-gap-reference.md](tpm-v183-v184-gap-reference.md)）。

| 类别 | 状态 |
|------|------|
| **命令码** | `0x19B`–`0x1A1` 已定义于 `tss2_tpm2_types.h` |
| **类型** | NV2、SetCapability、SPDM capability 结构已加入 |
| **MU** | `Tss2_MU_*` 已实现；单元测试见 `test/unit/v183-v184-marshal` |
| **Sys API** | 7 组 `Tss2_Sys_*` 已实现；`commandArray` 已登记 |
| **GetCapability** | `TPMU_CAPABILITIES` 已扩展 `pubKeys` / `spdmSessionInfo` |
| **ESYS / FAPI** | 无 `Esys_*` 包装（计划外） |
| **测试** | 有 unit（marshal/prepare）；无 v1.83 集成测试 |
| **CC 布局** | `0x1A2` 保留为 `SignVerifySequenceStart`；`0x1A9`/`0x1AA` 为 PQC 序列 Start |

### 建议实现顺序（Phase A → D）

1. **Phase A：** `tss2_tpm2_types.h` CC + 类型 + `tss2_mu.h` 声明 + MU 实现 + map/def
2. **Phase B：** 七组 `Tss2_Sys_*` + `sysapi_util.c` + `ValidateNV_Public2` + `GetCapability_Complete` 扩展
3. **Phase C：** `src_vars.mk`、vcxproj、导出符号；可选 ESYS
4. **Phase D：** `test/unit/`（NV2 / SetCapability / SPDM MU 往返）；`test/integration/`（需 v1.83+ TPM 或 wolfTPM）
