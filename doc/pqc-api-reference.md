# TPM 2.0 v1.85 PQC / EdDSA 头文件与实现摘录

按 **源码出现顺序** 整理 `include/tss2/` 下三个头文件中的 **v1.85 后量子（ML-KEM / ML-DSA / Hash-ML-DSA）** 与 **EdDSA / Hash-EdDSA** 定义，并在 **[实现代码（`.c`）](#实现代码c)** 一节摘录对应 **Sys / MU** 源文件实现。行号对应当前仓库版本。

规范：**TPM 2.0 Library Specification v1.85**

下文摘录头文件中**已有**定义。PQC 核心（算法、尺寸、结构、命令码、验签 `TPM2_ST_*`）已齐；**仍缺**部分 `TPM2_RC_*`、`TPM2_PT_ML_PARAMETER_SETS`、Hash/XOF/HKDF 算法 ID 等，见 **[规范常量缺口](#规范常量缺口tss2_tpm2_typesh-未定义)**。

**目录（节选）**

| 节 | 内容 |
|----|------|
| [`tss2_tpm2_types.h`](#includetss2tss2_tpm2_typesh) | 尺寸 / 算法 / 参数集 / 命令码；含缺口常量摘要 |
| [规范常量缺口](#规范常量缺口tss2_tpm2_typesh-未定义) | 规范有、头文件无的 `TPM2_ST` / `TPM2_RC` / `TPM2_PT` 等 |
| [实现代码（`.c`）](#实现代码c) | Sys / MU 源文件摘录 |
| [测试](#测试) | 单元与 wolfTPM 集成 |
| [Known gaps](#known-gaps相对完整-tpm2-tss-发行版) | ESYS、ABI 等待办 |

---

## TSS Sys API 约定（nullable 参数与 session 解密）

**实现范围：** 本文档描述 **TSS2-Sys** 与 **TSS2-MU**。**ESYS**（`src/tss2-esys/`、`tss2_esys.h`）与 **FAPI** 不在 PQC v1.85 实现范围内——未提供、亦不在当前变更之列。

与 upstream tpm2-tss 一致：

| 规则 | 说明 |
|------|------|
| **可空 TPM2B** | `Prepare` 时指针为 `NULL` → 使用栈上 `{ .size = 0 }` 占位，统一经 `Tss2_MU_TPM2B_*_Marshal`（wire 上为 `UINT16(0)`） |
| **`decryptNull`** | **仅**在该命令的**第一个** session-decrypt 目标 TPM2B 为 `NULL` **或** `size==0` 时置 `ctx->decryptNull = 1`；后续可空 TPM2B **不**再置位 |
| **`SetDecryptParam`** | 通过 `Tss2_Sys_GetDecryptParam` 只能取得**第一个** decrypt 参数（`cpBuffer`）；`SetDecryptParam` 亦只能替换该参数。多 decrypt 参数命令不在此 API 覆盖范围内 |
| **auth 标志** | `decryptAllowed` / `encryptAllowed` / `authAllowed` 在 `Prepare` 末尾、`CommonPrepareEpilogue` 之前设置 |

v1.85 PQC / 签名命令的第一个 decrypt 目标：

| 命令 | 第一个 decrypt 参数 | 其他可空 TPM2B（仅 size 0，无 `decryptNull`） |
|------|---------------------|-----------------------------------------------|
| `SignDigest` | `context`（`NULL` 或 `size==0` → `decryptNull`） | `digest` |
| `VerifyDigestSignature` | `context`（`NULL` 或 `size==0` → `decryptNull`） | `digest` |
| `SignSequenceStart` / `VerifySequenceStart` | `auth`（`NULL` 或 `size==0` → `decryptNull`） | `context`；验签另有 `hint` |
| `SignSequenceComplete` | `buffer`（`NULL` 或 `size==0` → `decryptNull`） | — |
| `Decapsulate` | `ciphertext`（`NULL` 或 `size==0` → `decryptNull`，供 `SetDecryptParam` 延迟填入） | — |
| `Encapsulate` | 无（`decryptAllowed = 0`） | — |
| `VerifySequenceComplete` | 无（`signature` 为 `TPMT_SIGNATURE`；`decryptAllowed = 0`） | — |

### 必填 / 可选参数（Prepare 与一体式）

| API | 必填 | 可选（`NULL` → `UINT16(0)`） |
|-----|------|-------------------------------|
| `Encapsulate` | `sysContext`, `keyHandle` | — |
| `Decapsulate` | `sysContext`, `keyHandle` | `ciphertext`（`NULL` 或 `size==0` → `decryptNull`） |
| `SignDigest` | `sysContext`, `keyHandle`, `validation` | `context`（`NULL`/`size==0` → `decryptNull`）, `digest` |
| `VerifyDigestSignature` | `sysContext`, `keyHandle`, `signature` | `context`（`NULL`/`size==0` → `decryptNull`）, `digest` |
| `SignSequenceStart` | `sysContext`, `keyHandle` | `auth`（`NULL`/`size==0` → `decryptNull`）, `context` |
| `VerifySequenceStart` | `sysContext`, `keyHandle` | `auth`（`NULL`/`size==0` → `decryptNull`）, `hint`, `context` |
| `SignSequenceComplete` | `sysContext`, `sequenceHandle`, `keyHandle` | `buffer`（`NULL`/`size==0` → `decryptNull`） |
| `VerifySequenceComplete` | `sysContext`, `sequenceHandle`, `keyHandle`, `signature` | — |

一体式函数仅在规范要求非空的参数上返回 `TSS2_SYS_RC_BAD_REFERENCE`（如 `validation`、`signature`）；可空 TPM2B 由 Prepare 处理。

**`SetDecryptParam` 限制：** 仅覆盖**第一个** decrypt TPM2B。例如 `SignDigest` 中 `context` 为 decrypt 目标，`digest` 虽可空但**不能**经 `SetDecryptParam` 延迟填入。

### 参数边界矩阵（Prepare）

| API | 参数 | `NULL` | `size==0` | 有效值 | 超大 `size` |
|-----|------|--------|-----------|--------|-------------|
| `Encapsulate` | `keyHandle` | — | — | marshal `UINT32` | — |
| `Decapsulate` | `ciphertext` | `decryptNull` + marshal empty TPM2B | 同左 | marshal TPM2B | MU `BAD_SIZE` |
| `SignDigest` | `context` | `decryptNull` + marshal empty TPM2B | 同左 | marshal TPM2B | MU `BAD_SIZE` |
| `SignDigest` | `digest` | marshal empty TPM2B | marshal（size 0） | marshal TPM2B | MU `BAD_SIZE` |
| `SignDigest` | `validation` | `BAD_REFERENCE` | marshal | marshal TPMT | MU 错误 |
| `VerifyDigestSignature` | `context` | `decryptNull` + marshal empty TPM2B | 同左 | marshal TPM2B | MU `BAD_SIZE` |
| `VerifyDigestSignature` | `digest` | marshal empty TPM2B | marshal（size 0） | marshal TPM2B | MU `BAD_SIZE` |
| `VerifyDigestSignature` | `signature` | `BAD_REFERENCE` | marshal | marshal TPMT | MU 错误 |
| `SignSequenceStart` | `auth` | `decryptNull` + marshal empty TPM2B | 同左 | marshal TPM2B | MU `BAD_SIZE` |
| `SignSequenceStart` | `context` | marshal empty TPM2B | marshal（size 0） | marshal TPM2B | MU `BAD_SIZE` |
| `VerifySequenceStart` | `auth` | `decryptNull` + marshal empty TPM2B | 同左 | marshal TPM2B | MU `BAD_SIZE` |
| `VerifySequenceStart` | `hint` / `context` | marshal empty TPM2B | marshal（size 0） | marshal TPM2B | MU `BAD_SIZE` |
| `SignSequenceComplete` | `buffer` | `decryptNull` + marshal empty TPM2B | 同左 | marshal TPM2B | MU `BAD_SIZE` |
| `VerifySequenceComplete` | `signature` | `BAD_REFERENCE` | marshal | marshal TPMT | MU 错误 |

---

## `include/tss2/tss2_tpm2_types.h`

### 尺寸常量

```c
/* ML-DSA Size Constants */
#define TPM2_MLDSA_PRIVATE_KEY_SEED_SIZE 32
#define TPM2_MLDSA_44_PUB_SIZE           1312 /* ML-DSA-44 public key */
#define TPM2_MLDSA_44_SIG_SIZE           2420 /* ML-DSA-44 signature */
#define TPM2_MLDSA_65_PUB_SIZE           1952 /* ML-DSA-65 public key */
#define TPM2_MLDSA_65_SIG_SIZE           3309 /* ML-DSA-65 signature */
#define TPM2_MLDSA_87_PUB_SIZE           2592 /* ML-DSA-87 public key */
#define TPM2_MLDSA_87_SIG_SIZE           4627 /* ML-DSA-87 signature */
#define TPM2_MLDSA_CTX_MAX_SIZE          255  /* Context string max size */
#define TPM2_MAX_MLDSA_PUB_SIZE          TPM2_MLDSA_87_PUB_SIZE
#define TPM2_MAX_MLDSA_SIG_SIZE          TPM2_MLDSA_87_SIG_SIZE

/* ML-KEM Individual Parameter Set Sizes */
#define TPM2_MLKEM_PRIVATE_KEY_SEED_SIZE  64
#define TPM2_MLKEM_SHARED_SECRET_SIZE     32
#define TPM2_MLKEM_512_PUB_SIZE           800  /* ML-KEM-512 public key */
#define TPM2_MLKEM_512_CT_SIZE            768  /* ML-KEM-512 ciphertext */
#define TPM2_MLKEM_768_PUB_SIZE           1184 /* ML-KEM-768 public key */
#define TPM2_MLKEM_768_CT_SIZE            1088 /* ML-KEM-768 ciphertext */
#define TPM2_MLKEM_1024_PUB_SIZE          1568 /* ML-KEM-1024 public key */
#define TPM2_MLKEM_1024_CT_SIZE           1568 /* ML-KEM-1024 ciphertext */
#define TPM2_MAX_MLKEM_PUB_SIZE           TPM2_MLKEM_1024_PUB_SIZE
#define TPM2_MAX_MLKEM_CT_SIZE            TPM2_MLKEM_1024_CT_SIZE
#define TPM2_MAX_MLKEM_SHARED_SECRET_SIZE TPM2_MLKEM_SHARED_SECRET_SIZE
#define TPM2_MAX_SIGNATURE_HINT_SIZE      TPM2_MAX_ECC_KEY_BYTES
```

`L46`–`L70`

### 算法 ID

```c
#define TPM2_ALG_EDDSA          ((TPM2_ALG_ID)0x0060)
#define TPM2_ALG_HASH_EDDSA     ((TPM2_ALG_ID)0x0061)
#define TPM2_ALG_MLKEM          ((TPM2_ALG_ID)0x00A0)
#define TPM2_ALG_MLDSA          ((TPM2_ALG_ID)0x00A1)
#define TPM2_ALG_HASH_MLDSA     ((TPM2_ALG_ID)0x00A2)
#define TPM2_ALG_LAST           ((TPM2_ALG_ID)0x00A2)
```

`L143`–`L149`

### ECC 曲线（EdDSA）

```c
#define TPM2_ECC_CURVE_25519 ((TPM2_ECC_CURVE)0x0040)
#define TPM2_ECC_CURVE_448   ((TPM2_ECC_CURVE)0x0041)
```

`L162`–`L163`

EdDSA 密钥仍使用 `TPM2_ALG_ECC` 对象类型，通过 `TPMS_ECC_PARMS.curveID` 选择 Curve25519 / Curve448。

### 参数集类型

```c
/* Definition of TPMI_MLKEM_PARMS Constants */
typedef UINT16 TPMI_MLKEM_PARMS;
#define TYPE_OF_TPM_MLKEM_PARMS UINT16
#define TPM2_MLKEM_PARMS_NONE   ((TPMI_MLKEM_PARMS)0x0000)
#define TPM2_MLKEM_PARMS_512    ((TPMI_MLKEM_PARMS)0x0001)
#define TPM2_MLKEM_PARMS_768    ((TPMI_MLKEM_PARMS)0x0002)
#define TPM2_MLKEM_PARMS_1024   ((TPMI_MLKEM_PARMS)0x0003)

/* Definition of TPMI_MLDSA_PARMS Constants */
typedef UINT16 TPMI_MLDSA_PARMS;
#define TYPE_OF_TPM_MLDSA_PARMS UINT16
#define TPM2_MLDSA_PARMS_NONE   ((TPMI_MLDSA_PARMS)0x0000)
#define TPM2_MLDSA_PARMS_44     ((TPMI_MLDSA_PARMS)0x0001)
#define TPM2_MLDSA_PARMS_65     ((TPMI_MLDSA_PARMS)0x0002)
#define TPM2_MLDSA_PARMS_87     ((TPMI_MLDSA_PARMS)0x0003)
```

`L165`–`L179`

### 命令码

```c
#define TPM2_CC_SignVerifySequenceStart    ((TPM2_CC)0x000001a2) /* 遗留宏；wire 上勿用，见下文 */
#define TPM2_CC_VerifySequenceComplete     ((TPM2_CC)0x000001a3)
#define TPM2_CC_SignSequenceComplete       ((TPM2_CC)0x000001a4)
#define TPM2_CC_VerifyDigestSignature      ((TPM2_CC)0x000001a5)
#define TPM2_CC_SignDigest                 ((TPM2_CC)0x000001a6)
#define TPM2_CC_Encapsulate                ((TPM2_CC)0x000001a7)
#define TPM2_CC_Decapsulate                ((TPM2_CC)0x000001a8)
#define TPM2_CC_VerifySequenceStart        ((TPM2_CC)0x000001a9)
#define TPM2_CC_SignSequenceStart          ((TPM2_CC)0x000001aa)
#define TPM2_CC_LAST                       ((TPM2_CC)0x000001aa)
```

`L312`–`L321`

| CC | 宏 | Prepare 使用方 | 说明 |
|----|-----|----------------|------|
| `0x1A2` | `TPM2_CC_SignVerifySequenceStart` | —（无独立 Sys API） | 遗留 fork 宏；`sysapi_util.c` 仍注册句柄元数据 |
| `0x1A9` | `TPM2_CC_VerifySequenceStart` | `Tss2_Sys_VerifySequenceStart_Prepare` | 流式验签 Start |
| `0x1AA` | `TPM2_CC_SignSequenceStart` | `Tss2_Sys_SignSequenceStart_Prepare` | 流式签名 Start |

与 wolfTPM / 较新 Part 2 草案对齐时，`0x1A9`/`0x1AA` 为独立 Start 命令；较早 Part 2 rc2 文本仍将 `0x1A2` 标为 `SignVerifySequenceStart` 且 `TPM_CC_LAST = 0x1A8`——以你集成的 TPM 固件与 Part 2 版本为准。

### 验签票据结构标签（`TPM2_ST`）

`TPMT_TK_VERIFIED.tag` 在 PQC / 流式路径上须与产生命令一致：

```c
#define TPM2_ST_VERIFIED         ((TPM2_ST)0x8022) /* TPM2_VerifySignature() */
#define TPM2_ST_MESSAGE_VERIFIED ((TPM2_ST)0x8026) /* TPM2_VerifySequenceComplete() */
#define TPM2_ST_DIGEST_VERIFIED  ((TPM2_ST)0x8027) /* TPM2_VerifyDigestSignature() */
```

`L705`–`L710`（插在 `TPM2_ST_AUTH_SIGNED` 与 `TPM2_ST_FU_MANIFEST` 之间）

| 宏 | 值 | 产生命令 | 路径 |
|----|-----|----------|------|
| `TPM2_ST_VERIFIED` | `0x8022` | `VerifySignature` | 传统 digest + `TPMT_SIGNATURE` |
| `TPM2_ST_MESSAGE_VERIFIED` | `0x8026` | `VerifySequenceComplete` | 流式验签（`SignSequence*` / ML-DSA 消息） |
| `TPM2_ST_DIGEST_VERIFIED` | `0x8027` | `VerifyDigestSignature` | 预计算 digest（`SignDigest` / Hash-ML-DSA） |

`TPMU_TK_VERIFIED_META` 仍未进头文件，见 [规范常量缺口 § 类型结构](#类型结构规范新增非-define)。

### PQC 返回码与 TPM 属性（**头文件未定义**）

| 宏（建议） | 编码 | 典型场景 |
|------------|------|----------|
| `TPM2_RC_PARMS` | `TPM2_RC_FMT1 + 0x02A` | 不支持的 ML-KEM / ML-DSA 参数集 |
| `TPM2_RC_EXT_MU` | `+ 0x02B` | `allowExternalMu=0` 密钥上调用 `SignDigest` |
| `TPM2_RC_ONE_SHOT_SIGNATURE` | `+ 0x02C` | TPM 不支持一次性 digest 签名 |
| `TPM2_RC_SIGN_CONTEXT_KEY` | `+ 0x02D` | 流式验签 `keyHandle` 与 Start 不一致 |
| `TPM2_PT_ML_PARAMETER_SETS` | `TPM2_PT_FIXED + 49` | `GetCapability` 查询 ML 参数集位图（`TPMA_ML_PARAMETER_SET`） |

详见 [规范常量缺口](#规范常量缺口tss2_tpm2_typesh-未定义)。

### 签名方案（EdDSA / Hash-EdDSA）

EdDSA 与 Hash-EdDSA 的**方案参数体均为空**（`TPMS_EMPTY`），与 ECDSA 等带 `hashAlg` 的 `TPMS_SCHEME_HASH` 不同：

```c
typedef TPMS_EMPTY TPMS_SIG_SCHEME_EDDSA;
typedef TPMS_EMPTY TPMS_SIG_SCHEME_HASH_EDDSA;
```

`L2344`–`L2345`

`TPMU_SIG_SCHEME` 完整联合体（EdDSA 成员）：

```c
union TPMU_SIG_SCHEME {
    TPMS_SIG_SCHEME_RSASSA    rsassa;
    TPMS_SIG_SCHEME_RSAPSS    rsapss;
    TPMS_SIG_SCHEME_ECDSA     ecdsa;
    TPMS_SIG_SCHEME_ECDAA     ecdaa;
    TPMS_SIG_SCHEME_SM2       sm2;
    TPMS_SIG_SCHEME_ECSCHNORR ecschnorr;
    TPMS_SIG_SCHEME_EDDSA     eddsa;
    TPMS_SIG_SCHEME_HASH_EDDSA hash_eddsa;
    TPMS_SCHEME_HMAC          hmac;
    TPMS_SCHEME_HASH          any;
    TPMS_EMPTY                null;
};
```

`L2349`–`L2361`

`TPMT_SIG_SCHEME`（`TPMT_SIGNATURE` 之外的通用签名方案包装）：

```c
struct TPMT_SIG_SCHEME {
    TPMI_ALG_SIG_SCHEME scheme;  /* TPM2_ALG_EDDSA 或 TPM2_ALG_HASH_EDDSA */
    TPMU_SIG_SCHEME     details; /* EdDSA/Hash-EdDSA 时 details 为空 */
};
```

`L2365`–`L2368`

`TPMU_ASYM_SCHEME` 完整联合体（EdDSA 成员，亦用于 `TPMT_ECC_SCHEME.details`）：

```c
union TPMU_ASYM_SCHEME {
    TPMS_KEY_SCHEME_ECDH       ecdh;
    TPMS_KEY_SCHEME_ECMQV      ecmqv;
    TPMS_SIG_SCHEME_RSASSA     rsassa;
    TPMS_SIG_SCHEME_RSAPSS     rsapss;
    TPMS_SIG_SCHEME_ECDSA      ecdsa;
    TPMS_SIG_SCHEME_ECDAA      ecdaa;
    TPMS_SIG_SCHEME_SM2        sm2;
    TPMS_SIG_SCHEME_ECSCHNORR  ecschnorr;
    TPMS_SIG_SCHEME_EDDSA      eddsa;      /* signing and anonymous signing */
    TPMS_SIG_SCHEME_HASH_EDDSA hash_eddsa; /* signing and anonymous signing */
    TPMS_ENC_SCHEME_RSAES      rsaes;
    TPMS_ENC_SCHEME_OAEP       oaep;
    TPMS_SCHEME_HASH           anySig;
    TPMS_EMPTY                 null;
};
```

`L2408`–`L2423`

`TPMT_ASYM_SCHEME` / `TPMT_ECC_SCHEME`（ECC 密钥对象上的 scheme 选择器）：

```c
struct TPMT_ASYM_SCHEME {
    TPMI_ALG_ASYM_SCHEME scheme;
    TPMU_ASYM_SCHEME     details;
};

struct TPMT_ECC_SCHEME {
    TPMI_ALG_ECC_SCHEME scheme;  /* TPM2_ALG_EDDSA 或 TPM2_ALG_HASH_EDDSA */
    TPMU_ASYM_SCHEME    details; /* EdDSA/Hash-EdDSA 时 details 为空 */
};
```

`L2427`–`L2430`、`L2498`–`L2501`

ECC 密钥通过 `TPMS_ECC_PARMS` 绑定曲线与签名方案：

```c
struct TPMS_ECC_PARMS {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ECC_SCHEME     scheme;  /* sign 属性为 SET 时须为有效签名方案 */
    TPMI_ECC_CURVE      curveID; /* TPM2_ECC_CURVE_25519 或 TPM2_ECC_CURVE_448 */
    TPMT_KDF_SCHEME     kdf;
};
```

`L2691`–`L2708`

| 对比项 | `TPM2_ALG_EDDSA` | `TPM2_ALG_HASH_EDDSA` |
|--------|------------------|----------------------|
| 对象类型 | `TPM2_ALG_ECC` + Curve25519/448 | 同左 |
| 方案参数 (`TPMU_SIG_SCHEME` / `TPMU_ASYM_SCHEME`) | `TPMS_EMPTY` | `TPMS_EMPTY` |
| 签名联合体成员 | `eddsa` | `hash_eddsa` |
| 签名载荷类型 | `TPM2B_SIGNATURE_EDDSA` | `TPM2B_SIGNATURE_EDDSA`（与 EdDSA 相同） |
| 与 Hash-ML-DSA 差异 | 签名中**不**嵌入 hash 元数据 | 亦**不**嵌入；hash 在 digest/命令层处理 |
| v1.85 命令路径 | `SignDigest` / `SignSequence*` / `VerifyDigestSignature` / `VerifySequence*` | 同左 |

### 签名类型

```c
/* EdDSA Signature Types (must be defined before TPMU_SIGNATURE) */
typedef struct TPM2B_SIGNATURE_EDDSA {
    UINT16 size;
    BYTE   buffer[2 * TPM2_MAX_ECC_KEY_BYTES];
} TPM2B_SIGNATURE_EDDSA;

/* ML-DSA Signature Types (must be defined before TPMU_SIGNATURE) */
typedef struct TPM2B_SIGNATURE_MLDSA {
    UINT16 size;
    BYTE   buffer[TPM2_MAX_MLDSA_SIG_SIZE];
} TPM2B_SIGNATURE_MLDSA;

typedef struct TPMS_SIGNATURE_HASH_MLDSA {
    TPMI_ALG_HASH         hash;
    TPM2B_SIGNATURE_MLDSA signature;
} TPMS_SIGNATURE_HASH_MLDSA;
```

`L2548`–`L2563`

**说明（Part 2 Table 217）：** `mldsa`、`eddsa`、`hash_eddsa` 在 `TPMU_SIGNATURE` 中使用 **TPM2B** 而非 **TPMS**，因为签名元数据中不包含可选 hash 字段；`hash_mldsa` 则使用带 `hash` 的 `TPMS_SIGNATURE_HASH_MLDSA`。`hash_eddsa` 与 `eddsa` 同为 `TPM2B_SIGNATURE_EDDSA`（不同于 Hash-ML-DSA 的 TPMS 包装）。

### `TPMU_SIGNATURE`（PQC / EdDSA 成员）

```c
union TPMU_SIGNATURE {
    TPMS_SIGNATURE_RSASSA     rsassa;
    TPMS_SIGNATURE_RSAPSS     rsapss;
    TPMS_SIGNATURE_ECDSA      ecdsa;
    TPMS_SIGNATURE_ECDAA      ecdaa;
    TPMS_SIGNATURE_SM2        sm2;
    TPMS_SIGNATURE_ECSCHNORR  ecschnorr;
    TPM2B_SIGNATURE_EDDSA     eddsa;      /* EdDSA signature */
    TPM2B_SIGNATURE_EDDSA     hash_eddsa; /* Hash-EdDSA signature */
    TPM2B_SIGNATURE_MLDSA     mldsa;      /* ML-DSA signature */
    TPMS_SIGNATURE_HASH_MLDSA hash_mldsa; /* Hash-ML-DSA signature (hash + signature) */
    TPMT_HA                   hmac;
    TPMS_SCHEME_HASH          any;
    TPMS_EMPTY                null;
};
```

`L2567`–`L2581`

`TPMT_SIGNATURE` 包装（EdDSA 验签时 `sigAlg` 须与密钥 scheme 一致）：

```c
struct TPMT_SIGNATURE {
    TPMI_ALG_SIG_SCHEME sigAlg;    /* TPM2_ALG_EDDSA 或 TPM2_ALG_HASH_EDDSA */
    TPMU_SIGNATURE      signature;
};
```

`L2585`–`L2588`

### `TPMU_ENCRYPTED_SECRET`（PQC 成员）

```c
union TPMU_ENCRYPTED_SECRET {
    BYTE ecc[sizeof(TPMS_ECC_POINT)];
    BYTE rsa[TPM2_MAX_RSA_KEY_BYTES];
    BYTE mlkem[TPM2_MAX_MLKEM_CT_SIZE];
    BYTE symmetric[sizeof(TPM2B_DIGEST)];
    BYTE keyedHash[sizeof(TPM2B_DIGEST)];
};
```

`L2592`–`L2599`

### ML-KEM / ML-DSA 密钥缓冲区

```c
/* Definition of ML-KEM TPM2B_PUBLIC_KEY_MLKEM Structure */
typedef struct TPM2B_PUBLIC_KEY_MLKEM TPM2B_PUBLIC_KEY_MLKEM;
struct TPM2B_PUBLIC_KEY_MLKEM {
    UINT16 size;
    BYTE   buffer[TPM2_MAX_MLKEM_PUB_SIZE];
};

/* Definition of ML-KEM TPM2B_PRIVATE_KEY_MLKEM Structure */
typedef struct TPM2B_PRIVATE_KEY_MLKEM TPM2B_PRIVATE_KEY_MLKEM;
struct TPM2B_PRIVATE_KEY_MLKEM {
    UINT16 size;
    BYTE   buffer[TPM2_MLKEM_PRIVATE_KEY_SEED_SIZE];
};

/* ML-DSA Key Types */
typedef struct TPM2B_PUBLIC_KEY_MLDSA {
    UINT16 size;
    BYTE   buffer[TPM2_MAX_MLDSA_PUB_SIZE];
} TPM2B_PUBLIC_KEY_MLDSA;

typedef struct TPM2B_PRIVATE_KEY_MLDSA {
    UINT16 size;
    BYTE   buffer[TPM2_MLDSA_PRIVATE_KEY_SEED_SIZE];
} TPM2B_PRIVATE_KEY_MLDSA;
```

`L2611`–`L2634`

### `TPMU_PUBLIC_ID`（PQC 成员）

```c
union TPMU_PUBLIC_ID {
    /* ... keyedHash, sym, rsa, ecc, derive ... */
    TPM2B_PUBLIC_KEY_MLKEM mlkem;
    TPM2B_PUBLIC_KEY_MLDSA mldsa;
};
```

`L2638`–`L2646`（节选）

### PQC 参数结构与 KEM 缓冲区

```c
/* Definition of TPMS_MLKEM_PARMS Structure */
typedef struct TPMS_MLKEM_PARMS TPMS_MLKEM_PARMS;
struct TPMS_MLKEM_PARMS {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMI_MLKEM_PARMS parameterSet; /* ML-KEM parameter set (512, 768, or 1024) */
};

/* Definition of ML-KEM TPM2B_KEM_CIPHERTEXT Structure */
typedef struct TPM2B_KEM_CIPHERTEXT TPM2B_KEM_CIPHERTEXT;
struct TPM2B_KEM_CIPHERTEXT {
    UINT16 size;
    BYTE   buffer[TPM2_MAX_MLKEM_CT_SIZE];
};

/* Definition of TPM2B_SHARED_SECRET Structure */
typedef struct TPM2B_SHARED_SECRET TPM2B_SHARED_SECRET;
struct TPM2B_SHARED_SECRET {
    UINT16 size;
    BYTE   buffer[TPM2_MLKEM_SHARED_SECRET_SIZE];
};

/* ML-DSA Parameter Structures */
typedef struct TPMS_MLDSA_PARMS {
    TPMI_MLDSA_PARMS parameterSet;
    UINT8            allowExternalMu; /* TPM spec BOOL is a single byte (BYTE/UINT8) */
} TPMS_MLDSA_PARMS;

typedef struct TPMS_HASH_MLDSA_PARMS {
    TPMI_MLDSA_PARMS parameterSet;
    TPMI_ALG_HASH    hashAlg;
} TPMS_HASH_MLDSA_PARMS;
```

`L2710`–`L2743`（约）

### 签名 context / hint

```c
typedef union TPMU_SIGNATURE_CTX TPMU_SIGNATURE_CTX;
union TPMU_SIGNATURE_CTX {
    BYTE buffer[TPM2_MLDSA_CTX_MAX_SIZE];
};

typedef struct TPM2B_SIGNATURE_CTX {
    UINT16 size;
    BYTE   buffer[sizeof(TPMU_SIGNATURE_CTX)];
} TPM2B_SIGNATURE_CTX;

typedef struct TPM2B_SIGNATURE_HINT {
    UINT16 size;
    BYTE   buffer[TPM2_MAX_SIGNATURE_HINT_SIZE];
} TPM2B_SIGNATURE_HINT;
```

`L2745`–`L2758`（约）

### `TPMU_PUBLIC_PARMS`（PQC 成员）

```c
union TPMU_PUBLIC_PARMS {
    /* ... keyedHashDetail, symDetail, rsaDetail, eccDetail, asymDetail ... */
    TPMS_MLKEM_PARMS      mlkemDetail;      /* ML-KEM decrypt */
    TPMS_MLDSA_PARMS      mldsaDetail;      /* ML-DSA sign */
    TPMS_HASH_MLDSA_PARMS hash_mldsaDetail; /* Hash-based ML-DSA sign */
};
```

`L2762`–`L2771`（节选）

### `TPMU_SENSITIVE_COMPOSITE`（PQC 成员）

```c
union TPMU_SENSITIVE_COMPOSITE {
    /* ... rsa, ecc, bits, sym, any ... */
    TPM2B_PRIVATE_KEY_MLDSA mldsa; /* ML-DSA private key seed */
    TPM2B_PRIVATE_KEY_MLKEM mlkem; /* ML-KEM private key seed */
};
```

`L2820`–`L2828`（节选）

`TPM2_ALG_HASH_MLDSA` 对象在 MU 层 selector 映射到同一 `mldsa` 成员（与 `TPM2_ALG_MLDSA` 共用）。

---

## `include/tss2/tss2_sys.h`

`L1927`–`L2053`

```c
TSS2_RC Tss2_Sys_Encapsulate_Prepare(TSS2_SYS_CONTEXT *sysContext, TPMI_DH_OBJECT keyHandle);

TSS2_RC Tss2_Sys_Encapsulate_Complete(TSS2_SYS_CONTEXT     *sysContext,
                                      TPM2B_SHARED_SECRET  *sharedSecret,
                                      TPM2B_KEM_CIPHERTEXT *ciphertext);

TSS2_RC Tss2_Sys_Encapsulate(TSS2_SYS_CONTEXT             *sysContext,
                             TPMI_DH_OBJECT                keyHandle,
                             TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                             TPM2B_SHARED_SECRET          *sharedSecret,
                             TPM2B_KEM_CIPHERTEXT         *ciphertext,
                             TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);

TSS2_RC Tss2_Sys_Decapsulate_Prepare(TSS2_SYS_CONTEXT           *sysContext,
                                     TPMI_DH_OBJECT              keyHandle,
                                     const TPM2B_KEM_CIPHERTEXT *ciphertext);

TSS2_RC Tss2_Sys_Decapsulate_Complete(TSS2_SYS_CONTEXT    *sysContext,
                                      TPM2B_SHARED_SECRET *sharedSecret);

TSS2_RC Tss2_Sys_Decapsulate(TSS2_SYS_CONTEXT             *sysContext,
                             TPMI_DH_OBJECT                keyHandle,
                             TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                             const TPM2B_KEM_CIPHERTEXT   *ciphertext,
                             TPM2B_SHARED_SECRET          *sharedSecret,
                             TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);

TSS2_RC Tss2_Sys_SignDigest_Prepare(TSS2_SYS_CONTEXT          *sysContext,
                                    TPMI_DH_OBJECT             keyHandle,
                                    const TPM2B_SIGNATURE_CTX *context,
                                    const TPM2B_DIGEST        *digest,
                                    const TPMT_TK_HASHCHECK   *validation);

TSS2_RC Tss2_Sys_SignDigest_Complete(TSS2_SYS_CONTEXT *sysContext, TPMT_SIGNATURE *signature);

TSS2_RC Tss2_Sys_SignDigest(TSS2_SYS_CONTEXT             *sysContext,
                            TPMI_DH_OBJECT                keyHandle,
                            TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                            const TPM2B_SIGNATURE_CTX    *context,
                            const TPM2B_DIGEST           *digest,
                            const TPMT_TK_HASHCHECK      *validation,
                            TPMT_SIGNATURE               *signature,
                            TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);

TSS2_RC Tss2_Sys_VerifyDigestSignature_Prepare(TSS2_SYS_CONTEXT          *sysContext,
                                               TPMI_DH_OBJECT             keyHandle,
                                               const TPM2B_SIGNATURE_CTX *context,
                                               const TPM2B_DIGEST        *digest,
                                               const TPMT_SIGNATURE      *signature);

TSS2_RC Tss2_Sys_VerifyDigestSignature_Complete(TSS2_SYS_CONTEXT *sysContext,
                                                TPMT_TK_VERIFIED *validation);

TSS2_RC Tss2_Sys_VerifyDigestSignature(TSS2_SYS_CONTEXT             *sysContext,
                                       TPMI_DH_OBJECT                keyHandle,
                                       TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                       const TPM2B_SIGNATURE_CTX    *context,
                                       const TPM2B_DIGEST           *digest,
                                       const TPMT_SIGNATURE         *signature,
                                       TPMT_TK_VERIFIED             *validation,
                                       TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);

TSS2_RC Tss2_Sys_SignSequenceStart_Prepare(TSS2_SYS_CONTEXT          *sysContext,
                                           TPMI_DH_OBJECT             keyHandle,
                                           const TPM2B_AUTH          *auth,
                                           const TPM2B_SIGNATURE_CTX *context);

TSS2_RC Tss2_Sys_SignSequenceStart_Complete(TSS2_SYS_CONTEXT *sysContext,
                                            TPMI_DH_OBJECT   *sequenceHandle);

TSS2_RC Tss2_Sys_SignSequenceStart(TSS2_SYS_CONTEXT             *sysContext,
                                   TPMI_DH_OBJECT                keyHandle,
                                   TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                   const TPM2B_AUTH             *auth,
                                   const TPM2B_SIGNATURE_CTX    *context,
                                   TPMI_DH_OBJECT               *sequenceHandle,
                                   TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);

TSS2_RC Tss2_Sys_VerifySequenceStart_Prepare(TSS2_SYS_CONTEXT           *sysContext,
                                             TPMI_DH_OBJECT              keyHandle,
                                             const TPM2B_AUTH           *auth,
                                             const TPM2B_SIGNATURE_HINT *hint,
                                             const TPM2B_SIGNATURE_CTX  *context);

TSS2_RC Tss2_Sys_VerifySequenceStart_Complete(TSS2_SYS_CONTEXT *sysContext,
                                              TPMI_DH_OBJECT   *sequenceHandle);

TSS2_RC Tss2_Sys_VerifySequenceStart(TSS2_SYS_CONTEXT             *sysContext,
                                     TPMI_DH_OBJECT                keyHandle,
                                     TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                     const TPM2B_AUTH             *auth,
                                     const TPM2B_SIGNATURE_HINT   *hint,
                                     const TPM2B_SIGNATURE_CTX    *context,
                                     TPMI_DH_OBJECT               *sequenceHandle,
                                     TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);

TSS2_RC Tss2_Sys_SignSequenceComplete_Prepare(TSS2_SYS_CONTEXT       *sysContext,
                                              TPMI_DH_OBJECT          sequenceHandle,
                                              TPMI_DH_OBJECT          keyHandle,
                                              const TPM2B_MAX_BUFFER *buffer);

TSS2_RC Tss2_Sys_SignSequenceComplete_Complete(TSS2_SYS_CONTEXT *sysContext,
                                               TPMT_SIGNATURE   *signature);

TSS2_RC Tss2_Sys_SignSequenceComplete(TSS2_SYS_CONTEXT             *sysContext,
                                      TPMI_DH_OBJECT                sequenceHandle,
                                      TPMI_DH_OBJECT                keyHandle,
                                      TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                      const TPM2B_MAX_BUFFER       *buffer,
                                      TPMT_SIGNATURE               *signature,
                                      TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);

TSS2_RC Tss2_Sys_VerifySequenceComplete_Prepare(TSS2_SYS_CONTEXT     *sysContext,
                                                TPMI_DH_OBJECT        sequenceHandle,
                                                TPMI_DH_OBJECT        keyHandle,
                                                const TPMT_SIGNATURE *signature);

TSS2_RC Tss2_Sys_VerifySequenceComplete_Complete(TSS2_SYS_CONTEXT *sysContext,
                                                 TPMT_TK_VERIFIED *validation);

TSS2_RC Tss2_Sys_VerifySequenceComplete(TSS2_SYS_CONTEXT             *sysContext,
                                        TPMI_DH_OBJECT                sequenceHandle,
                                        TPMI_DH_OBJECT                keyHandle,
                                        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                        const TPMT_SIGNATURE         *signature,
                                        TPMT_TK_VERIFIED             *validation,
                                        TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray);
```

EdDSA / Hash-EdDSA 签名与验签**复用**上述 v1.85 命令，**无独立 Sys API**。典型调用关系：

| 操作 | 命令 | 关键参数 |
|------|------|----------|
| 对 digest 签名 | `Tss2_Sys_SignDigest` | `keyHandle`（ECC+EdDSA 密钥）、`digest`、`validation` → `TPMT_SIGNATURE` |
| 验签 digest | `Tss2_Sys_VerifyDigestSignature` | `signature.sigAlg` 为 `TPM2_ALG_EDDSA` 或 `TPM2_ALG_HASH_EDDSA` |
| 流式签名 | `SignSequenceStart` → `SequenceUpdate`* → `SignSequenceComplete` | CC `SignVerifySequenceStart`（0x1a2）；`auth` 可空 → `decryptNull`；`context` 可空（size 0） |
| 流式验签 | `VerifySequenceStart` → `SequenceUpdate`* → `VerifySequenceComplete` | CC `SignVerifySequenceStart`（0x1a2）；`auth` 可空 → `decryptNull`；`hint` / `context` 可空（size 0） |
| ML-KEM 解封装 | `Tss2_Sys_Decapsulate` | `ciphertext` 为 `NULL` 或 `size==0` 时置 `decryptNull` 并 marshal size 0，供 `SetDecryptParam` / session 加密；一体式调用须提供有效非空密文 |

\* `SequenceUpdate` 为既有命令，非 v1.85 新增。

函数体见 **实现代码（`.c`）→ EdDSA / Hash-EdDSA** 小节。

---

## `include/tss2/tss2_mu.h`

### `TPM2B_*` Marshal / Unmarshal

`L272`–`L390`（约）

```c
TSS2_RC
Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Marshal(TPM2B_PUBLIC_KEY_MLKEM const *src,
                                       uint8_t                       buffer[],
                                       size_t                        buffer_size,
                                       size_t                       *offset);

TSS2_RC
Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Unmarshal(uint8_t const           buffer[],
                                         size_t                  buffer_size,
                                         size_t                 *offset,
                                         TPM2B_PUBLIC_KEY_MLKEM *dest);

TSS2_RC
Tss2_MU_TPM2B_PRIVATE_KEY_MLKEM_Marshal(TPM2B_PRIVATE_KEY_MLKEM const *src,
                                        uint8_t                        buffer[],
                                        size_t                         buffer_size,
                                        size_t                        *offset);

TSS2_RC
Tss2_MU_TPM2B_PRIVATE_KEY_MLKEM_Unmarshal(uint8_t const            buffer[],
                                          size_t                   buffer_size,
                                          size_t                  *offset,
                                          TPM2B_PRIVATE_KEY_MLKEM *dest);

TSS2_RC
Tss2_MU_TPM2B_KEM_CIPHERTEXT_Marshal(TPM2B_KEM_CIPHERTEXT const *src,
                                     uint8_t                     buffer[],
                                     size_t                      buffer_size,
                                     size_t                     *offset);

TSS2_RC
Tss2_MU_TPM2B_KEM_CIPHERTEXT_Unmarshal(uint8_t const         buffer[],
                                       size_t                buffer_size,
                                       size_t               *offset,
                                       TPM2B_KEM_CIPHERTEXT *dest);

TSS2_RC
Tss2_MU_TPM2B_SHARED_SECRET_Marshal(TPM2B_SHARED_SECRET const *src,
                                    uint8_t                    buffer[],
                                    size_t                     buffer_size,
                                    size_t                    *offset);

TSS2_RC
Tss2_MU_TPM2B_SHARED_SECRET_Unmarshal(uint8_t const        buffer[],
                                      size_t               buffer_size,
                                      size_t              *offset,
                                      TPM2B_SHARED_SECRET *dest);

TSS2_RC
Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Marshal(TPM2B_PUBLIC_KEY_MLDSA const *src,
                                       uint8_t                       buffer[],
                                       size_t                        buffer_size,
                                       size_t                       *offset);

TSS2_RC
Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Unmarshal(uint8_t const           buffer[],
                                         size_t                  buffer_size,
                                         size_t                 *offset,
                                         TPM2B_PUBLIC_KEY_MLDSA *dest);

TSS2_RC
Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Marshal(TPM2B_PRIVATE_KEY_MLDSA const *src,
                                        uint8_t                        buffer[],
                                        size_t                         buffer_size,
                                        size_t                        *offset);

TSS2_RC
Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Unmarshal(uint8_t const            buffer[],
                                          size_t                   buffer_size,
                                          size_t                  *offset,
                                          TPM2B_PRIVATE_KEY_MLDSA *dest);

TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_EDDSA_Marshal(TPM2B_SIGNATURE_EDDSA const *src,
                                      uint8_t                      buffer[],
                                      size_t                       buffer_size,
                                      size_t                      *offset);

TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_EDDSA_Unmarshal(uint8_t const          buffer[],
                                        size_t                 buffer_size,
                                        size_t                *offset,
                                        TPM2B_SIGNATURE_EDDSA *dest);
```

`L345`–`L354`（EdDSA / Hash-EdDSA 签名均经此 `TPM2B` 编解码；**无** `TPMS_SIG_SCHEME_EDDSA` 的独立 MU 入口，方案体为空时走 `marshal_null`。）

```c
TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_MLDSA_Marshal(TPM2B_SIGNATURE_MLDSA const *src,
                                      uint8_t                      buffer[],
                                      size_t                       buffer_size,
                                      size_t                      *offset);

TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_MLDSA_Unmarshal(uint8_t const          buffer[],
                                        size_t                 buffer_size,
                                        size_t                *offset,
                                        TPM2B_SIGNATURE_MLDSA *dest);

TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(TPM2B_SIGNATURE_CTX const *src,
                                  uint8_t                    buffer[],
                                  size_t                     buffer_size,
                                  size_t                    *offset);

TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_CTX_Unmarshal(uint8_t const        buffer[],
                                    size_t               buffer_size,
                                    size_t              *offset,
                                    TPM2B_SIGNATURE_CTX *dest);

TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_HINT_Marshal(TPM2B_SIGNATURE_HINT const *src,
                                     uint8_t                     buffer[],
                                     size_t                      buffer_size,
                                     size_t                     *offset);

TSS2_RC
Tss2_MU_TPM2B_SIGNATURE_HINT_Unmarshal(uint8_t const         buffer[],
                                       size_t                buffer_size,
                                       size_t               *offset,
                                       TPM2B_SIGNATURE_HINT *dest);
```

### `TPMS_*` / `TPMI_*` Marshal / Unmarshal

`L905`–`L915`（约）

```c
TSS2_RC
Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Marshal(TPMS_SIGNATURE_HASH_MLDSA const *src,
                                          uint8_t                          buffer[],
                                          size_t                           buffer_size,
                                          size_t                          *offset);

TSS2_RC
Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Unmarshal(uint8_t const              buffer[],
                                            size_t                     buffer_size,
                                            size_t                    *offset,
                                            TPMS_SIGNATURE_HASH_MLDSA *dest);
```

`L1073`–`L1131`（约）

```c
TSS2_RC
Tss2_MU_TPMI_MLKEM_PARMS_Marshal(TPMI_MLKEM_PARMS src,
                                 uint8_t          buffer[],
                                 size_t           buffer_size,
                                 size_t          *offset);

TSS2_RC
Tss2_MU_TPMI_MLKEM_PARMS_Unmarshal(uint8_t const     buffer[],
                                   size_t            buffer_size,
                                   size_t           *offset,
                                   TPMI_MLKEM_PARMS *dest);

TSS2_RC
Tss2_MU_TPMS_MLKEM_PARMS_Marshal(TPMS_MLKEM_PARMS const *src,
                                 uint8_t                 buffer[],
                                 size_t                  buffer_size,
                                 size_t                 *offset);

TSS2_RC
Tss2_MU_TPMS_MLKEM_PARMS_Unmarshal(uint8_t const     buffer[],
                                   size_t            buffer_size,
                                   size_t           *offset,
                                   TPMS_MLKEM_PARMS *dest);

TSS2_RC
Tss2_MU_TPMI_MLDSA_PARMS_Marshal(TPMI_MLDSA_PARMS src,
                                 uint8_t          buffer[],
                                 size_t           buffer_size,
                                 size_t          *offset);

TSS2_RC
Tss2_MU_TPMI_MLDSA_PARMS_Unmarshal(uint8_t const     buffer[],
                                   size_t            buffer_size,
                                   size_t           *offset,
                                   TPMI_MLDSA_PARMS *dest);

TSS2_RC
Tss2_MU_TPMS_MLDSA_PARMS_Marshal(TPMS_MLDSA_PARMS const *src,
                                 uint8_t                 buffer[],
                                 size_t                  buffer_size,
                                 size_t                 *offset);

TSS2_RC
Tss2_MU_TPMS_MLDSA_PARMS_Unmarshal(uint8_t const     buffer[],
                                   size_t            buffer_size,
                                   size_t           *offset,
                                   TPMS_MLDSA_PARMS *dest);

TSS2_RC
Tss2_MU_TPMS_HASH_MLDSA_PARMS_Marshal(TPMS_HASH_MLDSA_PARMS const *src,
                                      uint8_t                      buffer[],
                                      size_t                       buffer_size,
                                      size_t                      *offset);

TSS2_RC
Tss2_MU_TPMS_HASH_MLDSA_PARMS_Unmarshal(uint8_t const          buffer[],
                                        size_t                 buffer_size,
                                        size_t                *offset,
                                        TPMS_HASH_MLDSA_PARMS *dest);
```

PQC / EdDSA 成员所在的联合体经既有 `Tss2_MU_TPMU_*` / `Tss2_MU_TPMT_*` 按 selector 编解码，**无单独联合体 MU 入口**。涉及：

| 联合体 | PQC / EdDSA 相关 selector |
|--------|---------------------------|
| `TPMU_SIGNATURE` | `TPM2_ALG_EDDSA`、`TPM2_ALG_HASH_EDDSA`、`TPM2_ALG_MLDSA`、`TPM2_ALG_HASH_MLDSA` |
| `TPMU_SIG_SCHEME` | `TPM2_ALG_EDDSA`、`TPM2_ALG_HASH_EDDSA` |
| `TPMU_ASYM_SCHEME` | `TPM2_ALG_EDDSA`、`TPM2_ALG_HASH_EDDSA` |
| `TPMU_PUBLIC_PARMS` | `TPM2_ALG_MLKEM`、`TPM2_ALG_MLDSA`、`TPM2_ALG_HASH_MLDSA` |
| `TPMU_PUBLIC_ID` | `TPM2_ALG_MLKEM`、`TPM2_ALG_MLDSA`（`HASH_MLDSA` 共用 `mldsa`） |
| `TPMU_SENSITIVE_COMPOSITE` | `TPM2_ALG_MLDSA`、`TPM2_ALG_HASH_MLDSA`、`TPM2_ALG_MLKEM` |
| `TPMU_ENCRYPTED_SECRET` | `TPM2_ALG_MLKEM` |

实现见下文 **实现代码（`.c`）→ `src/tss2-mu/tpmu-types.c`** 小节。

---

## 实现代码（`.c`）

以下摘录各 `.c` 源文件中的 PQC / EdDSA 相关实现（省略文件头版权与 `#include`）。

### `src/tss2-sys/sysapi_util.c`

v1.85 命令在 `commandArray` 中的句柄计数（`numCommandHandles`, `numResponseHandles`）：

```c
{ TPM2_CC_Encapsulate, 1, 0 },
{ TPM2_CC_Decapsulate, 1, 0 },
{ TPM2_CC_SignDigest, 1, 0 },
{ TPM2_CC_VerifyDigestSignature, 1, 0 },
{ TPM2_CC_SignVerifySequenceStart, 1, 1 },
{ TPM2_CC_SignSequenceComplete, 2, 0 },
{ TPM2_CC_VerifySequenceComplete, 2, 0 }
```

`L281`–`L288`

### `src/tss2-sys/api/Tss2_Sys_Encapsulate.c`

```c
TSS2_RC
Tss2_Sys_Encapsulate_Prepare(TSS2_SYS_CONTEXT *sysContext, TPMI_DH_OBJECT keyHandle) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_Encapsulate);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_Encapsulate_Complete(TSS2_SYS_CONTEXT     *sysContext,
                              TPM2B_SHARED_SECRET  *sharedSecret,
                              TPM2B_KEM_CIPHERTEXT *ciphertext) {
    /* ... CommonComplete ... */
    rval = Tss2_MU_TPM2B_SHARED_SECRET_Unmarshal(..., sharedSecret);
    return Tss2_MU_TPM2B_KEM_CIPHERTEXT_Unmarshal(..., ciphertext);
}

TSS2_RC
Tss2_Sys_Encapsulate(...) {
    rval = Tss2_Sys_Encapsulate_Prepare(sysContext, keyHandle);
    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    return Tss2_Sys_Encapsulate_Complete(sysContext, sharedSecret, ciphertext);
}
```

`L17`–`L82`（`Complete` / 一体式函数体见源文件）

### `src/tss2-sys/api/Tss2_Sys_Decapsulate.c`

```c
TSS2_RC
Tss2_Sys_Decapsulate_Prepare(TSS2_SYS_CONTEXT           *sysContext,
                             TPMI_DH_OBJECT              keyHandle,
                             const TPM2B_KEM_CIPHERTEXT *ciphertext) {
    /* ... */
    rval = Tss2_MU_UINT32_Marshal(keyHandle, ...);
    TPM2B_KEM_CIPHERTEXT empty = { .size = 0 };
    const TPM2B_KEM_CIPHERTEXT *in = ciphertext ? ciphertext : &empty;
    if (!ciphertext || ciphertext->size == 0)
        ctx->decryptNull = 1;
    rval = Tss2_MU_TPM2B_KEM_CIPHERTEXT_Marshal(in, ...);
    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_Decapsulate_Complete(TSS2_SYS_CONTEXT *sysContext, TPM2B_SHARED_SECRET *sharedSecret) {
    /* ... CommonComplete ... */
    return Tss2_MU_TPM2B_SHARED_SECRET_Unmarshal(..., sharedSecret);
}

/* 一体式 Tss2_Sys_Decapsulate：ciphertext 允许 NULL 或 size==0（与 Prepare 一致） */
```

`L17`–`L85`

### `src/tss2-sys/api/Tss2_Sys_SignDigest.c`

```c
TSS2_RC
Tss2_Sys_SignDigest_Prepare(...) {
    /* keyHandle */
    TPM2B_SIGNATURE_CTX empty_ctx = { .size = 0 };
    const TPM2B_SIGNATURE_CTX *context_in = context ? context : &empty_ctx;
    if (!context || context->size == 0)
        ctx->decryptNull = 1;
    rval = Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(context_in, ...);
    TPM2B_DIGEST empty_digest = { .size = 0 };
    const TPM2B_DIGEST *digest_in = digest ? digest : &empty_digest;
    rval = Tss2_MU_TPM2B_DIGEST_Marshal(digest_in, ...);
    rval = Tss2_MU_TPMT_TK_HASHCHECK_Marshal(validation, ...);
    ctx->decryptAllowed = 1;
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_SignDigest_Complete(...) {
    return Tss2_MU_TPMT_SIGNATURE_Unmarshal(..., signature);
}
```

`L17`–`L114`

**EdDSA / Hash-EdDSA：** 与 ML-DSA 共用同一实现；区别在 TPM 侧根据密钥 `TPMT_ECC_SCHEME.scheme`（`TPM2_ALG_EDDSA` / `TPM2_ALG_HASH_EDDSA`）选择算法，返回的 `TPMT_SIGNATURE.sigAlg` 与 `signature.eddsa` / `signature.hash_eddsa` 成员对应。

### `src/tss2-sys/api/Tss2_Sys_VerifyDigestSignature.c`

```c
TSS2_RC
Tss2_Sys_VerifyDigestSignature_Prepare(...) {
    /* context：NULL/size==0 → decryptNull；统一 empty TPM2B + Marshal */
    TPM2B_SIGNATURE_CTX empty_ctx = { .size = 0 };
    const TPM2B_SIGNATURE_CTX *context_in = context ? context : &empty_ctx;
    if (!context || context->size == 0)
        ctx->decryptNull = 1;
    rval = Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(context_in, ...);
    /* digest：secondary nullable，不置 decryptNull */
    TPM2B_DIGEST empty_digest = { .size = 0 };
    const TPM2B_DIGEST *digest_in = digest ? digest : &empty_digest;
    rval = Tss2_MU_TPM2B_DIGEST_Marshal(digest_in, ...);
    rval = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, ...);
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_VerifyDigestSignature_Complete(...) {
    return Tss2_MU_TPMT_TK_VERIFIED_Unmarshal(..., validation);
}
```

`L17`–`L116`

**EdDSA / Hash-EdDSA：** `Tss2_MU_TPMT_SIGNATURE_Marshal` 根据 `signature->sigAlg` 在 `TPMU_SIGNATURE` 中选择 `eddsa` 或 `hash_eddsa` 分支（见 `tpmu-types.c`）。

### `src/tss2-sys/api/Tss2_Sys_SignSequenceStart.c`

```c
TSS2_RC
Tss2_Sys_SignSequenceStart_Prepare(...) {
    rval = CommonPreparePrologue(ctx, TPM2_CC_SignVerifySequenceStart);
    TPM2B_AUTH empty_auth = { .size = 0 };
    const TPM2B_AUTH *auth_in = auth ? auth : &empty_auth;
    if (!auth || auth->size == 0)
        ctx->decryptNull = 1;
    rval = Tss2_MU_TPM2B_AUTH_Marshal(auth_in, ...);
    /* context：secondary nullable，不置 decryptNull */
    TPM2B_SIGNATURE_CTX empty_ctx = { .size = 0 };
    const TPM2B_SIGNATURE_CTX *context_in = context ? context : &empty_ctx;
    rval = Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(context_in, ...);
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_SignSequenceStart_Complete(...) {
    rval = Tss2_MU_UINT32_Unmarshal(..., sequenceHandle);
    return CommonComplete(ctx);
}
```

`L17`–`L99`

### `src/tss2-sys/api/Tss2_Sys_VerifySequenceStart.c`

```c
TSS2_RC
Tss2_Sys_VerifySequenceStart_Prepare(...) {
    rval = CommonPreparePrologue(ctx, TPM2_CC_SignVerifySequenceStart);
    TPM2B_AUTH empty_auth = { .size = 0 };
    const TPM2B_AUTH *auth_in = auth ? auth : &empty_auth;
    if (!auth || auth->size == 0)
        ctx->decryptNull = 1;
    rval = Tss2_MU_TPM2B_AUTH_Marshal(auth_in, ...);
    /* hint / context：secondary nullable，不置 decryptNull */
    TPM2B_SIGNATURE_HINT empty_hint = { .size = 0 };
    const TPM2B_SIGNATURE_HINT *hint_in = hint ? hint : &empty_hint;
    rval = Tss2_MU_TPM2B_SIGNATURE_HINT_Marshal(hint_in, ...);
    TPM2B_SIGNATURE_CTX empty_ctx = { .size = 0 };
    const TPM2B_SIGNATURE_CTX *context_in = context ? context : &empty_ctx;
    rval = Tss2_MU_TPM2B_SIGNATURE_CTX_Marshal(context_in, ...);
    return CommonPrepareEpilogue(ctx);
}
```

`L17`–`L114`

### `src/tss2-sys/api/Tss2_Sys_SignSequenceComplete.c`

```c
TSS2_RC
Tss2_Sys_SignSequenceComplete_Prepare(...) {
    rval = Tss2_MU_UINT32_Marshal(sequenceHandle, ...);
    rval = Tss2_MU_UINT32_Marshal(keyHandle, ...);
    TPM2B_MAX_BUFFER empty = { .size = 0 };
    const TPM2B_MAX_BUFFER *in = buffer ? buffer : &empty;
    if (!buffer || buffer->size == 0)
        ctx->decryptNull = 1;
    rval = Tss2_MU_TPM2B_MAX_BUFFER_Marshal(in, ...);
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_SignSequenceComplete_Complete(...) {
    return Tss2_MU_TPMT_SIGNATURE_Unmarshal(..., signature);
}
```

`L17`–`L96`

**EdDSA / Hash-EdDSA：** 流式签名完成时 `Complete` 经 `Tss2_MU_TPMT_SIGNATURE_Unmarshal` 解析 `TPM2B_SIGNATURE_EDDSA`。

### `src/tss2-sys/api/Tss2_Sys_VerifySequenceComplete.c`

```c
TSS2_RC
Tss2_Sys_VerifySequenceComplete_Prepare(...) {
    rval = Tss2_MU_UINT32_Marshal(sequenceHandle, ...);
    rval = Tss2_MU_UINT32_Marshal(keyHandle, ...);
    rval = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, ...);
    ctx->decryptAllowed = 0;  /* 无 TPM2B decrypt 参数 */
    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_VerifySequenceComplete_Complete(...) {
    return Tss2_MU_TPMT_TK_VERIFIED_Unmarshal(..., validation);
}
```

`L17`–`L92`

**EdDSA / Hash-EdDSA：** 验签时 `Prepare` 将 `TPMT_SIGNATURE`（含 `sigAlg` + `TPM2B_SIGNATURE_EDDSA`）写入命令缓冲。

链接脚本 / 导出：`lib/tss2-sys.map`、`lib/tss2-sys.def`（EdDSA 无额外 Sys 符号，复用 v1.85 八条命令）。

### EdDSA / Hash-EdDSA（MU 与联合体 selector）

EdDSA 在 TSS 中的实现分散于 `tpm2b-types.c`（签名 blob）与 `tpmu-types.c`（方案 selector 与 `TPMU_SIGNATURE` 分支）。**无** `tpms-types.c` 条目——方案类型为 `TPMS_EMPTY`。

#### `marshal_null` / `unmarshal_null`（空方案体）

`TPMS_SIG_SCHEME_EDDSA` / `TPMS_SIG_SCHEME_HASH_EDDSA` 无字段可序列化，联合体编解码使用空操作：

```c
static TSS2_RC
marshal_null(void const *src, uint8_t buffer[], size_t buffer_size, size_t *offset) {
    UNUSED(src);
    UNUSED(buffer);
    UNUSED(buffer_size);
    UNUSED(offset);
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
unmarshal_null(uint8_t const buffer[], size_t buffer_size, size_t *offset, void *dest) {
    UNUSED(buffer);
    UNUSED(buffer_size);
    UNUSED(offset);
    UNUSED(dest);
    return TSS2_RC_SUCCESS;
}
```

`L118`–`L125`、`L214`–`L221`

#### `src/tss2-mu/tpm2b-types.c`

`TPM2B_MARSHAL` / `TPM2B_UNMARSHAL` 宏展开为各类型的 Marshal/Unmarshal 函数：

```c
TPM2B_MARSHAL(TPM2B_PUBLIC_KEY_MLKEM);
TPM2B_UNMARSHAL(TPM2B_PUBLIC_KEY_MLKEM, buffer);
TPM2B_MARSHAL(TPM2B_PRIVATE_KEY_MLKEM);
TPM2B_UNMARSHAL(TPM2B_PRIVATE_KEY_MLKEM, buffer);
TPM2B_MARSHAL(TPM2B_KEM_CIPHERTEXT);
TPM2B_UNMARSHAL(TPM2B_KEM_CIPHERTEXT, buffer);
TPM2B_MARSHAL(TPM2B_SHARED_SECRET);
TPM2B_UNMARSHAL(TPM2B_SHARED_SECRET, buffer);
TPM2B_MARSHAL(TPM2B_PUBLIC_KEY_MLDSA);
TPM2B_UNMARSHAL(TPM2B_PUBLIC_KEY_MLDSA, buffer);
TPM2B_MARSHAL(TPM2B_PRIVATE_KEY_MLDSA);
TPM2B_UNMARSHAL(TPM2B_PRIVATE_KEY_MLDSA, buffer);
TPM2B_MARSHAL(TPM2B_SIGNATURE_EDDSA);
TPM2B_UNMARSHAL(TPM2B_SIGNATURE_EDDSA, buffer);
TPM2B_MARSHAL(TPM2B_SIGNATURE_MLDSA);
TPM2B_UNMARSHAL(TPM2B_SIGNATURE_MLDSA, buffer);
TPM2B_MARSHAL(TPM2B_SIGNATURE_CTX);
TPM2B_UNMARSHAL(TPM2B_SIGNATURE_CTX, buffer);
TPM2B_MARSHAL(TPM2B_SIGNATURE_HINT);
TPM2B_UNMARSHAL(TPM2B_SIGNATURE_HINT, buffer);
```

`L290`–`L291`（EdDSA 签名 blob；`eddsa` 与 `hash_eddsa` 共用同一 Marshal 函数）

链接导出（`lib/tss2-mu.map` / `lib/tss2-mu.def` `L65`–`L66`）：

```
Tss2_MU_TPM2B_SIGNATURE_EDDSA_Marshal
Tss2_MU_TPM2B_SIGNATURE_EDDSA_Unmarshal
```

### `src/tss2-mu/base-types.c`

```c
BASE_MARSHAL(TPMI_MLKEM_PARMS)
BASE_UNMARSHAL(TPMI_MLKEM_PARMS)
BASE_MARSHAL(TPMI_MLDSA_PARMS)
BASE_UNMARSHAL(TPMI_MLDSA_PARMS)
```

`L172`–`L175`

### `src/tss2-mu/tpms-types.c`

```c
TPMS_MARSHAL_2(TPMS_SIGNATURE_HASH_MLDSA,
               hash, VAL, Tss2_MU_TPMI_ALG_HASH_Marshal,
               signature, ADDR, Tss2_MU_TPM2B_SIGNATURE_MLDSA_Marshal)
TPMS_UNMARSHAL_2(TPMS_SIGNATURE_HASH_MLDSA, ...)

TPMS_MARSHAL_2(TPMS_MLKEM_PARMS,
               symmetric, ADDR, Tss2_MU_TPMT_SYM_DEF_OBJECT_Marshal,
               parameterSet, VAL, Tss2_MU_TPMI_MLKEM_PARMS_Marshal)
TPMS_UNMARSHAL_2(TPMS_MLKEM_PARMS, ...)

TPMS_MARSHAL_2(TPMS_MLDSA_PARMS,
               parameterSet, VAL, Tss2_MU_TPMI_MLDSA_PARMS_Marshal,
               allowExternalMu, VAL, Tss2_MU_UINT8_Marshal)
TPMS_UNMARSHAL_2(TPMS_MLDSA_PARMS, ...)

TPMS_MARSHAL_2(TPMS_HASH_MLDSA_PARMS,
               parameterSet, VAL, Tss2_MU_TPMI_MLDSA_PARMS_Marshal,
               hashAlg, VAL, Tss2_MU_TPMI_ALG_HASH_Marshal)
TPMS_UNMARSHAL_2(TPMS_HASH_MLDSA_PARMS, ...)
```

`L1279`–`L1291`、`L1595`–`L1635`

### `src/tss2-mu/tpmu-types.c`

ML-KEM 密文辅助编解码（`TPMU_ENCRYPTED_SECRET.mlkem` 为定长字节区）：

```c
static TSS2_RC
marshal_mlkem(BYTE const *src, uint8_t buffer[], size_t buffer_size, size_t *offset) {
    return marshal_tab(src, buffer, buffer_size, offset, TPM2_MAX_MLKEM_CT_SIZE);
}

static TSS2_RC
unmarshal_mlkem(uint8_t const buffer[], size_t buffer_size, size_t *offset, BYTE *dest) {
    return unmarshal_tab(buffer, buffer_size, offset, dest, TPM2_MAX_MLKEM_CT_SIZE);
}
```

`L113`–`L116`、`L209`–`L212`

`TPMU_SIG_SCHEME`（EdDSA / Hash-EdDSA 完整 selector 映射）：

```c
TPMU_MARSHAL2(TPMU_SIG_SCHEME,
              TPM2_ALG_RSASSA, ADDR, rsassa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_RSAPSS, ADDR, rsapss, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDSA, ADDR, ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDAA, ADDR, ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Marshal,
              TPM2_ALG_SM2, ADDR, sm2, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECSCHNORR, ADDR, ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_EDDSA, ADDR, eddsa, marshal_null,
              TPM2_ALG_HASH_EDDSA, ADDR, hash_eddsa, marshal_null,
              TPM2_ALG_HMAC, ADDR, hmac, Tss2_MU_TPMS_SCHEME_HASH_Marshal)
TPMU_UNMARSHAL2(TPMU_SIG_SCHEME,
                TPM2_ALG_RSASSA, rsassa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_RSAPSS, rsapss, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDSA, ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDAA, ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Unmarshal,
                TPM2_ALG_SM2, sm2, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECSCHNORR, ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_EDDSA, eddsa, unmarshal_null,
                TPM2_ALG_HASH_EDDSA, hash_eddsa, unmarshal_null,
                TPM2_ALG_HMAC, hmac, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal)
```

`L699`–`L763`

`TPMU_ASYM_SCHEME`（`TPMT_ECC_SCHEME.details` 亦走此映射）：

```c
TPMU_MARSHAL2(TPMU_ASYM_SCHEME,
              TPM2_ALG_ECDH, ADDR, ecdh, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECMQV, ADDR, ecmqv, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_RSASSA, ADDR, rsassa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_RSAPSS, ADDR, rsapss, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDSA, ADDR, ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECDAA, ADDR, ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Marshal,
              TPM2_ALG_SM2, ADDR, sm2, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_ECSCHNORR, ADDR, ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Marshal,
              TPM2_ALG_EDDSA, ADDR, eddsa, marshal_null,
              TPM2_ALG_HASH_EDDSA, ADDR, hash_eddsa, marshal_null,
              TPM2_ALG_RSAES, ADDR, rsaes, marshal_null,
              TPM2_ALG_OAEP, ADDR, oaep, Tss2_MU_TPMS_SCHEME_HASH_Marshal)
TPMU_UNMARSHAL2(TPMU_ASYM_SCHEME,
                TPM2_ALG_ECDH, ecdh, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECMQV, ecmqv, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_RSASSA, rsassa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_RSAPSS, rsapss, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDSA, ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECDAA, ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Unmarshal,
                TPM2_ALG_SM2, sm2, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_ECSCHNORR, ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
                TPM2_ALG_EDDSA, eddsa, unmarshal_null,
                TPM2_ALG_HASH_EDDSA, hash_eddsa, unmarshal_null,
                TPM2_ALG_RSAES, rsaes, unmarshal_null,
                TPM2_ALG_OAEP, oaep, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal)
```

`L796`–`L881`

`TPMU_SIGNATURE`（EdDSA / Hash-EdDSA 与 PQC 并列的 selector 映射）：

```c
TPMU_MARSHAL2(TPMU_SIGNATURE,
              TPM2_ALG_RSASSA, ADDR, rsassa, Tss2_MU_TPMS_SIGNATURE_RSA_Marshal,
              TPM2_ALG_RSAPSS, ADDR, rsapss, Tss2_MU_TPMS_SIGNATURE_RSA_Marshal,
              TPM2_ALG_ECDSA, ADDR, ecdsa, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_ECDAA, ADDR, ecdaa, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_SM2, ADDR, sm2, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_ECSCHNORR, ADDR, ecschnorr, Tss2_MU_TPMS_SIGNATURE_ECC_Marshal,
              TPM2_ALG_EDDSA, ADDR, eddsa, Tss2_MU_TPM2B_SIGNATURE_EDDSA_Marshal,
              TPM2_ALG_HASH_EDDSA, ADDR, hash_eddsa, Tss2_MU_TPM2B_SIGNATURE_EDDSA_Marshal,
              TPM2_ALG_MLDSA, ADDR, mldsa, Tss2_MU_TPM2B_SIGNATURE_MLDSA_Marshal,
              TPM2_ALG_HASH_MLDSA, ADDR, hash_mldsa, Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Marshal,
              TPM2_ALG_HMAC, ADDR, hmac, Tss2_MU_TPMT_HA_Marshal)
TPMU_UNMARSHAL2(TPMU_SIGNATURE,
                TPM2_ALG_RSASSA, rsassa, Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal,
                TPM2_ALG_RSAPSS, rsapss, Tss2_MU_TPMS_SIGNATURE_RSA_Unmarshal,
                TPM2_ALG_ECDSA, ecdsa, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_ECDAA, ecdaa, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_SM2, sm2, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_ECSCHNORR, ecschnorr, Tss2_MU_TPMS_SIGNATURE_ECC_Unmarshal,
                TPM2_ALG_EDDSA, eddsa, Tss2_MU_TPM2B_SIGNATURE_EDDSA_Unmarshal,
                TPM2_ALG_HASH_EDDSA, hash_eddsa, Tss2_MU_TPM2B_SIGNATURE_EDDSA_Unmarshal,
                TPM2_ALG_MLDSA, mldsa, Tss2_MU_TPM2B_SIGNATURE_MLDSA_Unmarshal,
                TPM2_ALG_HASH_MLDSA, hash_mldsa, Tss2_MU_TPMS_SIGNATURE_HASH_MLDSA_Unmarshal,
                TPM2_ALG_HMAC, hmac, Tss2_MU_TPMT_HA_Unmarshal)
```

`L900`–`L978`

`TPMU_SENSITIVE_COMPOSITE` / `TPMU_ENCRYPTED_SECRET` / `TPMU_PUBLIC_ID` / `TPMU_PUBLIC_PARMS`：

```c
TPMU_MARSHAL2(TPMU_SENSITIVE_COMPOSITE,
              /* ... */
              TPM2_ALG_MLDSA, ADDR, mldsa, Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Marshal,
              TPM2_ALG_HASH_MLDSA, ADDR, mldsa, Tss2_MU_TPM2B_PRIVATE_KEY_MLDSA_Marshal,
              TPM2_ALG_MLKEM, ADDR, mlkem, Tss2_MU_TPM2B_PRIVATE_KEY_MLKEM_Marshal)

TPMU_MARSHAL2(TPMU_ENCRYPTED_SECRET,
              /* ... */
              TPM2_ALG_MLKEM, ADDR, mlkem[0], marshal_mlkem)

TPMU_MARSHAL2(TPMU_PUBLIC_ID,
              /* ... */
              TPM2_ALG_MLKEM, ADDR, mlkem, Tss2_MU_TPM2B_PUBLIC_KEY_MLKEM_Marshal,
              TPM2_ALG_MLDSA, ADDR, mldsa, Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Marshal,
              TPM2_ALG_HASH_MLDSA, ADDR, mldsa, Tss2_MU_TPM2B_PUBLIC_KEY_MLDSA_Marshal)

TPMU_MARSHAL2(TPMU_PUBLIC_PARMS,
              /* ... */
              TPM2_ALG_MLKEM, ADDR, mlkemDetail, Tss2_MU_TPMS_MLKEM_PARMS_Marshal,
              TPM2_ALG_MLDSA, ADDR, mldsaDetail, Tss2_MU_TPMS_MLDSA_PARMS_Marshal,
              TPM2_ALG_HASH_MLDSA, ADDR, hash_mldsaDetail, Tss2_MU_TPMS_HASH_MLDSA_PARMS_Marshal)
```

`L980`–`L1150`（各 `TPMU_UNMARSHAL2` 块见源文件）

链接脚本 / 导出：`lib/tss2-mu.map`、`lib/tss2-mu.def`。

---

## 对象布局速查（源码映射）

| `TPMT_PUBLIC.type` | `parameters` | `unique` | `TPMU_SENSITIVE_COMPOSITE` |
|--------------------|--------------|----------|----------------------------|
| `TPM2_ALG_MLKEM` | `mlkemDetail` | `mlkem` | `mlkem` |
| `TPM2_ALG_MLDSA` | `mldsaDetail` | `mldsa` | `mldsa` |
| `TPM2_ALG_HASH_MLDSA` | `hash_mldsaDetail` | `mldsa` | `mldsa` |
| `TPM2_ALG_ECC` + Curve25519/448 + EdDSA scheme | `eccDetail.scheme` = `TPM2_ALG_EDDSA` | `ecc` | `ecc` |
| `TPM2_ALG_ECC` + Curve25519/448 + Hash-EdDSA scheme | `eccDetail.scheme` = `TPM2_ALG_HASH_EDDSA` | `ecc` | `ecc` |

| `TPMT_SIGNATURE.sigAlg` | `TPMU_SIGNATURE` 成员 |
|-------------------------|----------------------|
| `TPM2_ALG_EDDSA` | `eddsa` (`TPM2B_SIGNATURE_EDDSA`) |
| `TPM2_ALG_HASH_EDDSA` | `hash_eddsa` (`TPM2B_SIGNATURE_EDDSA`) |
| `TPM2_ALG_MLDSA` | `mldsa` (`TPM2B_SIGNATURE_MLDSA`) |
| `TPM2_ALG_HASH_MLDSA` | `hash_mldsa` (`TPMS_SIGNATURE_HASH_MLDSA`) |

| `TPMT_SIG_SCHEME.scheme` / `TPMT_ECC_SCHEME.scheme` | `TPMU_SIG_SCHEME` / `TPMU_ASYM_SCHEME` 成员 | MU 编解码 |
|-----------------------------------------------------|---------------------------------------------|-----------|
| `TPM2_ALG_EDDSA` | `eddsa` (`TPMS_EMPTY`) | `marshal_null` / `unmarshal_null` |
| `TPM2_ALG_HASH_EDDSA` | `hash_eddsa` (`TPMS_EMPTY`) | `marshal_null` / `unmarshal_null` |

**EdDSA 签名 buffer 尺寸：** `TPM2B_SIGNATURE_EDDSA.buffer` 为 `2 * TPM2_MAX_ECC_KEY_BYTES`（Curve25519/448 公钥长度的两倍，容纳 EdDSA 签名 R‖S）。

---

## 测试

PQC v1.85 **Sys / MU** 测试分两层：**单元测试**（无 TPM，验证编组与 `Prepare`）与 **集成测试**（经 **wolfTPM fwTPM** + `tcti-mssim` 跑真实命令往返）。ESYS / FAPI 无对应用例。

### 文件与构建注册

| 类型 | 路径 | `Makefile-test.am` 目标 |
|------|------|-------------------------|
| MU 往返 | `test/unit/pqc-marshal.c` | `test/unit/pqc-marshal` |
| Sys Prepare | `test/unit/sys-pqc-prepare.c` | `test/unit/sys-pqc-prepare` |
| wolfTPM 集成 | `test/integration/sys-pqc-wolftpm.int.c` | `test/integration/sys-pqc-wolftpm.int` |
| 集成入口 | `test/integration/main-sys-wolftpm.c` | （与上项同目标链接） |
| 日志编译器 | `script/int-log-compiler-wolftpm.sh` | `test_integration_sys_pqc_wolftpm_int_LOG_COMPILER` |

`script/int-log-compiler.sh` 在测试名匹配 `*sys-pqc-wolftpm*` 时自动 `exec` 到 `int-log-compiler-wolftpm.sh`（不启动 `tpm_server`，改启 `fwtpm_server`）。

### 单元测试（`make check` / `test/unit/pqc-marshal`）

**`pqc-marshal`**：PQC / EdDSA 相关 `Tss2_MU_*` 往返与边界（约 27 个 cmocka 用例），覆盖例如：

- `TPM2B_PUBLIC_KEY_MLKEM` / `TPM2B_KEM_CIPHERTEXT` / `TPM2B_SHARED_SECRET`
- `TPM2B_PUBLIC_KEY_MLDSA` / `TPM2B_PRIVATE_KEY_MLDSA` / `TPM2B_PRIVATE_KEY_MLKEM`
- `TPM2B_SIGNATURE_MLDSA`（含 44/65/87 尺寸与 `BAD_SIZE`）
- `TPM2B_SIGNATURE_EDDSA`、`TPM2B_SIGNATURE_CTX`、`TPM2B_SIGNATURE_HINT`
- `TPMT_SIGNATURE`（`MLDSA`、`HASH_MLDSA`、`EDDSA`、`HASH_EDDSA`）
- `TPMU_PUBLIC_PARMS` / `TPMU_PUBLIC_ID` / `TPMU_SENSITIVE_COMPOSITE` / `TPMU_ENCRYPTED_SECRET`（ML-KEM）
- `TPMI_MLKEM_PARMS` / `TPMI_MLDSA_PARMS`、`TPMS_*_PARMS`、`TPMS_SIGNATURE_HASH_MLDSA`

**`sys-pqc-prepare`**：七条 v1.85 PQC Sys 命令的 `*_Prepare`（无 `Execute`），校验 `commandCode`、`decryptNull`、`decryptAllowed` / `encryptAllowed` / `authAllowed` 及 `BAD_REFERENCE`：

| 用例 | 命令 |
|------|------|
| `sys_encapsulate_prepare_flags` | `Encapsulate` |
| `sys_decapsulate_prepare_null_ciphertext` / `sys_decapsulate_prepare_command_code` | `Decapsulate` |
| `sys_sign_digest_prepare_null_context` / `sys_sign_digest_prepare_bad_ref` | `SignDigest` |
| `sys_verify_digest_signature_prepare_null_context` / `sys_verify_digest_signature_prepare_bad_ref` | `VerifyDigestSignature` |
| `sys_sign_sequence_start_prepare_null_auth` | `SignSequenceStart` |
| `sys_verify_sequence_start_prepare_null_auth` | `VerifySequenceStart` |
| `sys_sign_sequence_complete_prepare_null_buffer` | `SignSequenceComplete` |
| `sys_verify_sequence_complete_prepare_flags` | `VerifySequenceComplete` |

### wolfTPM 集成测试（`test/integration/sys-pqc-wolftpm.int`）

**传输：** `TPM20TEST_TCTI=mssim:host=127.0.0.1,port=<port>` → `tcti-mssim` → wolfTPM **`fwtpm_server`**（mssim 线格式，**非** IBM `tpm_server`）。

**前置：**

1. wolfTPM 构建时启用 PQC：`./configure --enable-fwtpm --enable-pqc`（或 `--enable-v185`）。
2. `fwtpm_server` 在 `PATH`，或通过环境变量指定（见下表）。
3. 集成入口 `main-sys-wolftpm.c` 与 `test-common.c` 中 `FWTPM_SKIP_STATE_CHECKS=1`：跳过 MS 仿真器假设的 PCR capability `dumpstate` 比对（fwTPM 布局与 `tpm_server` 不一致时避免误败）。

**环境变量（`int-log-compiler-wolftpm.sh`）：**

| 变量 | 说明 |
|------|------|
| `FWTPM_SERVER` / `WOLFTPM_FWSERVER` | `fwtpm_server` 可执行文件路径 |
| `FWTPM_SRC` | wolfTPM 源码根；回退查找 `$FWTPM_SRC/src/fwtpm/fwtpm_server` |
| `FWTPM_PORT` | 命令端口（默认 `2321`）；platform 端口为 `port+1` |
| `FWTPM_USE_EXISTING` | 已设置则连接已有 listener，不启动新进程 |
| `FWTPM_SKIP_STATE_CHECKS` | 跳过 pre/post `dumpstate`（脚本默认导出 `1`） |
| `TPM20TEST_TCTI` | 由脚本设为 `mssim:host=127.0.0.1,port=…` |

找不到 `fwtpm_server` 时脚本 **exit 77**（Automake `SKIP`）；端口已有 listener 时自动复用。

**运行：**

```bash
# CI / 本地（自动启停 fwtpm_server）
make check TESTS=test/integration/sys-pqc-wolftpm.int

# 仅单元测试
make check TESTS='test/unit/pqc-marshal test/unit/sys-pqc-prepare'

# 手动：先起 server，再跑二进制
FWTPM_NV_FILE=/tmp/nv.bin /path/to/wolfTPM/src/fwtpm/fwtpm_server \
    --port 2321 --platform-port 2322 --clear &
TPM20TEST_TCTI=mssim:host=127.0.0.1,port=2321 \
    FWTPM_SKIP_STATE_CHECKS=1 \
    ./test/integration/sys-pqc-wolftpm.int
```

日志：`${TEST_BIN}_fwtpm_server.log`（脚本启动时）、`test/integration/sys-pqc-wolftpm.int.log`（`make check`）。

### 集成用例矩阵（`test_invoke`）

执行顺序：`require_pqc_algorithms` → 下列三组；全部通过返回 `0`。

| 函数 | 算法 / 参数集 | Sys API | 断言要点 |
|------|---------------|---------|----------|
| `require_pqc_algorithms` | — | `GetCapability(ALGS)` | 必须宣告 `TPM2_ALG_MLKEM`、`TPM2_ALG_MLDSA`、`TPM2_ALG_HASH_MLDSA` |
| `test_mlkem_encap_decap` | ML-KEM-768 | `CreatePrimary` → `Encapsulate` → `Decapsulate` → `FlushContext` | `ct.size == TPM2_MLKEM_768_CT_SIZE`；`ss_enc` 与 `ss_dec` **memcmp** 一致 |
| `test_hash_mldsa_digest` | Hash-ML-DSA-65 + SHA-256 | `SignDigest` → `VerifyDigestSignature` | `sigAlg == HASH_MLDSA`；签名长 `TPM2_MLDSA_65_SIG_SIZE`；ticket `TPM2_ST_DIGEST_VERIFIED` |
| `test_mldsa_sequence` | ML-DSA-44，`allowExternalMu=0` | 见下表 | 纯 ML-DSA 走流式路径；`sigAlg == MLDSA`；ticket `TPM2_ST_MESSAGE_VERIFIED` |

**`test_mldsa_sequence` 流式路径（对齐传统 `SequenceUpdate` 分片）：**

| 阶段 | 调用 |
|------|------|
| 签名 | `SignSequenceStart` → `SequenceUpdate(chunk1)` → `SignSequenceComplete(chunk2)` |
| 验签 | `VerifySequenceStart` → `SequenceUpdate(chunk1)` → `SequenceUpdate(chunk2)` → `VerifySequenceComplete` |

消息为固定字符串 `"tpm2-tss PQC Sys API ML-DSA sequence test"`，从中点对半拆分。Hash-ML-DSA digest 用例使用 32 字节 pattern `0xAA`，`validation` 为 `TPM2_ST_HASHCHECK` + `TPM2_RH_NULL`。**纯 ML-DSA** 的 `SignDigest` 须 `allowExternalMu=1`（外部 digest），与 `allowExternalMu=0` 的 `SignSequence*` 互斥；当前 wolfTPM fwTPM 集成未覆盖纯 ML-DSA digest 路径（`SignDigest` 在 `allowExternalMu=0` 时返回 `TPM2_RC_ATTRIBUTES`）。

### 覆盖与缺口（测试视角）

| 已覆盖 | 未覆盖（当前 `test/`） |
|--------|------------------------|
| 七条 v1.85 PQC Sys 命令的 MU + Prepare | EdDSA / Hash-EdDSA **集成**（无 wolfTPM 曲线密钥用例） |
| ML-KEM / Hash-ML-DSA digest / ML-DSA sequence 正向 wolfTPM 往返 | 纯 ML-DSA `SignDigest`（`allowExternalMu=1` 密钥） |
| | ML-KEM-512/1024、ML-DSA-65/87 等其他参数集 |
| | 负向（篡改 digest / 签名 / 密文） |
| `SetDecryptParam` 延迟填入（Prepare 层 `decryptNull`） | ESYS / FAPI 包装测试 |

v1.83 / v1.84（`0x19B`–`0x1A1`）另有 `test/unit/v183-v184-marshal` 与 `test/unit/sys-v183-v184-prepare`，见 [v183-v184-api-reference.md](v183-v184-api-reference.md)。

---

## 规范常量缺口（`tss2_tpm2_types.h` 未定义）

对照 **TPM 2.0 Library Part 2 v1.85**、**TCG Algorithm Registry** 与 wolfTPM `WOLFTPM_V185`，下列为 `include/tss2/tss2_tpm2_types.h` 与规范的差异。**2025-06 审计**（`grep` 头文件 + 与规范表对照）。

### 已在头文件中完整定义（PQC / EdDSA 核心）

| 类别 | 状态 |
|------|------|
| ML-KEM / ML-DSA / Hash-ML-DSA 算法 ID、`TPMI_*_PARMS`、尺寸宏 | ✓ |
| EdDSA / Hash-EdDSA 算法 ID、Curve25519/448 | ✓ |
| PQC 结构体（`TPM2B_*` / `TPMS_*` / `TPMU_*` 扩展成员） | ✓ |
| v1.85 命令码 `0x1A3`–`0x1AA`（含 `SignSequenceStart` / `VerifySequenceStart`） | ✓ |
| 验签票据 tag：`TPM2_ST_VERIFIED` / `MESSAGE_VERIFIED` / `DIGEST_VERIFIED` | ✓（`L705`–`L710`） |

### 仍缺失或不全（按优先级）

### 票据结构标签（`TPM2_ST`）— 已补全

下列三个 `TPMT_TK_VERIFIED` 票据 tag 均已定义于 `tss2_tpm2_types.h`（见上文 [验签票据结构标签](#验签票据结构标签tpm2_st)）。应用代码直接 `#include <tss2/tss2_tpm2_types.h>` 即可，**勿**再本地 `#define`。

| 头文件宏 | 值 | 产生命令 |
|----------|-----|----------|
| `TPM2_ST_VERIFIED` | `0x8022` | `TPM2_VerifySignature` |
| `TPM2_ST_MESSAGE_VERIFIED` | `0x8026` | `TPM2_VerifySequenceComplete` |
| `TPM2_ST_DIGEST_VERIFIED` | `0x8027` | `TPM2_VerifyDigestSignature` |

PQC / 流式路径须断言 `MESSAGE_VERIFIED` 或 `DIGEST_VERIFIED`，**不能**用 `TPM2_ST_VERIFIED`（`0x8022`）代替。

### PQC 相关返回码（`TPM2_RC`，`TPM2_RC_FMT1` 组）

规范在 `TPM2_RC_ECC_POINT`（`+0x027`）与 `TPM2_RC_CHANNEL`（`+0x030`）之间为 ML-KEM / ML-DSA / 流式签名新增四条 **format-1** 码；头文件在 `TPM2_RC_SVN_LIMITED`（`+0x029`）后直接转入 `TPM2_RC_WARN`，**未定义 `+0x02A`–`+0x02D`**：

| 规范名 | 建议头文件宏 | 编码 | 典型场景 |
|--------|--------------|------|----------|
| `TPM_RC_PARMS` | `TPM2_RC_PARMS` | `TPM2_RC_FMT1 + 0x02A`（低 12 位 `0x0AA`） | 不支持的 ML-KEM / ML-DSA 参数集 |
| `TPM_RC_EXT_MU` | `TPM2_RC_EXT_MU` | `TPM2_RC_FMT1 + 0x02B`（`0x0AB`） | 密钥 `allowExternalMu=0` 时调用 `SignDigest`（需外部 μ） |
| `TPM_RC_ONE_SHOT_SIGNATURE` | `TPM2_RC_ONE_SHOT_SIGNATURE` | `TPM2_RC_FMT1 + 0x02C`（`0x0AC`） | TPM 不支持一次性 digest 签名 |
| `TPM_RC_SIGN_CONTEXT_KEY` | `TPM2_RC_SIGN_CONTEXT_KEY` | `TPM2_RC_FMT1 + 0x02D`（`0x0AD`） | `VerifySequenceComplete` 的 `keyHandle` 与 Start 时不一致 |

集成测试已观测：`allowExternalMu=0` 的 ML-DSA 密钥上调用 `SignDigest` 可得到 `TPM2_RC_ATTRIBUTES`（`+0x002`）；规范语义上亦可出现 `TPM2_RC_EXT_MU`（`+0x02B`），取决于 TPM 实现。

### TPM 固定属性（`TPM2_PT`）

| 规范名 | 建议头文件宏 | 编码 | 说明 |
|--------|--------------|------|------|
| `TPM_PT_ML_PARAMETER_SETS` | `TPM2_PT_ML_PARAMETER_SETS` | `TPM2_PT_FIXED + 49` | `GetCapability(TPM2_CAP_TPM_PROPERTIES)` 返回支持的 ML 参数集位图 |

头文件在 `TPM_PT_FIRMWARE_MAX_SVN`（`PT_FIXED + 48`，**注意：宏名缺 `TPM2_` 前缀**，见下文「命名不一致」）之后无 `+49`。属性值类型为 **`TPMA_ML_PARAMETER_SET`**（`UINT32` 位域，规范 Table 46）：

| 位 | 规范字段名 | 含义 |
|----|------------|------|
| 0 | `mlKem_512` | 支持 ML-KEM-512 |
| 1 | `mlKem_768` | 支持 ML-KEM-768 |
| 2 | `mlKem_1024` | 支持 ML-KEM-1024 |
| 3 | `mlDsa_44` | 支持 ML-DSA-44 |
| 4 | `mlDsa_65` | 支持 ML-DSA-65 |
| 5 | `mlDsa_87` | 支持 ML-DSA-87 |
| 6 | `extMu` | ML-DSA 支持 `allowExternalMu`（外部 μ / `SignDigest`） |
| 32:7 | Reserved | 须为 0 |

当前仓库无 `TPMA_ML_PARAMETER_SET` typedef 及位宏；探测参数集能力时需自行按位解析或继续用 `GetCapability(TPM2_CAP_ALGS)`。

### 类型结构（规范新增，非 `#define`）

| 规范类型 | 头文件状态 | 说明 |
|----------|------------|------|
| `TPMU_TK_VERIFIED_META` | **未定义** | `TPMT_TK_VERIFIED` 的 tag 相关元数据联合体 |
| `messageVerified` 成员 | — | `TPMS_EMPTY`，对应 `TPM2_ST_MESSAGE_VERIFIED` |
| `digestVerified` 成员 | — | `TPMI_ALG_HASH`，对应 `TPM2_ST_DIGEST_VERIFIED`（wire 上携带 hash/XOF 算法 ID） |

现有 `TPMT_TK_VERIFIED` 仅含 `tag` / `hierarchy` / `digest`（`L1883`–`L1889`），MU 仅有 `Tss2_MU_TPMT_TK_VERIFIED_*`，**未按 tag 序列化 meta 区**。解析 v1.85 验签票据时，除 `tag` 外可能还需读取 tag 后的 meta（`digestVerified` 时为 `TPMI_ALG_HASH`）。

### 算法 ID 扩展（Hash / KDF，v1.85 相关）

规范 **TPMI_ALG_HASH** 与 Algorithm Registry 在 `TPM2_ALG_SHA512`（`0x000D`）与 `TPM2_ALG_NULL`（`0x0010`）之间、`TPM2_ALG_ECMQV`（`0x001D`）与 KDF 块之间留有空洞；下列 **未** 在头文件定义（`grep` 无 `TPM2_ALG_HKDF` / `SHAKE` / `SHA256_192`）：

| 建议宏 | 值 | 规范用途 | 与 PQC 关系 |
|--------|-----|----------|-------------|
| `TPM2_ALG_SHA256_192` | `0x000E` | Hash（NIST SP 800-208 截断 SHA-256） | Hash-ML-DSA / PCR 等可选 hash |
| `TPM2_ALG_HKDF` | `0x001F` | KDF（RFC 5869） | KDF scheme；`TPMU_KDF_SCHEME` 亦缺 `hkdf` 成员 |
| `TPM2_ALG_SHAKE128` | `0x002A` | XOF（Registry / wolfTPM v185） | 扩展 hash 族 |
| `TPM2_ALG_SHAKE256` | `0x002B` | 同上 | 同上 |
| `TPM2_ALG_SHAKE256_192` | `0x002C` | Hash（SHAKE256 截断 192 bit） | Hash-ML-DSA 可选 `hashAlg` |
| `TPM2_ALG_SHAKE256_256` | `0x002D` | 截断 256 bit | 同上 |
| `TPM2_ALG_SHAKE256_512` | `0x002E` | 截断 512 bit | 同上 |

当前 `TPMU_KDF_SCHEME`（`L2440`–`L2446`）仅有 `mgf1` / `kdf1_sp800_56a` / `kdf2` / `kdf1_sp800_108` / `null`，**无** `TPMS_KDF_SCHEME_HKDF` / `hkdf` selector 分支（MU 亦未扩展）。

### 返回码边界常量

| 建议宏 | 编码 | 说明 |
|--------|------|------|
| `TPM2_RC_MAX_FMT1` | `TPM2_RC_FMT1 + 0x03F` | Format-1 组上限（wolfTPM 已定义；本仓库仅有 `TPM2_RC_MAX_FM0`） |

### 命名不一致（已存在但易误用）

| 头文件现状 | 规范 / 惯例 | 说明 |
|------------|-------------|------|
| `TPM_PT_FIRMWARE_SVN` | `TPM_PT_FIRMWARE_SVN` / 宜为 `TPM2_PT_FIRMWARE_SVN` | `PT_FIXED + 47`，缺 `TPM2_` 前缀 |
| `TPM_PT_FIRMWARE_MAX_SVN` | 同上 | `PT_FIXED + 48` |
| `TPM2_MLKEM_PARMS_*` | Registry 名 `TPM_MLKEM_512` 等 | 数值一致，仅命名前缀/`_PARMS_` 不同（见下表） |

### 规范命名与头文件命名对照（已定义部分）

Part 2 表题与 TCG Algorithm Registry 使用短名；本仓库 `tss2_tpm2_types.h` 统一加 `TPM2_` 前缀并在 ML 参数集上带 `_PARMS_`：

| 规范（Table 204 / 207） | 头文件（已实现） | 数值 |
|-------------------------|------------------|------|
| `TPM_MLKEM_512` | `TPM2_MLKEM_PARMS_512` | `0x0001` |
| `TPM_MLKEM_768` | `TPM2_MLKEM_PARMS_768` | `0x0002` |
| `TPM_MLKEM_1024` | `TPM2_MLKEM_PARMS_1024` | `0x0003` |
| `TPM_MLDSA_44` | `TPM2_MLDSA_PARMS_44` | `0x0001` |
| `TPM_MLDSA_65` | `TPM2_MLDSA_PARMS_65` | `0x0002` |
| `TPM_MLDSA_87` | `TPM2_MLDSA_PARMS_87` | `0x0003` |

规范表内**无** `NONE`（`0x0000`）行；头文件额外提供 `TPM2_MLKEM_PARMS_NONE` / `TPM2_MLDSA_PARMS_NONE`（tpm2-tss 惯例，非 Part 2 表内枚举项）。

尺寸宏对照（均已定义）：规范 `MAX_MLKEM_PUB_SIZE` → `TPM2_MAX_MLKEM_PUB_SIZE`；`MAX_MLDSA_SIG_SIZE` → `TPM2_MAX_MLDSA_SIG_SIZE`；`MAX_SIG_CTX_BYTES`（实现相关，ML-DSA 至少 255）→ `TPM2_MLDSA_CTX_MAX_SIZE`（`255`）。

### 缺口汇总

| 类别 | 缺失项数 | 建议补全位置 |
|------|----------|--------------|
| `TPM2_ST_*` 验签票据 tag | 0 | `L705`–`L710` |
| `TPM2_RC_*`（PQC / 流式签名） | 4 | `TPM2_RC_SVN_LIMITED`（`+0x029`）之后、`TPM2_RC_WARN` 之前 |
| `TPM2_RC_MAX_FMT1` | 1 | 同上 Format-1 组末尾 |
| `TPM2_PT_*` + `TPMA_ML_PARAMETER_SET` | 1 + 7 位 | `PT_FIXED + 49`；位掩码宜仿 `TPMA_OBJECT_*` |
| 类型 `TPMU_TK_VERIFIED_META` + MU | 1 union | `TPMT_TK_VERIFIED` 旁；`Tss2_MU_TPMT_TK_VERIFIED_*` 按 tag 分支 |
| Hash / KDF 算法 ID | 7 | `TPM2_ALG_*` 块填 `0x000E`、`0x001F`、`0x002A`–`0x002E` |
| `TPMU_KDF_SCHEME.hkdf` | 1 成员 + MU | `L2440` 附近 |

**不影响当前 PQC Sys 集成测试的缺口：** Hash/XOF 算法 ID、`HKDF`、`TPMU_TK_VERIFIED_META`（测试只检查 `ticket.tag`，未解析 meta）。**建议优先补：** 四条 `TPM2_RC_*`、`TPM2_PT_ML_PARAMETER_SETS` / `TPMA_ML_PARAMETER_SET`（能力探测与负向断言）。

---

## Known gaps（相对完整 tpm2-tss 发行版）

**v1.83 / v184（`0x19B`–`0x1A1`）设计详见** [v183-v184-api-reference.md](v183-v184-api-reference.md)；缺口清单见 [tpm-v183-v184-gap-reference.md](tpm-v183-v184-gap-reference.md)。

| 项 | 状态 |
|----|------|
| **ESYS** | `src/tss2-esys` 尚无 `Esys_Encapsulate` / `Esys_Decapsulate` / `Esys_SignDigest` 等 v1.85 包装 |
| **集成 / 单元测试** | 已有 `pqc-marshal`、`sys-pqc-prepare` 与 wolfTPM `sys-pqc-wolftpm.int`（见 [测试](#测试)）；缺 EdDSA 集成、多参数集与负向用例 |
| **ABI / SONAME** | 新符号已加入 `lib/tss2-sys.map` / `lib/tss2-mu.map`；是否 bump `-version-info` 待发布策略决定 |
| **Autotools 源列表** | 新 `.c` 已通过 `src_vars.mk` / `tss2-sys.vcxproj` 纳入；需确认 `configure.ac` 生成 Makefile 与 CI 一致 |
| **FAPI / Policy** | 未扩展 PQC 策略或配置文件路径 |
| **PQC 规范常量** | `TPM2_ST_*` 已定义；仍缺 `TPM2_RC_*`（×4）、`TPM2_PT_ML_PARAMETER_SETS`、`TPMA_ML_PARAMETER_SET`、`TPMU_TK_VERIFIED_META`、Hash/XOF/HKDF 算法 ID 等（见 [规范常量缺口](#规范常量缺口tss2_tpm2_typesh-未定义)） |
