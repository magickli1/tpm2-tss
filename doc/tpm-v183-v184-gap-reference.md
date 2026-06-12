# TPM 2.0 v1.83 / v184 命令与类型缺口参考

## Implementation status

**Date:** 2025-06-11  
**Scope:** Types/MU, Sys API, unit tests (ESYS intentionally excluded)

| Layer | Status |
|-------|--------|
| `TPM2_CC` 0x19B–0x1A1 | ✓ |
| NV2 / SetCapability / SPDM types in `tss2_tpm2_types.h` | ✓ |
| MU marshal/unmarshal | ✓ |
| `Tss2_Sys_*` (7 commands) | ✓ |
| `GetCapability` union arms (`pubKeys`, `spdmSessionInfo`) | ✓ |
| Unit tests (`v183-v184-marshal`, `sys-v183-v184-prepare`) | ✓ |
| ESYS wrappers | ✗ (out of scope) |
| Integration tests (hardware/simulator) | ✗ |

---

按 **TCG TPM 2.0 Library Specification**（Part 0/2/3，v185 rc4 交叉核对）整理 **tpm2-tss_pqc** 相对规范的缺口。本文档覆盖命令码 **0x19B–0x1A1**（7 条）及其关联类型、能力与 SPDM 策略生态。

**规范依据：** TCG Part 2（结构）、Part 3（命令）、Part 0（版本变更日志）  
**实现快照：** 当前仓库 `include/tss2/`、`src/tss2-sys/`、`src/tss2-mu/`、`src/tss2-esys/`

**相关文档：**

- [v183-v184-api-reference.md](v183-v184-api-reference.md) — v1.83/v184 **设计摘录**（与 [pqc-api-reference.md](pqc-api-reference.md) 同版式）
- [pqc-api-reference.md](pqc-api-reference.md)（v1.85 PQC / EdDSA 已实现部分）

---

## 总览

本仓库在 `TPM2_CC_ECC_Decrypt`（`0x19A`，v1.83）之后 **跳过** `0x19B`–`0x1A1`，直接实现 v1.85 PQC 命令（`0x1A2` 起；且 `0x1A2` 在规范中为 **Reserved**，本 fork 用作合并 SequenceStart）。因此 **v1.83 后段 5 条 + v184 2 条** 全部缺失。

| CC | 规范命令 | 规范版本 | TSS 状态 | 缺口摘要 |
|----|----------|----------|----------|----------|
| `0x19B` | `TPM2_PolicyCapability` | 1.83 | ✓ | Sys + MU |
| `0x19C` | `TPM2_PolicyParameters` | 1.83 | ✓ | Sys |
| `0x19D` | `TPM2_NV_DefineSpace2` | 1.83 | ✓ | NV2 types + MU + Sys |
| `0x19E` | `TPM2_NV_ReadPublic2` | 1.83 | ✓ | NV2 types + MU + Sys |
| `0x19F` | `TPM2_SetCapability` | 1.83 | ✓ | SetCapability types + MU + Sys |
| `0x1A0` | `TPM2_ReadOnlyControl` | **184** | ✓ | Sys only (no ESYS) |
| `0x1A1` | `TPM2_PolicyTransportSPDM` | **184** | ✓ | Sys + SPDM cap types |

**头文件 CC 空洞（证据）：** `include/tss2/tss2_tpm2_types.h` 在 `TPM2_CC_ECC_Decrypt`（`0x19A`）与 `TPM2_CC_SignVerifySequenceStart`（`0x1A2`，本 fork 扩展）之间无 `0x19B`–`0x1A1` 定义。

**Sys 侧证据：** `src/tss2-sys/sysapi_util.c` 的 `commandArray[]` 无上述 7 条；`lib/tss2-sys.map` / `lib/tss2-sys.def` 无对应 `Tss2_Sys_*` 导出。

**ESYS：** 无 `Esys_ReadOnlyControl`、`Esys_PolicyTransportSPDM` 等；策略/NV 高层封装亦未扩展。

---

## 版本归属（以规范为准）

| 版本 | 命令码段 | 说明 |
|------|----------|------|
| **1.83** | `0x199`–`0x19F` | `ECC_Encrypt/Decrypt` + 策略扩展 + NV2 + `SetCapability` |
| **184** | `0x1A0`–`0x1A1` | `ReadOnlyControl`、SPDM 传输策略 |
| **185** | `0x1A2` Reserved；`0x1A3`–`0x1AA` PQC/摘要签名 | 见 [pqc-api-reference.md](pqc-api-reference.md) |

**注意：** SPDM 属于 **184** 能力/策略层，**不是** v1.85 PQC。SPDM 握手与传输在 TPM Library **规范范围之外**（由 TPM 安全传输层等独立规范实现）；Library 内仅定义策略门控与能力查询。

---

## 命令详解

### `0x19B` — `TPM2_PolicyCapability`（v1.83）

**作用：** 策略 **立即断言**——根据 TPM 某 capability 属性值与 `operandB` 做逻辑比较；失败返回 `TPM_RC_POLICY`。成功则更新 `policyDigest`（式 10，Part 3 §23.23）。

**命令参数（Part 3 Table 185）：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `policySession` | `TPMI_SH_POLICY` | 策略会话句柄 |
| `operandB` | `TPM2B_OPERAND` | 比较数据（与 `TPM2B_DIGEST` 同尺寸上限） |
| `offset` | `UINT16` | capability 数据结构内 operand A 起始偏移 |
| `operation` | `TPM2_EO` | 比较运算（EQ/NEQ/GT/LT/位域等） |
| `capability` | `TPM2_CAP` | 能力组（决定 operand A 最大尺寸） |
| `property` | `UINT32` | capability 限定符 |

**支持的 capability（Table 184，节选）：** `TPM2_CAP_ALGS`、`TPM2_CAP_TPM_PROPERTIES`、`TPM2_CAP_ACT`、**`TPM2_CAP_PUB_KEYS`（184）**、**`TPM2_CAP_SPDM_SESSION_INFO`（184）** 等。  
**不支持：** `TPM2_CAP_PCRS`（规范示例明确返回 `TPM_RC_VALUE`）。

**本仓库已有、可复用：**

- `TPM2B_OPERAND`（`typedef TPM2B_DIGEST`，`tss2_tpm2_types.h`）
- `TPM2_EO` 常量族
- 同类策略命令模板：`src/tss2-sys/api/Tss2_Sys_PolicyCommandCode.c`、`Tss2_Sys_PolicyCpHash.c`

**缺口：**

- `TPM2_CC_PolicyCapability`
- `Tss2_Sys_PolicyCapability_{Prepare,Complete,}` + `tss2_sys.h` 声明
- `sysapi_util.c` 句柄计数：`{ TPM2_CC_PolicyCapability, 1, 0 }`
- `TPMU_CAPABILITIES` 需扩展 `pubKeys` / `spdmSessionInfo` 方能完整支持 `GetCapability` 响应解码（见下文「关联能力」）

---

### `0x19C` — `TPM2_PolicyParameters`（v1.83）

**作用：** 策略 **延迟断言**——将策略绑定到**特定命令的参数摘要** `pHash`（不含 object Name；与 `PolicyCpHash` / `PolicyNameHash` / `PolicyTemplate` / bound session **互斥**）。

**命令参数（Part 3 Table 187）：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `policySession` | `TPMI_SH_POLICY` | 策略会话 |
| `pHash` | `TPM2B_DIGEST` | 被授权命令的 parameter digest |

**digest 更新：** `policyDigestnew ≔ H(policyDigestold ∥ TPM_CC_PolicyParameters ∥ pHash)`

**本仓库已有：** `TPM2B_DIGEST`、MU、`Tss2_Sys_PolicyCpHash`（结构几乎相同，仅 CC 与语义不同）。

**缺口：** `TPM2_CC_PolicyParameters`、`Tss2_Sys_PolicyParameters_*`、导出符号。

---

### `0x19D` — `TPM2_NV_DefineSpace2`（v1.83）

**作用：** 与 `TPM2_NV_DefineSpace` 相同授权模型，但 `publicInfo` 为 **`TPM2B_NV_PUBLIC_2`**，可定义：

- `TPM_HT_NV_INDEX`（遗留 NV）
- **`TPM_HT_EXTERNAL_NV`**（v1.83 新增）
- `TPM_HT_PERMANENT_NV`（v1.83 句柄类型）

**命令参数（Part 3 Table 273）：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `@authHandle` | `TPMI_RH_PROVISION` | `TPM_RH_OWNER` 或 `TPM_RH_PLATFORM+{PP}` |
| `auth` | `TPM2B_AUTH` | 索引授权值（可空 → `decryptNull`） |
| `publicInfo` | `TPM2B_NV_PUBLIC_2` | NV 公共区域 |

**本仓库已有（v1.59 遗留）：** `TPMS_NV_PUBLIC`、`TPM2B_NV_PUBLIC`、`Tss2_Sys_NV_DefineSpace`、`Tss2_MU_*_NV_PUBLIC_*`。

**缺口（NV2 类型链，Part 2 §13.8–13.11）：**

| 类型 | 说明 |
|------|------|
| `TPMA_NV_EXP` | 64 位扩展 NV 属性（`TPMS_NV_PUBLIC_EXP_ATTR` 用） |
| `TPMI_RH_NV_EXP_INDEX` | 扩展 NV 索引句柄类型 |
| `TPMS_NV_PUBLIC_EXP_ATTR` | 含 `TPMA_NV_EXP` 的 public 区 |
| `TPMU_NV_PUBLIC_2` | union：`nvIndex` / `externalNV` / `permanentNV` |
| `TPMT_NV_PUBLIC_2` | `handleType` + `publicArea` |
| `TPM2B_NV_PUBLIC_2` | 线上传输包装 |
| `TPM_HT_EXTERNAL_NV`（`0x11`）、`TPM_HT_PERMANENT_NV`（`0x12`） | 句柄 MSO |
| MU：`Tss2_MU_TPM2B_NV_PUBLIC_2_{Marshal,Unmarshal}` 及子结构 MU |
| Sys：`Tss2_Sys_NV_DefineSpace2_*`（可参考 `Tss2_Sys_NV_DefineSpace.c`；`ValidateNV_Public` 需 NV2 变体或泛化） |

---

### `0x19E` — `TPM2_NV_ReadPublic2`（v1.83）

**作用：** 与 `TPM2_NV_ReadPublic` 类似，但支持全部 NV 句柄类型，返回 **`TPM2B_NV_PUBLIC_2`** + `TPM2B_NAME`。  
**Name 计算：** 与 `NV_ReadPublic` 对 `TPM_HT_NV_INDEX` 一致（marshal `TPMU_NV_PUBLIC_2` 时不含 `handleType` 标签）。

**命令参数（Part 3 Table 275）：**

| 方向 | 参数 | 类型 |
|------|------|------|
| in | `nvIndex` | `TPMI_RH_NV_INDEX` |
| out | `nvPublic` | `TPM2B_NV_PUBLIC_2` |
| out | `nvName` | `TPM2B_NAME` |

**缺口：** 依赖上一节 NV2 类型/MU；`Tss2_Sys_NV_ReadPublic2_*`（可参考 `Tss2_Sys_NV_ReadPublic.c`）。

---

### `0x19F` — `TPM2_SetCapability`（v1.83）

**作用：** 按 capability 写入 TPM 配置（每次**仅设一个** property）；与 `TPM2_GetCapability` 共用 capability/property 命名空间。授权随 capability 变化；`@authHandle` 可为 `TPM_RH_LOCKOUT`、`TPM_RH_ENDORSEMENT`、`TPM_RH_OWNER`、`TPM_RH_PLATFORM+{PP}` 或 **`TPM_RH_NULL`**（v1.83 扩展）。

**命令参数（Part 3 Table 242）：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `@authHandle` | `TPMI_RH_HIERARCHY_AUTH+` | 层次授权 |
| `setCapabilityData` | `TPM2B_SET_CAPABILITY_DATA` | 待写入数据（支持参数加密） |

**结构（Part 2）：**

```
TPM2B_SET_CAPABILITY_DATA
  └─ TPMS_SET_CAPABILITY_DATA
       ├─ setCapability: TPM2_CAP
       └─ data: TPMU_SET_CAPABILITIES   // 由 TCG Registry 定义
```

**本仓库已有：** `Tss2_Sys_GetCapability`、`TPMU_CAPABILITIES`（**无** `TPMU_SET_CAPABILITIES` / `TPM2B_SET_CAPABILITY_DATA`）。

**缺口：**

- `TPMS_SET_CAPABILITY_DATA`、`TPMU_SET_CAPABILITIES`、`TPM2B_SET_CAPABILITY_DATA`
- 对应 MU
- `TPM2_CC_SetCapability`、`Tss2_Sys_SetCapability_*`（`decryptAllowed=1`，`authAllowed=1`）
- `GetCapability` 的 `TPMU_CAPABILITIES` 与 `TPM2_CAP_LAST` 需同步扩展（当前 `TPM2_CAP_LAST = 0x0A`，规范为 `0x0C`）

---

### `0x1A0` — `TPM2_ReadOnlyControl`（v184）

**作用：** 在 **Platform Authorization** 下启用/禁用 TPM **全局只读模式**。只读时禁止创建对象、定义/修改 NV 等（完整允许列表见 Part 3 Table 207）。状态反映在 `TPMA_STARTUP_CLEAR.readOnly`。

**命令参数（Part 3 Table 208）：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `@authHandle` | `TPMI_RH_PLATFORM` | `TPM_RH_PLATFORM+{PP}` |
| `state` | `TPMI_YES_NO` | `YES` 进入只读；`NO` 退出 |

**Read-Only 模式下仍允许（节选）：** `TPM2_PolicyCapability`、`TPM2_PolicyParameters`、**`TPM2_PolicyTransportSPDM`**、**`TPM2_ReadOnlyControl`**、`TPM2_NV_ReadPublic2`（读）；**不允许** `TPM2_SetCapability`、`TPM2_NV_DefineSpace2` 等写操作。

**缺口：** 无专用新结构；仅需 `TPM2_CC_ReadOnlyControl` + `Tss2_Sys_ReadOnlyControl_*` + ESYS 可选封装。

**与 NV/对象 “read only” 属性的区别：** `TPMA_NV`、`TPMA_OBJECT` 等是**单对象/索引**权限；`ReadOnlyControl` 是 **TPM 全局运行模式**。

---

### `0x1A1` — `TPM2_PolicyTransportSPDM`（v184）

**作用：** 策略 **延迟断言**——授权时要求存在 **SPDM 非对称密钥交换** 安全信道；可选绑定 requester / TPM 安全信道公钥 **Name**。

**命令参数（Part 3 Table 189）：**

| 参数 | 类型 | 说明 |
|------|------|------|
| `policySession` | `TPMI_SH_POLICY` | 策略会话 |
| `reqKeyName` | `TPM2B_NAME` | 请求方安全信道密钥 Name（可 Empty Buffer） |
| `tpmKeyName` | `TPM2B_NAME` | TPM 安全信道密钥 Name（可 Empty Buffer） |

**授权时检查：** 无信道 → `TPM_RC_CHANNEL`；密钥 Name 不匹配 → `TPM_RC_CHANNEL_KEY`。  
**约束：** 每个策略会话仅可执行一次（`checkSecureChannel` 已 SET 则 `TPM_RC_VALUE`）。

**缺口：**

- `TPM2_CC_PolicyTransportSPDM`
- `Tss2_Sys_PolicyTransportSPDM_*`（模式同 `Tss2_Sys_PolicyCpHash`：两个可空 `TPM2B_NAME`）
- 下游策略工具 / FAPI 未识别该 assertion

---

## 关联能力（184，非独立 CC）

实现 `PolicyCapability` / `PolicyTransportSPDM` 的完整工作流还需补齐 **GetCapability** 侧类型（Part 2 §6.16、§10.7.6）：

| `TPM2_CAP` | 值 | Property 类型 | 返回类型 | 用途 |
|------------|-----|---------------|----------|------|
| `TPM2_CAP_PUB_KEYS` | `0x0B` | `TPM_PUB_KEY` | `TPML_PUB_KEY`（`TPM2B_PUBLIC` 列表） | 读取 TPM SPDM 认证公钥（非 TPM Object） |
| `TPM2_CAP_SPDM_SESSION_INFO` | `0x0C` | reserved | `TPML_SPDM_SESSION_INFO` | 当前 SPDM 会话的 requester/TPM 密钥 Name |

**`TPM_PUB_KEY` 常量（节选）：** `TPM_PUB_KEY_TPM_SPDM_00` … `TPM_PUB_KEY_TPM_SPDM_FF`

**`TPMS_SPDM_SESSION_INFO`：**

| 字段 | 类型 |
|------|------|
| `reqKeyName` | `TPM2B_NAME` |
| `tpmKeyName` | `TPM2B_NAME` |

**本仓库缺口：** `TPM2_CAP_PUB_KEYS`、`TPM2_CAP_SPDM_SESSION_INFO`、`TPM_PUB_KEY`、`TPML_PUB_KEY`、`TPMS_SPDM_SESSION_INFO`、`TPML_SPDM_SESSION_INFO`；`TPMU_CAPABILITIES` 无 `pubKeys` / `spdmSessionInfo` 成员；`Tss2_Sys_GetCapability_Complete` 解码分支需扩展。

---

## 本仓库已部分对齐的 v1.83 项（非本文 7 命令）

以下类型/命令 **已存在**，便于对照实现，但**不能替代**上表缺口：

| 项 | 仓库状态 |
|----|----------|
| `TPM2_CC_ECC_Encrypt` / `Decrypt`（`0x199`/`0x19A`） | ✓ CC + Sys + ESYS |
| `TPMA_OBJECT_FIRMWARELIMITED` / `SVNLIMITED` | ✓ `tss2_tpm2_types.h` |
| `TPM2B_OPERAND`、`TPM2_EO` | ✓ |
| `TPM2_NV_DefineSpace` / `NV_ReadPublic`（遗留 `TPM2B_NV_PUBLIC`） | ✓ |
| `Tss2_Sys_GetCapability` | ✓（能力枚举未扩展到 `0x0C`） |
| v1.85 PQC（`0x1A3`–`0x1AA` 等） | ✓ 见 [pqc-api-reference.md](pqc-api-reference.md) |

---

## 实现清单（建议顺序）

对齐规范 CC 布局时，建议 **先补类型/MU，再补 Sys**，并避免继续占用规范 Reserved 的 `0x1A2`。

### Phase A — 头文件与 MU（`include/tss2/tss2_tpm2_types.h`、`tss2_mu.h`、`src/tss2-mu/`）

1. `TPM2_CC_PolicyCapability` … `TPM2_CC_PolicyTransportSPDM`（`0x19B`–`0x1A1`）
2. NV2：`TPMA_NV_EXP`、`TPMS_NV_PUBLIC_EXP_ATTR`、`TPMU_NV_PUBLIC_2`、`TPMT_NV_PUBLIC_2`、`TPM2B_NV_PUBLIC_2`、`TPM_HT_EXTERNAL_NV`、`TPM_HT_PERMANENT_NV`
3. SetCapability：`TPMS_SET_CAPABILITY_DATA`、`TPMU_SET_CAPABILITIES`、`TPM2B_SET_CAPABILITY_DATA`
4. SPDM 能力：`TPM2_CAP_PUB_KEYS`、`TPM2_CAP_SPDM_SESSION_INFO`、`TPM_PUB_KEY`、`TPML_PUB_KEY`、`TPMS_SPDM_SESSION_INFO`、`TPML_SPDM_SESSION_INFO`；更新 `TPM2_CAP_LAST`、`TPMU_CAPABILITIES`
5. 全部 MU + `lib/tss2-mu.map` / `lib/tss2-mu.def`

### Phase B — Sys API（`src/tss2-sys/api/`、`tss2_sys.h`、`sysapi_util.c`）

| API 文件 | 参考模板 | auth / decrypt 提示 |
|----------|----------|---------------------|
| `Tss2_Sys_PolicyCapability.c` | `Tss2_Sys_PolicyCommandCode.c` | `authAllowed=1` |
| `Tss2_Sys_PolicyParameters.c` | `Tss2_Sys_PolicyCpHash.c` | `decryptAllowed=1` |
| `Tss2_Sys_NV_DefineSpace2.c` | `Tss2_Sys_NV_DefineSpace.c` | `decryptAllowed=1` |
| `Tss2_Sys_NV_ReadPublic2.c` | `Tss2_Sys_NV_ReadPublic.c` | response 含 NV2 |
| `Tss2_Sys_SetCapability.c` | `Tss2_Sys_GetCapability.c`（反向） | `decryptAllowed=1` |
| `Tss2_Sys_ReadOnlyControl.c` | `Tss2_Sys_ClearControl.c` | platform auth |
| `Tss2_Sys_PolicyTransportSPDM.c` | `Tss2_Sys_PolicySecret.c`（双 TPM2B） | 可空 Name |

扩展 `Tss2_Sys_GetCapability_Complete` 以解码新 capability 分支。

### Phase C — 构建与导出

- `src_vars.mk`、`tss2-sys.vcxproj`、`lib/tss2-sys.map`、`lib/tss2-sys.def`
- 可选：`src/tss2-esys/api/Esys_*.c`（至少 `ReadOnlyControl`、NV2、SPDM policy）

### Phase D — 测试

- `test/unit/`：NV2 / SetCapability / SPDM 结构 MU 往返
- `test/integration/`：需 v1.83+ TPM 或仿真器（wolfTPM 等）支持对应 CC

---

## 与规范 CC 表对照（`0x198` 之后）

| CC | Part 2 命令名 | 本仓库 |
|----|---------------|--------|
| `0x198` | `ACT_SetTimeout` | ✓ |
| `0x199` | `ECC_Encrypt` | ✓ |
| `0x19A` | `ECC_Decrypt` | ✓ |
| `0x19B` | `PolicyCapability` | ✓ |
| `0x19C` | `PolicyParameters` | ✓ |
| `0x19D` | `NV_DefineSpace2` | ✓ |
| `0x19E` | `NV_ReadPublic2` | ✓ |
| `0x19F` | `SetCapability` | ✓ |
| `0x1A0` | `ReadOnlyControl` | ✓ |
| `0x1A1` | `PolicyTransportSPDM` | ✓ |
| `0x1A2` | **Reserved** | ⚠ 本 fork：`SignVerifySequenceStart` |
| `0x1A3`–`0x1AA` | v1.85 签名/PQC | ✓（部分 CC 编号与规范 Start 命令有偏差，见 PQC 文档） |

---

## 规范索引

| 命令 | Part 3 章节 |
|------|-------------|
| `PolicyCapability` | §23.23 |
| `PolicyParameters` | §23.24 |
| `PolicyTransportSPDM` | §23.25 |
| `ReadOnlyControl` | §24.9（Table 207 只读模式命令表） |
| `SetCapability` | §30.4 |
| `NV_DefineSpace2` | §31.17 |
| `NV_ReadPublic2` | §31.18 |

| 结构 / 能力 | Part 2 章节 |
|-------------|-------------|
| `TPM2B_NV_PUBLIC_2` 族 | §13.8–13.11 |
| `TPM2B_SET_CAPABILITY_DATA` | §10.9.3–10.9.4 |
| `TPMS_SPDM_SESSION_INFO` | §10.7.6 |
| `TPM_PUB_KEY` / `TPM2_CAP_PUB_KEYS` | §6.16、Capability 表 |
| `TPM_HT_EXTERNAL_NV` | §7.2 Table 32 |

---

## Known gaps 汇总

| 类别 | 缺口 |
|------|------|
| **ESYS / FAPI / Policy** | 无 v1.83/v184 高层包装与策略断言 |
| **Integration 测试** | 需 v1.83+ TPM 或仿真器 |
| **TPMU_SET_CAPABILITIES** | 仅实现 `TPM2_CAP_TPM_PROPERTIES` 分支；其余走 `TPM2B_MAX_CAP_BUFFER` |
| **CC 布局** | `0x1A2` 被本 fork 占用；与规范 Reserved 及 `0x1A9`/`0x1AA` Start 命令布局不一致 |
