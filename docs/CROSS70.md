# 7.0 交叉验证实测报告

日期：2026-10-17
样本：`version/7.0`（gi.exe 431MB + gi/Managed/Metadata/global-metadata.dat 76.8MB）
对照版本：`version/7.1`（version.json 的来源版本）

---

## 一、一句话结论

**7.0 上真正可靠的自动发现只有 3 个**（2 张表 + 1 个 blob）。
`sig` 能找回 48/54 个函数，但 `relocate` 的表定位能力**几乎全部依赖旧 slot，而旧 slot 已经失效**。

---

## 二、两个工具的实测覆盖

| 工具 | 7.0 覆盖 | 说明 |
|---|---|---|
| `sig.py scan` | **48 / 54 函数** | 42 个精确匹配 + 6 个模糊匹配，0 歧义、0 撞址，默认 3.2s |
| `relocate.py` 强证据 | **3 / 34 表** | ④ 结构自证 2 张 + ③ 常量签名 1 个 blob |
| `relocate.py` 弱证据 | 16 / 34 表 | ⚠ **实测全是垃圾值**，见下 |

### 强证据（可信）
```
fieldDefaultValuesOffset = 0x1022CA8 (73818 项)  12B, +0 严格递增, +8 全为合法 Il2CppType 索引
methodPointerIndexOffset = 0xD5E6BC  (200000 项) 4B, 值域 [-1, 79765), -1 占 4.5%
blob                     = 0x41FB4E0             让 AttributeTargets 签名落在某条 dataIndex 上
```
两张表都能**反查回唯一 (slot, op, key)**（`0x1022CA8 → slot 0xC xor 0x720EB389`、
`0xD5E6BC → slot 0x130 add 0xA3B3FC56`），这是唯一真正"换版本可全自动"的通道。

### 弱证据（不可信）
`⑥ slot 提示` 打出的 16 个"唯一确定"，逐个检查后全是错值：

| 表 | ⑥ 给的值 | 问题 |
|---|---|---|
| `methodsOffset` | `0x2248` | 落在 global-metadata.dat 的头部区（头才 0x210 起） |
| `parameterDefaultValuesCount` | `0x38D9094` | 一个"数量"解出 59,479,700 |
| `fieldDefaultValuesOffset` | `0x52385C` | 与 ④ 结构自证的 `0x1022CA8` 冲突 |
| `methodPointerIndexOffset` | `0x113C14` | 与 ④ 的 `0xD5E6BC` 冲突 |

**而且 ⑥ 与 ⑦ 自相矛盾**：⑥ 说 `genericMethodTableCount @ slot 0x130 = 0xD5E6BC`，
⑦ 说 `methodPointerIndexOffset = 0xD5E6BC → slot 0x130`。
同一个 slot 不可能既是"表基址"又是"表长度"。

> **结论：「唯一落进元数据范围」这个判据毫无鉴别力。** 它只能证明
> `(slot, op, key)` 算出了一个看起来像偏移的数，完全没有验证那是不是那张表。

---

## 三、slot 跨版本稳定性 —— 已被证伪

`docs/UPDATE.md §8.6` 原本假设"30 张表靠 slot 提示就能自动跨版本"。7.0 实测：

| | 7.1（同版本自测） | 7.0（跨版本） |
|---|---|---|
| slot 唯一确定 | 30 / 34 | **16 / 34** |
| 多候选 | 0 | 1 |
| 无候选 | 4 | **17** |

已观察到的 slot 搬家：
```
fieldDefaultValuesOffset : 0x13C -> 0xC
methodPointerIndexOffset : 0x094 -> 0x130
```
所以 slot **不是**跨版本常量，不能作为换版本的主路径，只能当"生成候选值"的粗筛。

---

## 四、为什么 ④ 结构自证在 7.0 几乎失效

`relocate.py` 的结构探针是**按表逐个写死的**（fDV / pdv / methodPointerIndex /
typeDefs / nestedTypes / interfaces）。7.0 上只有前两个能验出来，
因为它们的判据是**表内部自洽**（fDV 的 +0 严格递增、+8 全是合法 Il2CppType 索引），
不依赖任何版本常量。

而 `typeDefinitions` 的探针依赖 `version.json` 的 `fieldDecode.typeDef` 密钥，
7.0 密钥全变了 → 探针直接失效。

### 曾经走过的两条弯路（都已被实测否定）

**(1) 「多函数一致性」排序选 top-1 字段密钥 —— 7.1 上只有 12/18 正确**

| 字段 | top-1 | 真值 | |
|---|---|---|---|
| `methodStart` | `xor 0x4D8127F2` | 同 | ✅ |
| `fieldStart` / `field_count` / `interfacesStart` / `nestedTypesCount` … | 同 | 同 | ✅ |
| `namespaceIndex` | `add 0xBBB4CF40` | `add 0xFEB47CB0` | ❌ |
| `parentIndex` | `add 0xE1` | `add 0xC28B6FE1` | ❌ |
| `nameIndex` | `xor 0x6A3E22EA` | `add 0xFBAD8E98`（排第 2） | ❌ |
| `flags` | `xor 0x774A3BA6` | `add 0xBEAA4472`（不在前 4） | ❌ |
| `method_count` | `add 0xFFFFFFF8` | `add 0xFFFF1266`（不在前 3） | ❌ |

根因：**混淆器共用密钥池**，同一个 key 会被多个字段用，`add 0xE1`/`add 0x20`
这类小常量更是满地都是。所以"多函数一致性"只能当**候选排序**，不能当判定。
`slot_scan --struct` 的输出标签已改成"⚠ 这里只是候选排序，不是判定"。

**(2) 靠字符串块做无锚定位 —— 两条路都不通**
`find_string_block` / `discover_typedefs` 已标【实验性·不可用】：
最长连续可打印段只有 0.4KB；"可打印密度最高的那块"在 7.1 落到 `0xF44000`（真值 `0x444C1E8`）。

---

## 五、有效的做法：语义不变量（累计索引单调）

判据换成**语义**而不是字节指纹：`methodStart / fieldStart / eventStart /
nestedTypesStart / interfacesStart` 解出的是**跨类型单调不减的累计索引**，
这个不变量**不需要任何外部锚**。

**7.1 自测通过**，两种独立方法互相印证：
```
字符串法（nameIndex 可打印）  -> 0x92140
累计索引单调法              -> 0x92140   命中 5 个字段，密钥与 version.json 真值完全一致
        +0x0C xor 0x4D8127F2 = methodStart
        +0x1C xor 0x29010897 = fieldStart
        +0x34 add 0xD02       = eventStart
        +0x36 add 0x19E7      = nestedTypesStart
        +0x3C xor 0x43DA      = interfacesStart
```

三个真实 bug（都是自测逼出来的）：
1. **字段宽度**：+0x30 `method_count` 是 **u16**，用 u32 读会得到 342425600 而不是 3
2. **必须按位宽掩码 + 有符号解释**：+0x34 `raw=0xF2FD + key 0x0D02 = 0xFFFF`，
   按 u16 看成 65535（正数）→ 不认成哨兵 → 全表等值 → 被当噪声拒掉；
   按 i16 看成 -1（哨兵）→ carry-forward → 单调 → 通过
3. **不能把"全同值"一律当噪声**：+0x34/+0x36/+0x3C 在前几百个类型里全是 -1 哨兵
   （那些类型没有事件/嵌套/接口），**真值也长这样**

**7.0 上 0 候选** —— 瓶颈不是判据，是**候选召回**：`slot_scan` 给的
`methodStart` 6 个候选里没有 7.0 的真密钥。

---

## 六、无密钥反解的新进展（方向已验证，未完成）

既然累计索引字段的**哨兵 -1 的 raw 值会大量重复**，就能**从数据反解密钥**，
完全绕开 `slot_scan` 的候选召回问题：

```
哨兵 raw = v*
xor 编码 -> K = ~v*              (0xFFFF... xor v*)
add 编码 -> K = 0xFFFFFFFF - v*
sub 编码 -> K = v* + 1
```

**7.1 自测成功**（单次探针 1ms，3715 个候选共 0.3s）：
真表 `0x92140` 排第 1（6 字段），解出的 5 个密钥与 `version.json` **完全一致**。

但有两个待解决的问题：
1. **常量填充区会刷出误报**：raw 全同的列，任何 key 都"单调且值域窄"，
   会解出 `add 0xFFFF` 这种**空操作密钥**。已加 `distinct >= 16` 挡掉
   （7.0 上 `0x1017A4C` 5 个字段全是空操作密钥，就是这么来的）。
2. **同一个元数据里有多份同构的 70 字节表**：7.1 的 `0x92140` / `0x100000` /
   `0x10CFD0` 用**完全相同的 6 个密钥**解出单调累计值，且后两者 max 更大。
   光靠"单调"分不开，需要更强的判据（候选：`fieldStart(i+1) - fieldStart(i) ==
   field_count(i)` 的连续性校验）。

---

## 七、下一步（按性价比排序）

1. **给 `typeDefinitions` 加连续性校验**：`fieldStart` 相邻差 == `field_count`。
   这是能同时解决"多份同构表分不开"和"误报"的唯一硬判据。
2. **7.0 上先确认步长**：7.1 是 70 字节，但 slot 都搬家了，结构体布局也可能变。
   已写好 `run_stride.py`（步长 56/60/64/68/70/72/76/80/88/96 × 全交叉候选），
   在 7.0 上跑一遍就能确认。
3. **把无密钥反解并进 `relocate.py`**（现在只在 `/tmp/opencode/keyless.py` 里验证过）。
4. **更正 `docs/UPDATE.md §1`**：那里写"30 张表靠 slot 提示能自动跨版本"，
   已被本次 7.0 实测推翻（实际 16/34，且值全错）。

---

## 附：怎么复现

```bash
# sig 找回多少函数
python3 tools/sig.py scan version/7.0/gi.exe --sigs tools/sigs.json --fuzzy --json /tmp/opencode/h70c.json
#  → 48/54

# relocate 找到什么
python3 tools/relocate.py version/7.0 --slots /tmp/opencode/slots_cache_70.json --keys /tmp/opencode/keys70.json
#  → 强证据 3 个（fDV / methodPointerIndex / blob），弱证据 16 个但全错
```