# 版本更新维护手册（gi.exe 换版本后怎么重做）

> 适用：`gi.exe` / `Managed/Metadata/*.dat` 随游戏更新后，本 dumper 需要重新"抄"一遍版本常量。
> **本文是操作手册，不是背景介绍。** 按 §1 的命令顺序做，每步都有 PASS/FAIL 判据。
> 数字全都会变，**方法和锚点不会**。

---

## §0 代码结构（面向对象）与「更新」的本质

```
version.json            ← 唯一的版本常量来源（数据）
tools/gen_version.py      生成 ↓（make 自动调用）
src/version.hpp            ver:: 常量/Table/OpKey（生成物，勿手改）

src/metadata_files.hpp     MetadataFiles : 装载 gi.exe/*.dat + 解析 PE（RAII）
src/il2cpp_image.hpp       Il2CppImage   : 版本常量 + 文件字节 -> 可查询视图
                                             （表定位 / 逐索引 key / 字段解码 / 名字解析）
src/dumper.hpp             Dumper        : 把视图渲染成 dump.cs / stringliteral.json
src/attributes.hpp         属性位掩码（与版本无关）
src/main.cpp               入口：MetadataFiles -> Il2CppImage -> Dumper
```

**所以「换版本」= 改 `version.json` → `make` → `./gi-dump` → `python3 verify.py`。**
只有 §8 那种「字段本身要重新定位」的情况才需要动 C++（把新找到的 offset/key 填回 JSON 对应字段）。

## §1 30 秒总览（照这个顺序做）

```bash
# 0) 先看现状（用旧常量跑，会 FAIL 一堆 —— 这就是待办清单）
python3 verify.py

# 1) 反编译静态构造器 → 更新 3 个全局地址（main.cpp: MHY_VA / T0_VA / T1_VA 一带）
#    见 §3

# 2) 重扫槽位+密钥（脚本自带 3 条锚点自检）
python3 tools/slot_scan.py gi.exe Managed/Metadata/global-metadata.dat
#    把结果填进 decryptHeader()  →  §4 + §5

# 3) 逐索引 key / 结构体字段：到反编译里抄表达式  →  §5 + §6 + §7

# 4) 无计数表实测（3 个）                        →  §6.5

# 5) 构建 + 跑 + 逐项验收
make && ./gi-dump version/7.1
python3 verify.py            # 必须 28/28 PASS
```

**做完任何一步都跑一次 `verify.py`。** 本项目最危险的 bug 都是「不崩、只静默产出垃圾」，
只有统计量能发现（见 §9 陷阱 7 与 10）。

---

## §2 版本更新会变的三类东西（互相独立，分开验收）

| 类别 | 例子 | 变了会怎样 | 定位手段 |
|---|---|---|---|
| **① 全局地址** | MHY / T0 / T1 三个表 | 全盘读错（但**不崩**，读到别处的数据） | §3 静态构造器 |
| **② 槽位 + 密钥** | `MHY[0x13C] ^ 0x593DE464` | 表基址错 → 乱码/越界 | §4 `slot_scan.py` |
| **③ 结构布局 + 逐索引 key** | typeDef 70 字节、`paramKey` | 字段名/类型错、乱码 | §5–§7 抄反编译 |

> 想快速判断是①还是②：**`verify.py` 里「imagesCount == 75」和「程序集名 75/75」这两项**。
> 若这两项也 FAIL → 大概率是①（地址）；若它们 PASS 而别的 FAIL → 大概率是②③。

---

## §3 三个全局表地址

### 3.1 MHY 表（混淆槽位表）

它是 `.rdata` 里一段以 `"MHY\0"` 开头的 4 字节槽位数组。当前：`0x1427D4BD0`。

```bash
python3 - <<'PY'
D=open('gi.exe','rb').read(); i=0
while True:
    j=D.find(b'MHY\x00', i)
    if j<0: break
    print("file 0x%X" % j); i=j+1
PY
```

再用 PE 段表把 file offset 换成 RVA/VA：

```python
# 段表解析（verify.py 里已有实现，直接抄）
def va2off(v):                       # VA -> 文件偏移，**必须逐段**
    for nm, va, roff, sz in SEC:
        if va <= v < va + sz: return roff + (v - va)
```

### 3.2 T0 / T1（运行时数组总表）

当前 `T0 = 0x1422DE370`、`T1 = 0x142870A88`。
**找法**：反编译 `GIMeta_RuntimeInit`（当前 `0x140534B80`），末尾对这两个全局的赋值；
或从 MHY 表附近的 `.rdata` 指针布局推。

### 3.3 T0 / T1 字段含义（本版本实测，换版本必须复核）

| 表 | 偏移 | 含义 | 验收 |
|---|---|---|---|
| T0 | `+0x30` | `.text` 指针数组 | 长度 ~5 万 |
| T0 | `+0x48` | **invoker 数组**（虚方法用） | 长度 == methodSlotCount |
| T0 | `+0x60` | **genericMethodPointers**（**不是方法地址表！**）| 长度 ~8 万，全在 `.text` |
| T0 | `+0x88` | **每方法地址表**（按 methodIndex 直接索引）| 非零项 ≈ 方法数 |
| T0 | `+0xA0` | `.text` 指针数组 | |
| T1 | `+0x08` | **genericInsts**（16 字节项 `{argc, pad, argv}`）| argc 合理、argv 是 VA |
| T1 | `+0x48` | **Il2CppType 数组**（16 字节项）| 抽样 `type` 字节 ∈ [1,0x1D] 100% |
| T1 | `+0x50` | `genericInstsCount = 值 + 0x9B1B5919` | == 69146（本版本）|

**判定 T0+0x88 是否真是方法地址表**（防诱饵表，§9 陷阱 7）：

```
统计 dump.cs 里方法 RVA 的不同值个数 / 总行数 → 必须 ≈ 1（本版本 710507/711021）
若只有一两万 → 用错了表
```

---

## §4 重扫「槽位 + 密钥」

```bash
python3 tools/slot_scan.py gi.exe Managed/Metadata/global-metadata.dat
```

脚本做的三件事（细节见脚本注释）：
1. 按 **PE 段表**逐段做 VA→file offset（**不能拿 `.rdata` 线性外推 `.text`**，陷阱 1）
2. capstone 线性反汇编全 `.text`（**必须 `md.skipdata=True`**，陷阱 2）
3. 匹配 `mov reg,[base+disp]`（`disp < 0x300`）后 8 条指令内的 `op reg,imm` → `(slot, op, key)`

**自检**（脚本会打印；换版本后这 3 个值会变，但都必须落在结构化数据上）：

```
MHY[0x13C] ^ 0x593DE464 = 0x3D00478     本版本 fieldDefaultValues
MHY[0x0A0] ^ 0x3F525210 = 0xF1754C      本版本常量值 blob
MHY[0x104] ^ 0x094C42AB = 0x37274C0     本版本 parameterDefaultValues
```

**怎么从 3000+ 个候选里认出真表**：
- 12 字节表 → 看 `{index, dataIndex, typeIndex}` 结构（index 严格递增、typeIndex < typesCount）
- 4 字节表 → 看值域（如 `classIndices` 全 < typeDefCount）
- 8 字节表 → 看 `{index, ...}` 是否平铺/递增
- **任何表都要有一个语义锚点**，见 §8

---

## §5 常量清单（**全量**；标 ⚠️ 的是多处重复，最容易漏换）

> 「出现次数」= `grep -c` 的结果。**⚠️ 的必须全部换掉**（本项目就漏换过一处 → 2787 行乱码）。

### 5.1 字符串解密（`il2cpp::utils` 顶部）

| 常量 | main.cpp:行 | 含义 |
|---|---|---|
| `kStringEntryXor = 0x772FA51E` | L448 | 字符串条目解码 XOR |
| `kKeyMulA = 0x5C2B4E660E2D0544` | L449 | 解密密钥派生 |
| `kKeyMulB = 0x694418957C890198` | L450 | 〃 |
| `kKeySeed = 0x55A357D81EF0E48B` | L451 | 〃 |
| `kKeyStep = 0x6B0B40C349AE61E5` | L452 | 每 8 字节递增 |

**验收**：`verify.py` 的「程序集名解码 75/75」。
**重定位**：见 `gi_string_decrypt.py`（同一算法的独立实现，可对照）与文章 §string。

### 5.2 逐索引 key（8 个）

| key | 表达式（当前版本） | 行 | 出现次数 | 验收 |
|---|---|---|---|---|
| `methodKey` | `((860405619*i) ^ 0x73758947) + 1547935323` | L574,584,589,602,608,656,661 | **7 ⚠️** | 方法名 + flags 分布合理 |
| `fieldKey` | `((1824013172*((34782*i)^0x59B1DB19))>>16)+1410079245` | L695 | 1 | `fields[].typeIndex` 100% 合法 |
| `propertyKey` | `((976451930*((0x17A5419F8A28*i)>>9))>>12)^0x70BE4B04` | L681 | 1 | 属性名可读 |
| `eventKey` | `((-1599256506*i+1725894951)^0x1B23E40F)` | L703 | 1 | 事件名 628/628 |
| `paramKey` | `((1457992407*((41617*i+1219887025)^0x19E1D47A))>>21)+2068375556` | L667 | 2 | `parameters[].typeIndex` 100% 合法 |
| `genericContainerKey` | `(1714760523*((1015151837*((10661*c+1371718001)^0x146D2C3D))^0x5D7F95E0))>>19` | L532 | 1 | argc == 名字里的 `N` |
| `genericParameterKey` | `(((1845531077*((12124*p+1969070457)^0x423B2C8D))>>10)+1212570291)^0x62A3A8F4` | L544 | 1 | 参数名 = `T`/`T1`/`TKey` |
| `ImageIndexKey` | `(1368137530*((667674736*((13029*i)^0x43E2DEB7)+0xCB287082F0)>>8)+1505552983)` | L470 | 2 | 程序集名 75/75 |

> ⚠️ **`methodKey` 在 7 个地方各抄了一份**（`methodNameIndex` / `methodFlags` / `methodIFlags` /
> `methodReturnType` / `methodDeclaringType` / `methodParamStart` / `methodParamCount`）。
> 这 7 处**必须同步换**。

### 5.3 各字段的解码常量（⚠️ 多处重复）

| 常量 | 含义 | 行 | 次数 |
|---|---|---|---|
| `0x4159BB8E` | typeDef `+0x28` flags | L558 | **2 ⚠️**（另有注释 1 处）|
| `0x3D74901F` | typeDef `+0x18` parentIndex | L525 | 1 |
| `26230` / `26229` | typeDef `+0x3E` genericContainerIndex + 哨兵 | L529 | 3 ⚠️ |
| `452544412` | 事件 `+0x00` typeIndex | L1608 | **2 ⚠️** |
| `1037298109` | 事件 `+0x04` nameIndex | L709 | **2 ⚠️** |
| `0xBEA7` / `0xEE66` / `30703` | 事件 add / remove / raise | L1556–1558 | 各 1 |
| `23324` | 属性 `+0x08` set | L1554 | **3 ⚠️**（另有注释 2 处）|
| `0xE5A2` | 属性 `+0x06` get | L1553 | **3 ⚠️** |
| `1953953095` | 属性 `+0x00` nameIndex | L687 | 1 |
| `0x2D27D873` | 字段 typeIndex | L1086 | 1 |
| `1475293452` + `0x2D027B84` | 字段 nameIndex | L699 | 1 |
| `0x31BF59F3` | 参数 typeIndex | L677 | 1 |
| `1764493660` + `0x4CDBD093` | 参数 nameIndex | L673 | 1 |
| `257927898` | 方法 `+0x04` parameterStart | L657 | 2 ⚠️ |
| `0x8F60` | 方法 `+0x16` flags | L585 | 2 ⚠️ |
| `25344` | 方法 `+0x10` iflags | L590 | 2 ⚠️ |
| `0x59244785` | 方法 `+0x0C` declaringType | L603 | **3 ⚠️** |
| `0x3F7BDF39` | 方法 `+0x08` returnType | L597 | **3 ⚠️** |
| `1524016681` | 方法 `+0x00` nameIndex | L575 | 1 |
| `0x4D8127F2` | typeDef `+0x0C` methodStart | L521 | 1 |
| `0x29010897` | typeDef `+0x1C` fieldStart | L522 | 1 |
| `1995389561` | typeDef `+0x08` propertyStart | L523 | 1 |
| `1145778368` | typeDef `+0x00` namespaceIndex | L520 | 1 |
| `72511848` | typeDef `+0x24` nameIndex | L519 | 1 |
| `0xED3A` / `0x51A8` / `0x43DA` / `0x16` / `0xBA` | 各 width 字段的 count | L551 / L552 / L562 / L564 / L567 | 各 1 |
| `56` / `113` / `3330` / `6631` | interfaces_count / event_count / eventStart / nestedStart | L565 / L568 / L554 / L566 | 各 1 ⚠️ **必须 8 位截断** |
| `0x2E8C0EB8` | typeDef `+0x20`（**语义未定**）| L200 | 1 |
| `0x138FD4C7` / `1053517166` | 容器 `+0x04` parameterStart / `+0x08` argc | L541 / L537 | 1 |
| `0x664CCEB9` | 泛型参数 `+0x00` nameIndex | L549 | 1 |
| `0x9B1B5919` | T1`+0x50` → genericInstsCount | L426, L2509 | 2 ⚠️ |
| `0x558E11EC` | MHY[0x134] → genericClassRange | L427, L2513 | 2 ⚠️ |

### 5.4 decryptHeader 的槽位表（40 张表）

见 `status.md` §3.2（那份表与代码逐条一致）。**换版本时逐行复核**：
每行都有「槽位 / 运算 / 密钥 / 步长」，改完用 `verify.py` 与 §6.5 的实测计数交叉核对。

### 5.5 计数：优先找**公式**，实在没有才实测

本版本 40 张表的计数**全部**有来源，分三类：

| 来源 | 例子 |
|---|---|
| MHY 侧槽位 | `(MHY[0x188] ^ 0x1B58E334) / 26` = methodsCount |
| **T0/T1 侧字段** | `T1+0x50 + 0x9B1B5919` = genericInstsCount；`T0+0x80 ^ 0x4E013BBD` = **genericClassRangeCount** |
| 运行时从**数据**推导 | `fieldDefaultValuesCount`（fieldIndex 严格递增扫到断点）、`methodSpecsCount`（`max(genericMethodTable[].genericMethodIndex)+1`）|

**教训**：先找消费者（`RuntimeInit` 里谁给循环定界、谁给数组分配）—— 那里一定有**公式或推导**，别急着「实测」。
`genericClassRangeCount` 我一开始当它是"只能实测"，结果 `init_534B80.c:2064` 里明摆着 `T0+128 ^ 0x4E013BBD`。

### 5.5b 实测法（仅当真的找不到公式时）

| 字段 | 值 | 行 | 重测方法 |
|---|---|---|---|
| `fieldDefaultValuesCount` | 75548 | L2469 | 从表起点往后扫到 `fieldIndex` 不再严格递增 |
| `methodSpecsCount` | 610109 | L2507 | `methodSpecs` 12 字节项按 `methodDefinitionIndex` 递增扫到底；**安全下界 563653** |
| `genericClassRangeCount` | 13671 | L2515 | 8 字节项，`argStart` 从 0 重新开始处即表尾 |

### 5.6 三个全局地址（`main()` 内）

| 变量 | 值 | 验收 |
|---|---|---|
| `s_MHYTable` | `0x1427D4BD0` | 开头是 `"MHY\0"` |
| `s_Table1` | `0x142870A88` | `*(T1+0x48)` 指向的表抽样 `type` 字节 100% 合法 |
| `s_Table0` | `0x1422DE370` | `*(T0+0x88)` 非零项 ≈ 方法数 |
| `s_GlobalMetadataHeader` | `global.data() + 0x210` | **所有 global 侧偏移都要 +0x210** |

---

## §6 结构体字段表（含 typeDef 内的隐藏字段）

### 6.1 Il2CppTypeDefinition（70 字节）

见 `UPDATE.md` 上一版 §5.2（`status.md` §3.1 也有）。**重点**：
- 已知字段的 offset/解码 → §5.3
- `+0x18 parentIndex`、`+0x3E genericContainerIndex` 是**后来才找到的隐藏字段**，
  用的是 §8 的**锚点法**（不是扫数据猜）

### 6.2 方法（26 字节）

```
+0x00 nameIndex       (key ^ (raw - 1524016681))
+0x04 parameterStart  (key ^ (raw - 257927898))      全局参数索引
+0x08 returnType      ((raw ^ key) ^ 0x3F7BDF39)     Il2CppType 索引
+0x0C declaringType   (key ^ raw ^ 0x59244785)       typeDef 索引
+0x10 iflags          (key ^ (raw - 25344))
+0x16 flags           (key ^ raw ^ 0x8F60)
+0x18 parameterCount  ((raw - 31) & 0xFF) ^ (key & 0xFF)   ← **字节运算！** 不是 16/32 位
```

### 6.3 其它（步长 / 关键字段）

| 结构 | 步长 | 关键字段 |
|---|---|---|
| Field | 8 | nameIndex@+4；typeIndex@+0 |
| Property | 10 | nameIndex@+0；**get@+6**；set@+8 |
| Event | 14 | **typeIndex@+0**；nameIndex@+4；add@+8；remove@+0xA；raise@+0xC |
| Parameter | 8 | typeIndex@+0；nameIndex@+4 |
| GenericContainer | 16 | parameterStart@+4；argc@+8 |
| GenericParameter | 14 | nameIndex@+0；ownerIndex@+8 |
| FieldDefaultValue | 12 | fieldIndex@+0；dataIndex@+4；typeIndex@+8 |
| ParameterDefaultValue | 12 | parameterIndex@+0；dataIndex@+4；typeIndex@+8 |
| AttributesInfo | 8 | start@+0；token@+4 |
| MethodSpec | 12 | |
| GenericMethodTable | 14 | |

> **字段顺序错=静默全错**：`Event`/`Property` 都栽过（事件 628→0、属性访问器全空）。

### 6.5 无计数表实测法（§5.5 的展开）

```python
# fieldDefaultValues：严格递增到断点
n=0; prev=-1
while True:
    v = i32(FIELDDEF + 12*n)
    if v <= prev or v < 0: break
    prev = v; n += 1          # 本版本 n == 75548
```

---

## §7 方法地址（**双路径**，文章 §methodPointer）

> 文章原文：*"…the methodIndex → slot array with class flag 0x40, if found … the **+0x90[slot]** variant is taken
> (for override/virtual), otherwise **+0x80[index]** (for the rest)"*

```cpp
非虚/其余 : methodPointer = *( *(T0+0x88) + 8 * methodIndex )      // 按 methodIndex 直接索引
虚/重写   : methodPointer = *( *(T0+0x48) + 8 * slot )             // slot 来自 6 字节 slot 表二分
```

- `*(T0+0x60)` = **genericMethodPointers**（文章 `CR+0x60`）—— **只给泛型实例用**
- 误用它**不崩**，只会让 RVA 大量重复（症状：不同值只有一两万）。**验收见 §9 陷阱 7**

---

## §8 锚点库（找不到字段时用这些"自带答案"的东西）

| 锚点 | 怎么用 | 实例 |
|---|---|---|
| **枚举 → `System.Enum`** | 所有枚举父类相同 | 定位 `parentIndex` |
| **结构体 → `System.ValueType`** | 所有结构体父类相同 | 同上 |
| **`` Foo`N `` 的名字自带参数个数** | 容器 `argc` 必须 == N | 定位 `genericContainerIndex` |
| **已知继承链** | `MonoBehaviour→Behaviour`、`FileStream→Stream` | 验收 `parentIndex` |
| **`[Flags]` 枚举的值** | `AttributeTargets` 的 16 个值确定 → 当字节签名搜 | 定位常量值 blob |
| **区间平铺 / 无缝累计** | `start_{i+1} == start_i + count_i` | 定位嵌套表、CSR 表 |
| **值域** | `typeIndex < 683574`、`klassIndex < 88902` | 排除噪声 |
| **哨兵值** | `-1` / `0xFFFF` / `26229` / `0x8F` | 判「无此字段」|
| **严格递增** | `fieldIndex` / `parameterIndex` 排序 | 定位 + 二分 |

**校验必须要求接近 100%，例外要能逐个解释。** 例：`genericContainerIndex` 第一次用错字段时
得到 `152/711` —— 远高于随机，但**是错的**。

### Worked example A：`parentIndex`（typeDef +0x18）

1. 从 `dump.cs` 取 `System.Enum` / `System.ValueType` 的**真实** typeDef 索引（204 / 405）
2. **注意单位**：`parentIndex` 存的是 **Il2CppType 索引** → 在 Il2CppType 表里找
   `klassIndex == 204` 的项（得 401709）、`klassIndex == 405` 的项（得 425583）
3. 要求「枚举原始值恒定 + 结构体原始值恒定 + 单一 op/K 同时映射到这两个目标」→ 一次命中
   `raw32@+0x18 - 0x3D74901F`

### Worked example B：`genericContainerIndex`（typeDef +0x3E）

1. 反编译里搜容器表 key `0x774A3BA6` → 4 个函数命中
2. 其中 `sub_140511DB0` 读的是 `70*idx + typeDefinitionsOffset`（即 typeDefinition）→ 就是它：
   `v9 = (int16)(*(WORD*)(typeDef + 62) - 26230)`，`62 = 0x3E`
3. 用 `` Foo`N `` 锚点验收：容器 `argc` 必须 == N → 702/711（其余 9 个是 Roslyn 闭包，解释得通）

---

## §8.5 两个自动化工具（换版本时用）

### `tools/sig.py` —— 结构签名（找函数）

不做「前 N 条字节 + 通配 imm」那种脆的：**跳过序言、从函数中部取指令**，
每代指令编成两种 token：

```
loose : mnemonic + 操作数种类（寄存器位置全用 R 通配）      ← 跨版本稳，用来找候选
strict: 额外保留**小立即数/小偏移**（<0x1000，语义常量）     ← 用来确认
```

```bash
python3 tools/sig.py gen  version/7.1/gi.exe --names tools/sig_names.txt -o tools/sigs.json
python3 tools/sig.py scan version/7.2/gi.exe --sigs tools/sigs.json     # → 新的函数起点
```

**速度**：scan 走**字节模式优先** —— 取签名里最长的「全固定子串」做 `bytes.find`，
只在候选地址处反汇编核对 token。**不反汇编整个 `.text`**（那是几分钟）。
本机自测：36 条签名 **36/36 命中、函数起点全部精确复原、0.6 秒**。

**掩码精度**：用 capstone 的 `insn.encoding.imm_offset/imm_size`、`disp_offset/disp_size`
**精确**通配 imm/disp，而不是"尾部 4 字节全 ?? "——固定前缀更长 → 又快又准。

生成时会打印**弱签名警告**（区分度 <4：说明那 8 条指令太重复，如 `movaps` 刷栈），
这类函数签名不可靠 → 退回字符串/调用图锚。

### `tools/relocate.py` —— 自动重定位表常量（numpy 秒级）

只用跨版本稳定的三层锚，**不给字节签名当判据**：

```
① 魔数 "MHY\0"                          → MHY_Table
② slot_scan 的 (slot,op,key) 候选          → 常量只存在于指令里
③ 数据侧结构自证（numpy 向量化）            → 判真伪
     · 12B + 第 0 字段严格递增 + 第 8 字段是合法 Il2CppType 索引 → fieldDefaultValues
     · 12B + 严格递增 + 第 4 字段有 -1 哨兵                    → parameterDefaultValues
     · AttributeTargets 的 16 个 [Flags] 值做字节签名           → 常量值 blob
       （再靠「让签名正好落在某条 dataIndex 上」反推 blob 基址）
     · 70B flags 只有 ~106 种 / 26B parameterCount 只有 ~33 种 …
```

```bash
python3 tools/relocate.py version/7.1          # 自测：应能复原已知值
```

**自测意义**：拿 7.1 跑，它**不需要知道旧的 slot/key** 就能推出
`fieldDefaultValues=0x3D00478`、`blob=0xF1754C` —— 证明这套锚是有效的。



| # | 症状 | 根因 / 修法 |
|---|---|---|
| 1 | 读到的数据整体错位 | 拿 `.rdata` 的 VA→file 线性关系外推 `.text`（差 `0x400`）。**必须逐段换算** |
| 2 | slot_scan「什么都没找到」 | `capstone.md.disasm` 遇非法字节即停。**必须 `md.skipdata=True`** |
| 3 | 名字正确但带垃圾尾巴 | 逐索引 key 用了 32 位乘法（`41617*i` i≈73891、`34782*i` i≈123482 处超 2³²）→ **低 24 位对、高 8 位错**。**一律 64 位** |
| 4 | SIGSEGV 在解引用 | 把镜像 **VA** 当宿主指针。必须 `exe.data()+va_to_offset(VA)` |
| 5 | 字段类型大量只剩 `[]` 或 `*` | VA 与宿主指针**混用**（算索引要减**镜像 VA**，不是宿主指针）|
| 6 | SIGSEGV 在读 count 之后 | `+N` 型 count 未按 **8 位**截断（`0xC8+56=256` 应为 0）→ 读 256 个元素越界 |
| 7 | **方法 RVA 大量重复**（不同值只有一两万，单个地址被几十万方法共用）| 把 `*(T0+0x60)`（genericMethodPointers）当方法地址表。改用 `*(T0+0x88)[methodIndex]` |
| 8 | 穷举扫描全败（零命中）| **锚点单位搞错**（`parentIndex` 是 Il2CppType 索引，用 typeDef 索引当锚 → 必然全败）|
| 9 | 「部分命中」 | `152/711` 看着像对的。**必须接近 100%**，例外要能解释 |
| 10 | 某功能整块失效但不崩 | 活路径里残留旧版常量（VAR/MVAR 用了 6.7 公式→2787 行乱码）；或赋值语句还在 `#if 0` 里（`methods[]` 永远为空→访问器名全丢）|
| 11 | 事件 628→0 / 属性访问器全空 | 结构体**字段顺序**抄错（Event 的 `typeIndex/nameIndex`、Property 的 `get/set`）|
| 12 | 表长度不对 | 把「能排到文件尾」当长度（parameters 真实 548400，按 `(len-起点)/8` 会估成 2915543）。**长度要语义交叉验证** |
| 13 | 泛型参数名解出乱码 | VAR/MVAR 分支还在用旧版 `(nameIndex ^ 0x2DD1C9C6) - …` 公式；应用 `genericParameterNameIndex` |
| 14 | C 里 `key ^ *(WORD*)` | 结果是 **32 位**（16 位零扩展）；`parameterCount` 是**字节** XOR |

---

## §8.6 「引导阶梯」—— 让另外 38 张表也能自动定位

**问题**：那些表的**内容都是逐索引混淆的**（`raw op key(i)`），所以**没有干净的原始指纹** ——
靠"独特结构"最多只能认出 2~3 张。

**办法**：不再要求"这张表自己有独特结构"，改成**每级借用上一级当证据**：

```
① "MHY\0" 魔数                                     -> MHY 表              ✅ 已实现
② 已知的 75 个程序集名                               -> 字符串解密(5 密钥+数据块)
③ 用「名字可打印」当二次证据 -> typeDefinitions(70B)   ✅ 已实现且**自证 100%**
④ 用 typeDefs 的 methodStart/fieldStart/propertyStart/ ✅ 已实现（解出各表预期长度）
  eventStart/interfacesStart/nestedTypesStart
⑤ 用「长度 + 结构自证」钉住可自证的表                  ✅ nestedTypes / interfaces 已钉住
⑥ fields 表长度 == fieldOffset 表长度                 ⏳ 长度有了，但 fieldOffset 索引基是
                                                       typeDef+0x20（不是 fieldStart）→ 暂缓
⑦ attributesInfo(+0 严格递增) 的 range 覆盖           ⏳ 待做 -> attributeTypes
⑧ genericContainers 的 argc/parameterStart            ⏳ 待做 -> genericParameters
⑨ startup 侧 type args 是合法 Il2CppType 索引         ⏳ 待做 -> genericClassRange/genericTypeArg
```

三段式：**旧 version.json 当提示 -> 用另一张表/字符串解码做二次证据 -> 任何一步不过就 FAIL（不静默接受）**。
这样即使指纹不独特，也**不会误报**。

**⚠️ 已验证：候选生成曾是薄弱环节（已修）**

阶梯刚搭好时，`typeDefinitions` 的二次证据**完全成立**，**但 `slot_scan.py` 根本没产出它的候选** ✗
—— 因为真实读取点走了**别的指令形态**。修法是让 `slot_scan.py` 覆盖**三种形态 + 数据流追踪**：

```
A) mov reg,[mhy+slot]   ...  op reg,imm               槽位在前
B) mov reg,imm          ...  op reg,[mhy+slot]        密钥在前
C) mov reg,[mhy+slot]   ...  op reg,reg2              寄存器对寄存器（槽位+密钥各占一个寄存器）
```

**关键教训：密钥不一定紧邻读取点** —— 实测它常被提到**函数入口**装载：

```asm
; 函数入口:  mov r15d, 0xA584BD79        ; = -1518027399 (interfaces 的密钥)
; ...
; 读取点:    mov ecx, [rcx+0x1c4]        ; 槽位
;            add ecx, r15d                ; ← 中间隔了上百条指令 ✗ 8 条窗口挡掉了
```

所以**不能**用"距离 N 条指令以内"来配对，必须做**数据流追踪**：
寄存器被写就失效、`call/ret` 清掉调用者保存寄存器（rax/rcx/rdx/rsi/rdi/r8-r11），
只要没被写就一直有效。

实测效果（本版本）：唯一 `(slot,op,key)` 组合 **3028 → 4153（形态B）→ 4353（形态C）→ 4730（去窗口）**，
两处关键漏报被补上：`interfacesTable`、`nestedTypesTable`。
`slot_scan.py` 现在把缓存固定写到 `tools/slots_cache.json`（`relocate.py` 就在这儿找）。

**阶梯 ④⑤ 的落地（本版本已实现）**

`ladder_expected_lengths()` 用旧 JSON 的 `fieldDecode.typeDef` 键解码 typeDefs 各字段 → 得到各表预期长度：

```
fields=440172  methods=733442  properties=115596  events=628  nested=25981  interfaces=37562
```

再用「长度 + 结构自证」钉候选。**只有自测能推出已知正确值的探针才启用**（宁可漏报不可误报）：

| 表 | 判据 | 结果 |
|---|---|---|
| `typeDefinitions` | 70B + flags 种类 + nameIndex 解出可打印名字 | ✅ 0x92140 |
| `nestedTypesTable` | 4B，typeDefs 的 nested 区间**恰好铺满** [0,25981) **且条目两两不同** | ✅ 0x22800F8 |
| `interfacesTable` | 6B，+0 **全**为合法 Il2CppType 索引（-1=null），含 36667 个大索引 | ✅ 0x4D5AB04 |
| `fieldDefaultValues` | 12B，+0 严格递增，+8 全为合法 Il2CppType 索引 | ✅ 0x3D00478 |
| `methodPointerIndex` | 4B，值域 [-1, 79765)，-1 占 4.3% | ✅ 0xC48E6C（仅参考） |

**"条目两两不同"是杀误报的关键**：只要求"98% 条目 < typeDefCount"时，
`0xD576F0` 会**误命中**（唯一值只有 1163/25981）；加上去重后只剩真值（25981/25981 唯一）。

**仍未启用（判据不足）**：
- `fields` / `methods` / `properties` / `events`：内容逐索引混淆，**无原始指纹**；
  长度只能当**范围约束**，不能唯一定位（见下）
- `fieldOffset`：**不是**按 `fieldStart` 索引，而是按 `typeDef+0x20`(`unknown20`) + k；
  且实测"类型内偏移非递减"只有 57%（用 unknown20 当基）/ 45%（用 fieldStart）→ 判据不足

**结构体偏移能不能定位？—— 分两类，答案不同**

| 类别 | 例子 | 能否自动定位 |
|---|---|---|
| **A. 全局表槽位** | `MHY[0xB4]` / `T0+0x88` / `T1+0x48` | ✅ **能（反查）** |
| **B. 被解码结构体内部的字段** | `typeDef+0x18`(parentIndex) / `+0x24`(nameIndex) / `+0x28`(flags) | ❌ **不能**（候选太多 + 部分没被枚举） |

**A 类——反查法（本版本实测）**

先结构自证求出**值 V**，再问候选表：**哪些 `(slot,op,key)` 解出 V**？

```
typeDefinitions   0x92140   → 唯一 → slot 0xB4  add 0xEC48AB9F
nestedTypesTable  0x22800F8 → 唯一 → slot 0x5C  add 0xE93D6D0D
interfacesTable   0x4D5AB04 → 唯一 → slot 0x1C4 add 0xA584BD79
fieldDefaultValues 0x3D00478→ 唯一 → slot 0x13C xor 0x593DE464
blob              0xF1754C  → 唯一 → slot 0xA0  xor 0x3F525210
methodPointerIndex 0xC48E6C → 唯一 → slot 0x94  xor 0x4A4C0A71
```

整体判别力：4730 个三元组产生 3715 个不同值，其中 **3334 个值（90%）只被唯一一个三元组产生**。
→ **只要表的值能结构自证，它的 `(slot, op, key)` 就能唯一反查出来**：

```
结构自证（值 V） --反查--> 唯一 (slot,op,key) --写入--> 新 version.json
```

这条闭环**不依赖旧 JSON、也不依赖"slot 跨版本稳定"** ✓✓ —— 是 6 张表换版本的**全自动**通道。

**B 类——为什么不能**

同一位移有大量 `(op,key)` 候选（实测）：

```
typeDef+0x0C  55 种     typeDef+0x18  103 种     typeDef+0x1C  37 种
typeDef+0x20  117 种    typeDef+0x28  88 种      typeDef+0x38  86 种
```

而且**有些真值压根没进候选**：`(0x24,sub,72511848)` / `(0x18,sub,0x3D74901F)` /
`(0x28,sub,0x4159BB8E)` 全都不在缓存里 —— 因为它们的密钥**不在 `.text` 立即数**里，
而在**数据段常量池**（`op reg,[rip+const]`，**第 4 种读取形态**，已补扫）。

要定位 B 类，只能靠**语义/二次证据**（例：`nameIndex` 用"解出的名字可打印"当判据、
count 用"÷70 == 类型数"当判据），或 IDA 单点确认 —— **没有通用结构探针**。

> **补充**：B 类的**偏移本身**（0x0C/0x18/0x1C…）是**结构体布局**，由目标 C 结构体定义决定，
> 跨版本大概率不变（变的是**密钥**，已在 JSON 里 ✓）。
> 但目前这些偏移**硬编码在 `src/*.hpp`**，不在"单一事实来源" —— 可考虑移进 JSON 的 `structSizes` 旁边。



**⚠️ 反直觉实测：长度约束对"定位"几乎没用**

本以为"表长一致"能大幅筛候选，实测（435 个去重候选）：

```
typeDefinitionsOffset  (70B x 88902) = 6.2 MB → 通过长度约束的候选 432 个 ✗
methodsOffset          (26B x 733442) = 19 MB → 通过 422 个 ✗
eventsOffset           (14B x 628)            → 通过 435 个 ✗（全部）
```

因为候选本身就是"元数据内部的小偏移"，"加 19 MB 不越界"太容易满足。
**结论：长度只能当合理性检查（且只在表很大时才有一点点筛选力），定位必须靠结构自证。**

**布局连续也当不了锚**：实测表间有大量空隙
（`+7464` / `+46792` / `+599292` / `+822869` / `+16240956` 字节…），不是紧密排布 ✗。
顺序（表在文件里的先后）与 il2cpp 规范一致，**可当弱约束**（"位于 A 和 B 之间"），
但不能唯一确定。

**其它实测结论**：
- `interfaces` 的每类型区间**不铺满**（有重叠）：`sum(count)=37562` 但 `max(start+count)=65542`
  → 长度必须用 **sum**（真窗口 100% 合法），不能用 max
- 所有从 MHY 槽位解出来的偏移都是 **global 相对**的，读文件要 **+0x210**（`d.hdr`）
  —— 诊断脚本漏这个会看到一堆"越界"假象（本版本踩过）

**阶梯 ⓪ 级（最实用）：slot 提示 → 逐表重新解值**

实测（本版本）：**知道某张表的 slot，就基本能直接重新解出它的值** ——
因为该 slot 的候选里，**落进"元数据合理范围"的通常只有一个**：

```
imagesOffset            slot 0x20C   唯一 ✅
typeDefinitionsOffset   slot 0xB4    唯一 ✅     (其余候选是 and/or 位运算 → 值越界)
methodsOffset           slot 0x16C   唯一 ✅
...
合计: slot 唯一确定 30 张, 多候选 0 张, 无候选 4 张
```

那 4 张"无"是：`imagesCount`（是**计数** 3000，不是偏移）、`genericTypeArgOffset`（本版本值 0）、
两张 `*_deprecated`（代码里已不读）。**即：真正在用的表 30/30 全部 slot 唯一确定。**

> ⚠️ **唯一未验证的前提：slot 跨版本是否稳定。**
> 若混淆器每次构建都重排槽位，这一级就失效 —— 那时只剩下面 6 张"结构自证"能独立定位。
> 需拿第二个样本（如 6.7）验证。这是**换版本工具链目前最大的未知数**。

**⓪ 级做不到的**：如果同一个 slot 被多个读取点用不同 key 读（本版本 slot 0x5C 有 23 种候选），
就必须靠结构自证（⑤）或人工确认 —— 本版本这种情况**没有发生**（0 张多候选）。

## §10 验收标准（`verify.py` 的 28 项）

```bash
python3 verify.py     # 必须 28/28 PASS
```

覆盖：
- **元数据侧**：MHY 魔数与 3 条锚点、imagesCount、程序集名 75/75、typeDefCount/methodsCount、
  泛型类型数、**parentIndex 枚举/结构体锚点**、**genericContainerIndex argc 锚点**、
  nestedTypes 铺满、fieldDefaultValues/parameterDefaultValues 严格递增
- **输出侧**：类型数、带基类、嵌套前缀、泛型参数、属性访问器 ≥99%、事件 628/628、
  参数默认值、字段常量值、**乱码行 < 200**、**签名 `?` < 8%**、
  **方法 RVA 去重率 > 90%**、**单一 RVA 共用 < 1000 次**

### 基线数字（本版本，供对比）

| 项 | 值 |
|---|---|
| 类型 / 带基类 / 嵌套前缀 / 带泛型参数 | 88902 / 47780 / 25980 / 1852 |
| 方法 / 字段 | 733442 / 439974 |
| 属性（带访问器名） | 115596（115427 = 99.85%）|
| 事件（带访问器名） | 628 / 628 |
| 字段常量值 / 参数默认值 | 74629 / 17601 |
| 方法 RVA | 711021 行 / **710507 不同值** |
| 乱码行 | < 30（中文常量少 1 字节，已知）|
| `dump.cs` | ≈178 MB，耗时 ≈1.4 s |

---

## §11 换版本后**仍然会缺**的（不是这次没做完）

| 缺 | 原因 |
|---|---|
| 自定义属性的**值** | `Il2CppCodeRegistration` 运行时构造，文件镜像里没有 |
| `attributesInfo` 的 `token` | 非标准 ECMA token（高字节 1..0x54、低 24 位单调）|
| 泛型**实例**的类型名 | `type->data.generic_class` 指向的表未定位（值域 0..406568 连续，疑似 8 字节项）|
| 泛型参数的 `in`/`out` | 14 字节参数项整体加密，`+8` 实测是 ownerIndex |
| `typeDef +0x20` | 语义未定（已排除 genericContainerIndex）|

---

## §12 附录

### 12.1 IDA MCP 速查

```python
# 反编译一个地址所在函数
import ida_funcs, ida_hexrays, ida_lines
f = ida_funcs.get_func(0x1404B7EE6)
cf = ida_hexrays.decompile(f.start_ea)
ls = [ida_lines.tag_remove(str(x.line)) for x in cf.get_pseudocode()]
open('/tmp/fn_%X.c' % f.start_ea,'w').write('\n'.join(ls))

# 全局变量的 xref（找读取点）
import idautils, ida_funcs
xs = list(idautils.XrefsTo(0x145AD52C8, 0))
```

> 单次 `py_eval` 必须 1–2 秒内返回；批量分析放进程外脚本（别把大循环塞进 `py_eval`）。

### 12.2 崩溃调试

```bash
make clean && make OPT="-O0 -g"
gdb -batch -ex run -ex "bt 12" --args ./gi-dump version/7.1
```

### 12.3 一键回归

```bash
make && ./gi-dump version/7.1 && python3 verify.py
```

---

## §13 方法论（一句话）

> **能用 IDA 读到的，绝不去扫数据猜；**
> **扫数据只是"读不到"时的兜底，而且必须带语义锚点验收；**
> **验收标准是 100%，例外必须逐个能解释；**
> **同一个公式族的所有引用点必须一起换（⚠️ 标记的 2+ 次出现）。**
