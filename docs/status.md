# GIMetadata 逆向进度状态

> 目标：把 `main.cpp` 适配到仓库内这份 `gi.exe`（原 dumper 只支持 6.7 版）
> 方法：严格按 unknowncheats 原文《Exploring custom struct in Genshin Impact》——
> ① 版本源码当地图（用 `main.cpp` 代替）→ ② 文件名/静态构造器 xref 定位 → ③ 在 `Runtime::Init` 的
> calloc 展开串与各读取函数里逐个抄 `(槽位, 运算, 密钥)` → ④ **用「能解出可读字符串」/ 区间平铺 / 位掩码语义验收**
>
> 配套：`gi_fields.md`（字段表）· `mhytab_pairs.md`（配对表 + 解密算法）· `gi_string_decrypt.py`（可运行解密）
> · `ANALYSIS.md`（总报告）· `METHOD.md`（文章方法中文整理）

样本：`gi.exe` · `global-metadata.dat` 82,724,152 B · `startup-metadata.dat` 4,060,776 B

---

## 1. 总体结论

| 阶段 | 状态 |
|---|---|
| ① 跨平台编译（Linux ELF，5 处改动，不影响 Windows 行为） | ✅ 完成并验证 |
| ② 字符串解密算法 | ✅ **完全攻克，75/75** |
| ③ 混淆表定位 | ✅ 5 张表（静态构造器 `0x1402F2910`） |
| ④ 结构体逐个抄公式 | ✅ **Image / Type / Method / Field / Property / Event / Interfaces / Generics 全部打通** |
| ⑤ main.cpp 适配 | 🟡 已接：解密 + 全部结构 + 类型 flags/bitfield + 方法（名字/修饰符/返回类型/地址/参数/泛型实例）|
| ⑥ **字段常量默认值**（fieldDefaultValues + blob） | ✅ **已定位并验证**（AttributeTargets 16/16）|
| ⑦ **参数默认值**（parameterDefaultValues） | ✅ **已定位并按读取点验证**（见 §3.2 与 §6 附 4）|
| ⑧ 自定义属性**值**、类型 parent/declaring/genericContainer | ❌ 未取得（见 §5）|

**main.cpp 当前能正确输出**：

```
// Namespace: Mono.Xml
// FullName: Mono.Xml.SecurityParser
public sealed class SecurityParser : IContentHandler, IDisposable // TypeDefIndex: 22
{
    // RVA: 0x?? Offset: 0x?? VA: 0x??
    /* GenericInstMethod : ... */
    public static int get_Length(string msg)
}
```

即：类型名/命名空间/**可见性**/**种类(class/struct/enum/interface/abstract/sealed/static)**/[Serializable]/接口列表；
字段；方法（名字/修饰符/**返回类型**/**RVA+VA 双路径**/参数类型+名/**泛型实例**）；属性；事件；泛型参数。

---

## 2. 文章 §9 操作清单 —— 逐条状态

| # | 步骤 | 状态 | 证据 |
|---|---|---|---|
| 1 | 拿版本源码当地图 | ✅ 用 `main.cpp` 代替 | — |
| 2 | 文件名 xref → 确认 `+0x210` | ✅ | `GIMeta_RuntimeInit` |
| 3 | 静态构造器 `lea`/`mov cs:` → 定位混淆表 | ✅ | `0x1402F2910` 注册 5 张表 |
| 4a | ImageDefinition | ✅ | 75/75 程序集名 |
| 4b | TypeDefinition | ✅ | 88902/88902 名字+命名空间 |
| 4c | MethodDefinition（名字/flags/iflags/地址） | ✅ | 名字 400/400、flags 位掩码形态、地址双路径互证 |
| 4c' | Method returnType | ❌ | 未定位 |
| 4d | FieldDefinition | ✅ | 440172 条区间零空洞零重叠 |
| 4e | PropertyDefinition | ✅ | 115596 条，99.81% |
| 4f | EventDefinition | ✅ | **628/628**，解出 `AssemblyLoad`/`DomainUnload`/`ProcessExit`（与文章示例同名）|
| 4g | StringLiteral | ✅ 本版本无独立条目表 | offset/length 打包进 nameIndex |
| 4h | CustomAttribute | 🟡 `attributesInfo`+`attributeTypes` 已定位；值(generators)未定位 |
| 4i | Generics | ✅ genericInsts / genericClasses(count) / genericMethodTable / methodSpecs 全定位 |
| 5 | 重抄 `decryptString` 6 个常数 | ✅ | 75/75 |
| 6 | 验收：解出可读字符串 | ✅ | `python3 tools/gi_string_decrypt.py` |
| 7 | 重抄 3 个 helper 地址 | ❌ | 未验证旧值是否失效 |

---

## 3. 已验收的字段（可安全使用）

### 3.1 字符串解密

```c
entry  = indexKey ^ rawNameIndex ^ 0x772FA51E;   // offset(24位)+length(8位) 打包
offset = entry & 0xFFFFFF;  length = entry >> 24;
key    = 0x5C2B4E660E2D0544 * ((0x694418957C890198 * offset) ^ 0x55A357D81EF0E48B);
out[k] = enc[k] ^ (key + k * 0x6B0B40C349AE61E5);   // uint64 溢出
```

### 3.2 数组偏移 —— MHY 表（`0x1427D4BD0`）

| 字段 | 槽位 | 运算 | 密钥 | 步长 | 侧 | 验收 |
|---|---|---|---|---|---|---|
| imagesCount(字节) | `0x02C` | `-` | `0x2465B023` | `/0x28`=75 | — | 75/75 |
| imagesOffset | `0x20C` | `-` | `0x0ECB27F5` | 40 | **S** | 75/75 |
| stringLiteralDataOffset | `0x184` | `+` | `0xBF9D4735` | — | G | 解密基准 |
| typeDefinitionsOffset | `0x0B4` | `-` | `0x13B75461` | **70** | G | 88902/88902 |
| typeDefinitionsCount | `0x0E0` | `-` | `0x1D064F83` | `/70`−2 = **88902** | — | 守卫 `>=0x46` |
| methodsOffset | `0x16C` | `-` | `0x1CCA7654` | **26** | G | 400/400 |
| methodsCount | `0x188` | `^` | `0x1B58E334` | `/26` = **733442** | — | 守卫 `>=0x1A` |
| **methodPointerIndex** | `0x094` | `^` | `0x4A4C0A71` | 4 | G | 见 3.4 |
| **methodSlot 表** | `0x140` | `-` | `1832561230` | **6** | G | 见 3.4 |
| **methodSlotCount** | `0x1FC` | `-` | `127184164` | `/6` = **12827** | — | 与 invoker 数组长度吻合 |
| parametersOffset | `0x114` | `^` | `0x3E5D33E6` | **8** | G | 参数名 12/12 |
| propertiesOffset | `0x150` | `-` | `0x1C3D5389` | **10** | G | 99.81% |
| fieldsOffset | `0x18C` | `-` | `336578260` | **8** | G | 440172 |
| eventsOffset | `0x1E8` | `^` | `0x100547B1` | **14** | G | 628/628 |
| fieldOffset 表 | `0x204` | `-` | `450622139` | 4 | G | 带 tag |
| interfaces 表 | `0x1C4` | `-` | `1518027399` | **6** | G | 语义验证 |
| nestedTypes 表 | `0x05C` | `-` | `381850355` | 4 | G | 从 `IterNestedTypes` |
| genericContainers | `0x028` | `^` | `0x774A3BA6` | 16 | G | `+12` 取 start |
| genericParameters | `0x170` | `^` | `0x7B3B96A2` | 14 | G | 已解出 |
| **fieldDefaultValues** | — | — | **实测 `0x3D00478`** | **12** | G | 75548 项，fieldIndex 155..440164 严格递增 |
| **常量值 blob** | — | — | **实测 `0xF1754C`** | — | G | AttributeTargets 16/16（见 §6）|
| **parentIndex**（类型）| typeDef `+0x18` | `-` | `0x3D74901F` | — | G | 解出 **Il2CppType 索引**；-1=无父类（§6 附 7）|
| **genericContainerIndex** | typeDef `+0x3E` | `-` | `26230` | — | G | int16；哨兵 `26229`=无泛型（§6 附 9）|
| 容器表 | `0x028` | `^` | `0x774A3BA6` | **16** | G | `+4`=parameterStart(^0x138FD4C7)、`+8`=argc；每索引 key 见附 9 |
| 泛型参数表 | `0x170` | `^` | `0x7B3B96A2` | **14** | G | `+0`=nameIndex(^0x664CCEB9)，减每索引 key |
| **parameterDefaultValues** | `0x104` | `^` | `0x094C42AB` | **12** | G | 25374 项；线性查找（未排序）；见 §6 附 4 |
| **parameterDefaultValuesCount** | `0x09C` | `-` | `259975212` | — | G | 字节数 = **304488** → /12 = 25374 |
| attributesInfo | `0x024` | `-` | `1545100391` | **8** | G | range 无缝平铺，count=1115 |
| attributesInfoCount | `0x198` | `-` | `1137860102` | `/8` = **1115** | — | — |
| attributeTypes | `0x0D8` | `-` | `1927885444` | 4 | G | **带 tag，取 `&0xFFFFFF`** |
| methodSpecs | `0x1D8` | `^` | `0x1F85ABE5` | **12** | G | 见 3.5 |
| genericMethodTable | `0x0C0` | `-` | `1630172749` | **14** | G | 见 3.5 |
| genericMethodTableCount | `0x130` | `-` | `565220529` | `/14` = **560659** | — | — |

### 3.3 typeDefinition（70 字节，17 个字段已定位）

| 偏移 | 字段 | 解码 | 来源 |
|---|---|---|---|
| `0x00` | namespaceIndex | `- 1145778368` | 25 处一致 |
| `0x08` | propertyStart | `- 1995389561` | SetupPropertiesLocked |
| `0x0C` | methodStart | `^ 0x4D8127F2` | SetupMethodsLocked |
| `0x1C` | fieldStart | `^ 0x29010897` | GetFieldName |
| `0x20` | ? | `^ 0x2E8C0EB8` | 索引带 tag 的 4 字节表（语义未定）|
| `0x24` | nameIndex | `- 72511848` | 25 处一致 |
| **`0x28`** | **flags** | **`- 0x4159BB8E`** | 106 值全在 TYPE_ATTRIBUTE 掩码内；SpecialName 0%；visibility 全合法 |
| `0x30` | method_count | `- 0xED3A` | u16 |
| `0x34` | eventStart | `+ 3330` | i16 |
| `0x36` | nestedTypesStart | `+ 6631` | i16，IterNestedTypes |
| `0x38` | field_count | `^ 0x51A8` | u16 |
| **`0x3A`** | **bitfield** | **valuetype `= raw&1`；enumtype `= ~(raw>>1)&1`** | valuetype 全量 88884/88884；enum 用 13 枚举+11 struct 锚点全对 |
| `0x3C` | interfacesStart | `^ 0x43DA` | u16 |
| `0x40` | interfaces_count | `+ 56`（0xC8 编码 0）| u8，IsAssignableFrom 印证 |
| `0x43` | property_count | `^ 0x16` | u8 |
| `0x44` | event_count | `+ 113`（0x8F 编码 0）| u8，8 位回绕 |
| `0x45` | nestedTypesCount | `^ 0xBA`（0xBA 编码 0）| u8 |

### 3.4 方法字段与地址
**方法结构（26 字节）**：`+0x00` nameIndex、`+0x04` parameterStart、
**`+0x08` returnType = `(raw ^ key) ^ 0x3F7BDF39`**（Il2CppType 索引；验收 50000/50000，void 占 50%）、
`+0x0C` declaringType（`key^raw^0x59244785`）、`+0x10` iflags、`+0x14` token、`+0x16` flags、`+0x18` parameterCount。
`key` = 方法名 key = `((860405619*i) ^ 0x73758947) + 1547935323`。

**地址双路径**（文章：`+0x80[index]` / `+0x90[slot]`）：

```
非虚:     ptr  = *(T0+0x60)[ MHY[0x94][methodIndex] ]          // 79765 项，索引表 max=25650
虚/重写:  slot = bsearch(MHY[0x140], methodIndex); ptr = *(T0+0x48)[slot]   // 12827 项
```
验收：`*(T0+0x60)` 前 3000/3000 项落在 `.text`，且 **79765 项后正好紧接表 T1 起始**（边界吻合）；
`slot` 范围恰为 `0..12826` == count−1。

### 3.5 泛型

| 结构 | 位置 | 步长 | 验收 |
|---|---|---|---|
| genericInsts | `*(T1+0x08)` | 16 | `argv[0]` → `0x142E1EA30` = Il2CppType[1] ✓ |
| methodSpecs | `MHY[0x1D8] ^ 0x1F85ABE5` | 12 | `classIndexIndex`/`methodIndexIndex` 索引 genericInsts **20319/0** |
| genericMethodTable | `MHY[0xC0] - 1630172749` | 14 | methodIndex 全 < 733442 |
| **genericInstsCount** | `*(T1+0x50) + 0x9B1B5919` | — | 69146；`*(T1+0x08)` 经 argv→Il2CppType 判定为 **genericInsts** |

---

## 4. 表 T0 / T1 布局（运行时数组总表）

静态构造器 `0x1402F2910` 注册 5 张表：

```
qword_145AD5298 = 0x1422DE370   (T0)
qword_145AD52A0 = 0x142870A88   (T1)
qword_145AD52A8 = 0x142870B28
qword_145AD52B0 = 0x1422DE418
qword_145AD52B8 = 0x1427D4BD0   (MHY 表)
```

| T0 槽位 | 含义 | 验收 |
|---|---|---|
| `+0x48` | 8 字节函数指针数组（按 slot）| 12827 项，= methodSlotCount |
| `+0x60` | 8 字节函数指针数组（按指针索引）| 79765 项，尾接 T1 |

| T1 槽位 | 含义 | 验收 |
|---|---|---|
| `+0x08` | genericInsts（16B `{argc, pad, argv}`）| argv → Il2CppType ✓ |
| `+0x48` | Il2CppType 数组（16B，type@+0x0A）| 683574 项，CLASS/VALUETYPE max klassIndex = 88901 |
| `+0x50` | **genericInstsCount** 的混淆值 | `+0x9B1B5919` = 69146 |
| `+0x54` | typesCount 的混淆值 | `^0x6622B34E` = 683574 |
| `+0x58` | uint16 表 | — |

---

## 5. 仍未完成（诚实清单）

| # | 项 | 状态 |
|---|---|---|
| 1 | ~~类型 `parentIndex`~~ | ✅ **已解决**：typeDef **+0x18**，解码 `raw - 0x3D74901F` → **Il2CppType 索引**（-1=无父类）。**47780 个类型已出基类** |
| 2 | **类型 `declaringTypeIndex`** | ❌ 未定位（嵌套类前缀因此缺失）|
| 3 | ~~类型 `genericContainerIndex`~~ | ✅ **已解决**：typeDef **+0x3E**（int16），解码 `raw - 26230`，哨兵 26229=无泛型。**1852 个类型已出 `<T>`** |
| 4 | `genericClasses` 数组本体 | ❌ 只找到 count（69146），数组未定位 |
| 5 | ~~`fieldDefaultValues` / `fieldAndParameterDefaultValueData`~~ | ✅ **已解决**（见 §3.2 与 §6）|
| 6 | ~~`parameterDefaultValues`~~ | ✅ **已解决**（槽位 `0x104`^`0x094C42AB`；count 槽位 `0x9C`；线性查找）|
| 7 | `customAttributeGenerators` | ❌ 旧地址实测是函数尾部。**本轮查明：CodeRegistration 在文件镜像里不存在（运行时构造）** → 静态拿不到 → 属性**值**输出不了。详见 §6 附 5 |
| 8 | 3 个 helper：`String::NewLen`/`typeof`/`bool` | ❌ 未定位，**且从未验证旧值是否失效**（线索：`sub_1404B6A50`）|
| 9 | `typeDef +0x20` 语义 | 🟡 **已定性一半**：它是 **`fieldOffset` 表的每类型索引基** —— 反编译 `sub_140512DB0` 里 `fieldOffset[ (typeData+0x20 ^ 0x2E8C0EB8) + k ]`（k=类型内字段序号）。所以 fieldOffset **不是**按 `fieldStart` 索引。但"类型内偏移非递减"实测仅 ~57% → 尚不能当结构判据 |
| 10 | `methodSpecsCount` | 🟡 用实测 **610109**（表里无此计数；安全下界 563653）|
| 11 | 槽位 `0x030`/`0x0A4`/`0x1F8`/`0x174` | ⚠️ 未定性/已废弃，代码里已逐行标注「❌ 读错表」|
| 12 | ~~dump 实跑~~ | ✅ **已跑通**：`exit=0`，`dump.cs` **174.6 MB**，耗时 **1.4s**；详见 §6 附 6（共 13 个修复）|
| 16 | ~~事件输出~~ | ✅ **已解决**：结构体字段顺序反了（`typeIndex` 在 **+0**，解码 `key ^ (raw - 452544412)`；`nameIndex` 在 +4）→ **628/628 全出，全部带 add/remove 名** |
| 17 | ~~属性类型 + 访问器名~~ | ✅ **已解决**：结构体 `get/set` 写反（权威 `get@+6`、`set@+8`，setter 常数 **23324** 而非 23304）。且 `methods[index]=…` 原本在 `#if 0` 里 → `methods` **永远是空的**。修后 **115427/115596 (99.85%)** 有访问器名 |
| 18 | ~~参数默认值输出~~ | ✅ **已解决**：调用点在 `#if 0` 里未接线；已接。同时把 `GetParamDefault`/`GetDefaultValueForField` 从**线性扫描**改成**二分**（全 dump 从 >4s 降到 **1.4s**）|
| 13 | ~~parameters/fields 逐索引 key 的 32 位回绕~~ | ✅ **已解决**：`paramKey`/`fieldKey` 必须 **64 位不回绕**（`41617*pi`、`34782*fi` 会超 2³²）。修后 `parameters[].typeIndex` 由 4.81% → **100%**、`fields[].typeIndex` 由 123483/440172 → **440172/440172** |
| 14 | parameters 表真实长度 | ✅ **548400**（= 全部 733442 个方法的参数数之和，与 pDV 最大键 548362 吻合）。此前按「到文件尾」估的 2915543 是错的 |
| 15 | `attributesInfo` 的 `token`(+4) 重映射 | ❌ 非标准 ECMA token（高字节 1..0x54、低 24 位单调）；不解开则**属性名字**也挂不回成员（§6 附 5）|
| 21 | ~~`genericClassRangeCount` 的判据~~ | ✅ **已解决**：也是**公式** —— `*(u32*)(T0+0x80) ^ 0x4E013BBD = 13671`。消费者是 `RuntimeInit` 的泛型注册循环（`init_534B80.c:2064`）。**`version.json` 的 `measuredCounts` 现已整块删除**（另两个改成运行时从数据推导）|
| 20 | 字符串常量默认值**截断**（中文/韩文少 1 字节）| 🟡 仅 **29 行**（3 个方法 + 26 个字段），如 `const string CJKYearSuff = "年"`。字符串常量路径的长度问题 |
| 19 | ~~嵌套类前缀 `Outer.Inner`~~ | ✅ **已解决**：用 `nestedTypes` 表反推「子→父」映射（绕开未定位的 `declaringTypeIndex`）。已验收：25481 表项铺满整表、**25980/25981 个嵌套类型都出了前缀**，且命名空间继承最外层父类 |
| 22 | ~~自动重定位表常量（换版本工具链）~~ | ✅ **`tools/relocate.py` 已能自动定位 5 张表 + 1 个 blob**（`typeDefinitions` / `nestedTypesTable` / `interfacesTable` / `fieldDefaultValues` / `methodPointerIndex` + `fieldAndParameterDefaultValueData`），全部**结构自证**、3~4 秒。详见 `docs/UPDATE.md` §8.5/§8.6 |

## 6. `parentIndex` 的失败记录（避免重复）

| 尝试 | 结果 |
|---|---|
| 偏移 0..0x46 × 宽度 1/2/4 × 运算 {`-`,`^`}，用 `Int32(251)→ValueType(405)` 定 K，再用 `ValueType(405)→Object(371)` 与 `Enum(204)→ValueType(405)` 验证 | **零命中** |
| 用 `Object(371)→哨兵` 定 K 后再验链 | 零命中 |
| 4 个类型名唯一性核对（Int32/ValueType/Enum/Object 各出现 1 次）| 确认索引无误，测试有效 |

**结论**：`parentIndex` **不是** typeDefinition 里常数-K 解码的索引字段（其它类型字段 name/ns/flags 都是常数）。
要么用逐索引 key，要么不在 typeDefinition 里（`GIMeta_SetupTypeInfoLocked` 确实只读 `+60`/`+32`）。

### 2026-10-25：7.0 `parentIndex` 重新验证成功

上面“7.0 穷举零命中”的结论是针对**旧锚点/旧布局**的；按附录 7 的正确方法重新做：

```text
parentIndex 存的是 Il2CppType 索引
枚举 parent -> System.Enum 的 Il2CppType
结构体 parent -> System.ValueType 的 Il2CppType
```

对 7.0 的所有候选偏移/宽度/op/key 重扫后，唯一同时满足：

```text
枚举  7965/7965
结构体 4702/4702
```

的组合是：

```text
typeDef +0x0C
raw ^ 0x4339F98A
```

验证：

```text
NEDGCCFMKBC -> MoleMole.GlobalManager
GlobalManager -> MoleMole.BaseManager
TimerManager -> MoleMole.GlobalManager
```

因此 7.0 不再使用 `+0x1C - 0x6748C2A3`。`docs/UPDATE.md` 的
§15.4d 已同步修正；`version/7.0/version.json` 的 `parentIndex`、
`structOffsets`/`typeDefOffsets` 和 `decodeExpr` 也已改为上值。

### 附 2：`fieldDefaultValues` / 常量值 blob 的**成功**记录（两种可复用方法）

**方法 ① 结构 + 已知计数锚点**
- 文章给结构：`Il2CppFieldDefaultValue` = 12 字节 `{fieldIndex, dataIndex, typeIndex}`，**按 fieldIndex 排序**
- 我们已知**字段总数 440172**（fields 表已验证）
- 全 `.dat` 向量化扫「12 字节步长 + 第 1 个 dword 严格递增 + < 440172」→ `meta 0x3D00478`，75548 项
- 注意：起点需**向前回溯**（扫描的段起点可能偏后 0x210 字节）

**方法 ② 确定性语义值做签名（最强）**
- `AttributeTargets` 是 `[Flags]` 枚举，值确定：`Field=256 Event=512 Interface=1024 ... All=32767`
- 把这些值的 4 字节 LE 序列拼成 32 字节签名 → 全 `.dat` **唯一命中** → blob = `meta 0xF1754C`
- 再用该类型 16 个字段反验证 → **全对**
- 三重佐证：`DayOfWeek` 解出 `0,1,2,3,4,5`；`KeyCode` 解出小整数；`typeIndex` 大量 = 70 = `Il2CppType[70]` = `Int32`

### 附 3：`parameterDefaultValues` 的失败记录

| 尝试 | 结果 |
|---|---|
| 12 字节 + `parameterIndex` 严格递增且 < 参数总数 | 只命中 fieldDefaultValues 区 + 2 个不合法候选 |
| 12 字节 + 三字段全在合法范围（含 dataIndex 指向 blob） | 5 个候选，逐一验证**全是噪声** |
| 查 `fieldDefaultValues` 结束处（`meta 0x3DDD9C8`）紧后面 | 是大小交替的数据，非 12 字节排序数组 |

**结论**：本版本的 `parameterDefaultValues` **不满足**「12 字节 + 按 parameterIndex 排序」假设。
下一步应走文章的路：找 `GetParameterDefaultValue`（经 `GetDefaultParameterValueObject` 到达）的读取点。

### 附 4：`parameterDefaultValues` 的**成功**记录（附 3 的反例被推翻）

**附 3 的失败原因**：我假设该数组「按 parameterIndex 排序」——**本版本是线性查找，并未排序**。
（`GetDefaultParameterValueObject` 里 `while (v != *v8) { v8 += 3; ... }` 就是线性扫描。）

**最终定案（全部来自读取点，非推测）**

读取函数：**`GetDefaultParameterValueObject` @ `0x140529DC0`**（944 字节）。

```c
v8 = s_GlobalMetadataHeader + (*(int*)(MHY + 260) ^ 0x94C42AB);      // 0x104 → 基址
v9 = &v8[3 * ((*(DWORD*)(MHY + 156) - 259975212) / 0xCuLL)];         // 0x9C  → 字节数/12
while (v7 != *v8) { v8 += 3; if (v8 >= v9) return 0; }               // 线性查找，键在 +0
v10 = (int)v8[2];   // +8 → *(T1+0x48) + 16*idx  => typeIndex
v12 = (int)v8[1];   // +4 → + (MHY[0x0A0]^0x3F525210) + base => dataIndex
if (v10 == -1) ...;  if (v12 == -1) { *a3 = 1; return 0; }            // -1 哨兵
```

| 项 | 值 |
|---|---|
| **结构** | `{parameterIndex@0, dataIndex@4, typeIndex@8}`，12 字节 |
| **offset** | `MHY[0x104] ^ 0x094C42AB` = `0x37274C0` |
| **count** | `(MHY[0x9C] - 259975212) / 12` = **25374** |
| 数据 blob | 与 fieldDefaultValues **共用** `MHY[0x0A0] ^ 0x3F525210`（`0xF1754C`）|
| `typeIndex` | 走 `*(T1+0x48) + 16*idx`（Il2CppType 索引）|

**全量验证（25374/25374）**：`parameterIndex` 全部 < 参数总数；`typeIndex` 全部 < 683574；
`dataIndex` 61% 落在 blob 内、其余**恰为 -1**（正是文章说的「无默认值」哨兵）。
抽样解码：`Int32` 型参数解出 `0`、`16` 等合理常量。

**三重交叉验证（全部数学上严密）**

1. **pDV 键 = 全局参数索引**：把全部 733442 个方法的参数区间 `[paramStart(m), paramStart(m)+paramCount(m))` 建索引，
   25374 个 pDV 键**全部**落在某个区间内，**0 个例外**。
2. **parameters 表长度 = 548400**（各方法参数数之和）；pDV 最大键 548362 < 548400 ✓。
3. **逐索引 key 解码 100% 合法**：`paramTypeIndex` 解出的类型索引 25374/25374 全 < 683574。

**顺带修掉两个真 bug（见 §9）**：`paramKey`/`fieldKey` 原写法用 32 位乘法会回绕 ——
`41617*paramIndex` 在 `paramIndex≈73891` 处、`34782*fieldIndex` 在 `fieldIndex≈123482` 处超过 2³²。
回绕会让**这些索引之后的参数名/类型、字段名/类型全部算错**。改成 64 位不回绕后合法率变 100%。

**⚠️ 与文章 6.7 版的差异（重要）**：文章给的是 `{typeIndex, parameterIndex, dataIndex}`，
本版本实测是 `{parameterIndex, dataIndex, typeIndex}`（与 fieldDefaultValues 同序）。
**照抄字段顺序会全错**，必须按读取点确定。

### 附 5：自定义属性链（P0）的**阶段结论**

**✅ 已确认（可安全使用）**

| 项 | 结论 |
|---|---|
| `attributesInfo` | `MHY[0x24] - 1545100391` = header `0xF15274`，**1115 项 × 8 字节** |
| 布局 | `{start@0, token@4}`；**`start` 严格单调**（109..88662）|
| **count** | **本版本没有独立的 count 字段** —— 是 **CSR 式隐含**：`count_i = start_{i+1} - start_i`。证据：`delta≥3` 的项在 `attributeTypes` 里覆盖的是**连续类型索引**（如 `0xc089a1a/1b/1c`）|
| `attributeTypes` | `MHY[0xD8] - 1927885444` = header `0x36BCDB0`，4 字节/项，**`&0xFFFFFF` 才是 Il2CppType 索引**（高字节是 tag：8 / 12）|
| 覆盖量 | 88553 个属性类型项 |

**❌ 卡住的两点**

1. **`token`(+4) 被重映射**，不是标准 ECMA token：高字节取值 1..0x54（非文章的 `02/04/06/08/14/17/20`），
   且低 24 位 **单调递增**（1,6,16,29,45,61,83,102,142,…）—— 不符合「按 kind 重置的 RID」。
   没有它就无法把属性挂回成员（连**名字**都输出不了）。
2. **`s_Il2CppCodeRegistration` 在文件镜像里不存在**。三种搜法全部 0 命中：
   - 全镜像搜「指向与候选数组等长的 `il2cpp` 指针数组」的指针
   - 搜 `attributesInfo`/`attributeTypes` 密钥立即数（`0x5C185C67`/`0x72E93284`/6.7 的 `0x6582BCC1`）
   - 枚举 `T0`/`T1` 全部指针字段（只有方法指针 79765、invoker 12827、genericInst 13671 等已知项）
   → 与 6.7 的关键差异：**本版本 CodeRegistration 是运行时构造的**，静态读不到 →
   `customAttributeGenerators`（属性**值**）静态不可得。

**可行的下一步**：先用 `attributeTypes` + 隐含 count 输出属性**名字**，前提是解开 `token` 重映射
（思路：拿一个必定带属性的已知成员，反推映射；或找读 `attributesInfo` 的那个函数看它怎么算 token）。

### 附 6：首次实跑 `dump.cs`（本轮）—— 跑通 + 修掉的 9 个 bug

**结果**：`./gi-dump $(pwd)` → `exit=0`，`dump.cs` **171 MB / 4,533,478 行**；`stringliteral.json` = `[]`（本版本无字面量条目表，预期）。

| # | bug | 现象 | 根因 |
|---|---|---|---|
| 1 | `readFile` 静默崩溃 | `std::length_error` | 文件打不开时 `tellg()` = -1 被当 size_t |
| 2 | `string_Literal()` | SIGSEGV | 遍历**本版本不存在**的字面量条目表（offset/length 打包进 nameIndex）→ 指针落在元数据头上 |
| 3 | `Il2CppImageDefinition.nameIndex` | 图像名乱码 | 偏移写成 0x24，实为 **0x20** |
| 4 | `ImageIndexKey` | 名字正确但**带垃圾尾巴** | `667674736u * …` 32 位回绕；已验收的 Python 用精确整数 → offset 对、**length 错** |
| 5 | `typeInterfacesCount` / `typeEventCount` | 野指针 SIGSEGV | `+N` 必须 **8 位截断**（`0xC8+56=256→0`），返回 uint32 就变 256 |
| 6 | `GetIl2CppTypeFromIndex` | SIGSEGV | `*(T1+0x48)` 是**镜像 VA**，当宿主指针解引用 → 新增 `s_Il2CppTypes` |
| 7 | PTR/SZARRAY/ARRAY 分支 | 字段类型乱 | 硬编码 `0x1429FB1E0` 是**旧版本** Il2CppType 基址；本版本是 `*(T1+0x48)=0x142E1EA20` |
| 8 | VA / 宿主指针混用 | **12423** 个字段类型只剩 `[]` | 算索引要减**镜像 VA**（`s_Il2CppTypesVA`），不能减宿主指针 → 修后降到 **29** |
| 9 | 属性/事件索引 | 越界 | 加边界保护（`methods[...]` 越界时用占位）|
| 10 | `Il2CppEventDefinition` | 事件全丢（628→0）| 字段顺序写反：权威是 `typeIndex@+0`（`key^(raw-452544412)`）、`nameIndex@+4`（`sub_140514CF0`）|
| 11 | `Il2CppPropertyDefinition` | 属性类型/访问器全空 | `get@+6`/`set@+8` 写反，且 setter 常数应为 **23324**（`sub_1405151D0`）|
| 12 | `methods[index] = …` | 访问器名全空 | 该赋值在 `#if 0`（旧版遗留）里，而活动路径在它之前就 `continue` 了 → `methods` **永远为空** |
| 13 | `GetParamDefault` / `GetDefaultValueForField` | 慢 + 未接线 | 调用点在 `#if 0`；且都是 O(n²) 线性扫描 → 改二分 |
| 14 | 嵌套类前缀 | `Outer.Inner` 缺失 | `declaringTypeIndex` 未定位。**替代方案**：`nestedTypes` 表（`MHY[0x05C]-381850355`，步长 4；`+0x36 +6631` / `+0x45 ^0xBA`）建「子→父」映射 → 递归拼前缀；命名空间为空时继承最外层父类（`sub_14051D5D0 GIMeta_IterNestedTypes` 就是读这张表）|

**修后 dump 质量**：类型 88902 ✓、方法 732894、字段 439974、属性 115596（**99.85% 带完整类型与访问器名**）、事件 **628/628 全出**、字段常量值 74629、**参数默认值 17601**。
**仍缺**：基类（`parentIndex`）、自定义属性、泛型类型名（`?<`）、类泛型参数、嵌套类前缀。|

### 附 7：`parentIndex`（基类）的**成功**记录 —— 以及之前穷举失败的真正原因

**旧的失败结论（已推翻）**：「已穷举 偏移×宽度×运算，用 Int32(251)→ValueType(405)→Object(371) 链锚定，零命中 → 不是常数-K 字段」。

**真正的错误**：锚点用了 **typeDefinition 索引**（204/405/371），但 `parentIndex` 存的是 **Il2CppType 索引**！目标值错了，穷举必然全败。

**正确锚点**（来自 dump.cs 里每个类型的真实索引）

```
所有枚举  -> parent 必须是 System.Enum      -> Il2CppType 索引 401709（klassIndex=204）
所有结构体 -> parent 必须是 System.ValueType -> Il2CppType 索引 425583（klassIndex=405）
```

再要求「枚举原始值恒定 + 结构体原始值恒定 + 存在单一 op/K 同时映射到这两个目标」→ 直接定出：

```
raw32@ +0x18 - 0x3D74901F
  枚举：1031450956 - 0x3D74901F = 401709
  结构体：1031474830 - 0x3D74901F = 425583
```

**验收（真实继承链）**

| 类型 | 解出的基类 |
|---|---|
| `UnityEngine.MonoBehaviour` | `UnityEngine.Behaviour` |
| `System.IO.FileStream` | `System.IO.Stream` |
| `System.ArgumentException` | `System.SystemException` |
| `System.String` / `System.Exception` | `System.Object` |
| `UnityEngine.Vector3` / `System.Int32` | `System.ValueType` |
| `System.Environment.SpecialFolder` | `System.Enum` |
| `System.Object` | `-1`（无父类哨兵）|

**输出**（照抄 6.7 版逻辑，只换常量）：`public class MonoBehaviour: Behaviour`。
沿用原逻辑的 `!valuetype && !enumtype` 与 `klassIndex != 405/204` 守卫（结构体/枚举不显示基类）。
全量：**47780 / 88902** 个类型带基类（其余是接口、Object/ValueType/Enum 本身等）。

### 附 8：【重要】非泛型方法 RVA 一直被**诱饵表**污染（已修）

**症状**（用户发现）：`dump.cs` 里 718552 条方法 RVA **只有 16217 个不同值**，其中单一地址 `0x1402F2B00`
被 **216261** 个方法共用；而**泛型实例**的 RVA（`|-RVA:` 行）是真的。

**根因**：把 `*(T0+0x60)` 当成了方法地址表。其实——**文章原文**（§methodPointer）：

> "…the method is looked up in the methodIndex -> slot array with class flag 0x40, if found …
>  the **+0x90[slot]** variant is taken (for override/virtual), otherwise **+0x80[index]** (for the rest)"

> `const auto* genericMethodPointers = exe.data() + pe->va_to_offset(*(uint64_t*)(s_Il2CppCodeRegistration + 0x60));`

即 **`*(T0+0x60)` == `genericMethodPointers`**（文章 CR+0x60），**只服务泛型实例**；
非泛型方法地址来自 **按 methodIndex 直接索引**的那张表（文章 `+0x80[index]`）。
本版本 `sub_140514630` 里逐字对应：`v16[0] = *(*(T0+0x88) + 8*methodIndex)`。

| | 修前 | 修后 |
|---|---|---|
| 方法 RVA 行 | 718552 | 711021 |
| **不同地址数** | **16217** | **710507** |
| 单一地址最多共用 | **216261** | 74（正常共享）|
| 落在 `il2cpp` 段比例 | — | **99.6%** |

**修法**：`methodPointer(m) = *(*(T0+0x88) + 8*m)`（虚/重写仍走 `*(T0+0x48)[slot]`，不变）。
旧的 ptrIndex 路径隔离到 `#if 0` 保留。

> 教训：`*(T0+0x60)` 有 79765 项且**全部落在 `.text`**，看着非常像方法地址表 —— 但它是泛型方法指针表。
> 两表混用不会崩，只会**静默产出垃圾**（RVA 大量重复）。必须用**「不同值个数」**这种统计量才能发现。

### 附 9：类泛型参数（`genericContainerIndex`）的**成功**记录

**锚点（本节关键）**：泛型类型的**名字里自带参数个数** —— `List`1`、`Dictionary`2`、`Action`3`。
所以可以要求「解出的容器 argc **必须等于**名字里的 N」来定案，不需要猜。

**走了弯路**：先试 `typeDef +0x20 ^ 0x2E8C0EB8`（那个之前标为「语义未定」的字段），
结果只有 **152/711** 的 argc 对得上 —— 比例远高于随机，但它**不是**容器索引。
（教训：部分命中 ≠ 命中，必须要求接近 100%。）

**权威来源**：在反编译里搜容器表 key `0x774A3BA6`，4 个函数命中；其中 **`sub_140511DB0`**
读的是 **typeDefinition**（`70*idx + typeDefinitionsOffset`）：

```c
v9 = (int16_t)(*(WORD*)(typeDef + 62) - 26230);   // 62 = 0x3E  ← 就是它
if (*(WORD*)(typeDef + 62) == 26229) v9 = 0;      // 26229 = 哨兵 = 无泛型
v99 = 容器表 + 16 * v9;
```

**完整链路（本版本常量，全部来自反编译）**

```
cIdx  = (int16)(raw16@typeDef+0x3E) - 26230          // 26229 -> 无泛型
ckey  = (1714760523 * ((1015151837 * ((10661*cIdx + 1371718001) ^ 0x146D2C3D)) ^ 0x5D7F95E0)) >> 19
argc  = raw32@(容器表+16*cIdx + 8) - ckey - 1053517166
pStart= (raw32@(容器表+16*cIdx + 4) ^ 0x138FD4C7) - ckey
pkey  = (((1845531077 * ((12124*p + 1969070457) ^ 0x423B2C8D)) >> 10) + 1212570291) ^ 0x62A3A8F4
name  = DecryptString( (raw32@(泛型参数表+14*p) ^ 0x664CCEB9) - pkey )
```

**验收（参数名全对）**

| 类型 | argc | 解出的参数名 |
|---|---|---|
| `List`1` | 1 | `T` |
| `Dictionary`2` | 2 | `TKey, TValue` |
| `ValueTuple`2` | 2 | `T1, T2` |
| `Action`3` | 3 | `T1, T2, T3` |
| `Nullable`1` | 1 | `T` |

全量：711 个泛型类型里 **702 个 argc==N**；余 9 个是 Roslyn 生成的闭包类型
（`<>c__DisplayClass38_0`1`），其容器含外层参数所以 argc 多 1 —— **符合预期**。

**输出**：`public class Dictionary<TKey, TValue>: ...`、`public interface IEnumerable<T>`。
共 **1852 个类型**带上 `<...>`（多于 711，因为嵌在泛型类里的嵌套类容器含外层参数）。

**仍缺**：泛型参数的 `in`/`out` 变体前缀 —— 14 字节参数项整体加密，`+8` 实测是 ownerIndex
（`sub_14050E030` 里按 `raw16 - 24033 - key` 解），变体 flags 的偏移/解密还没定。

### 附 10：VAR/MVAR 泛型参数名用了**旧版公式** → 2787 个方法签名乱码（已修）

**症状**：`dump.cs` 里出现**乱码行**（无法按 UTF-8 解码）—— 共 **7409 行**：
method 2787、field 237、property 241、other 4144。抽样：

```csharp
public static ? Create(<乱码>)
```

**根因**：`NameFromIl2CppType` 的 **VAR/MVAR 分支**（泛型参数类型 `T1`/`T2`）还在用 **6.7 的公式**：

```cpp
uint32_t nameKey = ((0x65DE21D74280ull * genericParameterIndex) ^ 0x154AA920) + 1912316114;
GetStringFromIndex((parameter->nameIndex ^ 0x2DD1C9C6u) - nameKey);   // ← 旧版常量
```

本版本应用 `genericParameterNameIndex(p)`（见附 9）。**A/B 对照**：

| p | 本版本公式 | 6.7 公式 |
|---|---|---|
| 2 | `T1` | 乱码 |
| 3 | `T2` | 乱码 |
| 6 | `T3` | 乱码 |

**修复效果**：乱码行 7409 → **29**。
剩下 29 行全是**被截断的中文/韩文常量默认值**（如 `internal const string CJKYearSuff = "年"` 少一个字节），
属字符串常量路径的长度问题，**不是结构性问题**。

> 教训：`#if 0` 里保留了旧版实现时，**活路径里可能还残留旧版常量**。换版本时必须把
> 「所有用同一公式族的地方」都列出来一起换 —— 这次 `genericParameterNameIndex` 已在附 9 定位，
> 但这里漏换了一处。

### 附：`flags` / `bitfield` 的**成功**记录（同法）

1. `flags`：`+0x28` 只有 106 个不同值（其余候选 2000+）→ 原始值间只差标志位（String=Object+0x100(SEALED)、Enum=Object+0x80(ABSTRACT)）→ base `0x4159BB8E` 让 IDisposable 解出 `0xA1`（Public|Interface|Abstract）→ 分布合理、**SpecialName 0%**（错 base 时是 54%）
2. `bitfield`：先用 Il2CppType 数组建 `klassIndex → type` 表（0x11=VALUETYPE 12926 个、0x12=CLASS 75958 个）→ 用「VALUETYPE 位全开、CLASS 全关」扫 → `+0x3A` 宽度 1 位 0 无变换命中 → 全量 **88884/88884**；bit1 反相用 13 枚举 + 11 struct 锚点验证

## 7. IDA 已命名（36+ 函数 + 16 数据，便于在这份 .i64 上继续）

**本轮新增（3 个，含读取点定案）**

```
0x1404C6DC0 GIMeta_GetFieldDefaultValue            读 fieldDefaultValues + blob
0x140529DC0 GIMeta_GetDefaultParameterValueObject  读 parameterDefaultValues + blob + count
0x1404C7050 GIMeta_GetGenericMethodParamInfo       泛型方法参数信息（读 genericContainers）
```

**MHY 表槽位注释已写入**：`MHY_Table`(0x1427D4BD0) 处 + `+0x09C/+0x0A0/+0x104/+0x114/+0x13C` 逐项标注公式。

```
0x1402F2910 GIMeta_RegisterTables          0x140534B80 GIMeta_RuntimeInit
0x14050F280 GIMeta_DecryptString           0x14050D9C0 GIMeta_TypeInfoDispatcher
0x14050DCD0 GIMeta_GetMethodByIndex        0x14050E030 GIMeta_GetGenericParameterInfo
0x140511AC0 GIMeta_SetupNestedLocked       0x140512510 GIMeta_IsAssignableFrom
0x140512870 GIMeta_SetupFieldsLocked       0x140512DB0 GIMeta_SetupTypeInfoLocked
0x140514630 GIMeta_SetupMethodsLocked      0x140514A70 GIMeta_GetMethodNameFromIndex
0x140514CF0 GIMeta_SetupEventsLocked       0x1405151D0 GIMeta_SetupPropertiesLocked
0x1405155C0 GIMeta_SetupTypeLocked2        0x140517260 GIMeta_CreateTypeInfo
0x14051CB80 GIMeta_GetFieldName            0x14051CD50 GIMeta_GetTypeInfoByIndex
0x14051D330 GIMeta_GetMethodInfoFromIndex  0x14051D5D0 GIMeta_IterNestedTypes
0x14051D850 GIMeta_GetMethodInfo2          0x140523120 GIMeta_LoadMetadataFile
0x140523400 GIMeta_GetDefaultValue         0x1405238F0 GIMeta_DecodeDefaultValue
0x140524560 GIMeta_GetTypeHandle           0x1405249E0 GIMeta_GetTypeInfoFromIndex2
0x140524E80 GIMeta_GetTypeInfoFromIndex    0x140525160 GIMeta_CmpToken
0x1405251F0 GIMeta_GetClassInfo            0x140528080 GIMeta_GetMethodName2
0x1405281A0 GIMeta_GetMethodNameCached     0x140528560 GIMeta_SetupParameters
0x1405476A0 GIMeta_RegisterTypeRecursive   0x140547A90 GIMeta_RegisterType

MHY_Table  0x1427D4BD0     Table_T1 0x142870A88     Table_T0 0x1422DE370
p_MHY_Table 0x145AD52B8    p_Table_T1 0x145AD52A0   p_Table_T0 0x145AD5298
s_GlobalMetadataHeader 0x145AD52C0   s_StartupMetadataHeader 0x145AD52C8
g_MethodPointerArray 0x1427D4DE0 (*T0+0x60)   g_InvokerArray 0x142237040 (*T0+0x48)
g_GenericInsts 0x142343960 (*T1+0x08)          g_Il2CppTypes 0x142E1EA20 (*T1+0x48)
g_TypeInfoCache 0x145AD52D0   g_MethodInfoCache 0x145AD52D8
g_MethodPointerCache 0x145AD52E0   g_FieldDefaultValueCache 0x145AD52E8
g_ImageCache 0x145AD52F8      g_AssemblyCache 0x145AD5308
g_ImagesCount 0x145AD52F0     g_MetadataAllocator 0x145AD4E90
```

## 8. 复现

```bash
python3 tools/gi_string_decrypt.py       # 解密自检 75/75
make                               # 跨平台构建（GCC/Clang 均通过）

./gi-dump version/7.1                 # 跑 dump（本仓库已放好 gi/Managed 软链）
```

> **换游戏版本时看 [`UPDATE.md`](UPDATE.md)**，并用 [`verify.py`](../verify.py) 验收（28 项）：
> ```bash
> make && ./gi-dump version/7.1 && python3 verify.py
> ```
> 变更说明： —— 版本更新维护手册：
> 三个全局表地址怎么找、槽位+密钥怎么重扫、逐索引 key 怎么抄、每个字段的锚点与验收标准、以及 14 条踩过的坑。

---

## 9. 我走过的弯路（记录以免重复）

| 坑 | 教训 |
|---|---|
| 漏 `+0x210` 基址 | `s_GlobalMetadataHeader = global.data() + 0x210` |
| `imagesCount` 槽位当成基址 | `0x2C` 是字节数，`0x20C` 才是 startup 侧基址 |
| 用 init 的 `if (count >= sizeof)` 守卫定步长 | 这是文章 #6 的正确做法（0xE0→0x46=70，0x188→0x1A=26）|
| 以为同一槽位只有一个密钥 | **同一槽位在不同读取点用不同 op/key** |
| 把 `0x130`/`0x1D8` 猜成 genericInstsCount/fieldDefaultValues | 实为 **genericMethodTableCount / methodSpecs** |
| 把 `0x94` 猜成 returnType | 实为 **方法指针索引表** |
| 把 `*(T1+0x08)` 猜成 genericClasses | 实为 **genericInsts** |
| 检查"argv 是否落在 Il2CppType 数组内" | argv 是**指向 Il2CppType\* 数组的指针**，数组在 `.data` —— 检查方法本身错了 |
| 32 位掩码 vs 字节运算 | `parameterCount` 是**字节 XOR**（`(raw-31)^(key&0xFF)`），按 32 位算会得到 0 个参数 |
| events 连续两轮解不出 | 漏了 key 里的 `+1725894951`；**main.cpp 里本来是对的** |
| 拿 `sub_140514630` 的 key 解元数据 | 它是**运行时**构建器，key 不能用于元数据 |
| 特征字节扫描没先按段过滤 | 5 个命中全在 `.il2cpp`（生成的 C# 代码）|
| 暴力扫/启发式打分代替 IDA 定位 | 已被用户纠正 3 次 |
| 改原逻辑而非只换版本常量 | 已被纠正；曾把 `reg+0x70` 换成自造 accessor |
| 删掉定位不到的实现 | 已被纠正；全部改成 `#if 0` 隔离 |
| python 写入把 CRLF 改成 LF | diff 虚增 3800 行 |
| 把验证代码写进 `#if 0` | 泛型实例那段差点白干，已移入活动路径 |
| 枚举锚点用错位宽（16 位截断）| `flags` 的四字段验证曾误判；C 里 `key ^ *(WORD*)` 是 32 位结果 |
| 把 `CLASS/VALUETYPE` 弄反（`0x11`/`0x12`）| 导致 `bitfield` 扫描锚点全错，改了才对上。il2cpp 里 **VALUETYPE=0x11、CLASS=0x12** |
| 判据对 2 字节是空的 | `0 <= v < 88902` 对 uint16 恒真，换用已知继承链才有效 |
| 把 `.rdata` 的 VA→文件偏移线性外推到 `.text` | `.rdata` 是 `file = VA - 0x140000C00`，`.text` 起点 VA `0x140001000` 对应**文件 `0x400`**（不是 0）。按 `.rdata` 公式外推 `.text` 会差 **0x400**（=256 个 dword），整段字节读取全部错位。**必须按 PE 段表逐段映射** |
| 反查密钥时用「立即数出现在 `.text`」当确认 | 上一个坑导致取到的是错位字节；且 `idc.generate_disasm_line` 按**字节**逐地址反汇编会把多字节指令拆开，所谓"命中"是**巧合字节**。正确做法：capstone 线性反汇编 + `md.skipdata=True` 重同步，再匹配 `mov reg,[base+disp]` 后跟 `op reg,imm` |
| 手写 numpy 索引做步长扫描 | 逆推“键在第几个 dword”时索引运算写错，导致后续**验证的偏移整体偏移 0x210**，把一个真候选判成噪声。教训：扫描输出的偏移要**先用已知表自检**（如 fieldDefaultValues 必须复现 `0x3D00478`）再拿去验证 |
| 逐索引 key 用 32 位乘法（`41617u * i`、`34782u * i`） | Hex-Rays 里是 `(41617 * v18 + 1219887025) ^ 0x19E1D47AuLL`，`uLL` 让整个表达式提升为 **64 位**。写成 `uint32` 会在 `41617*i` 的溢出点（i≈73891）之后整段解错。**看着像「前缀有效」的干净断点，其实全是同一个溢出点**。参数/字段各中一次 |
| 把「数组能排到文件尾」当成数组长度 | parameters 表真实长度 **548400**，我按 `(len-起点)/8` 估成 2915543。**长度要用语义交叉验证**（各方法参数数之和），不能靠「排到文件尾」 |
