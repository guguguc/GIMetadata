# 本样本（gi.exe）字段定位结果

> 全部按 unknowncheats 原文方法取得：先在 `Runtime::Init` 的 calloc 展开串与各读取函数里
> 抄 `(槽位, 运算, 密钥)`，再用守卫/区间平铺/位掩码语义/可读字符串验收。
> **本文数值与 `main.cpp` 的 `decryptHeader()` 完全一致**（曾不一致，已统一）。
>
> 完整进度与未完成清单见 `status.md`。

样本：`gi.exe` · `global-metadata.dat` 82,724,152 B · `startup-metadata.dat` 4,060,776 B
表本体 `MHY 0x1427D4BD0` · `T1 0x142870A88` · `T0 0x1422DE370`
`s_GlobalMetadataHeader=0x145AD52C0`（= `global.data()+0x210`）· `s_StartupMetadataHeader=0x145AD52C8`

---

## 1. 字符串解密（75/75 验收）

```c
entry  = indexKey ^ rawNameIndex ^ 0x772FA51E;
offset = entry & 0xFFFFFF;  length = entry >> 24;
key    = 0x5C2B4E660E2D0544 * ((0x694418957C890198 * offset) ^ 0x55A357D81EF0E48B);
out[k] = enc[k] ^ (key + k * 0x6B0B40C349AE61E5);   // uint64 溢出
```

逐索引 key：

```c
程序集名:   1368137530 * (((667674736*((13029*i)^0x43E2DEB7) + 0xCB287082F0)>>8)) + 1505552983
方法名:     ((860405619*i) ^ 0x73758947) + 1547935323
字段名:     ((1824013172 * ((34782*i) ^ 0x59B1DB19)) >> 16) + 1410079245
属性名:     ((976451930 * ((0x17A5419F8A28*i) >> 9)) >> 12) ^ 0x70BE4B04
事件名:     ((-1599256506*i + 1725894951) ^ 0x1B23E40F)
参数名:     ((1457992407 * ((41617*i + 1219887025) ^ 0x19E1D47A)) >> 21) + 2068375556
```

> ⚠️ **字段名/参数名必须 64 位运算、不得 32 位回绕**
> `34782*i` 在 `i≈123482` 处、`41617*i` 在 `i≈73891` 处超过 2³²。
> 用 `uint32` 乘法会让这些索引之后的名称/类型整段解错（实测字段类型合法率 28% → 100%，参数 4.8% → 100%）。
> 依据：Hex-Rays 里是 `(34782 * i) ^ 0x59B1DB19uLL` / `(41617 * i + 1219887025) ^ 0x19E1D47AuLL`，`uLL` 使整式提升为 64 位。

---

## 2. 数组字段（MHY 表，`0x1427D4BD0`）

| 字段 | 槽位 | 运算 | 密钥 | 步长 | 侧 | 验收 |
|---|---|---|---|---|---|---|
| `imagesCount`(字节) | `0x02C` | `-` | `0x2465B023` | `/0x28`=75 | — | 75/75 |
| `imagesOffset` | `0x20C` | `-` | `0x0ECB27F5` | **40** | **S** | 75/75 |
| `stringLiteralDataOffset` | `0x184` | `+` | `0xBF9D4735` | — | G | 解密基准 |
| `typeDefinitionsOffset` | `0x0B4` | `-` | `0x13B75461` | **70** | G | 88902/88902 名字+命名空间 |
| `typeDefinitionsCount` | `0x0E0` | `-` | `0x1D064F83` | `/70`−2 = **88902** | — | 守卫 `>=0x46` |
| `methodsOffset` | `0x16C` | `-` | `0x1CCA7654` | **26** | G | 400/400 方法名 |
| `methodsCount` | `0x188` | `^` | `0x1B58E334` | `/26` = **733442** | — | 守卫 `>=0x1A`；数组长度吻合 |
| `methodPointerIndex` | `0x094` | `^` | `0x4A4C0A71` | 4 | G | max=25650，-1=无实现 |
| `methodSlot` 表 | `0x140` | `-` | `1832561230` | **6** | G | methodIndex 严格递增 |
| `methodSlotCount` | `0x1FC` | `-` | `127184164` | `/6` = **12827** | — | 与 invoker 数组长度吻合 |
| `parametersOffset` | `0x114` | `^` | `0x3E5D33E6` | **8** | G | 长度 **548400**（各方法参数数之和）；解码后类型 25374/25374 合法 |
| `propertiesOffset` | `0x150` | `-` | `0x1C3D5389` | **10** | G | 115596 条，99.81% |
| `fieldsOffset` | `0x18C` | `-` | `336578260` | **8** | G | 440172 条零空洞零重叠 |
| `eventsOffset` | `0x1E8` | `^` | `0x100547B1` | **14** | G | **628/628** |
| `fieldOffset` 表 | `0x204` | `-` | `450622139` | 4 | G | 带 tag |
| `interfaces` 表 | `0x1C4` | `-` | `1518027399` | **6** | G | 语义验证 |
| `nestedTypes` 表 | `0x05C` | `-` | `381850355` | 4 | G | 从 `IterNestedTypes` |
| `genericContainers` | `0x028` | `^` | `0x774A3BA6` | **16** | G | `+12` 取 start |
| `genericParameters` | `0x170` | `^` | `0x7B3B96A2` | **14** | G | 已解出 |
| **`fieldDefaultValues`** | `0x13C` | `^` | `0x593DE464` | **12** | G | 75548 项，fieldIndex 严格递增 |
| **常量值 blob** | `0x0A0` | `^` | `0x3F525210` | — | G | AttributeTargets 16/16（字段+参数共用）|
| **`parameterDefaultValues`** | `0x104` | `^` | `0x094C42AB` | **12** | G | 25374 项，**线性查找**（未排序）|
| **`parameterDefaultValuesCount`** | `0x09C` | `-` | `259975212` | `/12` = **25374** | — | 读的是字节数 |
| `attributesInfo` | `0x024` | `-` | `1545100391` | **8** | G | range 无缝平铺 |
| `attributesInfoCount` | `0x198` | `-` | `1137860102` | `/8` = **1115** | — | — |
| `attributeTypes` | `0x0D8` | `-` | `1927885444` | 4 | G | **带 tag，取 `&0xFFFFFF`** |
| `methodSpecs` | `0x1D8` | `^` | `0x1F85ABE5` | **12** | G | 见 §4 |
| `genericMethodTable` | `0x0C0` | `-` | `1630172749` | **14** | G | 见 §4 |
| `genericMethodTableCount` | `0x130` | `-` | `565220529` | `/14` = **560659** | — | — |

表 T1 上：

| 字段 | 槽位 | 步长 | 验收 |
|---|---|---|---|
| `typesCount` | `T1+0x54` `^ 0x6622B34E` | — | **683574** |
| **`genericInstsCount`** | `T1+0x50` `+ 0x9B1B5919` | — | **69146**（`*(T1+0x08)` 判定为 genericInsts）|
| `Il2CppType` 数组 | `*(T1+0x48)` | 16 | type@+0x0A；CLASS/VALUETYPE max klassIndex = 88901 |
| `genericInsts` | `*(T1+0x08)` | 16 | `{argc@+0, pad, Il2CppType** argv@+8}`；argv[0] → Il2CppType[1] ✓ |

表 T0 上：

| 字段 | 槽位 | 验收 |
|---|---|---|
| `methodPointer` 数组 | `*(T0+0x60)` | 79765 项，尾接 T1 起始；3000/3000 落在 `.text` |
| `invoker` 数组 | `*(T0+0x48)` | 12827 项 == methodSlotCount；slot 范围 0..12826 |

> **同一槽位在不同读取点会用不同 op/key**，必须按读取点抄，不能按槽位建全局映射。
> 例：slot `0x184` 在 6.7 版是 `fieldAndParameterDefaultValueData`，本版本归 `stringLiteralDataOffset`。

---

## 3. typeDefinition 结构（70 字节，17 个字段已定位）

| 偏移 | 字段 | 解码 |
|---|---|---|
| `+0x00` | namespaceIndex | `- 1145778368` |
| `+0x08` | propertyStart | `- 1995389561` |
| `+0x0C` | methodStart | `^ 0x4D8127F2` |
| `+0x1C` | fieldStart | `^ 0x29010897` |
| `+0x20` | ? | `^ 0x2E8C0EB8`（索引带 tag 的 4 字节表，语义未定）|
| `+0x24` | nameIndex | `- 72511848` |
| **`+0x28`** | **flags** | **`- 0x4159BB8E`**（uint32，TYPE_ATTRIBUTE）|
| `+0x30` | method_count | `- 0xED3A`（u16）|
| `+0x34` | eventStart | `+ 3330`（i16）|
| `+0x36` | nestedTypesStart | `+ 6631`（i16）|
| `+0x38` | field_count | `^ 0x51A8`（u16）|
| **`+0x3A`** | **bitfield** | **valuetype `= raw&1`；enumtype `= ~(raw>>1)&1`**（u8）|
| `+0x3C` | interfacesStart | `^ 0x43DA`（u16）|
| `+0x40` | interfaces_count | `+ 56`（u8；`0xC8` 编码 0）|
| `+0x43` | property_count | `^ 0x16`（u8）|
| `+0x44` | event_count | `+ 113`（u8；`0x8F` 编码 0；8 位回绕）|
| `+0x45` | nestedTypesCount | `^ 0xBA`（u8；`0xBA` 编码 0）|

**缺**：`parentIndex` / `declaringTypeIndex` / `genericContainerIndex`
（`parentIndex` 已穷举扫描零命中，见 `status.md` §6）

---

## 4. 方法结构（26 字节）

| 偏移 | 字段 | 解码 |
|---|---|---|
| `+0x00` | nameIndex | `key ^ (raw - 1524016681)`，key = 方法名 key |
| `+0x04` | parameterStart | `key ^ (raw - 257927898)` |
| **`+0x08`** | **returnType** | **`(raw ^ key) ^ 0x3F7BDF39`**（Il2CppType 索引）|
| `+0x10` | iflags | `key ^ (*(uint16) - 25344)` |
| `+0x16` | flags | `key ^ raw ^ 0x8F60` |
| `+0x18` | parameterCount | `((raw - 31) & 0xFF) ^ (key & 0xFF)` ← **字节 XOR** |
| `+0x0C` | （类索引）| `key ^ raw ^ 0x59244785` |

验收：flags 的 METHOD_ATTRIBUTE 位分布呈教科书形态（access 6/1/3 为主，static 29%、
virtual 31%、abstract 2.5%、pinvoke 0.3%）；iflags 只取 0 / 0x1000。

---

## 5. 各结构步长与字段布局

| 结构 | 数组 | 步长 | 字段 |
|---|---|---|---|
| ImageDefinition | `MHY[0x20C]-0x0ECB27F5`（S）| 40 | nameIndex@+32 |
| FieldDefinition | `MHY[0x18C]-336578260` | **8** | typeIndex@+0（`key^raw^0x2D27D873`）、nameIndex@+4 |
| ParameterDefinition | `MHY[0x114]^0x3E5D33E6` | **8** | typeIndex@+0（`key^raw^0x31BF59F3`）、nameIndex@+4（`key^（raw-1764493660)^0x4CDBD093`）|
| PropertyDefinition | `MHY[0x150]-0x1C3D5389` | **10** | nameIndex@+0、token@+4、get@+6（`key^raw^0xE5A2`）、set@+8（`(raw-23304)^key`）|
| EventDefinition | `MHY[0x1E8]^0x100547B1` | **14** | typeIndex@+0、nameIndex@+4（`key^(raw-1037298109)`）、add@+0xC（`key^raw^0xBEA7`）、remove@+0x8（`key^raw^0xEE66`）、raise@+0xA（`(raw-30703)^key`）|
| InterfaceTable | `MHY[0x1C4]-1518027399` | **6** | Il2CppType 索引@+0 |
| MethodSpec | `MHY[0x1D8]^0x1F85ABE5` | **12** | methodDefinitionIndex@+0、classIndexIndex@+4、methodIndexIndex@+8（索引 genericInsts）|
| GenericMethodTable | `MHY[0xC0]-1630172749` | **14** | genericMethodIndex@+0、methodIndex@+4、invokerIndex@+8 |
| GenericInst | `*(T1+0x08)` | **16** | argc@+0、Il2CppType** argv@+8 |
| GenericContainer | `MHY[0x28]^0x774A3BA6` | 16 | genericParameterStart@+12 |
| GenericParameter | `MHY[0x170]^0x7B3B96A2` | 14 | nameIndex@+0 |
| FieldOffset 表 | `MHY[0x204]-450622139` | 4 | 低 29 位=偏移，`0xE0000000==0xC0000000` 为 static |
| **FieldDefaultValue** | `MHY[0x13C]^0x593DE464` | **12** | `fieldIndex@0`、`dataIndex@4`（相对 blob）、`typeIndex@8` |
| **ParameterDefaultValue** | `MHY[0x104]^0x094C42AB` | **12** | `parameterIndex@0`、`dataIndex@4`（-1=无默认）、`typeIndex@8` — **本版本顺序 ≠ 文章** |
| 常量值 blob | `MHY[0x0A0]^0x3F525210` | 4 | 常量字节，按 dataIndex 访问（字段与参数共用）|
| MethodSlot 表 | `MHY[0x140]-1832561230` | **6** | int32 methodIndex@+0、uint16 slot@+4 |
| AttributesInfo | `MHY[0x024]-1545100391` | **8** | ownerIndex@+0、range@+4（`count=>>24`、`start=&0xFFFFFF`）|
| AttributeTypes | `MHY[0x0D8]-1927885444` | 4 | **带 tag，取 `&0xFFFFFF`** 才是 Il2CppType 索引 |
| NestedTypes | `MHY[0x05C]-381850355` | 4 | 4 字节项 |

---

## 6. 方法地址（双路径，与文章 `+0x80[index]` / `+0x90[slot]` 对应）

```
非虚:     ptr  = *(T0+0x60)[ MHY[0x94][methodIndex] ]
虚/重写:  slot = bsearch(MHY[0x140], methodIndex); ptr = *(T0+0x48)[slot]
```

---

## 7. 复现

```bash
python3 gi_string_decrypt.py      # 解密自检，75/75
```

本文所有数值均由 `gi.exe` 直接读出，与 `main.cpp::decryptHeader()` 一一对应。
