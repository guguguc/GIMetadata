# 逐条溯源 —— `version.json` 的每个常量从哪来

> **本文件由 `tools/provenance.py` 生成**（直接扫 `gi.exe`，**不读** `slots_cache.json`）。

> 「证据」列 = 真正执行 `*(默认对象+位移) op 密钥` 的指令地址；
> 函数名来自 `tools/sigs.json`（54 条结构签名，`GIMeta_*`/`MetaStr_*`）。

> 生成命令：`python3 tools/provenance.py version/7.1/gi.exe`

> ⚠️ 未命中的条目**不是错**：它们通常由**结构自证 / 语义锚 / 反解**得到，
> 而不是从这条指令形态读出来的（见 `UPDATE.md` §5.7）。


## 一、表常量（`tables`，34 项）

| 表 | 槽位 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| imagesCount | `0x02C` | `sub` `0x2465B023` | `0x1405354F0` → **GIMeta_RuntimeInit+0x970** | 代码读取点（代码里用 `add 0xDB9A4FDD` 补码形式） |
| imagesOffset | `0x20C` | `sub` `0xECB27F5` | `0x140535F45` → **GIMeta_RuntimeInit+0x13C5** | 代码读取点（代码里用 `add 0xF134D80B` 补码形式） |
| typeDefinitionsOffset | `0x0B4` | `sub` `0x13B75461` | `0x1404B158D` ✓ `0x1404B8941` → **GIMeta_BuildMethodName+0xE21** | 代码读取点（代码里用 `add 0xEC48AB9F` 补码形式） |
| typeDefinitionsCount | `0x0E0` | `sub` `0x1D064F83` | `0x1404E09DA` → **GIMeta_AllocTypeInfoArray+0x89A** ✓ `0x14050E230` → **GIMeta_GetGenericParameterInfo+0x200** | 代码读取点（代码里用 `add 0xE2F9B07D` 补码形式） |
| methodsOffset | `0x16C` | `sub` `0x1CCA7654` | `0x140514830` → **GIMeta_SetupMethodsLocked+0x200** ✓ `0x140514B97` → **GIMeta_GetMethodNameFromIndex+0x127** | 代码读取点（代码里用 `add 0xE33589AC` 补码形式） |
| methodsCount | `0x188` | `xor` `0x1B58E334` | `0x140535422` → **GIMeta_RuntimeInit+0x8A2** ✓ `0x140536736` → **GIMeta_RuntimeInit+0x1BB6** | 代码读取点 |
| methodPointerIndexOffset | `0x094` | `xor` `0x4A4C0A71` | `0x140514947` → **GIMeta_SetupMethodsLocked+0x317** | 代码读取点 |
| methodSlotTableOffset | `0x140` | `sub` `0x6D3AAA4E` | `0x1405140B4` → **GIMeta_SetupTypeInfoLocked+0x1304** ✓ `0x140514888` → **GIMeta_SetupMethodsLocked+0x258** | 代码读取点（代码里用 `add 0x92C555B2` 补码形式） |
| methodSlotCount | `0x1FC` | `sub` `0x794AD24` | `0x1405140C7` → **GIMeta_SetupTypeInfoLocked+0x1317** ✓ `0x1405148A1` → **GIMeta_SetupMethodsLocked+0x271** | 代码读取点（代码里用 `add 0xF86B52DC` 补码形式） |
| parametersOffset | `0x114` | `xor` `0x3E5D33E6` | `0x14052880E` → **GIMeta_SetupParameters+0x2AE** | 代码读取点 |
| propertiesOffset | `0x150` | `sub` `0x1C3D5389` | `0x1405154D1` → **GIMeta_SetupPropertiesLocked+0x301** | 代码读取点（代码里用 `add 0xE3C2AC77` 补码形式） |
| fieldsOffset | `0x18C` | `sub` `0x140FC6D4` | `0x140512BF9` → **GIMeta_SetupFieldsLocked+0x389** ✓ `0x14051CC21` → **GIMeta_GetFieldName+0xA1** | 代码读取点（代码里用 `add 0xEBF0392C` 补码形式） |
| eventsOffset | `0x1E8` | `xor` `0x100547B1` | `0x14051507E` → **GIMeta_SetupEventsLocked+0x38E** | 代码读取点 |
| fieldOffset | `0x204` | `sub` `0x1ADBF2BB` | `0x1400011D8` ✓ `0x14000132C` | 代码读取点（代码里用 `add 0xE5240D45` 补码形式） |
| interfacesTable | `0x1C4` | `sub` `0x5A7B4287` | `0x140512FE1` → **GIMeta_SetupTypeInfoLocked+0x231** ✓ `0x1405139DB` → **GIMeta_SetupTypeInfoLocked+0xC2B** | 代码读取点（代码里用 `add 0xA584BD79` 补码形式） |
| nestedTypesTable | `0x05C` | `sub` `0x16C292F3` | `0x14051135E` → **GIMeta_FindMethodByNameA+0x5CE** ✓ `0x14051D665` → **GIMeta_IterNestedTypes+0x95** | 代码读取点（代码里用 `add 0xE93D6D0D` 补码形式） |
| genericContainers | `0x028` | `xor` `0x774A3BA6` | `0x1404B7EE6` → **GIMeta_BuildMethodName+0x3C6** ✓ `0x1404C7116` → **GIMeta_GetGenericMethodParamInfo+0xC6** | 代码读取点 |
| genericParameters | `0x170` | `xor` `0x7B3B96A2` | `0x1404B7F56` → **GIMeta_BuildMethodName+0x436** ✓ `0x1404B80F6` → **GIMeta_BuildMethodName+0x5D6** | 代码读取点 |
| fieldDefaultValuesOffset | `0x13C` | `xor` `0x593DE464` | `0x1404C6E76` → **GIMeta_GetFieldDefaultValue+0xB6** ✓ `0x14051A5D5` | 代码读取点 |
| parameterDefaultValuesOffset | `0x104` | `xor` `0x94C42AB` | `0x140529E8F` → **GIMeta_GetDefaultParameterValueObject+0xCF** | 代码读取点 |
| parameterDefaultValuesCount | `0x09C` | `sub` `0xF7EE82C` | `0x140529E13` → **GIMeta_GetDefaultParameterValueObject+0x53** | 代码读取点（代码里用 `add 0xF08117D4` 补码形式） |
| attributesInfoOffset | `0x024` | `sub` `0x5C185C67` | `0x140513CCC` → **GIMeta_SetupTypeInfoLocked+0xF1C** | 代码读取点（代码里用 `add 0xA3E7A399` 补码形式） |
| attributesInfoCount | `0x198` | `sub` `0x43D25E06` | `0x140513CDF` → **GIMeta_SetupTypeInfoLocked+0xF2F** | 代码读取点（代码里用 `add 0xBC2DA1FA` 补码形式） |
| attributeTypesOffset | `0x0D8` | `sub` `0x72E93284` | `0x1404E5DC2` ✓ `0x140513D3D` → **GIMeta_SetupTypeInfoLocked+0xF8D** | 代码读取点（代码里用 `add 0x8D16CD7C` 补码形式） |
| methodSpecs | `0x1D8` | `xor` `0x1F85ABE5` | `0x14000121D` ✓ `0x14000136F` | 代码读取点 |
| genericClassRangeOffset | `0x134` | `xor` `0x558E11EC` | `0x1405367D6` → **GIMeta_RuntimeInit+0x1C56** | 代码读取点 |
| genericTypeArgOffset | `0x180` | `sub` `0x35896A4D` | `0x140536881` → **GIMeta_RuntimeInit+0x1D01** | 代码读取点（代码里用 `add 0xCA7695B3` 补码形式） |
| genericMethodTable | `0x0C0` | `sub` `0x612A764D` | `0x140537B7A` → **GIMeta_RuntimeInit+0x2FFA** ✓ `0x14053A145` | 代码读取点（代码里用 `add 0x9ED589B3` 补码形式） |
| genericMethodTableCount | `0x130` | `sub` `0x21B094B1` | `0x140537B96` ✓ `0x14053A153` | 代码读取点（代码里用 `add 0xDE4F6B4F` 补码形式） |

## 二、结构体字段（`fieldDecode`，8 个结构体）


### `typeDef`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| typeDef.namespaceIndex | `0x00` | `sub` `0x444B30C0` | `0x1404B1493` ✓ `0x1405116C6` → **GIMeta_FindTypeByName2+0x96** | 代码读取点（代码里用 `add 0xBBB4CF40` 补码） |
| typeDef.propertyStart | `0x08` | `sub` `0x76EF3A79` | — | 未命中：可能用了别的读取形态/位宽（需 IDA 复核） |
| typeDef.methodStart | `0x0C` | `xor` `0x4D8127F2` | `0x1405147CA` → **GIMeta_SetupMethodsLocked+0x19A** ✓ `0x140514B13` → **GIMeta_GetMethodNameFromIndex+0xA3** | 代码读取点 |
| typeDef.parentIndex | `0x18` | `sub` `0x3D74901F` | — | **反解**（代码里没有这个立即数，见 §5.7.4） |
| typeDef.fieldStart | `0x1C` | `xor` `0x29010897` | `0x1404B18BF` ✓ `0x1404C6657` | 代码读取点 |
| typeDef.unknown20 | `0x20` | `xor` `0x2E8C0EB8` | `0x1400011BF` ✓ `0x140001314` | 代码读取点 |
| typeDef.nameIndex | `0x24` | `sub` `0x4527168` | `0x140515A14` → **GIMeta_Helper_5158B0+0x164** ✓ `0x140515B06` → **GIMeta_Helper_5158B0+0x256** | 代码读取点（代码里用 `add 0xFBAD8E98` 补码） |
| typeDef.flags | `0x28` | `sub` `0x4159BB8E` | — | 未命中：可能用了别的读取形态/位宽（需 IDA 复核） |
| typeDef.method_count | `0x30` | `sub` `0xED3A` | — | 未命中：可能用了别的读取形态/位宽（需 IDA 复核） |
| typeDef.eventStart | `0x34` | `add` `0xD02` | `0x1404C66F0` ✓ `0x140515032` → **GIMeta_SetupEventsLocked+0x342** | 代码读取点 |
| typeDef.nestedTypesStart | `0x36` | `add` `0x19E7` | `0x140511348` → **GIMeta_FindMethodByNameA+0x5B8** ✓ `0x14051D671` → **GIMeta_IterNestedTypes+0xA1** | 代码读取点 |
| typeDef.field_count | `0x38` | `xor` `0x51A8` | `0x1404C90DA` → **GIMeta_GetGenericMethodParamInfo+0x208A** ✓ `0x1404D2974` | 代码读取点 |
| typeDef.interfacesStart | `0x3C` | `xor` `0x43DA` | `0x140512FCD` → **GIMeta_SetupTypeInfoLocked+0x21D** ✓ `0x1405139C7` → **GIMeta_SetupTypeInfoLocked+0xC17** | 代码读取点 |
| typeDef.genericContainerIndex | `0x3E` | `sub` `0x6676` | `0x140516D02` → **GIMeta_Helper_5158B0+0x1452** ✓ `0x1405466FE` | 代码读取点（代码里用 `add 0xFFFF998A` 补码） |
| typeDef.interfaces_count | `0x40` | `add` `0x38` | `0x1404D34B4` ✓ `0x1404E2A8F` → **GIMeta_AllocTypeInfoArray+0x294F** | 代码读取点 |
| typeDef.property_count | `0x43` | `xor` `0x16` | `0x1404D419D` ✓ `0x1404D4249` | 代码读取点 |
| typeDef.event_count | `0x44` | `add` `0x71` | `0x1404D4EE4` ✓ `0x1404D53D4` | 代码读取点 |
| typeDef.nestedTypesCount | `0x45` | `xor` `0xBA` | `0x1404B13D4` ✓ `0x1404D5E26` | 代码读取点 |

### `method`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| method.nameIndex | `0x00` | `sub` `0x5AD6A629` | `0x140514BD7` → **GIMeta_GetMethodNameFromIndex+0x167** ✓ `0x140514CBB` → **GIMeta_GetMethodNameFromIndex+0x24B** | 代码读取点（代码里用 `add 0xA52959D7` 补码） |
| method.parameterStart | `0x04` | `sub` `0xF5FAADA` | `0x1405287F7` → **GIMeta_SetupParameters+0x297** | 代码读取点（代码里用 `add 0xF0A05526` 补码） |
| method.returnType | `0x08` | `xor` `0x3F7BDF39` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| method.declaringType | `0x0C` | `xor` `0x59244785` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| method.iflags | `0x10` | `sub` `0x6300` | `0x14051498E` → **GIMeta_SetupMethodsLocked+0x35E** | 代码读取点（代码里用 `add 0xFFFF9D00` 补码） |
| method.flags | `0x16` | `xor` `0x8F60` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| method.parameterCount | `0x18` | `sub` `0x1F` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |

### `field`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| field.typeIndex | `0x00` | `xor` `0x2D27D873` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| field.nameIndexBase | `0x04` | `sub` `0x57EF310C` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |

### `property`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| property.nameIndex | `0x00` | `sub` `0x7476F547` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| property.get | `0x06` | `xor` `0xE5A2` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| property.set | `0x08` | `sub` `0x5B1C` | `0x140515563` → **GIMeta_SetupPropertiesLocked+0x393** | 代码读取点（代码里用 `add 0xFFFFA4E4` 补码） |

### `event`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| event.typeIndex | `0x00` | `sub` `0x1AF9479C` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| event.nameIndex | `0x04` | `sub` `0x3DD3E9BD` | `0x140515102` → **GIMeta_SetupEventsLocked+0x412** | 代码读取点（代码里用 `add 0xC22C1643` 补码） |
| event.add | `0x08` | `xor` `0xBEA7` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| event.remove | `0x0A` | `xor` `0xEE66` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| event.raise | `0x0C` | `sub` `0x77EF` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |

### `parameter`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| parameter.typeIndex | `0x00` | `xor` `0x31BF59F3` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |
| parameter.nameIndexBase | `0x04` | `sub` `0x692C095C` | — | 未命中：该结构体的读取点未覆盖（候选排序见 slot_scan --struct，非判定） |

### `genericContainer`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| genericContainer.parameterStart | `0x04` | `xor` `0x138FD4C7` | `0x1404B7F43` → **GIMeta_BuildMethodName+0x423** ✓ `0x1404B80D9` → **GIMeta_BuildMethodName+0x5B9** | 代码读取点 |
| genericContainer.argc | `0x08` | `sub` `0x3ECB656E` | `0x1404C7155` → **GIMeta_GetGenericMethodParamInfo+0x105** | 代码读取点（代码里用 `add 0xC1349A92` 补码） |

### `genericParameter`

| 字段 | 位移 | 运算/密钥 | 代码证据（指令地址 / 函数）| 若未命中：来源 |
|---|---|---|---|---|
| genericParameter.nameIndex | `0x00` | `xor` `0x664CCEB9` | `0x1404D8893` ✓ `0x14050E277` → **GIMeta_GetGenericParameterInfo+0x247** | 代码读取点 |

## 三、非「指令立即数」类常量

| 类别 | 怎么来的 | 自证 |
|---|---|---|
| `keyFormulas.*` | 反编译 `xxxKey(i)` 的函数体（乘/加/移位/xor），**人工抄** | 名字可打印 / `typeIndex` 100% 合法 |
| `structSizes.*` | il2cpp 原始 C 结构体定义 + 反编译步长 | `count = raw/stride` 与实测一致 |
| `*CountFormula` | 找**消费者**（`RuntimeInit` 的循环定界/数组分配） | 算出的计数 == 实测 |
| `addresses.MHY` | 搜 `.rdata` 魔数 `"MHY\0"` | 表头魔数 |
| `addresses.T0/T1` | 反编译 `GIMeta_RuntimeInit` 的全局赋值 | `*(T1+0x48)` type 字节 100% 合法 |
| `stringDecrypt.*` | 文章算法 + `gi_string_decrypt.py` | 程序集名 75/75 |
| `registrationFields.*` | 反编译 `*(T0+K)`/`*(T1+K)` 的用法 | 见 `UPDATE.md` §3.3 |

---

**统计**：目标三元组 111 个，在代码里找到读取点 **51** 个，其余 60 个靠结构自证/公式/反解（属正常）。
