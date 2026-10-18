# IDA 全局变量记录（VA / name / 用途）

> 自动生成：`python3 tools/globals.py <export.json> <exe> <version.json> <out.json>`
> 完整清单见 `version/<ver>/globals.json`；IDA 重命名脚本见 `version/<ver>/rename_globals.py`。

## 1. 关键全局（已确认语义）

| 用途 | 7.0 name | 7.0 VA | 7.1 name | 7.1 VA | 证据 |
|---|---|---|---|---|---|
| MHY 槽位表指针 | `qword_145897158` | `0x145897158` | `qword_145AD52B8` | `0x145AD52B8` | `GM + *(_DWORD*)(MHY + slot)`；导出里的 `mhy_global` |
| GlobalMetadata 基址 (GM) | `qword_145897160` | `0x145897160` | `qword_145AD52C0` | `0x145AD52C0` | 所有 global 表偏移都加在它上面 |
| StartupMetadata 基址 | `qword_145897168` | `0x145897168` | `—` | `—` | `v122 = qword_145897168 + (MHY[0x14]^0x495C7A75)` → images 表 |
| Il2CppType 基址 | `qword_145897140` | `0x145897140` | `qword_145AD52A0` | `0x145AD52A0` | 7.0 `[+0x10]+16*idx`；7.1 `[+0x48]+16*idx` |
| 分配器 / domain | `qword_145896D30` | `0x145896D30` | `qword_145AD4E90` | `0x145AD4E90` | `sub_1404CFDC0(g_Allocator,size)`；7.1 `0x14051289E` |
| 字符串缓冲长度 | `qword_145896B50` | `0x145896B50` | `—` | `—` | MetaStr_* 长度累加 |
| 类型注册表 | `qword_145897A40` | `0x145897A40` | `—` | `—` | FindTypeByName / Helper_5158B0 |
| DecryptString 状态 | `qword_145897028` | `0x145897028` | `—` | `—` | DecryptString 内部 |
| 泛型参数位图 | `qword_145896C98` | `0x145896C98` | `—` | `—` | GetGenericParameterInfo |

> `.data` 的 raw 只覆盖前 1.5MB，这些全局都在 **BSS**（运行时初始化，文件里为 0）；VA 是稳定记录点。

## 7.0 MHY 槽位表（`0x142720238` = `qword_145897158`）

| slot | raw | op | key | decoded | table | confirmed |
|---|---|---|---|---|---|---|
| `0x00C` | `0x730C9F21` | `^` | `0x720EB389` | `0x01022CA8` | `parameterDefaultValuesOffset` | True |
| `0x014` | `0x4960D885` | `^` | `0x495C7A75` | `0x003CA2F0` | `imagesOffset` | True |
| `0x02C` | `0x25C4AC4E` | `^` | `0x25C585C2` | `0x0001298C` | `methodSlotCount` | True |
| `0x030` | `0x497F628B` | `^` | `0x72BDC288` | `0x3BC2A003` | `fieldTableOffset_deprecated` | False |
| `0x048` | `0x5AD082CC` | `^` | `0x5ECCBF54` | `0x041C3D98` | `genericParameters` | True |
| `0x064` | `0x05B693EC` | `+` | `0xFA496C14` | `0x00000000` | `propertiesOffset` | True |
| `0x06C` | `0x76232B5B` | `-` | `0x75C650E3` | `0x005CDA78` | `typeDefinitionsCount` | True |
| `0x080` | `0x6DCABF15` | `^` | `0x69D6A445` | `0x041C1B50` | `attributesInfoOffset` | True |
| `0x094` | `0x2C582762` | `-` | `0x2C46EB4E` | `0x00113C14` | `parametersOffset` | True |
| `0x098` | `0x43652FD0` | `^` | `0x427E10F8` | `0x011B3F28` | `methodsCount` | True |
| `0x0A4` | `0x3B567225` | `-` | `0x0F6CD032` | `0x2BE9A1F3` | `fieldIndexTableOffset_deprecated` | False |
| `0x0A8` | `0x520BEAB4` | `^` | `0x519F5FD4` | `0x0394B560` | `eventsOffset` | True |
| `0x0AC` | `0x126BD0E3` | `^` | `0x120B7FB3` | `0x0060AF50` | `genericMethodTable` | True |
| `0x0B4` | `0x51C66425` | `-` | `0x508E087D` | `0x01385BA8` | `methodSpecs` | likely |
| `0x0BC` | `0x0D0E3C69` | `-` | `0xAB2A6A9` | `0x025B95C0` | `interfacesTable` | True |
| `0x110` | `0x7F53058A` | `-` | `0x7B761D0A` | `0x03DCE880` | `fieldDefaultValuesOffset` | False |
| `0x118` | `0x288987A9` | `^` | `0x2B0F6E21` | `0x0386E988` | `genericContainers` | True |
| `0x120` | `0x4D9A1473` | `^` | `0x4D9E9E50` | `0x00048A23` | `parameterDefaultValuesCount` | True |
| `0x130` | `0x5D21EA66` | `+` | `0xA3B3FC56` | `0x00D5E6BC` | `methodPointerIndexOffset` | True |
| `0x134` | `0x708ADD8B` | `^` | `0x558E11EC` | `0x2504CC67` | `genericClassRangeOffset` | False |
| `0x138` | `0x36954A82` | `^` | `0x350FE3C2` | `0x039AA940` | `fieldOffset` | True |
| `0x168` | `0x1A4D727E` | `-` | `0x1915BEDE` | `0x0137B3A0` | `genericTypeArgOffset` | False |
| `0x16C` | `0x225B1F8C` | `-` | `0x225AFD44` | `0x00002248` | `attributeTypesOffset` | True |
| `0x174` | `0x0937724D` | `^` | `0xD1EDB05` | `0x0429A948` | `stringLiteralDataOffset` | True |
| `0x17C` | `0x6D5B3DB5` | `^` | `0x6EBA4F15` | `0x03E172A0` | `nestedTypesTable` | True |
| `0x18C` | `0x68A67C34` | `^` | `0x6ACCE7D4` | `0x026A9BE0` | `methodsOffset` | True |
| `0x198` | `0x156DD3D5` | `-` | `1137860102` | `0xD19B75CF` | `attributesInfoCount` | False |
| `0x1A0` | `0x4D7FDEEE` | `^` | `0x4CE7B502` | `0x01986BEC` | `typeDefinitionsOffset` | True |
| `0x1A4` | `0x47DBCD9A` | `^` | `0x47DBC620` | `0x00000BBA` | `imagesCount` | True |
| `0x1A8` | `0x4BA41C0E` | `-` | `0x4B9E6046` | `0x0005BBC8` | `genericMethodTableCount` | likely |
| `0x1B0` | `0x22B4ECB8` | `^` | `0x26AB5EF8` | `0x041FB240` | `fieldAndParameterDefaultValueDataOffset` | True |
| `0x1D0` | `0x20E5B7B6` | `+` | `0xE2FD458E` | `0x03E2FD44` | `fieldsOffset` | True |
| `0x1F8` | `0x5B72013D` | `^` | `0x5A7DB1D1` | `0x010FB0EC` | `methodSlotTableOffset` | True |

## 7.1 MHY 槽位表（`0x1427D4BD0` = `qword_145AD52B8`）

| slot | raw | op | key | decoded | table | confirmed |
|---|---|---|---|---|---|---|
| `0x024` | `0x5D09AEDB` | `-` | `1545100391` | `0x00F15274` | `attributesInfoOffset` | ✅ |
| `0x028` | `0x7789427A` | `^` | `0x774A3BA6` | `0x00C379DC` | `genericContainers` | ✅ |
| `0x02C` | `0x2465BBDB` | `-` | `0x2465B023` | `0x00000BB8` | `imagesCount` | ✅ |
| `0x030` | `0x5C9661CD` | `^` | `0x72BDC288` | `0x2E2BA345` | `fieldTableOffset_deprecated` | ✅ |
| `0x05C` | `0x18EA93EB` | `-` | `381850355` | `0x022800F8` | `nestedTypesTable` | ✅ |
| `0x094` | `0x4A88841D` | `^` | `0x4A4C0A71` | `0x00C48E6C` | `methodPointerIndexOffset` | ✅ |
| `0x09C` | `0x0F838D94` | `-` | `259975212` | `0x0004A568` | `parameterDefaultValuesCount` | ✅ |
| `0x0A0` | `0x3FA3275C` | `^` | `0x3F525210` | `0x00F1754C` | `fieldAndParameterDefaultValueDataOffset` | ✅ |
| `0x0A4` | `0x167C6B85` | `-` | `0x0F6CD032` | `0x070F9B53` | `fieldIndexTableOffset_deprecated` | ✅ |
| `0x0B4` | `0x13C075A1` | `-` | `0x13B75461` | `0x00092140` | `typeDefinitionsOffset` | ✅ |
| `0x0C0` | `0x626C4DB1` | `-` | `1630172749` | `0x0141D764` | `genericMethodTable` | ✅ |
| `0x0D8` | `0x76550034` | `-` | `1927885444` | `0x036BCDB0` | `attributeTypesOffset` | ✅ |
| `0x0E0` | `0x1D654533` | `-` | `0x1D064F83` | `0x005EF5B0` | `typeDefinitionsCount` | ✅ |
| `0x104` | `0x0A3E366B` | `^` | `0x094C42AB` | `0x037274C0` | `parameterDefaultValuesOffset` | ✅ |
| `0x114` | `0x3DD76F8A` | `^` | `0x3E5D33E6` | `0x038A5C6C` | `parametersOffset` | ✅ |
| `0x130` | `0x222859BD` | `-` | `565220529` | `0x0077C50C` | `genericMethodTableCount` | ✅ |
| `0x134` | `0x558C29F8` | `^` | `0x558E11EC` | `0x00023814` | `genericClassRangeOffset` | ✅ |
| `0x13C` | `0x5AEDE01C` | `^` | `0x593DE464` | `0x03D00478` | `fieldDefaultValuesOffset` | ✅ |
| `0x140` | `0x6F7D0FAE` | `-` | `1832561230` | `0x02426560` | `methodSlotTableOffset` | ✅ |
| `0x150` | `0x1E674F35` | `-` | `0x1C3D5389` | `0x0229FBAC` | `propertiesOffset` | ✅ |
| `0x16C` | `0x1F0E0858` | `-` | `0x1CCA7654` | `0x02439204` | `methodsOffset` | ✅ |
| `0x170` | `0x78B289D6` | `^` | `0x7B3B96A2` | `0x03891F74` | `genericParameters` | ✅ |
| `0x180` | `0x35896A4D` | `-` | `898198093` | `0x00000000` | `genericTypeArgOffset` | ✅ |
| `0x184` | `0x44A77AB3` | `+` | `0xBF9D4735` | `0x0444C1E8` | `stringLiteralDataOffset` | ✅ |
| `0x188` | `0x1A7A1901` | `^` | `0x1B58E334` | `0x0122FA35` | `methodsCount` | ✅ |
| `0x18C` | `0x149CCE88` | `-` | `336578260` | `0x008D07B4` | `fieldsOffset` | ✅ |
| `0x198` | `0x43D280DE` | `-` | `1137860102` | `0x000022D8` | `attributesInfoCount` | ✅ |
| `0x1C4` | `0x5F50ED8B` | `-` | `1518027399` | `0x04D5AB04` | `interfacesTable` | ✅ |
| `0x1D8` | `0x1E3C4BFD` | `^` | `0x1F85ABE5` | `0x01B9E018` | `methodSpecs` | ✅ |
| `0x1E8` | `0x100DA671` | `^` | `0x100547B1` | `0x0008E1C0` | `eventsOffset` | ✅ |
| `0x1F8` | `0x7A4CE881` | `-` | `0x7A409361` | `0x000C5520` | `interfacesOffset_deprecated` | ✅ |
| `0x1FC` | `0x0795D9C8` | `-` | `127184164` | `0x00012CA4` | `methodSlotCount` | ✅ |
| `0x204` | `0x1BD780EB` | `-` | `450622139` | `0x00FB8E30` | `fieldOffset` | ✅ |
| `0x20C` | `0x0ECD5451` | `-` | `0x0ECB27F5` | `0x00022C5C` | `imagesOffset` | ✅ |

## 4. 完整全局清单

- 7.0：**313** 个符号 → `version/7.0/globals.json`
- 7.1：**29** 个符号（合并/过滤导出，非全量）→ `version/7.1/globals.json`

7.0 引用最多的 20 个：

| name | VA | section | refs | role |
|---|---|---|---|---|
| `qword_145897158` | `0x145897158` | .data | 127 | MHY slot table pointer (mhy_global) |
| `qword_145897160` | `0x145897160` | .data | 102 | GlobalMetadata base (GM) |
| `qword_145897A40` | `0x145897A40` | .data | 96 | type registry (FindTypeByName / Helper_5158B0) |
| `qword_145896D30` | `0x145896D30` | .data | 86 | allocator / domain (first arg of sub_1404CFDC0) |
| `qword_145896B50` | `0x145896B50` | .data | 46 | MetaStr buffer length |
| `qword_1458977E8` | `0x1458977E8` | .data | 36 |  |
| `qword_145897140` | `0x145897140` | .data | 35 | Il2CppType base (array at +0x10) |
| `xmmword_1458958F8` | `0x1458958F8` | .data | 29 |  |
| `qword_145897138` | `0x145897138` | .data | 22 |  |
| `qword_145895090` | `0x145895090` | .data | 22 |  |
| `qword_145896DD0` | `0x145896DD0` | .data | 21 |  |
| `qword_145897028` | `0x145897028` | .data | 20 | DecryptString state |
| `xmmword_145896C38` | `0x145896C38` | .data | 20 |  |
| `qword_145896C98` | `0x145896C98` | .data | 19 | generic-param bit array (GetGenericParameterInfo) |
| `qword_145897148` | `0x145897148` | .data | 18 |  |
| `qword_145896E38` | `0x145896E38` | .data | 18 |  |
| `xmmword_145896ED8` | `0x145896ED8` | .data | 17 |  |
| `xmmword_145896F00` | `0x145896F00` | .data | 16 |  |
| `xmmword_145896DD8` | `0x145896DD8` | .data | 15 |  |
| `qword_145896E98` | `0x145896E98` | .data | 15 |  |

## 5. 换版本时怎么用

1. 导出新版本的 IDA JSON（带 `mhy` / `mhy_global`）。
2. `python3 tools/globals.py <新export.json> <新exe> <version.json> version/<ver>/globals.json`
3. diff 新旧 `mhy_slots`：同一个表名在哪个 slot、op/key 变了，一眼可见。
4. 打开 `.i64`，`File → Script file...` 运行 `version/<ver>/rename_globals.py`。

> 槽位编号会换（`fieldOffset` 7.0=0x138，7.1=0x204；`imagesOffset` 7.0=0x14，7.1=0x20C），按表名对应，不要按 slot 号复用。
