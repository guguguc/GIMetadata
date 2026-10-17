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
python3 verify.py version/<新版本>          # 也可先 make && ./gi-dump version/<新版本>

# 1) 找 3 个全局地址 MHY / T0 / T1 → 填进 version.json 的 addresses
#    反编译静态构造器；MHY 也可直接搜魔数 "MHY\0"      →  §3

# 2) 重扫槽位+密钥（4 种指令形态 + 数据流追踪，几分钟）
python3 tools/slot_scan.py <gi.exe> <Managed/Metadata/global-metadata.dat>
#    → 生成 tools/slots_cache.json

# 3) 自动重定位表常量（秒级；结构自证 + ⓪ slot 提示 + ⑦ 反查）
python3 tools/relocate.py version/<新版本>
#    ④ 结构自证（3 项跨版本可靠）/ ⑤ 对照 / ⑥ slot 提示 / ⑦ 反查
#    ⛔ ⑥ 的「✅ 唯一」**跨版本不可信**（7.0 实测 16/34 全错，见 docs/CROSS70.md）
#       只有 ④ 的「表内部自洽」判据（fDV / methodPointerIndex / blob）跨版本可靠

# 4) 逐索引 key / 结构体字段：到反编译里抄表达式（或用 §8 锚点法反解）
#    → version.json 的 keyFormulas / fieldDecode      →  §5 + §6 + §8

# 5) 构建 + 跑 + 逐项验收
make && ./gi-dump version/<新版本>
python3 verify.py version/<新版本>          # 必须 28/28 PASS
```

**分工（关键）**：

| 步骤 | 谁做 | 输出 |
|---|---|---|
| 全局地址 / 表常量 / key / 字段解码 | **工具 + 人工** | `version.json` |
| 生成 C++ 常量 | `make` 自动 | `src/version.hpp` |
| 验收 | `verify.py` | 28 项 PASS/FAIL |

> **不要手改 `src/version.hpp`**（生成物）。换版本**只改 `version.json`**；
> 只有 §8 那种「字段本身要重新定位」的情况才动 C++（把新 offset/key 填回 JSON 对应字段）。

**做完任何一步都跑一次 `verify.py version/<新版本>`。** 本项目最危险的 bug 都是「不崩、只静默产出垃圾」，
只有统计量能发现（见 §9 陷阱 7 与 10）。

**自动化能覆盖多少**（含 **7.0 跨版本实测**，详见 §8.6 与 `docs/CROSS70.md`）：

- **跨版本真正可靠：3 项**（`fieldDefaultValues` / `methodPointerIndex` / 常量 blob）
  —— 判据是**表内部自洽**，不依赖任何版本常量
- **6 张表 + blob** 在**同版本自测**下可完全独立定位（结构自证值 → ⑦ 反查唯一 slot）
- ⛔ **`slot` 提示不能当跨版本主路径**：7.0 实测 `fieldDefaultValues` 的 slot `0x13C→0xC`、
  `methodPointerIndex` `0x94→0x130`；靠旧 slot 得到的 16/34 个"唯一值"**全部是错的**
- **真正的瓶颈是「候选召回」**：7.0 上 `slot_scan` 的候选里**缺失真密钥**
  → 方向已转向**语义不变量**（累计索引单调）与**无密钥反解**（见 §8.6 五/六）
- **做不到**：内容逐索引混淆 + 无结构指纹的表、以及"结构体内部字段偏移"

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

### 4.1 脚本做的四件事（细节见脚本注释）

1. 按 **PE 段表**逐段做 VA→file offset（**不能拿 `.rdata` 线性外推 `.text`**，陷阱 1）
2. capstone 线性反汇编全 `.text`（**必须 `md.skipdata=True`**，陷阱 2）
3. 匹配下面**四种**「槽位 + 密钥」指令形态 → `(slot, op, key)`
4. 结果写 `tools/slots_cache.json`（`relocate.py` 就在这儿读；已进 `.gitignore`）

**四种形态**（实测都要覆盖，缺一种就会漏报真表）：

```
A) mov reg,[base+slot]  ...  op reg,imm         槽位在前
B) mov reg,imm          ...  op reg,[base+slot]  密钥在前
C) mov reg,[base+slot]  ...  op reg,reg2         寄存器对寄存器
D) op reg,[rip+const]                            密钥在**数据段常量池**（不在 .text 立即数）
```

**必须是数据流追踪，不能用"距离 N 条指令以内"**：

> 实测：密钥常被提到**函数入口**装载，读取点隔了上百条指令 ——
> `mov r15d,0xA584BD79` …（上百条）… `mov ecx,[rcx+0x1c4]` / `add ecx,r15d`。
> 用 8 条窗口会**全部漏掉**。
> 正确做法：寄存器**被写才失效**；`call/ret` 清掉调用者保存寄存器（rax/rcx/rdx/rsi/rdi/r8-r11）；
> 只要没被写就一直有效。

**判定 `disp < 0x300`** 只用于区分"结构体槽位"和"其它内存访问"；`D)` 形态靠 `rip` 目标解析单独处理。

### 4.1b 槽位读取点的**真实长相**（已用 capstone 逐条复核）

这是文章 §3.2 说的"偏移 + 解混淆密钥成对出现"。`typeDefinitionsOffset` 在 7.1 的现场：

```asm
1404B157A  mov   rax, [rip + 0x5623D3F]     ; 元数据基址
1404B1581  mov   rdx, [rip + 0x5623D30]     ; ← 从全局变量读出 MHY 基址
1404B1588  mov   esi, 0xEC48AB9F            ; 密钥装进寄存器（形态 B）
1404B158D  add   esi, dword ptr [rdx + 0xB4]  ; ← **槽位 + 密钥**，结果就是 typeDefsOffset
1404B1593  movsxd rsi, esi
1404B1596  add   rsi, rax                    ; 加上元数据基址 → 绝对偏移
1404B15B5  movsxd rsi, dword ptr [rdx + 0x19C]   ; 紧接着下一个槽位
1404B15BC  xor   rsi, 0x30F4D28E                  ; （= ANALYSIS.md 记的 0x19C ^ 0x30F4D28E）
```

**三个由此推出的自动化要点**（都是踩过坑的）：

| 要点 | 说明 |
|---|---|
| **MHY 基址是从 `.data` 全局读出来的，不能在文件里搜** | 文章判据 1 是 `lea rax, <MHY>` + `mov cs:s_MHYTable, rax`。那个全局在 `.data` 里，**运行时才填**，文件里是未初始化随机值（7.1 实测 `@0x145AD52B8 = 0x68F324628C8E3354`）。所以必须靠**指令形态**去找，不能搜字节。 |
| **函数边界从 PE 异常表取，不要线性反汇编** | `Data Directory[3]`（不是 `.pdata` **段**）给出 1177406 条 `RUNTIME_FUNCTION`，逐函数从入口反汇编。⚠️ 本二进制里 `.pdata` 段（off `0x562D400`）与真正的异常目录（rva `0x19EBDFB0` → off `0x19672FB0`）**不是同一块**，按段读全是垃圾。 |
| **默认不锚定会同时误报和漏报** | 脚本默认把任何 `[base+disp]`（`disp<0x300`）当槽位读。`--anchor` 会先按文章判据 1 定位「存 MHY 地址的全局」，之后**只认基址寄存器确实装着 MHY 的那些访问**。 |

> 本二进制是 **UPX 打包**的（段表里有 `.upx0`，还有个 **320MB 的 `il2cpp` 段**），段布局和常规 PE 不同，做 VA→file offset 时别想当然。

### 4.2 怎么从 4000+ 个候选里认出真表

**不要靠"表长一致"**（实测 435 个去重候选里 432 个都通过长度约束，见 §8.6）。

按这个顺序：

1. **`relocate.py` 先跑** —— 它会做结构自证 + ⓪ slot 提示 + ⑦ 反查，并打印
   `✅ 唯一 / ⚠ 多候选 / ✗ 无候选`（见 §8.5、§8.6）
2. 对**结构可自证**的表（12B 严格递增 / 4B 合法索引 / 70B flags …）→ 用 §8 的锚点
3. 对**内容逐索引混淆**的表 → **反查**：先由别的表推出**值**，再问"哪个 `(slot,op,key)` 解出它"
   （实测 90% 的值只对应唯一三元组）
4. 剩下人工：拿**语义**当判据（如 `MHY[slot] / 26 == methodsCount`）或 IDA 单点确认

**自检**（脚本会打印；换版本后这 3 个值会变，但都必须落在结构化数据上）：

```
MHY[0x13C] ^ 0x593DE464 = 0x3D00478     本版本 fieldDefaultValues
MHY[0x0A0] ^ 0x3F525210 = 0xF1754C      本版本常量值 blob
MHY[0x104] ^ 0x094C42AB = 0x37274C0     本版本 parameterDefaultValues
```

**其它结构快查**（§4.2 第 2 步的展开）：
- 12 字节表 → `{index, dataIndex, typeIndex}`（index 严格递增、typeIndex < typesCount）
- 4 字节表 → 值域（如全 < typeDefCount）；6 字节表 → `+0` 是合法 Il2CppType 索引
- 70 字节表 → flags 只有 ~106 种、nameIndex 解出可打印名字
- **任何表都要有一个语义锚点**，见 §8

---

## §5 常量清单（**全量**）→ 全部映射到 `version.json` 的键

> **换版本 = 改 `version.json` 的值**（`make` 生成 `src/version.hpp`）。
> 下表给出**「JSON 键 → 当前值 → 含义」**，直接照键名改即可。
> JSON 里是**一个键被多处引用**，所以历史上的"同一个常量抄了 7 份、必须同步换"的风险**已经消除**。
> **每个数是怎么找到、怎么复核的 → §5.7（溯源表）**。

### 5.1 字符串解密 → `stringDecrypt`

| `version.json` 键 | 当前值 | 含义 |
|---|---|---|
| `stringDecrypt.entryXor` | `0x772FA51E` | 条目解码：`entry = indexKey ^ raw ^ entryXor` |
| `stringDecrypt.keyMulA` | `0x5C2B4E660E2D0544` | 密钥派生（逐索引）|
| `stringDecrypt.keyMulB` | `0x694418957C890198` | 〃 |
| `stringDecrypt.keySeed` | `0x55A357D81EF0E48B` | 〃 |
| `stringDecrypt.keyStep` | `0x6B0B40C349AE61E5` | 每 8 字节递增 |
| `stringDecrypt.offsetMask` / `.lengthShift` | `0xFFFFFF` / `24` | 条目打包：`offset = idx & mask`、`length = idx >> shift` |

**验收**：`verify.py` 的「程序集名解码 75/75」。
**重定位**：`tools/relocate.py` ③ 用 `AttributeTargets` 签名反推数据块基址；
`tools/gi_string_decrypt.py` 是同一算法的独立实现，可对照。

### 5.2 逐索引 key（8 个）→ `keyFormulas`

| `version.json` 键 | 表达式 | 验收 |
|---|---|---|
| `keyFormulas.methodKey` | `((A*i) ^ xor) + add` | 方法名 + flags 分布合理 |
| `keyFormulas.fieldKey` | `((A*((B*i) ^ xor)) >> shift) + add` | `fields[].typeIndex` 100% 合法 |
| `keyFormulas.propertyKey` | `((A*((B*i) >> shift1)) >> shift2) ^ xor` | 属性名可读 |
| `keyFormulas.eventKey` | `((A*i + add) ^ xor)` | 事件名 628/628 |
| `keyFormulas.paramKey` | `((A*((B*i + add1) ^ xor1)) >> shift) + add2` | `parameters[].typeIndex` 100% 合法 |
| `keyFormulas.imageKey` | `(A*((B*((innerMul*i) ^ innerXor) + innerAdd) >> shift1)) + add` | 程序集名 75/75 |
| `keyFormulas.containerKey` | `(A*((B*((innerMul*c + innerAdd) ^ innerXor)) ^ xor)) >> shift` | `argc` == 名字里的 `N` |
| `keyFormulas.genericParamKey` | `(((A*((innerMul*p + innerAdd) ^ innerXor)) >> shift) + add) ^ xor` | 参数名 = `T`/`T1`/`TKey` |

**换版本就改这些子键**（⚠️ **全部 64 位不回绕** —— 用 32 位乘法会"低 24 位对、高 8 位错"，见陷阱 3）：

| key | 子键 → 值 |
|---|---|
| `methodKey` | `A=860405619` `xor=0x73758947` `add=1547935323` |
| `fieldKey` | `B=34782` `xor=0x59B1DB19` `A=1824013172` `shift=16` `add=1410079245` |
| `propertyKey` | `B=0x17A5419F8A28` `shift1=9` `A=976451930` `shift2=12` `xor=0x70BE4B04` |
| `eventKey` | `A=-1599256506` `add=1725894951` `xor=0x1B23E40F` |
| `paramKey` | `B=41617` `add1=1219887025` `xor1=0x19E1D47A` `A=1457992407` `shift=21` `add2=2068375556` |
| `imageKey` | `B=667674736` `innerMul=13029` `innerXor=0x43E2DEB7` `innerAdd=0xCB287082F0` `shift1=8` `A=1368137530` `add=1505552983` |
| `containerKey` | `B=1015151837` `innerMul=10661` `innerAdd=1371718001` `innerXor=0x146D2C3D` `xor=0x5D7F95E0` `A=1714760523` `shift=19` |
| `genericParamKey` | `B=1845531077` `innerMul=12124` `innerAdd=1969070457` `innerXor=0x423B2C8D` `shift=10` `add=1212570291` `xor=0x62A3A8F4` |

### 5.3 各字段的解码常量 → `fieldDecode`（结构体 → 字段 → `op:key`）

**格式**：`fieldDecode.<结构体>.<字段> = "<op>:<key>"`，`op ∈ {sub, xor, add}`。
解码时**按字段位宽截断**（`+N` 型必须 8/16 位截断，否则越界 —— 见陷阱 6）。

**`typeDef`（70 字节）**

| 偏移 | 字段（JSON 键名）| `op:key` |
|---|---|---|
| `+0x00` | `namespaceIndex` | `sub:1145778368` |
| `+0x08` | `propertyStart` | `sub:1995389561` |
| `+0x0C` | `methodStart` | `xor:0x4D8127F2` |
| `+0x18` | `parentIndex` | `sub:0x3D74901F`（Il2CppType 索引，-1=无父类）|
| `+0x1C` | `fieldStart` | `xor:0x29010897` |
| `+0x20` | `unknown20` | `xor:0x2E8C0EB8`（= `fieldOffset` 表的每类型索引基）|
| `+0x24` | `nameIndex` | `sub:72511848` |
| `+0x28` | `flags` | `sub:0x4159BB8E` |
| `+0x30` | `method_count` | `sub:0xED3A` |
| `+0x34` | `eventStart` | `add:3330` |
| `+0x36` | `nestedTypesStart` | `add:6631` |
| `+0x38` | `field_count` | `xor:0x51A8` |
| `+0x3C` | `interfacesStart` | `xor:0x43DA` |
| `+0x3E` | `genericContainerIndex` | `sub:26230`（哨兵 26229 = 无泛型）|
| `+0x40` | `interfaces_count` | `add:56`（`0xC8` 编码 0）|
| `+0x43` | `property_count` | `xor:0x16` |
| `+0x44` | `event_count` | `add:113`（`0x8F` 编码 0）|
| `+0x45` | `nestedTypesCount` | `xor:0xBA` |

**其它结构体**

| 结构体 | 字段（偏移）| `op:key` |
|---|---|---|
| `method` | `nameIndex(+0)` | `sub:1524016681` |
| `method` | `parameterStart(+4)` | `sub:257927898` |
| `method` | `returnType(+8)` | `xor:0x3F7BDF39` |
| `method` | `declaringType(+0xC)` | `xor:0x59244785` |
| `method` | `iflags(+0x10)` | `sub:25344` |
| `method` | `flags(+0x16)` | `xor:0x8F60` |
| `method` | `parameterCount(+0x18)` | `sub:31`（**字节运算**，见下注）|
| `field` | `typeIndex(+0)` | `xor:0x2D27D873` |
| `field` | `nameIndexBase(+4)` / `nameIndexXor` | `sub:1475293452` / `xor:0x2D027B84` |
| `property` | `nameIndex(+0)` | `sub:1953953095` |
| `property` | `get(+6)` / `set(+8)` | `xor:0xE5A2` / `sub:23324` |
| `event` | `typeIndex(+0)` | `sub:452544412` |
| `event` | `nameIndex(+4)` | `sub:1037298109` |
| `event` | `add(+8)` / `remove(+0xA)` / `raise(+0xC)` | `xor:0xBEA7` / `xor:0xEE66` / `sub:30703` |
| `parameter` | `typeIndex(+0)` | `xor:0x31BF59F3` |
| `parameter` | `nameIndexBase(+4)` / `nameIndexXor` | `sub:1764493660` / `xor:0x4CDBD093` |
| `genericContainer` | `parameterStart(+4)` / `argc(+8)` | `xor:0x138FD4C7` / `sub:1053517166` |
| `genericParameter` | `nameIndex(+0)` | `xor:0x664CCEB9` |

> **两个易错点**：
> - `parameterCount`（method `+0x18`）是**字节**运算：`((raw - 31) & 0xFF) ^ (key & 0xFF)`，不是 16/32 位
> - `field` / `parameter` 的 `nameIndex` 是**两段**：`(raw - nameIndexBase) ^ nameIndexXor`

**计数公式（不在 `fieldDecode`，单独三项；`version.json` 顶层）**

| `version.json` 键 | 表达式 | 本版本值 |
|---|---|---|
| `genericInstsCountFormula` | `*(u32*)(T1+0x50) + 0x9B1B5919` | 69146 |
| `genericClassRangeCountFormula` | `*(u32*)(T0+0x80) ^ 0x4E013BBD` | 13671 |
| `typesCountFormula` | `*(u32*)(T1+0x54) ^ 0x6622B34E` | 683574 |

> 另有 `fieldDefaultValuesCount` / `methodSpecsCount`：**没有公式**，运行时从数据推导
> （见 `src/il2cpp_image.hpp`）—— `version.json` 里**故意不存**这两个数。

### 5.4 槽位表（`version.json` 的 `tables`，共 **34** 项）

每项形如 `{slot, op, key, stride, side, role, …}`。**这才是换版本的主战场**。

- **逐条清单**：`docs/status.md` §3.2（与 `version.json` 逐条对应）
- **能自动重定位的**：先跑 `python3 tools/relocate.py version/<新版本>`
  - **④ 结构自证**（fDV / methodPointerIndex / blob）→ **跨版本可靠**，可直接采用
  - **⑥ slot 提示** → ⛔ **跨版本不可信**（7.0 实测 16/34"唯一"全错）→ 只能当粗筛
  - **⑦ 反查** → 需要先有可靠的值，才能反查回唯一 slot
- 改完用 `verify.py` 交叉核对；`relocate.py` ⑤ 会打印「探测值一致」的表

**`side` 字段**：`global`（`global-metadata.dat` 侧，偏移要 **+0x210**）/ `startup`（另一块数据）。

### 5.5 计数：优先找**公式**，实在没有才实测

本版本 34 张表的计数**全部**有来源，分三类：

| 来源 | 例子 |
|---|---|
| MHY 侧槽位 | `(MHY[0x188] ^ 0x1B58E334) / 26` = methodsCount |
| **T0/T1 侧字段** | `T1+0x50 + 0x9B1B5919` = genericInstsCount；`T0+0x80 ^ 0x4E013BBD` = **genericClassRangeCount** |
| 运行时从**数据**推导 | `fieldDefaultValuesCount`（fieldIndex 严格递增扫到断点）、`methodSpecsCount`（`max(genericMethodTable[].genericMethodIndex)+1`）|

**教训**：先找消费者（`RuntimeInit` 里谁给循环定界、谁给数组分配）—— 那里一定有**公式或推导**，别急着「实测」。
`genericClassRangeCount` 我一开始当它是"只能实测"，结果 `init_534B80.c:2064` 里明摆着 `T0+128 ^ 0x4E013BBD`。

### 5.5b 实测法（**已基本废弃** —— 优先找公式）

本版本已把"实测计数"**全部**换成公式或运行时推导，`version.json` 里的 `measuredCounts` **整块删除**。
历史上做过实测的三个，现在的正确来源：

| 字段 | 旧实测值 | 现在的来源 |
|---|---|---|
| `fieldDefaultValuesCount` | 75548 | 运行时按 `fieldIndex` 严格递增扫到断点（数据推导）|
| `methodSpecsCount` | ~~610109~~ | 运行时 `max(genericMethodTable[].genericMethodIndex)+1` = **563653** |
| `genericClassRangeCount` | 13671 | **公式** `*(u32*)(T0+0x80) ^ 0x4E013BBD` |

**教训**：先找**消费者**（`RuntimeInit` 里谁给循环定界/谁给数组分配）—— 那里一定有**公式或推导**。
`genericClassRangeCount` 当初被我当成"只能实测"，其实 `init_534B80.c:2064` 里明摆着。

### 5.6 三个全局地址（`version.json` 的 `addresses`）

| 键 | 值 | 验收 |
|---|---|---|
| `s_MHYTable` | `0x1427D4BD0` | 开头是 `"MHY\0"` |
| `s_Table1` | `0x142870A88` | `*(T1+0x48)` 指向的表抽样 `type` 字节 100% 合法 |
| `s_Table0` | `0x1422DE370` | `*(T0+0x88)` 非零项 ≈ 方法数 |
| （`s_GlobalMetadataHeader`）| `global.data() + 0x210` | **所有 global 侧偏移都要 +0x210**（陷阱 16）|

---

## §5.7 每个常量是怎么找到的（溯源表）

> 目标：让下一个人能**独立复核** `version.json` 里的每个数，而不是"信我"。
> 全部遵循**三步法**：**① 从代码读 → ② 从数据证 → ③ 用语义锚**。
> 只做 ① 不做 ② 的叫"抄了个数"，本项目禁止（§8 的教训）。

### 5.7.1 三步法

```
① 代码读：在反编译里找到"这个数被用在哪"的表达式
        （Hex-Rays 会把 obfuscation 摊开成 `global + *(MHY+K) op key + stride*idx`）
② 数据证：用**独立结构**证明这个值是表基址/正确 key
        （严格递增 / 区间铺满 / 值域 / 名字可打印 / 条目两两不同 …）
③ 语义锚：用"自带答案"的语义交叉验证
        （枚举父类=System.Enum、`Foo\`N` 的参数个数、已知继承链、count 与表长一致）
```

**三个数最容易搞错，各有专门检查**：

| 易错点 | 检查 |
|---|---|
| 偏移单位（global vs 文件） | 读文件要 **+0x210**（陷阱 16）|
| **计数修正量**（如 typeDef 要 `-2`）| 本版本 `(MHY[0xE0] - 0x1D064F83)/70 = 88904`，实际类型数 **88902** → 要 `-2`。换版本**必须复核这个修正量**（不是通用常数）|
| 16/8 位截断 | `+N` 型 count 必须按位宽截断（陷阱 6）|

### 5.7.2 逐类溯源

| `version.json` 项 | 怎么找到的 | 数据侧自证 | 失败时的退路 |
|---|---|---|---|
| `addresses.MHY` | 搜 `.rdata` 魔数 `"MHY\0"` | 表头魔数 | — |
| `addresses.T0/T1` | 反编译 `GIMeta_RuntimeInit`，末尾对两个全局的赋值 | `*(T1+0x48)` 抽样 `type` 字节 100% ∈[1,0x1D]；`*(T0+0x88)` 非零项 ≈ 方法数 | `tools/sig.py` 按结构签名找函数 |
| `tables[].slot` | 反编译里"表基址"表达式的 **`*(MHY+K)` 的 K** | 该槽位必须出现在 `slot_scan` 候选里 | 补 §4.1 的四种形态。⛔ **slot 跨版本不稳定**（7.0：`0x13C→0xC`）→ 只能当"同版本内定位"，不能当跨版本提示 |
| `tables[].op/key` | 同一表达式里的**运算与常数** | 用 `slot_scan` 的 `(slot,op,key)` 复算，值落进元数据且过结构自证 | `relocate.py` ⑦ **反查**（值→唯一三元组）|
| `tables[].stride` | il2cpp 结构体大小（`structSizes`）+ 反编译里的步长 | `count*stride` 不越界；`count = raw/stride [- 常数]` 与实测计数一致 | 用"区间铺满"反推步长 |
| `tables[].side` | `global`（+0x210）/ `startup`（另一块数据）| 值域落在对应块的尺寸内 | — |
| `keyFormulas.*` | 反编译里 `xxxKey(i)` 函数体：乘/加/移位/xor | 解出的名字**可打印**、`typeIndex` 100% 合法 | 用"名字可打印"逐项调 |
| `fieldDecode.*` | 反编译里字段读取表达式（`(raw op key)`）| 输出侧统计（基类/泛型/事件/属性访问器）| **锚点反解**（§8 Worked example A/B）|
| `structSizes.*` | il2cpp 原始 C 结构体定义 + 实测步长 | 表长/计数互相一致 | 用相邻表平铺反推 |
| `*CountFormula` | 找**消费者**：`RuntimeInit` 里谁给循环定界 / 谁给数组分配 | 算出的计数 == 实测（如 `13671`）| §5.5 |
| `registrationFields`（T0/T1 偏移）| 反编译里 `*(T0+K)` / `*(T1+K)` 的用法 + 类型 | 见 §3.3 的验收列 | — |
| `stringDecrypt` | 文章算法 + `tools/gi_string_decrypt.py` 独立实现 | 程序集名 **75/75** | — |

### 5.7.3 完整示例：`typeDefinitions` 端到端

```
① 代码读：某类型读取函数里出现
     *(DWORD*)(MHY + 180) - 330781793 + 70*index
   → 槽位 0xB4、op '-'、key 0x13B75461、步长 70
② 数据证（relocate.py ④）：
     70 字节步长下 flags 只有 106 种；抽样 nameIndex 解出的名字
     可打印率 100%（<Module>/Locale/SR/WIN32_FIND_DATA…）
③ 语义锚：typeDefinitionsCount = (MHY[0xE0] - 0x1D064F83)/70 - 2 = 88902
     → 与 verify.py 的「类型数 88902」一致
→ 写入 version.json → make → verify.py 28/28
```

**本版本已复核的公式**（换版本拿这张表当模板）：

| 值 | 公式 | 结果 |
|---|---|---|
| `typeDefinitionsOffset` | `MHY[0xB4] - 0x13B75461` | `0x92140` |
| `typeDefinitionsCount` | `(MHY[0xE0] - 0x1D064F83) / 70 - 2` | 88902 |
| `methodsOffset` | `MHY[0x16C] - 0x1CCA7654` | `0x2439204` |
| `methodsCount` | `(MHY[0x188] ^ 0x1B58E334) / 26` | 733442 |
| `methodPointerIndexOffset` | `MHY[0x94] ^ 0x4A4C0A71` | `0xC48E6C` |

**反查闭环**（**只要值可靠**就能全自动）：
`relocate.py ⑦` 拿 ② 得到的值 `0x92140` 反查候选表 → 唯一命中
`slot 0xB4 add 0xEC48AB9F`（补码形式，等价于 `- 0x13B75461`）✓
—— 7.0 上用 ④ 可靠得到的 `fieldDefaultValues=0x1022CA8` 也成功反查到 `slot 0xC xor 0x720EB389` ✓
（**前提**：值本身来自跨版本可靠的判据；靠旧 slot 提示得来的值不行 —— 见 §8.6）

### 5.7.4 哪些是"反解"出来的（不是从代码直接读）

这三个**代码里没有对应立即数**，是用**已知语义反解**的 —— 换版本时也要用同样方法，别去代码里搜常数：

| 字段 | 反解方法 | 锚 |
|---|---|---|
| `typeDef+0x18 parentIndex` | 取 `System.Enum`/`System.ValueType` 的真实 typeDef 索引 → 在 Il2CppType 表里找 `klassIndex==它` 的项 → 要求"单一 op/K 同时映射这两个目标" | 枚举/结构体父类恒定 |
| `typeDef+0x3E genericContainerIndex` | `Foo\`N` 的名字自带参数个数 → 容器的 `argc` 必须 == N | 名字里的 `` `N `` |
| `fieldOffset` 的索引基 `+0x20` | 反编译里 `fieldOffset[(typeDef+0x20 ^ 0x2E8C0EB8) + k]` 直接给出 | 反编译 |

> 判别方法：**在 `.text` 里搜不到那个常数** → 基本就是反解的（或密钥在数据段，见 §4.1 形态 D）。

### 5.7.5 逐条溯源报告（机器生成）

上面是**按类别**的说明。**逐条**（34 张表 + 8 个结构体的每个字段）的证据在：

```
docs/PROVENANCE.md        # 由 tools/provenance.py 生成
```

它**直接扫 `gi.exe`**（**不读** `slots_cache.json`），给出每一条的：

| 表/字段 | 槽位或位移 | 运算/密钥 | 代码证据（指令地址 / 函数） | 若未命中：来源 |

- 「代码证据」= 真正执行 `*(对象+位移) op 密钥` 的**指令地址**，并映射到
  `tools/sigs.json` 里的函数名（`GIMeta_*` / `MetaStr_*`）
- 「未命中」**不是错误**：说明它是**结构自证 / 公式 / 反解**来的（见 §5.7.4）

```bash
python3 tools/provenance.py version/7.1/gi.exe          # → docs/PROVENANCE.md
python3 tools/provenance.py version/7.0/gi.exe --out /tmp/P70.md
```

> 为什么不让它读缓存：缓存是**派生结果**（还可能漏报/含误报）。
> 溯源必须回到**一手证据**（机器码），否则就是"引用二手结论"。

## §5.8 换版本到底要改多少个数（`version.json` 全量分类）

`version.json` 现在有 **335 个叶子值**。按"换版本是否要改"分：

| 类别 | 必改 | 稳定/不改 | 说明 |
|---|---|---|---|
| `addresses`（MHY/T0/T1 等） | **5** | 0 | 7.0 实测会变 |
| `stringDecrypt` | **5** | 2 | 4 个密钥可用 `sig.py consts` **自动解出**；第 5 个 `entryXor` **可能连公式一起变** → 用 `sig.py entryexpr` 检查（7.1 `xor:xor`，7.0 `xor:sub`）；`offsetMask`/`lengthShift` 稳定 |
| `tables[].slot / .op / .key` | **102**（34×3） | 0 | slot 实测变；**op 也变**（7.1 `methodPointerIndex` 是 `xor`，7.0 是 `add`） |
| `tables[].stride / .side / .role / countBias` | 0 | 103 | `stride` 在 7.0 上**未验证** |
| `keyFormulas`（8 个公式的全部系数） | **43** | 0 | 每版重解 |
| `fieldDecode`（8 结构体全部字段密钥） | **42** | 0 | 每版重解 |
| `structSizes`（18 个结构体大小） | 0 | 18 | 布局，**未在 7.0 验证** |
| `registrationFields`（T0/T1 字段偏移） | 0 | 5 | **未在 7.0 验证** |
| `*CountFormula` 的 `key` / `op` | **6** | 0 | |
| `*CountFormula` 的 `table0Field/table1Field` | 0 | 3 | T0/T1 字段偏移 |
| `version` | 0 | 1 | |
| **合计** | **203** | **132** | 共 335 |

> **需要拿 7.0 复核的"稳定"项共 57 个**：`tables.stride` 34 + `structSizes` 18 + `registrationFields` 5。
> 若 7.0 的结构布局变了，这 57 个也要改（`CROSS70.md` §七 已列为待办）。

### 203 个必改项里，**自动/手工**各占多少

| 项 | 数量 | 怎么来 | 7.0 实测状态 |
|---|---|---|---|
| `tables[].slot/op/key` | 102 | `slot_scan` 候选 + `relocate`（④自证 / ⑥提示 / ⑦反查） | **4 表 + blob 全自动**（fDV / methodPointerIndex / methodSlotTable / attributesInfo / blob）；其余召回不足 |
| `fieldDecode` 字段密钥 | 42 | `slot_scan --struct` 候选 + 语义判定（累计索引单调 / 名字可打印 / count 很小） | 7.0：5/18 → **15/18**（`CROSS70.md`） |
| `keyFormulas` 系数 | 43 | 反编译 `xxxKey(i)` 函数体，人工抄 | 未自动 |
| `addresses` | 5 | 魔数 + `sig.py` 找 `RuntimeInit` | `sig.py` 7.0 找回 48/54 |
| `stringDecrypt` 密钥 | 5 | **`sig.py consts`**（4/5）+ **`sig.py entryexpr`**（推导公式） | 7.0：consts 4/5；entryexpr 报出形态 B（公式变了） |
| `*CountFormula` 的 key/op | 6 | 反编译消费者（`RuntimeInit`） | 未自动 |

**④ 的「纯结构、不需要 key」探针（跨版本可靠）**：

```
fieldDefaultValues  12B,+0 严格递增 + +8 合法类型索引
methodSlotTable     6B, 第 i 行 +4(u16) == i
attributesInfo      8B, +0 严格递增(<=2M) + +4 低24位严格递增 + 高字节多种 kind
methodPointerIndex  4B, 值域 [-1,79765)                       (弱, 仅参考)
blob                常量签名落在某条 dataIndex 上
```

**结论：真正要人工盯的只有「`keyFormulas` 43 + 字符串密钥 5 + 公式 6 + 地址 5 = 59 个」；
其余 144 个（表 102 + 字段 42）有自动/半自动通道，但 7.0 显示「候选召回」仍是瓶颈。**



## §5.9 202 个值逐个怎么找（工具映射 · 当前真实自动化程度）

> 只列**每版必改**的 202 项。判据全部实测过；标 ✅ 的是**不需要任何版本常量**的。

### 1) `addresses`（4 项）

| 键 | 怎么找 | 自动化 |
|---|---|---|
| `mhyTableVA` | 搜 `.rdata` 魔数 `"MHY\0"`（`relocate ①`） | ✅ |
| `table0VA` / `table1VA` | 反编译 `GIMeta_RuntimeInit` 末尾的全局赋值（`sig.py scan` 能定位函数） | ✗ 人工 |
| `codeRegistrationVA` | 同上 | ✗ 人工 |

### 2) `stringDecrypt`（5 项）

```bash
python3 tools/sig.py consts <exe> --func <DecryptString> --func <RuntimeInit>
```

| 键 | 判据 | 自动化 |
|---|---|---|
| `keyMulA/keyMulB/keySeed/keyStep` | 从 `movabs` 里**按算法结构**标注（xorshift 块后的 3 连 + 重复 3 次那个） | ✅ 4/4（7.0 实测） |
| `entryXor` | 同一寄存器连续两次 `xor`、第二次 imm32，**且之后 ≤4 条 call 解密函数** | 7.1 ✅ / 7.0 ✗（公式变成 `xor+sub`，用 `sig.py entryexpr` 看形态） |

### 3) `tables[].slot / .op / .key`（102 项 = 34 张 × 3）

按可靠性分三档：

| 档 | 判据 | 覆盖 | 自动化 |
|---|---|---|---|
| **A. 结构自证** | 表内部自洽：`12B +0 严格递增` / `6B 第 i 行 +4==i` / `8B +0 递增且 +4 低24位递增` / `4B 值域` / `6B +0 全是合法类型索引` / 常量签名落位 | `fieldDefaultValues`、`methodSlotTable`、`attributesInfo`、`methodPointerIndex`(弱)、blob | ✅ 全自动（`relocate ④`） |
| **B. 无密钥反解** | `/70` 魔数短名单 → 哨兵反推 key → 全表校验 → **区间铺满** → fDV 覆盖率 | `typeDefinitions`（含**布局**：`fieldStart/field_count`） | ✅ 全自动（`relocate ⑧`，7.1/7.0 都通过） |
| **C. slot 提示** | 旧 JSON 的 slot → 该 slot 的"唯一合理候选" | 7.1 30/34；**7.0 16/34 且值全错** ⛔ | 🟡 只能当提示（跨版本已证伪） |
| D. 其余 | 内容逐索引混淆、无原始指纹 | `methods/fields/properties/events/parameters/generic*` | ❌ 人工/IDA |

### 4) `keyFormulas`（43 项）

| 方法 | 效果 |
|---|---|
| 反编译 `xxxKey(i)` 函数体，人工抄乘/加/移位/xor | ❌ 唯一可靠 |
| `tools/port.py` 指令对齐 | 🟡 能给候选；实测**字段密钥 0/4 正确** ✗ 不可单独信任 |

### 5) `fieldDecode`（42 项）

| 字段 | 判据 | 自动化 |
|---|---|---|
| `typeDef.fieldStart` / `field_count` | `⑧` 区间铺满 + fDV 覆盖率 + 「N 刚好覆盖 fDV.fieldIndex 最大值」 | ✅ **7.1/7.0 都自动** |
| `typeDef.methodStart` / `method_count` | `⑧` 区间铺满，N ≈ methodsCount | ✅ 7.1（7.0 该对未铺满） |
| `typeDef.nameIndex` | `⑧` **字符串解密器裁决**（解出的 `offset\|len<<24` 必须给出可打印名字） | ✅ 7.1（唯一命中 `+0x24 add 0xFBAD8E98`）|
| `typeDef.flags` | bitmask、取值 4~200 种 | ❌ 83 个候选，不唯一 |
| `typeDef.parentIndex` | 合法 Il2CppType 索引、-1 占 5%~95% | ❌ 会误命中 `fieldStart` |
| `typeDef.genericContainerIndex` | 小索引、-1 占多数 | ❌ 3 个候选 |
| `typeDef.unknown20` | 非负、单调、≤2M | ❌ 真值不在候选里 |
| 其它结构体（method/field/property/event/parameter/generic*） | `slot_scan --struct` 给候选 + 语义判定（名字可打印 / typeIndex 合法 / argc==N） | 🟡 半自动 |

### 6) 计数公式 `key/op`（6 项）

| 方法 | 自动化 |
|---|---|
| 反编译 `RuntimeInit` 里给循环定界/分配的地方，抄 `(T0/T1 字段) op key` | ❌ 人工 |

### 当前自动化率（实测）

| | 全自动 | 半自动 | 人工 |
|---|---|---|---|
| **7.1** | ≈26 / 202（13%） | 144 | ~32 |
| **7.0** | ≈19 / 202（9.4%） | 144 | ~39 |

> 全自动 7.1：MHY + 5 张表×3 + typeDefs 布局(4) + nameIndex + 5 个字符串密钥
> 全自动 7.0：MHY + 4 张表×3 + typeDefs 布局(2) + 4 个字符串密钥

### 一条命令跑完能自动的部分

```bash
python3 tools/sig.py scan   <exe> --sigs tools/sigs.json --fuzzy --json /tmp/h.json
python3 tools/slot_scan.py  <exe> <dat> --out /tmp/slots.json
python3 tools/slot_scan.py  <exe> <dat> --struct typeDef --hits /tmp/h.json --struct-json /tmp/keys.json
python3 tools/sig.py consts <exe> --func <DecryptString> --func <RuntimeInit>
python3 tools/relocate.py   <root> --slots /tmp/slots.json --keys /tmp/keys.json --emit /tmp/layout.json
```

## §5.10 IDA 手抄指南（剩下那 ~80% 到底怎么抄）

> 适用：④/⑧ 自动不了的项 —— 剩余表常量、`keyFormulas`、`fieldDecode` 的其余字段。
> **不要凭记忆填**；每一步都要落在一个具体表达式上。

### 5.10.1 通用套路（4 步，任何表都一样）

```
① 入口：python3 tools/provenance.py <exe>   → docs/PROVENANCE.md
        里面有每张表的「读取指令地址 + 函数名」（实测证据）
② IDA 里跳过去（G 键输入地址），看 **Hex-Rays 伪代码**（F5）
③ 找这张形态（混淆被摊开后一定是这个形状）：
        *(DWORD*)(global + *(_DWORD*)(MHY + SLOT) OP KEY + STRIDE * i)
   抄 3 个东西：SLOT（位移）、OP（+ - ^）、KEY（常数）
④ 用数据验：按 (SLOT,OP,KEY) 算出偏移 → 检查表结构（步长/计数/值域/平铺）
```

### 5.10.2 三种代码形态（认得出就不用翻伪代码）

```asm
; 形态 B（key 在寄存器、槽位在第二操作数）—— 7.1 的 typeDefs
mov   esi, 0xec48ab9f          ; KEY（补码 = -0x13B75461）
add   esi, [rdx + 0xb4]        ; SLOT = 0xB4

; 形态 A（槽位先、key 后）
mov   ecx, [rdx + 0x1c4]       ; SLOT = 0x1C4
add   ecx, r15d                ; KEY 在 r15d（入口处 mov r15d, imm）

; 形态 D（key 在数据段常量池）
movsxd rsi, [rdx + 0x1a0]      ; SLOT = 0x1A0
xor   rsi, 0x4ce7b502          ; KEY
```

> **补码**：`add 0xE33589AC` 就是 `sub 0x1CCA7654` —— 抄的时候按 `version.json` 的
> `op` 约定换算（`-` 配正数），或者直接抄 `add` 形式。

### 5.10.3 每张表该去哪个函数找（7.1 实测）

| 表 | 函数（`GIMeta_*`） | 7.1 slot | 7.1 key | 形状 |
|---|---|---|---|---|
| typeDefinitions | *(不在 RegisterTables！)* 见 §5.7.4 | `0xB4` | `-0x13B75461` | B |
| fieldDefaultValues | `GetFieldDefaultValue` | `0x13C` | `^0x593DE464` | A |
| fieldAndParameterDefaultValueData(blob) | `GetFieldDefaultValue` 附近 | `0xA0` | `^0x3F525210` | — |
| methods | `SetupMethodsLocked` | `0x16C` | `-0x1CCA7654` | B |
| methodPointerIndex | `SetupMethodsLocked` | `0x094` | `^0x4A4C0A71` | A |
| methodSlotTable | `SetupTypeInfoLocked` | `0x140` | `-0x6D3AAA4E` | B |
| fields | `SetupFieldsLocked` | `0x18C` | `-0x140FC6D4` | B |
| properties | `SetupPropertiesLocked` | `0x150` | `-0x1C3D5389` | B |
| events | `SetupEventsLocked` | `0x1E8` | `^0x100547B1` | A |
| parameters | `SetupParameters` | `0x114` | `^0x3E5D33E6` | A |
| interfaces | `SetupTypeInfoLocked` | `0x1C4` | `-0x5A7B4287` | B |
| nestedTypes | `IterNestedTypes` | `0x05C` | `-0x16C292F3` | B |
| attributesInfo | `SetupTypeInfoLocked` | `0x024` | `-0x5C185C67` | B |
| attributeTypes | `AllocTypeInfoArray` | `0x0D8` | `-0x72E93284` | B |
| genericContainers | `BuildMethodName` | `0x028` | `^0x774A3BA6` | A |
| genericParameters | `BuildMethodName` | `0x170` | `^0x7B3B96A2` | A |
| methodSpecs | `RuntimeInit` | `0x1D8` | `^0x1F85ABE5` | A |
| genericMethodTable | `RuntimeInit` | `0x0C0` | `-0x612A764D` | B |
| parameterDefaultValues | `GetDefaultParameterValueObject` | `0x104` | `^0x094C42AB` | A |
| imagesOffset / imagesCount | `RuntimeInit` | `0x20C` / `0x02C` | `-0x0ECB27F5` / `-0x2465B023` | B |
| genericClassRange | `RuntimeInit` | `0x134` | `^0x558E11EC` | A |

> 换版本时**只换 SLOT/KEY，函数名不变**（`sig.py scan` 能重新定位函数）。
> 所以流程是：`sig.py scan` → 表的函数 → 在函数里找 `[MHY+slot]` 的读取 → 抄新的 slot/key。

### 5.10.4 `keyFormulas`（43 个）怎么抄

这些是**逐索引 key**：`key(i)` 的公式，藏在"解名字/解 typeIndex"的地方。

```
① 找消费者：比如方法名 → GIMeta_BuildMethodName / GetMethodNameFromIndex
            参数名 → SetupParameters
            字段名 → GetFieldName
② 伪代码里会看到：
     nameIndex = (raw ^ xxxKey(i))       或   (raw - xxxKey(i))
   而 xxxKey(i) 被内联成一段乘/加/移位/xor：
     ((1457992407*((41617*i+1219887025)^0x19E1D47A))>>21)+2068375556
③ 把这段**原样**抄进 version.json 的 keyFormulas.<name>（按 A/B/xor/add/shift 拆）
④ 验收：解出的名字必须可打印 / typeIndex 必须合法（见 §5.9 的字段表）
```

> 7 个公式共用同一个 `methodKey`（在 `methodNameIndex/methodFlags/methodIFlags/
> methodReturnType/methodDeclaringType/methodParamStart/methodParamCount` 七处）——
> 换版本时**七处必须同步**（JSON 里已合并成一个键 ✓）。

### 5.10.5 `fieldDecode` 的其余字段怎么抄

在**读结构体的函数**里，每个字段都是同一形状：

```c
*(DWORD*)(obj + 0x18) - 0x3D74901F      // typeDef.parentIndex
*(WORD*)(obj + 0x3E)  - 26230           // typeDef.genericContainerIndex
*(DWORD*)(obj + 0x28) - 0x4159BB8E      // typeDef.flags
```

步骤：

```
① 打开该结构体的主读取函数（typeDef → SetupTypeInfoLocked / SetupFieldsLocked 等；
   method → SetupMethodsLocked；field → SetupFieldsLocked；property → SetupPropertiesLocked；
   event → SetupEventsLocked；parameter → SetupParameters）
② 在伪代码里搜 `obj + 0x??` 的用法，看它后面跟的是 `- K` / `^ K` / `+ K`
③ 抄 位移 + op + key
④ 判宽度：`*(BYTE*)` / `*(WORD*)` / `*(DWORD*)` —— `+N` 型**必须按位宽截断**
```

**几个难字段的额外提示**（判据不唯一，必须靠语义）：

| 字段 | 怎么确认 |
|---|---|
| `nameIndex` | 解出的值必须是 `offset\|len<<24`，且解密后是可打印名字（**用字符串解密器裁决**，`relocate ⑧` 已自动化）。7.1 实测：`+0x24 sub 72511848`，可打印率 **1.000**、**502 个不同值** |
| `namespaceIndex` | 同上，但**允许 `len==0`**（无命名空间）；区分靠**不同值个数**：7.1 实测 `+0x00 sub 1145778368` → 可打印率 0.818（其余是空串）、**只有 17 个不同值**（类型名有 502 个）✓ |
| `flags` | 解码后只有几十种取值，且是 bitmask（`TYPE_ATTRIBUTE`） |
| `parentIndex` | 解码后必须是 **Il2CppType 索引**（`-1` = 无父类）；用 `System.Enum`/`System.ValueType` 的已知父类反解（见 §8 Worked example A） |
| `genericContainerIndex` | 解码后是**容器表**索引；用名字里的 `` `N `` 反解（argc 必须等于 N） |
| `unknown20` | 它是 **`fieldOffset` 表的每类型索引基**（`fieldOffset[(typeDef+0x20 ^ K) + k]`） |

### 5.10.6 抄完的验收清单

```
□ verify.py 28/28 PASS
□ 该表的 count 与「实际元素数」一致（§5.5）
□ 名字类字段：抽 200 个看可打印率 ≥ 95%
□ 索引类字段：typeIndex 100% < typesCount
□ 计数类字段：8/16 位截断后 ≤ 表长
□ 区间类：区间必须铺满 [0,N)（§KEYLESS §六）
```

### 5.10.7 ⚠️ 换版本时，§5.10.3 那张表**够用吗？—— 不够**

实测结论（7.1 → 7.0）：

| 表里给的 | 换版本后还能用吗 |
|---|---|
| **函数名**（`GIMeta_SetupFieldsLocked` 等） | ✅ 能，`sig.py scan` 重新定位（7.0: 48/54） |
| **代码形状**（A/B/C/D 四种） | ✅ 能，形状没变 |
| **slot / key** | ❌ **每版都变**，只能当"上一版的答案" |
| **步长**（26/10/14/8…） | ⚠️ 只有部分能用（见下） |

**步长锚实测**（在函数里找 `imul/lea/shl/add` 带该立即数）：

```
✓ GIMeta_SetupFieldsLocked     步长 8   出现 11 次
✓ GIMeta_IterNestedTypes       步长 4   出现 8 次
✓ GIMeta_SetupTypeInfoLocked   步长 6   出现 2 次
✗ GIMeta_SetupMethodsLocked    步长 26  一次都没有
✗ GIMeta_SetupPropertiesLocked 步长 10  一次都没有
✗ GIMeta_SetupEventsLocked     步长 14  一次都没有
✗ GIMeta_SetupParameters       步长 8   一次都没有
```

原因：很多函数走的是 `[base + i]`（i 已预乘），**根本不出现步长常数** ✗。

### 所以"函数内定位"要靠这四条（按可靠性排序）

| # | 手段 | 说明 |
|---|---|---|
| 1 | **上一版的指令地址** | `docs/PROVENANCE.md` 给了每张表的**读取指令地址**；用 `tools/port.py` 的对齐把它映射到新版，再核对结构 |
| 2 | **消费者**（base 被传给谁） | 例如 base 后面紧跟 `call GIMeta_GetFieldName` → 那就是 `fields`；被拿去 `[base + 4*i]` → 4 字节表（`attributeTypes`/`fieldOffset`/`nestedTypes`/`methodPointerIndex`） |
| 3 | **计数槽位反推**（⚠️ **只对 count 有效，对 offset 无效**） | `count = (MHY[slot] op key) / 步长 (±修正)`。实测：`methodsCount` 19069493/26=733442、`typeDefsCount` 6223280/70−2=88902、`attrinfoCount` 8920/8=1115、`pDVCount` 304488/12=25374、`imagesCount` 3000/40=75、`methodSlotCount` 76964/6=12827。**偏移槽位（methodsOffset 等）与计数无关，这招用不上** ✗ |
| 4 | **步长出现次数** | 只在少数函数里可用（上表 ✓ 的三行） |

### 实际换版本的推荐顺序

```bash
# 1) 先让工具把能自动的做完（大多数表会在这步被确认或给出候选）
python3 tools/relocate.py <root> --slots slots.json --keys keys.json --emit layout.json

# 2) 剩下的表：用 PROVENANCE 的地址 + port.py 对齐，拿到"候选读取点"
python3 tools/port.py --old <旧版本> --new <新版本> --sigs-old h_old.json --sigs-new h_new.json

# 3) 对每个候选读取点，用「计数公式」(手段 3) 一拍：除以步长 == 已知计数？
#    对不上就换下一个候选 —— 这一步不需要 IDA，纯算术

# 4) 只有 1~3 都失败的，才进 IDA 看伪代码（§5.10.1 的 4 步）
```

> **一句话**：§5.10.3 是**索引**（告诉你"去哪张函数找"），不是**答案**（slot/key 每版都变）。
> 真正把"函数 → 具体读取点"钉死的是 **PROVENANCE 的地址 + 计数公式**，
> 而这一步目前还**没有完全自动化**（`port.py` 只能给候选）。

## §6 结构体字段表（含 typeDef 内的隐藏字段）

### 6.1 Il2CppTypeDefinition（70 字节）

字段的 offset 与解码常量 → §5.3（JSON 的 `fieldDecode.typeDef`）+ §6.3。
`status.md` §3.3 有完整 17 字段表。

> **重点**：`+0x18 parentIndex`、`+0x3E genericContainerIndex` 是**后来才找到的隐藏字段**，
> 用的是 §8 的**锚点法**（不是扫数据猜）。
> `+0x20` 已定性为 **`fieldOffset` 表的每类型索引基**（`fieldOffset[(typeDef+0x20 ^ 0x2E8C0EB8) + k]`）。

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
本机自测：**54 条签名 54/54 命中、函数起点全部精确复原、0.8 秒**。

**判定规则（宁可"不可判"也不给错地址）** —— 这套规则是被 **7.0 跨版本实测**逼出来的：

```
1. gen 时拒绝「跳板/填充」        —— 不含函数体信息，只会匹配到别的跳板上
2. scan 过滤 PLT/IAT 跳板        —— int3/nop/jmp+填充
3. 候选 >64 -> 判"签名太弱"      —— 原来静默截断 200 并随手取第一个
4. loose token 必须全中才算命中   —— 字节模式可能碰巧对上但 token 一条不匹配
5. 最高分并列 -> 判"歧义"不给地址；两种定夺：
     · 同版本自测：可用 sigs.json 记录的原地址定夺（并标注）
     · 跨版本：扩展参考 token（--next 10）排序；仍并列则「同组按相对次序」
       （如 TypePredicateB/C/D 三个函数内容完全相同，但 .text 里的先后次序保留）
6. 两条签名落到同一地址 -> 明确报"撞址"
7. 起点存疑(未对齐/前字节非填充) -> 只标记不丢弃
```

**跨版本实测（签名库由 7.1 生成，扫两个版本）**：

| 目标 | 结果 |
|---|---|
| 7.1 自测 | **54/54 命中**，0 不可判，0 未命中 |
| 7.0 | **48 命中**（42 精确 + 6 模糊）、0 不可判、**6 未命中** |

**模糊救援 `--fuzzy`（未命中签名的第二条命）**：

那 6 个没命中的函数，在新版本里**字节模式完全变了**（放宽到中间 4 条子签名实测 0/12 能救），
所以**放宽签名长度救不回来**。改用**调用图锚定**：

```
1. 先用精确签名定位一批函数（本例 42 个）
2. 取这批函数体里所有 `call rel32` 目标 -> 调用图候选（本例 290 个）
3. 对每个未命中的签名，在候选上按 token 打分（loose 8 条 + 严格 token）
4. 采信门槛：最优 >= 5/8 **且** 与次优拉开 >= 2 分
```

要点：`_call_targets` **不能在第一个 `ret` 处停** —— 大函数（如 `RuntimeInit`）有多个返回点，
早停只能拿到 59 个候选（vs 正确的 290 个），直接决定 fuzzy 能不能work。

本例救回 6 个：`SetupNestedLocked` / `SetupEventsLocked` / `GetFieldName` /
`SetupParameters` / `RegisterTypeRecursive` / `MetaStr_AppendObject`（全部 7~8/8）。
剩下 6 个只有 3~5/8、与次优太近 → **不采信**（需首次逆向）。

> ⚠️ 旧版 `sig.py` 在 7.0 上报"43 命中"，但其中有 **1 个 PLT 跳板误报** + **8 个 loose 0/8 假命中**
> + 5 处静默塌成同一地址 —— **旧数字是虚高的**。

**那 12 个救不回来**（实测而非猜测）：把签名放宽到**中间 4 条** → 0/12 有 token 全中的候选；
**中间 2 条** → 1/12。说明它们在 7.0 里**代码真的变了**（不是位置偏移），
只能首次逆向，或用**已定位的调用者**重新锚定。

**被剔除的 1 条**：`GIMeta_GetTypeInfoByIndex` —— 它在 7.1 的原地址 `0x14051CD50`
本身就是 `jmp 0x159eae27C` + int3 填充的跳板（跳进 `.text` 之外的混淆区），
签名一直是假的。55 → **54 条**。

**掩码精度**：用 capstone 的 `insn.encoding.imm_offset/imm_size`、`disp_offset/disp_size`
**精确**通配 imm/disp，而不是"尾部 4 字节全 ?? "——固定前缀更长 → 又快又准。

生成时会打印**弱签名警告**（区分度 <4：说明那 8 条指令太重复，如 `movaps` 刷栈），
这类函数签名不可靠 → 退回字符串/调用图锚。

### `sig.py` 的另外两个子命令（常量抽取 / 命中验证）

`sig.py` 现在是四合一：`gen`（生成签名）、`scan`（跨版本定位）、`consts`（抽常数）、`verify`（验命中）。

#### `consts` —— 从 sig 定位的函数里**通用抽取** 64 位常量

密钥类常数**每版都变**（实测 7.0 的 5 个字符串解密常数**完全不在 7.1 的 `.text`** ✗），
但它们就在 `sig` 定位到的那个函数的 `movabs` 立即数里 ✓ —— 可以直接抽出来 ✓

```bash
python3 tools/sig.py consts <新版本>.exe --func <GIMeta_DecryptString 新地址> --role stringdecrypt
```

**通用性靠"排除内置常数"**，不依赖任何某版本的观测值：
函数里混着 **xxHash64 素数、位技巧掩码、SWAR 字节掩码**，它们**跨版本完全相同** ✗ 必须排除。
标注也靠**算法结构**：排除内置后"地址最靠前的 3 个连续 `movabs`" = `(keyMulB, keySeed, keyMulA)`，
"出现 ≥3 次的" = `keyStep` ✓

| | 7.1 自测 | 7.0 自动抽出 |
|---|---|---|
| `keyMulB` | `0x694418957C890198` ✅ 与 JSON 一致 | `0x552E0DA77096BD68` |
| `keySeed` | `0x55A357D81EF0E48B` ✅ | `0xD7A8F7865F61DE96` |
| `keyMulA` | `0x5C2B4E660E2D0544` ✅ | `0x6E06618323D1073A` |
| `keyStep` | `0x6B0B40C349AE61E5` ✅（出现 3 次）| `0x31BEA5AF4493F187`（也 3 次）|

> 这是目前**第一条真正跨版本自动迁移版本常数**的路：既不依赖 slot 稳定 ✓，也不依赖旧密钥 ✓。

#### `verify` —— 反汇编级验证「命中的到底对不对」

```bash
python3 tools/sig.py scan <新>.exe --sigs tools/sigs.json --fuzzy --json hits.json
python3 tools/sig.py verify --ref <旧>.exe --new <新>.exe --hits hits.json [--show 3]
```

对每个命中比较三样**互相独立**的东西：
① 函数引用的**字符串集合**（`lea/mov reg,[rip+X]` 指过去的 C 串，最硬的语义证据）
② **立即数指纹**（窗口内小立即数的交集）③ **指令序列相似度**（`difflib`，前 60 条助记符/完整 token）

7.0 的 48 个命中实测：**强证据 22（字符串完全一致）/ 中等 26 / 弱 0**，
指令序列相似度 **48/48 ≥78%**（33 个 100%、44 个 ≥92%）✓

### `tools/relocate.py` —— 自动重定位表常量（numpy 秒级）

只用跨版本稳定的锚，**不给字节签名当判据**。六级，逐级向上借证据：

```
① 魔数 "MHY\0"                              → MHY 表
② slot_scan 的 (slot,op,key) 候选（tools/slots_cache.json；--slots 可指定）
③ 常量值 blob（AttributeTargets 的 [Flags] 值做字节签名 → 再反推基址）
④ 数据侧结构自证（numpy 向量化）→ **跨版本可靠的是 3 项**：
     fieldDefaultValues(12B,+0 严格递增,+8 全为合法 Il2CppType 索引)
     methodPointerIndex(4B,值域[-1,79765))
     blob(常量签名落位)
   同版本内另可定位：typeDefinitions / nestedTypesTable / interfacesTable
   （它们依赖 fieldDecode 的密钥 → 跨版本密钥一变就失效）
⑤ 与现有 version.json 对照（自测：应全部一致）
⑥ 旧 JSON slot 提示 → 逐表重新解值（⛔ 跨版本不可信，见下）
⑦ 反查 slot：由④的**值**反查唯一 (slot,op,key)（真正全自动、不依赖旧 JSON）
```

```bash
python3 tools/relocate.py version/7.1                  # 自测
python3 tools/relocate.py version/7.2 --scan           # 无缓存时自动跑 slot_scan
python3 tools/relocate.py version/7.0 --slots /tmp/opencode/slots_cache_70.json
```

**7.1 自测意义**：④ 能**不需要知道旧 slot/key** 就推出
`typeDefinitions=0x92140`、`nestedTypesTable=0x22800F8`、`interfacesTable=0x4D5AB04`、
`fieldDefaultValues=0x3D00478`、`blob=0xF1754C`；⑦ 再把这些**值反查回 `(slot,op,key)`**（5/5 唯一）。

> ⛔ **7.0 跨版本实测（`docs/CROSS70.md`）**：
> - ④ 只剩 **3 项**（fDV / methodPointerIndex / blob）
> - ⑥ 打出 16/34 个"✅ 唯一"，**逐个检查全是错值**，且与 ⑦ 自相矛盾
> - 根因：`slot` 不是跨版本常量（`0x13C→0xC`、`0x94→0x130`）
> **所以 ⑥ 只能当"同版本内定位"的粗筛，不能当换版本判据。**

---

## §8.6 「引导阶梯」—— 让其余表也能自动定位（现状与边界）

**覆盖度总览（7.1 同版本自测 + 7.0 跨版本实测）**

| 能自动定位到什么 | 7.1（同版本）| 7.0（跨版本）| 依赖旧 JSON？ |
|---|---|---|---|
| **表常量（完全独立）** | 6 + blob | **3 + blob** | ❌ 不依赖 |
| **表常量（slot 提示）** | 30 / 34 | **16 / 34，且值全错** ⛔ | ✅ 且**不可用** |
| **全局地址** | 3（MHY/T0/T1） | `sig.py` 找回 48/54 函数 | 部分 |
| **结构体内部字段偏移+密钥** | ❌ 不能自动定位 | ❌ | — |

> ⛔ **`slot` 不是跨版本常量**（7.0：`0x13C→0xC`、`0x94→0x130`）。
> 所以 §1 里"靠 slot 提示自动换版本"**已被证伪** —— 详见 `docs/CROSS70.md`。
> 目前唯一跨版本可靠的路径是：**表内部自洽的 3 项** + **语义不变量（累计索引单调）** + **无密钥反解**。

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

> **编号说明**：上面 ①-⑨ 是**设计阶梯**；`relocate.py` 运行时打印的 ①-⑦ 是**另一套编号**
> （①魔数 ②候选 ③blob ④结构自证 ⑤对照 ⑥slot提示 ⑦反查）。两者不要混。

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

而且**有些真值不会进候选** —— 但要分清两种原因：

**(a) 密钥在数据段常量池（第 4 种形态，已实现并验证有效）**：
`nestedTypesStart` 的真实读取是 `movzx eax,[rsi+0x36]` + `add eax,[rip+const]`。
修前 Branch C 会把 `[rip+X]` 误当成"槽位"（`X < NSLOT` 时），既产不出真候选、又制造假候选；
补 `C2) op reg,[rip+const]`（解析 rip 目标、从数据段取 u32 当密钥）后正确产出 ✓。

**(b) 密钥是"解析推导"出来的，代码里根本没有这个立即数** —— 这是**正常**的，不是缺口：
`parentIndex (+0x18)` 的 `sub 0x3D74901F` 是用**两个已知目标反解**出来的（见 §8 Worked example A）：
取 `System.Enum`/`System.ValueType` 的真实 typeDef 索引 → 在 Il2CppType 表里找到对应项 →
要求"单一 op/K 同时映射两个目标"→ 一次命中。`nameIndex (+0x24)`、`flags (+0x28)` 同理。
所以它们**不应该**出现在候选表里 ✓

要定位 B 类，只能靠**语义/二次证据**（例：`nameIndex` 用"解出的名字可打印"当判据、
count 用"÷70 == 类型数"当判据），或 §8 的"反解法"，或 IDA 单点确认 —— **没有通用结构探针**。

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
两张 `*_deprecated`（代码里已不读）。**即：在 7.1 这个版本内，真正在用的表 30/30 都是 slot 唯一确定。**

> **⛔ 已用 7.0 样本验证：slot 跨版本【不稳定】，这一级基本失效。**
> 实测（`python3 tools/relocate.py version/7.0`）：
>
> ```
> ⑥ 旧 JSON slot 提示：slot 唯一确定 16 张, 多候选 1 张, 无候选 17 张
> ⑦ 反查 slot（结构自证的值 -> 唯一 slot）:
>    fieldDefaultValuesOffset 0x1022CA8 -> slot 0xC   xor  0x720EB389   ← 7.1 是 slot 0x13C
>    methodPointerIndexOffset 0xD5E6BC  -> slot 0x130 add 0xA3B3FC56   ← 7.1 是 slot 0x94
> ```
>
> **能自证的表里，至少 2 张的 slot 在 7.0 完全不同**（`0x13C→0xC`、`0x94→0x130`）——
> 混淆器**每次构建都重排槽位**。所以：
>
> - ❌ **不能**用「旧 JSON 的 slot」当提示（7.1 的 slot 在 7.0 上 17/34 找不到候选）
> - ✅ **必须**走「结构自证 → 反查 slot」闭环，它**完全不依赖 slot 稳定** ✓
> - ⚠️ ⑤ 对照显示 7.1 的**全部密钥**在 7.0 失效（一致 0 / 不一致 2），密钥每版都变

**⓪ 级做不到的**：如果同一个 slot 被多个读取点用不同 key 读（本版本 slot 0x5C 有 23 种候选），
就必须靠结构自证（⑤）或人工确认 —— 本版本这种情况**没有发生**（0 张多候选）。

## §9 版本更新时最容易踩的 18 个坑

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
| 15 | `slot_scan` 漏报某个槽位（候选里查不到真值）| 只匹配了一种指令形态。真实有**四种**（见 §4.1），且**密钥可能被提到函数入口** → 必须数据流追踪，不能用"距离 N 条内" |
| 16 | 偏移读出"越界"假象 | 从 MHY 槽位解出的偏移都是 **global 相对**的，读 `global-metadata.dat` 要 **+0x210** |
| 18 | **表内字段顺序被置换**，读数全错但你察觉不到 | 7.0 的 `Il2CppFieldDefaultValue`：7.1 是 `{fieldIndex@0, dataIndex@4, typeIndex@8}`，7.0 变成 `{dataIndex@0, typeIndex@4, fieldIndex@8}`。**结构探针仍会通过**（+0 递增、+8 是合法索引，只是含义变了）→ 任何"写死 +4"的代码静默读错。**修法：所有字段布局都要用数据核对，不要假设与上版一致**（`find_blob` 已改成两布局都试） |
| 17 | `relocate` ⑥/⓪ 打出一堆"✅ 唯一"，跨版本却全是错值 | **「候选里只有一个落进元数据范围」不是判据**（任何小偏移都满足）。7.0 实测 16/34"唯一"全错，且 ⑥/⑦ 会自相矛盾（同一 slot 既当表基址又当表长度）。**slot 跨版本不稳定**（`0x13C→0xC`、`0x94→0x130`）→ 见 `docs/CROSS70.md` |

---

## §10 验收标准（`verify.py` 的 28 项）

```bash
python3 verify.py                    # 默认 version/7.1
python3 verify.py version/<新版本>   # 换版本后指向新样本目录
# 另：python3 tools/relocate.py version/<新版本>   会打印 ⑤「探测值一致」交叉核对
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
| ~~`typeDef +0x20` 语义~~ | ✅ **已定性**：它是 **`fieldOffset` 表的每类型索引基**（`fieldOffset[(typeDef+0x20 ^ 0x2E8C0EB8) + k]`，k=类型内字段序号）|
| 结构体**内部字段偏移**的自动定位 | 无通用结构探针；只能靠**反解**（§8 锚点法）/ 语义 / IDA。**但偏移跨版本大概率不变**（变的是密钥，已在 JSON）|
| ~~`slot` 跨版本稳定~~ | ❌ **已用 7.0 证伪**：`fieldDefaultValues 0x13C→0xC`、`methodPointerIndex 0x94→0x130`。靠旧 slot 得到的"唯一值"16/34 **全错**（`docs/CROSS70.md`）|
| 7.0 上 `typeDefinitions` 的密钥召回 | ⏳ 7.0 的 `slot_scan` 候选里缺真密钥 → 方向：**语义不变量（累计索引单调）** + **无密钥反解**（`CROSS70.md` §五/§六，7.1 已验证，7.0 待跑） |

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
