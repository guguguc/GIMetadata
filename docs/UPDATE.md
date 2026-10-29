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

## §0.1 当前推荐流程（自动化版本，优先按这里做）

> 这一节记录当前工具链的实际做法。旧的手工流程仍保留在后面的章节，但新版本优先使用这里。

### 1. 准备目录

```text
version/<ver>/
├── gi.exe
├── gi/Managed/Metadata/global-metadata.dat
├── gi/Managed/Metadata/startup-metadata.dat
├── slots.json                 # slot_scan 生成
├── sig_hits.json              # sig.py scan 生成，可人工补已确认函数
├── ida.json                   # 可选：IDA 导出
├── ida/decomp/                # 可选：已知函数的反编译文本
├── ida/addresses.override.json# 可选：无法自动推导的地址
└── version.json               # 只用于最后的 --check
```

### 2. 生成 slots（离线，不占 IDA）

```bash
python3 tools/slot_scan.py version/<ver>/gi.exe \
  version/<ver>/gi/Managed/Metadata/global-metadata.dat \
  --out version/<ver>/slots.json \
  --jobs 8
```

这一步会扫 `.text`/`.pdata`。**不要用 IDA 做全量扫描**；IDA 只做局部函数确认。

`--jobs N` 按 `.pdata` 函数区间分片并行；默认 1，结果与串行一致。
6.7 实测：串行 589.6s → `--jobs 8` 84.6s，输出 json 的 md5 完全一致。

### 3. 用上一版 sig 找函数

```bash
python3 tools/sig.py scan version/<ver>/gi.exe \
  --sigs version/<prev>/sigs.json --fuzzy \
  --json version/<ver>/sig_hits.json
```

如果某些函数未命中，但已经通过局部 xref/callee 确认，可以手工补进：

```json
{
  "hits": {
    "GIMeta_SetupTypeInfoLocked": "0x1404BE950"
  },
  "_manual_added": {
    "GIMeta_SetupTypeInfoLocked": "0x1404BE950"
  }
}
```

`_manual_added` 只是来源标记，工具只读 `hits`。

### 4. IDA/decomp（可选，但影响 fieldDecode）

需要自动恢复字段时，导出已知函数即可：

```bash
IDAT=/path/to/idat64 tools/ida_headless.sh \
  version/<ver>/gi.exe version/<ver>/ida.json \
  version/<ver>/sig_hits.json
```

原则：

- 只导出 `sig_hits` / `funcs_wanted` 命中的函数；
- 不做全函数枚举；
- 不在 IDA Python 里遍历 `idautils.Functions()` 全库；
- 需要看某个函数时，用 MCP 单函数 `decompile`、`callees`、`xrefs_to`。

### 5. 一条命令跑自动链

以前一版为唯一基线，例如 7.0 → 7.1：

```bash
python3 tools/update.py version/7.1 \
  --base version/7.0/version.json \
  --slots version/7.1/slots.json \
  --ida version/7.1/ida.json
```

`update.py` 会自动执行：

```text
offline_extract.py
stringdecrypt_auto.py
fielddecode_auto.py
keyformulas_auto.py
count_auto.py
table_roles.py
regfields_auto.py
decodeexpr_auto.py
```

产物：

```text
version/<ver>/version.draft.json
version/<ver>/update-report.md
version/<ver>/ida/*.auto.json
```

> ⚠️ **`keyformulas_auto.py` 不是从任意反编译文本自动发现全部公式的。**
> 它需要一个已经人工确认的公式表达式文件：
>
> ```text
> version/<ver>/ida/keyformulas.values.json
> ```
>
> 公式本身仍然要人工从 IDA/decomp 或参考文章里提取。7.0/7.1 的 `keyformulas.values.json`
> 都是这样得到的；`keyformulas_auto.py` 只负责把表达式转成 `c0/c1/...` 常量和 `cpp`。
>
> `decodeexpr_auto.py` 也只消费 `keyFormulas`，不能补缺失公式。

#### keyFormulas 的人工输入格式

```json
{
  "formulas": {
    "methodKey": {
      "func": "GIMeta_SetupMethodsLocked",
      "expr": "((860405619 * i) ^ 0x73758947) + 1547935323"
    }
  }
}
```

至少要覆盖目标版本实际存在的 key。7.1 是 8 个：

```text
methodKey / paramKey / genericParamKey / fieldKey /
propertyKey / eventKey / imageKey / containerKey
```

7.0 还有 `methodParamKey` / `eventAccessorKey`，共 10 个。

生成：

```bash
python3 tools/keyformulas_auto.py version/<ver> \
  --base version/<prev>/version.json \
  --values version/<ver>/ida/keyformulas.values.json
```

验收：

- 用解出的方法/字段/属性名可打印率检查；
- 或与上一版公式语义 A/B 对比；
- 不能只看“生成的 cpp 能编译”。

### 6. 手工可覆盖项

如果某个地址/值确实无法从目标数据推导，可以写到：

```text
version/<ver>/ida/addresses.override.json
```

例如：

```json
{
  "codeRegistrationVA": "0x141F88938"
}
```

`update.py` 会覆盖并标记为：

```json
"addresses.codeRegistrationVA": "manual:addresses.override"
```

不要改 `tools/` 里的常数来适配单个版本。

### 7. 校验

目标已有 `version.json` 时，只能用于最后的 check：

```bash
python3 tools/json_coverage.py \
  --draft version/<ver>/version.draft.json \
  --target version/<ver>/version.json \
  --base version/<prev>/version.json
```

生成链不允许读取目标 `version.json`。覆盖率只说明被检查的字段，不等于 dump 能跑。

### 8. 来源标记

draft 默认包含：

```json
"_origin": {
  "fieldDecode.typeDef.parentIndex": "auto:fielddecode",
  "registrationFields.t1_il2CppTypes": "auto:regfields",
  "addresses.codeRegistrationVA": "manual:addresses.override"
}
```

`base:<path>` 表示仍是旧值；`auto:*` 表示自动生成；`manual:*` 表示人工覆盖。

不想要来源块时加 `--no-origin`。

### 9. 6.7 案例（文章公式，不写死到代码）

参考文章已保存：

```text
docs/reference/exploring-custom-struct-genshin-impact.md
```

6.7 的 `typeDefinitions` 公式：

```text
typeDefinitionsOffset = MHY[0x138] - 0x3D9122A9 = 0x57720
typeDefinitionsCount  = (MHY[0x12C] - 0xBBB76A5) / 70 ≈ 83775
```

验证：

```text
0x57720 + 83775 * 70 = 0x5EF25A
methodSlotTableOffset = 0x5EF25C
```

这类公式只写在版本文档/案例里，不要作为所有版本的硬编码常量。

## §0.2 6.7 冷启动实测记录（2026-10-18）

这一节记录 6.7 从 7.0 基线冷启动时实际确认过的地址、公式和验收结果。数字只属于 6.7，不能复制到别的版本；可复制的是查找方法和验证方法。

### 1. 函数重新定位

sig 扫描命中的地址不一定等于函数起点，必须用 MCP 的 `lookup_funcs` / `get_func` 归一化；落在函数内部的命中要回到 `start_ea`。6.7 修正结果：

```text
GIMeta_RuntimeInit                 0x1404E07C0
GIMeta_SetupFieldsLocked           0x1404BE3E0
GIMeta_SetupMethodsLocked          0x1404C0200
GIMeta_SetupPropertiesLocked       0x1404C0DF0
GIMeta_RegisterTables              0x1402B4920
```

`RegisterTables` 一开始被 IDA 当成“不是函数”，但直接反汇编发现它是真实函数：

```asm
lea rax, unk_141F88938
mov cs:qword_145370478, rax
lea rax, unk_1424A9F70
mov cs:qword_145370480, rax
lea rax, off_1424AA008
mov cs:qword_145370488, rax
lea rax, unk_141F889E0
mov cs:qword_145370490, rax
lea rax, unk_142419A40
mov cs:qword_145370498, rax
retn
```

结论：`.pdata` 或 IDA 函数表可以把地点当候选，但不能当唯一真理；真实注册函数可能不在其中。

### 2. T0 / T1 / MHY

6.7 实际注册值：

```text
MHY = 0x142419A40
T0  = 0x141F88938
T1  = 0x1424A9F70
```

从 `RegisterTables` 可以直接得到：

```text
qword_145370488 = T1 + 0x98
qword_145370490 = T0 + 0xA8
```

反编译消费者确认的关键字段：

```text
T1 + 0x70  Il2CppType 数组
T1 + 0x60  genericInsts
T0 + 0x60  genericMethodPointers
T0 + 0x80  按 methodIndex 直接索引的方法地址表
T0 + 0x90  invoker 数组
```

`T0+0x80` 的 RVA 验证见 §0.4。

### 3. typeDefinitions

```text
typeDefinitionsOffset = MHY[0x138] - 0x3D9122A9 = 0x57720
typeDefinitionsCount  = (MHY[0x12C] - 0xBBB76A5) / 70 = 83775
```

表尾校验：

```text
0x57720 + 83775 * 70 = 0x5EF25A
methodSlotTableOffset = 0x5EF25C
```

6.7 TypeDef 布局（都经过原始数据验证）：

```text
+0x04  propertyStart             sub:0x71AF8B48
+0x08  nameIndex                 sub:0x6220594E
+0x0C  flags                     xor:0x3C41A2FB
+0x14  methodStart               xor:0xDF2043C
+0x18  parentIndex               sub:0xC52CB9D
+0x20  namespaceIndex            xor:0x7309A337
+0x28  fieldStart                sub:0x2318D1B4
+0x2C  unknown20                 sub:0x3727654B
+0x30  nestedTypesStart          add:0x7E42
+0x34  genericContainerIndex     xor:0x1BD3
+0x36  bitfield                  raw（bit0 valuetype / bit1 enumtype）
+0x38  method_count              sub:0x5B59
+0x3A  field_count               xor:0xA791
+0x3C  eventStart                xor:0xBAE7
+0x3E  interfacesStart           xor:0xFB6C
+0x40  property_count            xor:0xE9
+0x41  interfaces_count          xor:0x48
+0x44  event_count               add:0x4D
+0x45  nestedTypesCount          add:0x19
```

> **更正（2026-10-18）**：旧版把 `+0x42` 标成 `bitfield xor:0xE7`，这是误判。
> `+0x42` 的原始字节不满足 class/struct/enum 的 bit 语义；真正的 bitfield 是
> **`+0x36`**，原始低两位直接表示 `00=class / 01=struct / 11=enum`。
> 用 `Il2CppType` 的 `0x11=VALUETYPE / 0x12=CLASS` 建权威标签，对 83,755 个
> TypeDef 全量核对，`+0x36` 零 mismatch。文章里的 6.7 反编译也读
> `*(_BYTE *)(v34 + 54)`，即 `+0x36`。

交叉验证：

```text
method_count 总和 = 687467 = methodsCount
field_count 总和  = 413644
property_count 总和 = 108747
event_count 总和 = 617
nestedTypesCount 总和 = 65645
```

### 4. 字符串解密

6.7 的 `GIMeta_DecryptString` 不再是 7.0/7.1 的两种旧形状：

```text
key = (A * ((B * offset) ^ C) + D) ^ E

A = 0x1A6057A96FEEC594
B = 0x7B42168B7FE02E56
C = 0x1393BD882CBEC20C
D = 0x195DC3DB6600CFFF
E = 0x19DCC66D6BBCCE72
step = 0x15C324F339F8A7B1
```

`offsetMask = 0xFFFFFF`，`lengthShift = 24`，`entryXor = 0`。

验证：

```text
typeDef 名字可打印：83729 / 83775
namespace 可打印：83775 / 83775
```

### 5. count formulas

```text
typesCount             = T1+0x50 - 1683598852 = 639893
genericInstsCount      = T1+0x54 - 1010087847 = 64723
genericClassRangeCount = T0+0x98 - 1613647105 = 12633
```

### 6. method 字段

6.7 的 method 表是 26 字节，但布局不是 7.0/7.1：

```text
+0x00  returnType               (raw - 978518114) ^ keyMethod(i)
+0x04  nameIndex                (raw - 871574903) ^ keyMethod(i)
+0x08  parameterStart            keyMethod(i) ^ raw ^ 0x5A970208
+0x0C  genericContainerIndex     keyMethod(i) ^ raw ^ 0x76714F67
+0x14  flags                    keyFlags(i) ^ (raw16 + 13697)
+0x16  iflags                   keyFlags(i) ^ raw16 ^ 0xDECB
+0x18  parameterCount            methodParamKey(i) ^ raw8 ^ 0xE1
```

其中：

```text
keyFlags(i) = ((-9788*i + 5882) ^ 0xDED) + 15325
methodParamKey(i) = ((-60*i - 6) ^ 0xED) - 35
```

`returnType` 不是独立并行表；它就是 method `+0x00`。这一点通过反编译和数据同时确认：

```text
.ctor  -> void
GetText -> string
```

### 7. 当前 dump 结果

6.7：

```text
output: out/dump67.cs
size:   182246180
md5:    195b10ea2aea57f520f989d8b52c8354
types:  83775
methods:665827
fields: 413644
props:  108747
events: 617
garbage:0
```

7.0/7.1 回归：

```text
7.0 dump md5: 3517cd7283c2db5f3428da6af59d21d7
7.1 dump md5: 3b5da679ee236d57ebb359d824055eb7
7.1 verify.py: 28 项全 PASS
```

## §0.3 可重跑的 override 层

新版本冷启动时，很多值来自自动工具，很多值来自人工确认。两者必须分开：

```text
auto:update 链生成
manual:override 文件覆盖
```

`update.py` 的最终覆盖顺序：

```text
offline_extract.py
stringdecrypt_auto.py
fielddecode_auto.py
keyformulas_auto.py
count_auto.py
table_roles.py
regfields_auto.py
decodeexpr_auto.py
        ↓
ida/*.override.json
        ↓
最终 version.draft.json
```

### 1. 6.7 使用的 override 文件

```text
version/6.7.0/ida/fieldDecode.override.json
version/6.7.0/ida/decodeExpr.override.json
```

6.7 的 `stringDecrypt.override.json`、`tables.override.json`、`addresses.override.json`
已经移除。表角色（包括 `imagesOffset`）、三处地址、三个 T0/T1 计数公式和
registrationFields 和关键公式现在由目标 decomp/PE 自动得到；
无这些 override 时 6.7 仍为 202/202。

### 2. 每个文件的作用

```text
fieldDecode.override.json
  typeDef/其它结构的字段 op/key、structOffsets、typeDefOffsets

stringdecrypt.auto.json
  从 GIMeta_DecryptString 自动提取的字符串公式

decodeExpr.override.json
  不能由通用模板表示的 decodeExpr（名称/type/accessor 顺序）

keyformulas.values.json
  人工从目标反编译抄出的逐索引公式
```

### 3. 确定性重跑

现在重跑：

```bash
python3 tools/update.py version/6.7.0 \
  --base version/7.0/version.json \
  --slots version/6.7.0/slots.json \
  --ida version/6.7.0/ida.json \
  --emit /tmp/draft67.json \
  --report /tmp/report67.md
```

数据部分和当前 draft 一致：

```text
新增字段: 0
缺失字段: 0
值不同:   0
```

例外只有：

```text
_origin
_update
```

它们包含来源/时间，每次都会变。

不要用“冻结整个 JSON”来伪造确定性。确定性应该来自显式 override；“frozen.json” 这种快照补丁不要用。

### 4. 修改 C++ 的边界

版本常量不应写进 C++。只有“通用机制”可以改，例如：

```text
按 fieldDecode.op 分派
按 structOffsets 读取
对非法 start 做防御
```

任何 C++ 改动都必须重新跑：

```text
7.0 dump md5
7.1 dump md5
7.1 verify.py
```

三者和基线一致才算通过。

## §0.4 verify / RVA 与通用化状态

### 1. 当前 verify.py

`verify.py` 仍然主要是 7.1 专用：

```text
MHY/T0/T1 写死
typeDefinitionsCount 写死
events 628 写死
images 75 写死
```

6.7 暂时不能直接用它。6.7 目前做的是：

```text
dump 成功
dump 统计检查
RVA 检查
```

### 2. RVA 检查是版本无关的

RVA 检查只依赖 dump：

```text
// RVA: ... Offset: ... VA: ...
```

6.7：

```text
RVA 总数:       665827
不同 RVA 数:    665353
去重率:         99.9288%
单一 RVA 最大:  61
```

判据：

```text
去重率 >= 90%     PASS
单一 RVA < 1000   PASS
```

7.0/7.1：

```text
7.0: 691941 total, 691430 distinct, 99.9261%, top 73
7.1: 711021 total, 710507 distinct, 99.9277%, top 74
```

如果方法地址表用错，通常会出现“不同 RVA 只有一两万、单个地址几十万次”的诱饵表特征。这个检查可以直接保留到通用 verify。

### 3. json_coverage 的 keyFormulas 权重

`tools/json_coverage.py` 已修正：不再无条件给 keyFormulas 计 43 分，而是按目标公式的实常数个数和语义匹配结果加权。

示例：

```text
7.1 全部公式命中: 8/8 公式, 43/43 常数, 202/202
7.1 无 keyFormulas: 0/8 公式, 0/43 常数, 156/202
```

这比之前的“0/8 但仍报 199/202”准确。

### 4. 通用 verify 的方向

通用 verify 应从版本 JSON 读取：

```text
addresses
tables
structOffsets
fieldDecode
keyFormulas
stringDecrypt
```

然后做：

```text
表地址/计数合法
typeDef name/parent/nested/genericContainer
字符串可打印
dump 类型数 == typeDefinitionsCount
RVA 去重
garbage/问号比例
```

暂时不支持的项应输出：

```text
SKIP
```

不能把“没检查”写成 PASS。

6.7 没有 target `version.json`，所以不能计算真正的 202 正确覆盖；只能做结构/数据不变量验证。

## §1 30 秒总览（照这个顺序做）

> ⚠️ 新版本优先看 §0.1。下面这段是早期总览，示例里的 `--base version.json` 只适用于根目录恰好是上一版的情况；7.0→7.1 应显式使用 `--base version/7.0/version.json`。

```bash
# 0) 先看现状（用旧常量跑，会 FAIL 一堆 —— 这就是待办清单）
python3 verify.py version/<新版本>          # 也可先 make && ./gi-dump version/<新版本>

# 1) 找 3 个全局地址 MHY / T0 / T1 → 填进 version.json 的 addresses
#    反编译静态构造器；MHY 也可直接搜魔数 "MHY\0"      →  §3

# 2) 重扫槽位+密钥（4 种指令形态 + 数据流追踪，几分钟）
python3 tools/slot_scan.py <gi.exe> <Managed/Metadata/global-metadata.dat>
#    → 生成 tools/slots_cache.json

# 3) 一条命令跑自动链：relocate + IDA/离线表 + fieldDecode + keyFormulas + 表角色
python3 tools/update.py version/<新版本> \
    --base version.json \
    --slots version/<新版本>/slots.json \
    --ida   version/<新版本>/ida.json
#    产出 version/<新版本>/version.draft.json + update-report.md
#    update.py 默认会自动跑 fielddecode_auto / keyformulas_auto / table_roles

# 4) 只做最终 JSON 对照（目标已有 version.json 时）
python3 tools/update.py version/<新版本> --base version.json \
    --slots version/<新版本>/slots.json --ida version/<新版本>/ida.json --check
python3 tools/json_coverage.py \
    --draft version/<新版本>/version.draft.json \
    --target version/<新版本>/version.json --base version.json
#    目标 version.json 只用于 check，不参与生成。

# 5) 剩余人工项（见下面 §5.9 / §5.10），补完后构建 + 逐项验收
make dump VERSION=<新版本>
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

#### 5.2.1 从 decomp 手工/自动生成 `keyFormulas`

`keyFormulas.values.json` 是**反编译表达式的缓存**，不是最终常量。  
流程：

```text
ida_export.py + GI_TEXT  →  version/<ver>/ida/decomp/
        ↓
在对应函数里找 RHS 表达式
        ↓
写 keyformulas.values.json
        ↓
keyformulas_auto.py
        ↓
keyformulas.auto.json  →  update.py 合并
```

### 1) 函数映射

| key | 函数 |
|---|---|
| `methodKey` | `GIMeta_GetMethodNameFromIndex` / `GIMeta_SetupParameters` |
| `fieldKey` | `GIMeta_SetupFieldsLocked` |
| `propertyKey` | `GIMeta_SetupPropertiesLocked` |
| `eventKey` | `GIMeta_SetupEventsLocked` |
| `paramKey` | `GIMeta_SetupParameters` |
| `imageKey` | `GIMeta_RuntimeInit` |
| `containerKey` | `GIMeta_GetGenericParameterInfo` / `GIMeta_BuildMethodName` |
| `genericParamKey` | `GIMeta_BuildMethodName` |
| `methodParamKey`（7.0 新增） | `GIMeta_SetupParameters` / `SetupMethodsLocked` |
| `eventAccessorKey`（7.0 新增） | `GIMeta_SetupEventsLocked` |

### 2) 7.1 实测表达式

```text
methodKey:
((860405619 * i) ^ 0x73758947) + 1547935323

fieldKey:
((1824013172 * ((34782 * i) ^ 0x59B1DB19)) >> 16) + 1410079245

propertyKey:
((976451930 * ((0x17A5419F8A28 * i) >> 9)) >> 12) ^ 0x70BE4B04

eventKey:
((-1599256506 * i + 1725894951) ^ 0x1B23E40F)

paramKey:
((1457992407 * ((41617 * i + 1219887025) ^ 0x19E1D47A)) >> 21) + 2068375556

imageKey:
1368137530 * ((667674736 * ((13029 * i) ^ 0x43E2DEB7) + 0xCB287082F0) >> 8) + 1505552983

containerKey:
1714760523 * ((1015151837 * ((10661 * i + 1371718001) ^ 0x146D2C3D)) ^ 0x5D7F95E0) >> 19

genericParamKey:
(((1845531077 * ((12124 * i + 1969070457) ^ 0x423B2C8D)) >> 10) + 1212570291) ^ 0x62A3A8F4
```

### 3) 写 `keyformulas.values.json`

```json
{
  "version": "7.1",
  "formulas": {
    "methodKey": {
      "func": "GIMeta_SetupParameters",
      "expr": "((860405619 * i) ^ 0x73758947) + 1547935323"
    },
    "fieldKey": {
      "func": "GIMeta_SetupFieldsLocked",
      "expr": "((1824013172 * ((34782 * i) ^ 0x59B1DB19)) >> 16) + 1410079245"
    }
  }
}
```

关键点：

- `func` 必须写，`keyformulas_auto` 会优先用它，不再依赖上一版常量匹配。
- 变量统一写成 `i`（container 可以写 `c`，工具会归一）。
- 表达式里的 **所有 64 位常量原样保留**，不要先截断。

### 4) 生成 `keyformulas.auto.json`

```bash
python3 tools/keyformulas_auto.py version/7.1 \
    --base version/7.0/version.json \
    --values version/7.1/ida/keyformulas.values.json \
    --out version/7.1/ida/keyformulas.auto.json
```

### 5) 验收

| key | 验收 |
|---|---|
| methodKey | 方法名可打印，flags 分布合理 |
| fieldKey | 字段名可打印，`typeIndex` 合法 |
| propertyKey | 属性名可打印，get/set 访问器名正确 |
| eventKey | 事件名可打印，add/remove/raise 合法 |
| paramKey | 参数名可打印，`typeIndex` 合法 |
| imageKey | 程序集名 75/75 |
| containerKey | `argc` == 名字里的 `N` |
| genericParamKey | 参数名 = `T`/`T1`/`TKey` |

> ⚠️ 7.0 的 `values.json` 里 `paramKey` 曾经写成 `methodParamKey` 的表达式；
> 两者不是一回事：
> `paramKey` 是 `0x2F41C44B80 * i + 0xBF6F453AB0 >> 8`，
> `methodParamKey` 是 `1631394208 * ((...) + 0x9EF8D46961E5672) ...`。

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
| `tables[].slot/op/key` | 102 | `slot_scan` 候选 + `relocate` + `table_roles`（函数/stride/结构自证） | 7.0：**102/102**；表值全部对齐 |
| `fieldDecode` 字段密钥 | 42 | `fielddecode_auto`（字符串/区间/表语义自证） | 7.0：**41/44**；剩 `typeDef.parentIndex`、`typeDef.flags`、`method.returnType` |
| `keyFormulas` 系数 | 43 | `keyformulas_auto`（反编译表达式 + 形状/缓存） | 7.0：**10/10 公式**（46/46 参数，语义等价） |
| `addresses` | 5 | 魔数 + `sig.py` + `RegisterTables` 里的 `&unk_` | 7.0：**5/5** |
| `stringDecrypt` 密钥 | 5 | `sig.py consts` + `stringkeys.json` + `entryXor` 形态判定 | 7.0：**7/7 字段**（4 key + mask/shift + entryXor） |
| `*CountFormula` 的 key/op | 6 | 反编译消费者（`RuntimeInit`） | 7.0：**1/6** |

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

| | 脚本自动/可复核 | 半自动 | 人工 |
|---|---|---|---|
| **7.1** | ≈26 / 202（13%） | 144 | ~32 |
| **7.0** | **196 / 202（97.0%）** | 剩余少量 | 少量 |

7.0 实测拆分（对照 `version/7.0/version.json`，只做最终 check）：

| 类别 | 正确 / 总数 |
|---|---:|
| `tables` 解码值 | 34 / 34（102 / 102 常量） |
| `fieldDecode` | 41 / 44 |
| `structOffsets` | 43 / 43 |
| `keyFormulas` | 10 / 10（语义等价） |
| `stringDecrypt` | 7 / 7 |
| `addresses` | 5 / 5 |
| 计数公式 | 1 / 6 |

仍缺：`typeDef.parentIndex`、`typeDef.flags`、`method.returnType`；5 个计数公式。

#### 这 12 项为什么没自动出来

| 项 | 为什么不在当前 `ida.json` / `decomp` 里 |
|---|---|
| `typeDef.parentIndex` | ✅ 2026-10-25 按 enum/struct 锚点确认：`+0x0C ^ 0x4339F98A`；不再按 `+0x1C - key` 猜测。见 §15.4d |
| `typeDef.flags` | 7.0 的 `TypeAttrGetter` 读的是另一张属性表（`MHY+340` / `MHY+180`），不是 `typeDef+0x18` |
| `method.returnType` | 7.0 把 returnType 放到并行 4 字节表（`sub_140514630`），该函数不在当前 decomp 里 |
| `nestedTypesTable` | ✅ 已从 `IterNestedTypes` 的 `MHY+0x17C ^ 0x6EBA4F15` 补上 |
| `fieldAndParameterDefaultValueDataOffset` | ✅ 已从 `GetDefaultParameterValueObject` 等函数的 `MHY+0x1B0 ^ 0x26AB5EF8` 补上 |
| 5 个计数公式 | 作用在 **T0/T1 字段**，不是 MHY 表；`ida_export.py` 目前没有 count formula 提取器 |

对应的强制导出函数（7.0）：

```text
GIMeta_TypeAttrGetter                  0x1404F69D0
GIMeta_GetTypeInfoFromIndex            0x1404F5E90
GIMeta_GetTypeInfoFromIndex2           0x1404F59E0
GIMeta_GetFieldDefaultValue            0x1404976F0   # 前面有 5 字节 NOP，sig.py 已自动跳过
GIMeta_GetDefaultValue                 0x1404F43F0
GIMeta_DecodeDefaultValue              0x1404F48F0
GIMeta_GetDefaultParameterValueObject  0x1404F8920
GIMeta_SetupNestedLocked               0x1404E2B30
GIMeta_IterNestedTypes                 0x1404EE5A0
GIMeta_GetMethodInfo2                  0x1404EE820
GIMeta_GetMethodInfoFromIndex          0x1404EE2E0
GIMeta_RuntimeInit                     0x140505BD0
```

> `GIMeta_GetTypeInfoByIndex` 在 7.1 是 `jmp` 跳板，`sig.py gen` 会 SKIP；
> 需要跟到 `jmp` 目标或换函数体地址，不能直接从 `0x14051CD50` 生成签名。

### 一条命令跑完能自动的部分

```bash
# 1) 冷启动 / 换版本：relocate + IDA 映射 + fieldDecode + keyFormulas + 表角色
python3 tools/update.py version/<ver> \
    --base version.json \
    --slots version/<ver>/slots.json \
    --ida   version/<ver>/ida.json

# 2) 只做最终 JSON 对照（不参与生成）
python3 tools/update.py version/<ver> --base version.json \
    --slots version/<ver>/slots.json --ida version/<ver>/ida.json --check

# 3) 覆盖率明细（draft vs held-out）
python3 tools/json_coverage.py \
    --draft version/<ver>/version.draft.json \
    --target version/<ver>/version.json --base version.json

# 关闭 update.py 的自动 3 步（fielddecode/keyformulas/table_roles）
python3 tools/update.py version/<ver> ... --no-auto
```

单步调试：

```bash
python3 tools/fielddecode_auto.py version/<ver> \
    --draft version/<ver>/version.draft.json \
    --keyformulas version/<ver>/ida/keyformulas.auto.json

python3 tools/keyformulas_auto.py version/<ver> \
    --base version.json --values version/<ver>/ida/keyformulas.values.json

python3 tools/table_roles.py version/<ver> \
    --draft version/<ver>/version.draft.json \
    --ida version/<ver>/ida.json --base version.json --apply
```

> `fielddecode.auto.json` / `keyformulas.auto.json` 是 `update.py` 自动读取的中间产物；
> `json_coverage.py` 只用于最终 check，生成链不读目标 `version.json`。

### 5.9.1 `--slots` / `--ida` 这两个 JSON 怎么来

`update.py` 的两个输入不是手写的，都是目标版本自己的产物：

```text
version/<ver>/
├── slots.json   # slot_scan.py：MHY 原始槽位 + 全 .text 的唯一 (slot,op,key) 候选
└── ida.json     # ida_export.py：IDA 反编译出的 tables / fieldDecode / formulas
```

#### 1) `slots.json`

```bash
# ① 可选：先用 sig 命中函数（给 struct 级扫描 / IDA --fast 用）
python3 tools/sig.py scan version/<ver>/gi.exe \
    --sigs tools/sigs.json --fuzzy --slow \
    --json version/<ver>/sig_hits.json

# ② 扫 MHY 槽位 + 指令里的 (slot, op, key)
python3 tools/slot_scan.py \
    version/<ver>/gi.exe \
    version/<ver>/gi/Managed/Metadata/global-metadata.dat \
    --out version/<ver>/slots.json
```

产物大致是：

```json
{
  "svals": { "316": 123456789, ... },          // MHY[slot] 原始 4 字节
  "uniq":  [["316", "-", 12345, 命中次数, "0x140..."], ...]
}
```

`relocate.py` / `update.py` 用它做：
- 槽位提示（旧 slot 在新版是否还能唯一命中，**只当提示**）
- 值 → `(slot,op,key)` 反查（例如 typeDefs 基址）
- 字段级候选（可选）：

```bash
python3 tools/slot_scan.py \
    version/<ver>/gi.exe \
    version/<ver>/gi/Managed/Metadata/global-metadata.dat \
    --struct typeDef --hits version/<ver>/sig_hits.json \
    --struct-json version/<ver>/keys.json
# → version/<ver>/keys.json
```

#### 2) `ida.json`

必须在 **IDA + Hex-Rays** 里跑；无头模式：

```bash
# gi.exe 旁边有比 exe 新的 gi.i64 时会自动复用，省掉小时级分析
IDAT=/path/to/idat64 \
GI_TEXT=version/<ver>/ida/decomp \
tools/ida_headless.sh \
    version/<ver>/gi.exe \
    version/<ver>/ida.json \
    version/<ver>/sig_hits.json
```

也可以直接传 `.i64`：

```bash
tools/ida_headless.sh \
    version/<ver>/gi.exe.i64 \
    version/<ver>/ida.json \
    version/<ver>/sig_hits.json
```

GUI 方式：IDA → `File → Script file...` → `tools/ida_export.py`，
脚本参数填：

```text
version/<ver>/ida.json version/<ver>/sig_hits.json --fast
```

产物：

```json
{
  "mhy": "0x...",
  "tables":      [ { "slot": "...", "op": "...", "key": "...", "value": "...",
                     "funcs": [...], "strides": [...] }, ... ],
  "fieldDecode": [ { "width": "...", "disp": "...", "op": "...", "key": "...",
                     "funcs": [...] }, ... ],
  "formulas":    [ { "func": "...", "text": "..." }, ... ]
}
```

`--fast` 只反编译 sig 命中的函数；`GI_TEXT=...` 会把每个函数的 Hex-Rays 文本
立刻落盘到 `ida/decomp/`（IDA 在导出后崩溃也不丢）。

`tools/ida_wanted.txt` 里列了自动恢复必须覆盖的函数
（`TypeAttrGetter` / `GetTypeInfoFromIndex*` / `DefaultValue*` /
`SetupNestedLocked` / `IterNestedTypes` / `GetMethodInfo*` / `RuntimeInit`）。
`ida_export.py` 会从 `sig_hits.json` 自动把这些名字解析成 EA 并强制加入反编译列表。

也可以单独生成地址：

```bash
python3 tools/ida_wanted.py version/<ver>/sig_hits.json
python3 tools/ida_wanted.py version/<ver>/sig_hits.json --command
# --command 直接打印 ida_headless.sh 的完整命令
```

#### 3) 离线补漏（IDA 正则会漏掉 `int` / 变量中转）

```bash
python3 tools/offline_extract.py version/<ver>
# 重扫 ida/decomp/*.c，补 ida.json 的 tables
# 同时写 version/<ver>/ida/tables_extra.json（函数读序 → 表名）
```

补完后就可以跑：

```bash
python3 tools/update.py version/<ver> \
    --base version.json \
    --slots version/<ver>/slots.json \
    --ida   version/<ver>/ida.json
```

> `update.py` 的 `--slots` / `--ida` 可省略：
> 默认就是 `version/<ver>/slots.json` 和 `version/<ver>/ida.json`。
> 两个文件都不参与 C++ 生成，只是自动定位的输入。

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

## §5.11 大头分析：202 个值里哪些是大头、它们原来是怎么来的

### 5.11.1 占比

| 大头 | 数量 | 占 202 | 本质 |
|---|---|---|---|
| **`tables[].slot/op/key`** | **102** | **50.5%** | 34 张表 × 3 个任意常数 |
| **`keyFormulas`** | **43** | **21.3%** | 8 个 `key(i)` 公式的全部系数 |
| **`fieldDecode`** | **42** | **20.8%** | 8 个结构体 × 每字段的常数 |
| 计数公式 `key/op` | 6 | 3.0% | `(T0/T1 字段) op key` |
| `stringDecrypt` | 5 | 2.5% | 5 个常数 |
| `addresses` | 4 | 2.0% | 3 个 VA + 1 个常量 |
| **合计** | **202** | 100% | |

**前三个 = 187 个（92.6%）**，而且它们是**同一类东西**：从代码里抄一个任意常数。

### 5.11.2 它们原来是怎么找到的（逐个举例）

**(1) `tables[].slot/op/key`（102）—— Hex-Rays 表达式里抄 3 个数**

```
在 IDA 里找到读这张表的函数 → F5 → 看到：
    *(DWORD*)(global + *(_DWORD*)(MHY + 180) - 330781793 + 70LL*i)
                              └槽位 0xB4┘  └key 0x13B75461┘  └步长 70┘
→ 抄 slot=0xB4, op='-', key=0x13B75461
```

34 张表就是**重复 34 次**这个过程。全部是**人工抄**。

**(2) `keyFormulas`（43）—— 在"解名字"的函数里抄整段表达式**

```
GIMeta_SetupParameters 里：
    paramNameIndex = key ^ (raw - 2068375556 …)
    其中 key = ((1457992407*((41617*i+1219887025)^0x19E1D47A))>>21)+2068375556
→ 把这段拆成 A/B/xor/add/shift 抄进 keyFormulas.paramKey
```

8 个公式、43 个系数，全是人工抄。**7 处共用 `methodKey`**（最容易漏换）。

**(3) `fieldDecode`（42）—— 结构体读取函数里抄 `obj+K` 的表达式**

```
GIMeta_SetupTypeInfoLocked 里：
    *(DWORD*)(obj + 0x28) - 0x4159BB8E        → typeDef.flags
    *(WORD*)(obj + 0x3E)  - 26230             → typeDef.genericContainerIndex
```

其中 **`parentIndex` / `genericContainerIndex` 没有直接常数** ✗，
是用**锚点反解**出来的（`System.Enum`/`ValueType` 的已知父类、名字里的 `` `N ``），
见 §8 Worked example A/B。

**(4) 计数公式（6）/ 字符串（5）/ 地址（4）**

- 计数：反编译 `RuntimeInit` 的循环定界（`init_534B80.c:2064`）
- 字符串：反编译解密函数，读 `movabs` 和 `xor imm32`
- 地址：魔数 `"MHY\0"` + `RuntimeInit` 末尾的全局赋值

### 5.11.3 为什么这 92.6% 自动不了（实测证据）

| 思路 | 实测结果 |
|---|---|
| 数据侧结构指纹 | 这些表的内容是 `raw op key(i)`，**没有原始指纹** ✗ |
| `relocate ⑥` slot 提示（旧 slot） | 7.0：16/34"唯一"，**值全错** ✗（slot 会搬家） |
| `port.py` 指令对齐（fieldDecode） | 与 `--struct` 候选 **0/4 一致** ✗（字段读取被**内联**到几十处） |
| `port.py` 指令对齐（keyFormulas） | 24/43 能映射，但 `methodKey.xor→0x12`、`shift 16→8` ✗ |
| `port.py` 指令对齐（tables） | 5 个已知站点里 **3 个所在函数在 7.0 未被 sig 定位** ✗；typeDefs 的站点在**未命名函数** ✗ |
| 语义判据（flags/parentIndex…） | 不唯一（736/83 个候选）✗ |

**根因**：常数是**任意的**（没有数据侧含义）＋ 代码位置会漂 ✗ ＋ 内联 ✗。

### 5.11.4 所以"过 50%"只有两条路（都不保证成功）

| 路 | 需要什么 | 风险 |
|---|---|---|
| **A. 对齐做到"指令级 + 数据流"** | 函数边界（7.0 的 `.pdata` 被混淆 ✗）+ 编译器内联映射 ✗ | 高（本轮两次尝试都失败 ✗）|
| **B. `keyFormulas` 搜索器** | 用"解名字必须可打印"当目标函数，在候选系数里搜（组合爆炸）✗ | 中高 |

**现实上限**（当前技术）：全自动 **12~15%**，半自动 **~70%**，纯人工 ~15%。
要真过 50%，必须先攻下 **B**（43 个）→ 才有 `keyFormulas` 去**验证** tables 的候选 ✗。

## §5.12 IDA 脚本导出（**替代手抄**：`tools/ida_export.py` + `ida_apply.py`）

> 手抄那 102 个 `tables` 的时代可以结束了 —— 在 IDA **里面**跑脚本，
> 直接拿到 Hex-Rays 解出来的表达式 + IDA 的真实函数边界。

### 5.12.1 为什么必须进 IDA

| 外部 capstone 拿不到的 | IDA 里有 |
|---|---|
| 真实函数边界（7.0 的 `.pdata` 被混淆 ✗） | `idautils.Functions()` ✓ |
| 混淆被摊开后的表达式 ✗ | Hex-Rays `str(cfunc)` 直接是 `global + *(MHY+SLOT) OP KEY` ✓ |
| 全局变量名 ✗ | `qword_145AD52B8` ✓（能按"被当槽位表的次数"认出哪个是 MHY ✓）|

### 5.12.2 用法

**⚠️ IDA 不认识我们起的名字**：IDA 里只有 `sub_1404E3850` 这种；`GIMeta_*` 是我们用
`sig.py` 起的标签 ✗。所以两者用**地址**当桥：

```
sig.py scan --json /tmp/h.json        # (name -> VA)
ida_export.py                         # 输出 funcs=IDA名 + func_eas=地址
ida_apply.py --hits /tmp/h.json       # 用 (VA -> name) 把名字补上 -> 再查 table_funcs.json
```

```bash
# 0) 先跑 sig（离线，3 秒）
python3 tools/sig.py scan <exe> --sigs tools/sigs.json --fuzzy --json /tmp/h.json
# ① 在新版本的 IDA 数据库里：File → Script file…  选 tools/ida_export.py
#    产物：/tmp/ida_export.json
#      tables      : slot / op / key / **value**（已用 MHY 槽位解出来）/ funcs
#      fieldDecode : 每个 `*(_DWORD*(a1+K) OP KEY)` 候选
#      formulas    : 含大常数 + `>>` 的内联表达式原文

# ② 配对到表名（用 §5.10.3 的「函数 -> 表」映射）
python3 tools/ida_apply.py /tmp/ida_export.json --hits /tmp/h.json --out /tmp/tables.json
#    单表函数 -> 直接确定；多表函数 -> 列出候选（带 value，便于按值匹配）
```

`tools/table_funcs.json` 已内置 13 个函数 → 表的映射（来自 §5.10.3 实测）。

### 5.12.3 实测（样本）

```
IDA 导出 7 个 (slot,op,key)
→ 自动确定 3 张：eventsOffset / fieldsOffset / propertiesOffset  ✓
→ 需消歧 8 张：SetupTypeInfoLocked 读了 5 张、SetupMethodsLocked 读了 3 张 ✗
```

### 5.12.4 消歧顺序（多表函数）

```
1. 如果该表的值已被 ④/⑧ 自动检测到  -> 按 value 精确匹配 ✓（最硬）
2. 如果该表是**计数** -> value/步长 应 ≈ 上一版的计数（§5.10.7 手段 3）✓
3. 如果该表在多个函数里被读（n_funcs 大）-> 优先给"核心表"（methods/fields…）✓
4. 都不行 -> 看 value 是否落在元数据范围内 + 人工确认（1 分钟）
```

### 5.12.5 这对自动化率意味着什么

| 之前 | 现在（**实测后更正**）|
|---|---|
| 102 个全手抄 ✗ | 导出 **69%** 的表常量 ✓；但**自动配对 = 0 张** ✗（见 §5.12.9）|
| 找不到函数边界 ✗ | IDA 直接给 ✓ |
| 不知道哪个全局是 MHY ✗ | 按"被当槽位表的次数"自动认 ✓ |

> ⚠️ 仍然**不是 100% 自动**：多表函数（`SetupTypeInfoLocked` 5 张、`RuntimeInit` 7 张）
> 需要 value/计数 消歧 ✗；而且这要求**跑 IDA**（不是纯离线）✗。

### 5.12.6 会不会误判？—— 会，这是**全部**已知误判点和对应守卫

| # | 误判点 | 后果 | 守卫 |
|---|---|---|---|
| 1 | **MHY 地址认错**（`"MHY\0"` 碰巧出现在别处） | 所有 `value` 变垃圾 ✗ | 导出后检查：**≥1/3 的值要落在 [0x1000, 0x8000000)**，否则打 `⚠⚠ MHY 可能认错` ✓ |
| 2 | **全局变量认错**（把别的结构体表当 MHY） | slot/key 全错 ✗ | 按「被当作槽位表的次数」排序，取第一 ✓（MHY 有 ~34 组，别的很少）|
| 3 | **正则过抓**（同一函数里别的表的 `[obj+K] OP K2`） | 候选里混入假项 ✗ | 多候选时**不自动确定** ✓，只列出来 ✗ |
| 4 | **`table_funcs.json` 映射写错**（我人工整理的那张表） | 张冠李戴 ✗ | 结果标 `[single-candidate(中)]` / `[value-match(最强)]`，**必须**用 `relocate`/`verify.py` 复核 ✓ |
| 5 | **函数名对不上**（IDA 只有 `sub_xxx`） | 全部配不上 ✗ | **地址桥**：`--hits /tmp/h.json` ✓（已修 ✓）|
| 6 | 同一函数读多张表（`SetupTypeInfoLocked` 5 张、`RuntimeInit` 7 张） | 无法自动分配 ✗ | 列候选 + `value` 供人工/`--detected` 匹配 ✓ |

### 最终闸门（任何"建议"都必须过）

```bash
python3 verify.py <root>        # 28 项；任何表/字段错了都会在这里 FAIL
python3 tools/relocate.py <root>  # ⑤ 会把「探测值 vs version.json」逐表对照
```

**原则**：`ida_apply.py` **只输出建议**（带置信度），**从不直接改 `version.json`** ✓ ——
宁可多一步人工确认，也不静默写错 ✗。

### 5.12.7 无头模式（不需要 GUI）：`idat64 -A -S`

```bash
# 直接跑（IDAT 默认 idat64，可用环境变量覆盖）
tools/ida_headless.sh version/7.0/gi.exe /tmp/ida70.json /tmp/h70.json
# 等价于：
idat64 -A -S"tools/ida_export.py /tmp/ida70.json /tmp/h70.json" version/7.0/gi.exe
```

**⚠️ 全量反编译是**没用的**（431MB 有 ~58 万函数，小时级 ✗，而且抓到也没法贴标签 ✗）**

> 关键认识：`ida_export` 只是**把表达式抓出来** ✗ —— 它**不知道** `*(_DWORD*)(MHY+0xB4)-0x13B75461`
> 是哪张表 ✗。**"这是哪张表"只能来自两处**：
> ① **函数名**（`table_funcs.json` ✓，已覆盖 28/29 张表 ✓）
> ② **值**的结构自证（`relocate ④` ✓，只有 6~7 张 ✓）
>
> 所以：**抓 5000 个没标签的表达式 = 0 收益** ✗。全量唯一有用的场景是"你愿意自己给每个表达式贴标签" ✗。

**54 个 sig 函数到底覆盖多少（实测）**

```
table_funcs.json: 13 个函数 -> 覆盖 28 / 29 张有步长的表 ✓（只差 fieldOffset）
  其中 7 个**单表函数** -> 可**全自动** ✓
       6 个**多表函数** -> 只能给候选 ✗
       （SetupTypeInfoLocked 5 张、RuntimeInit 7 张、SetupMethodsLocked 3 张 …）
```

**⚠️ 别全量反编译（431MB 有 ~58 万函数，小时级 ✗）**

```bash
# 默认就是 --fast：只反编译 sig 定位到的 54 个函数（秒级 ✓）
tools/ida_headless.sh ida/gi.exe.i64 /tmp/ida.json /tmp/h.json

# 未命名函数里的读取点（例如 7.1 的 typeDefs 在 0x1404B1588）显式加进来
tools/ida_headless.sh ida/gi.exe.i64 /tmp/ida.json /tmp/h.json 0x1404B1588

# 真要全量（小时级）
IDA_FULL=1 tools/ida_headless.sh ida/gi.exe.i64 /tmp/ida.json /tmp/h.json
```

> **为什么默认不全量**：`ida_hexrays.decompile()` 每个函数都要跑一次；
> 58 万个函数是**小时级** ✗。而 §5.10.3 的读取点**绝大多数**都在 sig 能定位的函数里 ✓，
> 只有少数（如 typeDefs）在未命名函数 ✗ —— 那些用 `0x...` 显式指出来即可 ✓。

- `-A` = autonomous（不弹对话框）✓
- `ida_export.py` 检测到批处理模式会 `qexit(0)` 自动退出 ✓
- 输出路径 / sig 命中表都由 `-S` 的参数传进去 ✓

**✅ 复用已分析的数据库（省掉小时级分析）**

`idat64` 的输入可以直接是 **`.i64` / `.idb`** ✓：

```bash
tools/ida_headless.sh version/7.0/gi.i64 /tmp/ida70.json      # 直接给数据库
tools/ida_headless.sh version/7.0/gi.exe  /tmp/ida70.json     # 自动找同目录 gi.i64
```

包装脚本的规则：
- 传 `.exe` 且同目录有**比 exe 新的** `gi.i64` → 自动改用它 ✓
- `.i64` 比 exe **旧** → 打印 `⚠ … 可能触发重建，很慢` ✓（但不会中止）
- 传 `.i64` 就直接用 ✓

**⚠️ 时间陷阱**

| 情况 | 耗时 |
|---|---|
| 首次对 `gi.exe`（431MB）自动分析 | **小时级** ✗ |
| 已有分析好的 `.i64` / `.idb` | 分钟级 ✓ |

建议：**先手动分析一次并存库**（IDA → File → Save database），之后每次换代：
```bash
# 新样本仍需分析一次；老样本/重跑时直接复用 .i64
tools/ida_headless.sh <新样本.i64 或 exe> /tmp/ida.json /tmp/h.json
```

**⚠️ 授权**：脚本调用 Hex-Rays `decompile()` → 需要 **反编译器授权** ✓
（没有的话 `ida_export.py` 会直接打印 `✗ Hex-Rays 不可用` 并退出 ✓）。

### 5.12.8 多表函数怎么自动消歧（21 张候选的正解方向）

`SetupTypeInfoLocked` 读了 5 张、`RuntimeInit` 读了 7 张 —— 只靠"函数名"分不开 ✗。
但 **Hex-Rays 的伪代码里有 3 条额外线索**（都能自动抓）：

| 线索 | 长什么样 | 能区分什么 |
|---|---|---|
| **步长** | `*(int *)(v25 + 6 * idx)` | 6 字节表（interfaces/methodSlot）vs 8/4 ✓ |
| **被调函数** | `sub_1404E3CC0(v25 + 8 * idx, ...)` | 交给谁解析 → 用途 ✓ |
| **常量用法** | `if (v25 == -1) / v25 >= 0x10000` | 哨兵/值域 ✓ |

**实现方式**（还没做）：
```python
# 1) 抓 LHS：v25 = ... + *(_DWORD *)(MHY + 452) - 1518027399
RE_ASSIGN = re.compile(r'(\w+)\s*=\s*[^;\n]*' + RE_TABLE.pattern)
# 2) 找该变量被怎么用：v25 + <N> * 或 (v25 + ...)
RE_USE    = re.compile(r'\b(\w+)\b\s*\+\s*(\d+)\s*\*')
# 3) 输出 {slot,op,key,value,funcs,stride,callee}
```

然后 `ida_apply.py` 用 **`(stride, callee)` 匹配 §5.10.3 的期望**：
- `stride == 6` → `interfacesTable` / `methodSlotTable` ✓
- `callee == GetFieldName` → `fields` ✓
- 剩下的才落到人工 ✗

> 这是目前**唯一**能把那 21 张候选自动收掉大半的路 ✓（全量抓表达式没用 ✗，因为没有标签来源）。

### 5.12.9 实测结果（7.1，IDA 9.4，`--fast`）—— 诚实版

```
输入: ida/gi.exe.i64 + /tmp/h71.json
输出: /tmp/opencode/ida71.json（55 KB）
      mhy = 0x1427D4BD0   mhy_global = p_MHY_Table
      tables 32 条 / fieldDecode 68 条 / formulas 182 条
```

| 指标 | 实测 |
|---|---|
| **召回** | **20 / 29 张表 = 69.0%** ✓（slot/op/key **20/20 全对** ✓）|
| 未导出 | 9 张：`events` `fDV` `genericClassRange` `genericContainers` `genericParameters` `methodPointerIndex` `methodSpecs` `pDV` `parameters` ✗ |
| 误报 | 12 条（多数是 **version.json 没登记的真表**，如 `stringLiteralDataOffset` 0x444C1E8 ✓）|
| **自动配对（安全模式）** | **0 张** ✗ |
| 自动配对（允许"只剩一个候选"） | 7~9 张，但**实测有错** ✗（见下）|

**"只剩一个候选就采用"为什么会张冠李戴**（实测）：

```
fieldDefaultValuesOffset  真值 slot 0x13C，但该读取点没被导出
                          -> 只剩一个错候选 slot 0x54 -> 被"自信地"采用 ✗
interfacesTable           真值 slot 0x1C4
                          -> 被分到 slot 0x140（那是 methodSlotTable）✗
parametersOffset          -> 被分到 slot 0x16C（那是 methodsOffset）✗
```

**结论（必须写清）**：

1. `ida_export.py` 的**价值**是：**确认** `relocate ④/⑧` 已找到的表 ✓ + 提供**带 value 的候选** ✓
2. 它**不能**单独把 `tables` 自动化 ✗ —— 因为**"这是哪张表"必须来自第二个独立证据**（结构自证/语义），
   而"函数名 + 只剩一个候选"**不是独立证据** ✗
3. 所以**全自动率没有提高**（仍是 7.1 ≈13%、7.0 ≈9.4%）✗
4. `ida_apply.py` 默认 **`--allow-guess` 关闭** ✓ —— 只输出候选，不冒充"已确定" ✓

> 这一节是**负结果**，但它避免了一个更坏的结局：**静默写错 5~7 张表** ✗。

### 5.12.10 「函数内读取顺序」贴标签（唯一可能到 ~45% 的路，但**未验证**）

**为什么它可能成立**：`SetupTypeInfoLocked` 里读 5~8 张表，**源码里的先后是逻辑顺序**：

```
interfacesStart -> methodSlotTable -> attributesInfo -> attributeTypes -> ...
```

`ida_export.py` 现在把每条记录的 **`seq`**（在 Hex-Rays 文本里的位置）也导出了 ✓。

**做法（已实现）**：

```bash
# 旧版本（我们知道真值）: 学「函数 -> [表名, 按 seq 排序]」
python3 tools/ida_apply.py <新导出.json> --hits <新hits.json> \
        --order <旧导出.json>
```

`ida_apply.py` 会：
1. 用旧版本的真值把旧导出的 `(func, seq)` 映射成表名 ✓
2. 得到 `{函数: [表名...]}` ✓
3. 对新版本：把同一函数导出的条目**按 seq 排序**，**逐位**赋给学到的表名 ✓

**实测（机制自测，2026-10-17）**

用 7.1 自己当"旧版本"学顺序 → 再对 7.1 自己分配：

```
=== 已确定 20 张表 ===   （全部 [order-match(学自旧版顺序)]）
  attributeTypesOffset  0xD8   ✓      methodsCount        0x188 ✓
  attributesInfoCount   0x198  ✓      methodsOffset       0x16C ✓
  attributesInfoOffset  0x24   ✓      nestedTypesTable    0x5C  ✓
  fieldOffset           0x204  ✓      parameterDefaultValuesCount 0x9C ✓
  fieldsOffset          0x18C  ✓      propertiesOffset    0x150 ✓
  genericMethodTable    0xC0   ✓      typeDefinitionsCount 0xE0 ✓
  genericMethodTableCount 0x130 ✓     typeDefinitionsOffset 0xB4 ✓
  genericTypeArgOffset  0x180  ✓      imagesCount         0x2C  ✓
  imagesOffset          0x20C  ✓      interfacesTable     0x1C4 ✓
  methodSlotCount       0x1FC  ✓      methodSlotTableOffset 0x140 ✓
→ 20 / 20 全对 ✓✓
```

**踩过的两个坑**（都已修）：
1. 学习顺序时**跳过**"没有真值"的条目 → 位置整体错位 ✗ → 必须保留 `None` 占位 ✓
2. `funcs` 里有**重复函数名**（`['A','A']`）→ 同一条目被加两次 → 位置翻倍 ✗ → 必须 `set()` 去重 ✓

**✅ 跨版本验证（capstone，`tools/cmp_funcs.py`，2026-10-17）**

不需要 IDA：直接把 7.1/7.0 的同名函数反汇编 + 对齐 + 比较**槽位读取顺序**：

| 函数 | 指令 7.1/7.0 | 相似度 | 槽位读取 | 顺序 |
|---|---|---|---|---|
| `RegisterTables` | 15530/15530 | **1.000** | 4031/4031 | ✅ 单调 |
| `IterNestedTypes` | 6719/6739 | 0.986 | 714/716 | ✅ |
| `RuntimeInit` | 7962/7978 | 0.973 | 804/801 | ✅ |
| `SetupPropertiesLocked` | 1575/1579 | 0.973 | 135/135 | ✅ |
| `AllocTypeInfoArray` | 3462/3448 | 0.964 | 359/359 | ✅ |
| `SetupEventsLocked` | 1853/1869 | 0.961 | 175/175 | ✅ |
| `SetupParameters` | 2046/1969 | 0.955 | 237/224 | ✅ |
| `SetupMethodsLocked` | 2314/2330 | 0.942 | 222/222 | ✅ |
| `SetupFieldsLocked` | 4123/4169 | 0.924 | 452/467 | ✅ |

**9/9 可比函数顺序全部保持单调** ✓✓ —— **`seq` 稳定性的假设得到支持** ✓

> ⚠️ 但**读取条数会变**（如 fields 452→467、parameters 237→224）✗
> → **不能按绝对序号对齐** ✗；已改成**序列对齐**（`difflib.SequenceMatcher`，
> 元素身份 = `strides`）✓

**序列对齐后自测（7.1 → 7.1）**：

```
=== 已确定 20 张表 ===   [order-match(序列对齐)]
=== 需要消歧 5 张 ===     （绝对序号法时是 9 张 ✗）
→ 20/20 全对 ✓
```
> 未定位的 4 个函数（`SetupTypeInfoLocked` / `GetFieldDefaultValue` /
> `GetDefaultParameterValueObject` / `BuildMethodName`）在 7.0 上 sig 没命中 ✗，无法比较 ✗

**⚠️ 未验证的关键假设**：**跨版本时 `seq` 顺序是否稳定** ✗
- 支持：源码逻辑顺序不变 ✓、代码结构相似（48/54 函数 8/8 命中）✓
- 反对：优化器可能**重排/拆分/内联**读取 ✗
- **需要**：7.0 的 `.i64` 跑一次同样导出，对照真值才能确认 ✗

**如果成立，收益**：`SetupTypeInfoLocked`(8) + `RuntimeInit`(12) + `SetupMethodsLocked`(3) 等
多表函数能自动配 → 全自动从 **0/20** 提到 **~20/29** ✓
→ 按值算 ≈ **+60 个**，全自动率 **13% → ~43%** ✓（接近目标 50% ✓）

### 5.12.11 合并账（relocate ∪ IDA）—— 7.1 实测 **107 / 202 = 53.0%**

| 来源 | 内容 | 数量 |
|---|---|---|
| `relocate ④/⑧/⑦` | 9 张表（fDV / methodPtr / methodSlot / attrinfo / blob / typeDefs / nestedTypes / interfaces / pDV） | 9 |
| `ida_apply --order` | 20 张表（含 5 张与上重叠） | 20 |
| **并集** | **24 张 × 3 = 72** ✓ | 72 |
| `relocate ①` | MHY 地址 | 1 |
| `sig.py consts` | 字符串密钥 5 | 5 |
| `relocate ⑧` | typeDef 字段 6（fieldStart/count、methodStart/count、nameIndex、namespaceIndex） | 6 |
| `ida_formulas` | keyFormulas **5/8** 公式的系数（method3+field5+property5+event3+container7） | 23 |
| **合计** | | **107 / 202 = 53.0%** ✓ |

**重叠只有 5 张**（`attrinfo` / `interfaces` / `methodSlot` / `nestedTypes` / `typeDefs`）——
`relocate` 独有的 4 张（fDV / methodPtr / pDV / **blob**）IDA 没导出 ✗；
IDA 独有的 15 张 `relocate` 检测不出 ✓。**两者互补** ✓。

**⚠️ 这个 53% 的前提**（必须写在旁边）：

1. `ida_apply --order` 的**跨版本顺序稳定** —— capstone 已验证 **9/9 单调** ✓，
   但 **7.1→7.0 的端到端**还要一次 7.0 导出才能拍板 ✗
2. `keyFormulas` 只覆盖 **5/8** 公式（23 系数）✗
3. **7.0 的实际数字未知** ✗ —— 因为 4 个读表函数在 7.0 上 sig 没定位
   （`SetupTypeInfoLocked` / `GetFieldDefaultValue` / `GetDefaultParameterValueObject` /
   `BuildMethodName`）→ 那 10 张表会掉 ✗ → 估计 **~44%**

### 5.12.12 试过「纯 capstone 版」（不用 IDA）—— **失败** ✗

`tools/order_apply.py`：用 `PROVENANCE.md` 里 7.1 的**读取指令地址**做锚，
指令级对齐到 7.0，再按形态取 `(slot,key)`。

**结果（7.0，已知 6 张真值）**：

```
fieldDefaultValuesOffset  0xC ^ 0x720EB389   ✅（唯一对上的）
其余 28 张                  ✗ 没推出来
（宽松版 ±3 条乱抓时能出 9 个，但含明显错的：typeDefinitionsCount 0x6C + 0xFFFFFFFF ✗）
```

**根因**：**指令形态会变** ✗

```
7.1: mov esi, 0xec48ab9f ; add esi, [rdx+0xb4]        ← 形态 B
7.0: movsxd rsi,[rdx+0x1a0] ; xor rsi,0x4ce7b502      ← 形态 A
```

形态一变 → **token 不同** → `SequenceMatcher` 不认为这两条是"同一位置" ✗
→ 位置锚失效 ✗ → 只能退回"按函数内第 k 个读取"的**序数**对齐 ✗（脆弱 ✗）

**结论**：**IDA 的 Hex-Rays 不是可选项** ✓ —— 它把不同形态**归一成同一个表达式**
（`*(DWORD*)(MHY+slot) op key`）✓，这正是 `ida_export` 能 20/20 的原因 ✓。

> 所以「7.0 不跑 IDA」这条路**走不通** ✗；
> 要么给 7.0 的 `.i64`（分钟级 ✓），要么花几小时让 IDA 分析 7.0 的 exe ✗。

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

---

## §14 签名扫描：7.0 **54/54 全自动**（2026-10-17 实测）

### 14.1 结论

```
无缓存（全新扫描）：  54/54    ~19s
有缓存（同目录缓存）：54/54    0.5s
缓存文件：version/7.0/sig_hits.json   ← 扫描自己能生成，不是手写
```

**4 个曾经漏掉的函数，现在默认扫描就能出**：

| 函数 | 7.0 地址 | 判定证据 |
|---|---|---|
| `SetupTypeInfoLocked` | `0x1404E3DB0` | 17 个 callee 命中 10（第二 4）；大小 0x173F vs 7.1 0x171F；序言 `lea rbp,[rsp+0x80]; mov [rbp+0x20],-2` 一致 |
| `GetMethodInfoFromIndex` | `0x1404EE2E0` | 序言逐条一致：`lea rbp,[rsp+0x30]`→`mov [rbp-8],-2`→`movsxd r14,ecx`→`mov rax,[rax+r14*8]` |
| `GetDefaultValue` | `0x1404F43F0` | 调用序列与 7.1 一字不差：`GetMethodInfoFromIndex → DecryptString → GetTypeInfoFromIndex ×3 → DecodeDefaultValue` |
| `GetDefaultParameterValueObject` | `0x1404F8920` | 与 7.1 逐条同构（flag 检查 → 取方法索引 → `-1` 判断 → 计数 `/12` 取 pDV），且**全 .text 只被调用 1 次**（7.1 也是 1 次）|

### 14.2 新增的第四轮：**结构锚**（默认开启）

前三轮（字节模式 / 三段投票 / 模糊调用图）为什么不够：

- 这 4 个函数的寄存器分配、flag 掩码、结构偏移都变了 → 8 条连续字节签名必灭 ✗
- 但它们的**某几条指令没变**，例如 `movzx eax,[rcx+0x2f]` 在两版都是 `0f b6 41 2f` ✓

做法（`_struct_fallback`）：

```
① 取签名前 6 条指令的**原始字节**，每条找最长固定段 >= 4 字节当种子
② 每个命中推回「签名窗口起点」= hit - 前面指令的字节偏移
③ 在窗口起点做 8+ext 全序列打分（loose + ext_loose）
④ 回退到**函数起点**：前面 >=2 个连续 0xCC，且从该点反汇编能正好走到窗口起点
⑤ 按函数起点去重；要求 (loose+ext) >= n+en-6、loose >= n-2、领先第二名 >= 2
```

实测代价：每个未命中签名 0.2–1.2s；7.0 共 8 个走这条路，总计约 +5s。

### 14.3 缓存的定位

`sig_hits.json` **不是手工答案**，是扫描产物：

```bash
# 删掉缓存也能重算（验证过：54/54，19s）
rm version/7.0/sig_hits.json
python3 tools/sig.py scan version/7.0/gi.exe --sigs tools/sigs.json --fuzzy

# 确认后写回缓存，下次 0.5s
python3 tools/sig.py scan version/7.0/gi.exe --sigs tools/sigs.json --fuzzy \
        --json version/7.0/sig_hits.json
```

### 14.4 关于「4 对次序反转」

7.0 实测：1431 对里 4 对反转，全部涉及 `GetDefaultParameterValueObject`。
这是**真实的函数重排**（7.0 把它放在 `SetupParameters` 前面，7.1 在后面），不是地址错。
其余 1427 对单调 ✓。

### 14.5 用法

```bash
# 默认（快，有缓存）
python3 tools/sig.py scan version/7.0/gi.exe --sigs tools/sigs.json --fuzzy

# 无缓存全自动
rm -f version/7.0/sig_hits.json && python3 tools/sig.py scan ... --fuzzy

# 最后兜底（--slow：立即数种子 + callee 指纹），一般用不到
python3 tools/sig.py scan ... --fuzzy --slow
```

---

### 14.4 IDA 函数表 + sig gen / sig scan（2026-10-18）

目标：不再只看函数头 8 条；用 IDA 的真实函数边界生成/验证签名。

#### 导出函数表（只导已知函数，不做全量）

```bash
# 在 IDA 里（GUI Script file 或 MCP py_eval）
GI_HITS=/.../version/7.0/sig_hits.json
GI_FUNCS_OUT=/.../version/7.0/funcs_wanted.json
exec(open('/.../tools/ida_funcs_export.py').read())
```

输出只包含 `GI_HITS` / `GI_NAMES` 里的函数：

```json
{"funcs": [{"name","start","end","size","thunk","jmp_target","callees"}]}
```

#### 生成签名

```bash
python3 tools/sig.py gen version/7.0/gi.exe \
    --names /tmp/opencode/sig_names70.txt \
    --windows 1
```

`sig.py gen` 现在会：

- 自动在 exe 同目录找 `funcs_wanted.json`
- 用真实 `start/end`
- 遍历整个函数体，选“固定字节多、有 call/imm/mem”的最佳窗口
- 跳过 `ret/jmp/int3` 窗口
- `--windows N` 可输出 `name__w0..wN`

输出示例：

```text
using function table: version/7.0/funcs_wanted.json
生成 54 条签名
```

#### 扫描

```bash
# 默认：快（约 1.5s）
python3 tools/sig.py scan version/7.1/gi.exe \
    --sigs version/7.0/sigs.json --json version/7.1/sig_hits.json

# 准确模式：targeted rescue（约 14s）
python3 tools/sig.py scan version/7.1/gi.exe \
    --sigs version/7.0/sigs_features.json --features \
    --json version/7.1/sig_hits_targeted.json

# 打印各阶段耗时
python3 tools/sig.py scan ... --timing
```

- `--callee-recall`：遍历所有 `.pdata` 函数起点做 call 图（约 50s）
- `--features`：只扫描调用 reference callee 的候选 + 特征匹配（约 14s）
- `--timing`：打印 `load / byte scan / ambiguity / fuzzy / targeted rescue` 耗时

#### 当前 7.1 实测

```text
纯扫描 + targeted rescue     50 / 55 一致
纯扫描 + callee recall       49 / 55 一致
用旧 7.1 地址修正的表         54 / 55 一致
```

仍错：

```text
GIMeta_GetMethodInfoFromIndex  0x140524E80 vs 0x14051D330
GIMeta_SetupEventsLocked       0x141F214C2 vs 0x140514CF0
```

仍缺：

```text
GIMeta_GetDefaultValue
GIMeta_GetFieldDefaultValue
GIMeta_GetTypeInfoByIndex
```

#### 注意

- `_pdata` 有 decoy：`0x141F214C77`/`0x141F214C2` 在 `.pdata` 里但不是真函数；`0x1402F2910` 是真 `RegisterTables` 却不在 `.pdata`。所以 `.pdata` 只能当候选，不能当真理。
- 全量 feature/callee 每次重新算会慢；默认关闭。后续应缓存 `func_features.json` / `callgraph.json`。
- `sig_group.py` / `sig_refine.py` 是实验脚本，未接入主链。

## §15 7.0 字段定位记录（2026-10-17，方法 + 验证）

> **规则（以后每新增一个字段都按这个格式记）**
> 1. 版本 / 字段 / 值
> 2. **在哪找到**（函数名 + VA + 反编译行 / 数据偏移）
> 3. **怎么找到的**（导出 `fieldDecode` 列表 / keyless 哨兵反解 / 差分连续性 / 可打印字符串 / 结构自证）
> 4. **怎么验证的**（通过率 / 样本数）
> 5. 置信度（confirmed / likely / 待定）
> 弯路也记，避免下次重复。

### 15.1 表偏移（7.0）

| 表 | 7.0 值 | 槽位/解码 | 怎么找到 | 验证 |
|---|---|---|---|---|
| `propertiesOffset` | `0x0` | slot `0x64` `+0xFA496C14` | 反汇编 `SetupPropertiesLocked` 0x1404E6521 | 属性名 **1823/1823** |
| `fieldOffset` | `0x39AA940` | slot `0x138` `^0x350FE3C2` | 反汇编 `SetupFieldsLocked` 0x1404E4110（`and 0x1FFFFFFF / 0xE0000000`）| 静态标志结构 40/40 |
| `fieldsOffset` | `0x3E2FD44` | slot `0x1D0` `+0xE2FD458E` | 反汇编 0x1404E3C0A + 0x1404E3C30 | 字段名 **1981/1981** |
| `fieldDefaultValuesOffset` | `0x3DCE880` | slot `0x110` `-0x7B761D0A` | 结构扫描：12B 记录、fieldIndex 在 **+8** | count **24,792**，严格递增 |
| `parameterDefaultValuesOffset` | `0x1022CA8` | slot `0x0C` `^0x720EB389` | 结构扫描：12B、paramIndex 在 +0 | 首字段 `0,4,8,…` 29/29 |
| `imagesOffset` | `0x3CA2F0`（startup）| slot `0x14` `^0x495C7A75` | 反编译 `RuntimeInit`：`v122 = qword_145897168 + (MHY[0x14]^0x495C7A75)`；名字在 **+8** | 程序集名 **12/12**（`mscorlib.dll`…）|

**关键教训**
- 7.0 的 `Il2CppFieldDefaultValue` 字段顺序是 `{typeIndex,dataIndex,fieldIndex}`（7.1 是 `{fieldIndex,dataIndex,typeIndex}`）；`-1` 是 **typeIndex**，不是 fieldIndex。
- 7.0 的 `Il2CppParameterDefaultValue` 是 `{parameterIndex,typeIndex,dataIndex}`（7.1 是 `{parameterIndex,dataIndex,typeIndex}`）。
- `imagesOffset` 是 **startup 偏移**，基址是 `qword_145897168`，不是 `g_Metadata_Base`。

### 15.2 公式（7.0）

| 公式 | 值 | 怎么找到 | 验证 |
|---|---|---|---|
| `imageKey` | `(((899978779*((18582*i)^0x1A32087B))>>11)+1714073770)^0x6688B322` | 反编译 `RuntimeInit` 的 `v125` | 图像名 12/12 |
| `fieldKey` | 原公式 + **索引偏置 `0x1E6871E4`** | 反编译 `SetupFieldsLocked`：表用 decoded 索引，key 用 raw fieldStart | 字段名 **1981/1981** |
| `eventKeyAccessor` | `((-12735*i)^0x7723)-16191` | 反编译 `SetupEventsLocked` 的 `v31/v32/v33` | add 2000/2000、remove 2000/2000、raise 1375/1375 |
| `eventKey` | `((-951857599*i)^0x614E7723)+398639297` | 反编译 `SetupEventsLocked` `v26` | 事件名 591/739 |

### 15.3 fieldDecode（7.0）

| 结构.字段 | 偏移 | 解码 | 怎么找到 | 验证 |
|---|---|---|---|---|
| `event.typeIndex` | +0 | `-740753572` | `SetupEventsLocked` `v28` | add/remove/raise 联动通过 |
| `event.nameIndex` | +4 | `^0x71EEBABF` | 同上 `*(v25-4)` | 591/739 |
| `event.add` | +8 | `^0x74A4` | 同上 `v31` | 2000/2000 |
| `event.remove` | +10 | `^0xEBDA` | 同上 `v32` | 2000/2000 |
| `event.raise` | +12 | `-14096` | 同上 `v33` | 1375/1375 |
| `method.parameterStart` | +12 | `-11222` | `SetupMethodsLocked` 0x1404E5978 | 与 `typeDef.methodStart` 联动 |
| `method.flags` | +18 | `^0xEF3B` | 同上 `v17+21` | — |
| `method.iflags` | +22 | `-5486` | 同上 `v17+20` | — |

### 15.4 typeDef（7.0，表 `0x1986BEC`，步长 70，N=86,932）

| 字段 | 偏移 | 解码 | 怎么找到 | 验证 |
|---|---|---|---|---|
| `propertyStart` | +0x20 | `-0x6AE4E32A` | keyless 累计索引（`sub`）| mono=1.0, max 112,948 |
| `methodStart` | +0x24 | `-0x42C81546` | 同上 + 导出 `fieldDecode`（`GetMethodNameFromIndex`）| mono=1.0, max 713,953 |
| `fieldStart` | +0x2C | `-0x1E6871E4` | 同上 + 连续性 | **73,625/73,625** |
| `eventStart` | +0x32 | `-0x53B6` | 导出 `fieldDecode`（`SetupEventsLocked`）| mono=1.0, max 623 |
| `method_count` | +0x36 | `+0x28` | 差分反推 key | **75,924/75,924** |
| `field_count` | +0x3C | `-0x8B` | 导出 `fieldDecode`（`SetupFieldsLocked`）| **73,580/73,580** |
| `property_count` | +0x40 | `^0xCA` | 导出 `fieldDecode`（`SetupPropertiesLocked`，被误读成 QWORD）| **29,679/29,679** |
| `event_count` | +0x42 | `+0x09` | 差分反推 key | **221/221** |

**怎么找到的（可复用流程）**
1. `sig.py scan` 找回 7.0 函数（54/54），IDA MCP `rename` 成 `GIMeta_*`。
2. 反编译 `SetupTypeInfoLocked` / `SetupEventsLocked` / `SetupFieldsLocked` / `SetupPropertiesLocked`，过滤带常量的行。
3. 同时看 **7.0 导出的 `fieldDecode` 列表**：每条是 `(width, base, disp, op, key, funcs)`；`(disp, op)` 稳定，`key` 就是 7.0 值。
4. 没有导出的字段用 **keyless 哨兵反解**：取列里最常出现的 raw `v*`：
   `xor: K=~v*` / `add: K=-v*` / `sub: K=v*+1`。
5. 累计索引用 **单调性**；计数用 **相邻 start 差分反推 key**（不能用"最常见值"，0/1 会抢 mode）。
6. 表长用 **连续性校验**：`fieldStart[i+1]-fieldStart[i]==field_count[i]`（跳过 `-1` 无字段类型）。

### 15.5 本轮弯路（不要重复）

- **不要在新版本里搜旧版本的常数**：7.0 代码里搜 `1145778368/1995389561/72511848/0x4D8127F2` 全部 0 命中。
- **`fieldDecode` 是列表，不是字典**；`(width, disp, op, key, funcs)` 才是完整信息。
- **计数器不能用 mode 反解**：`method_count` 的 mode 是 0/1，不是哨兵；要用差分。
- **导出会把 u8 读成 QWORD**（`+0x40 ^0xCA`、`+0x44 ^0xFD`），别被 `width` 误导，按结构实际宽度用。
- **`-1` 不是表尾**：类型可以整段 `fieldStart=-1`（无字段），连续性要跳过它们。

### 15.6 还没定位的 typeDef 字段（10 个）

`namespaceIndex` / `nameIndex` / `parentIndex` / `flags` / `unknown20` / `genericContainerIndex` / `interfacesStart` / `interfaces_count` / `nestedTypesStart` / `nestedTypesCount`

- `nameIndex` / `namespaceIndex`：可打印字符串反查（entry = off|len<<24）
- `parentIndex`：Il2CppType 索引簇
- `flags`：TYPE_ATTRIBUTE 位分布
- `interfaces*` / `nestedTypes*`：`+0x3E ^0x1DE4`、`+0x41 +0x5A`、`+0x44 ^0xFD` 候选待定

### 15.7 `Il2CppTypeDefinition` struct 偏移通用化（2026-10-17）

- `version.json` 与 `version/7.0/version.json` 新增 `structOffsets.Il2CppTypeDefinition`。
- 7.1 偏移来自 `docs/gi_fields.md §3`；7.0 已确认 8 个（见 §15.4），其余 10 个**暂用 7.1 占位**。
- `src/il2cpp_image.hpp` 新增：
  `tdI32 / tdU32 / tdI16 / tdU16 / tdU8`，dumper 里所有 `typeDefinition->字段` 改为按 JSON 偏移读。
- `Il2CppTypeDefinition` 结构体成员保留但不再使用（只用于 `sizeof` 断言）。
- 7.0 生成的偏移：
  `propertyStart=0x20, methodStart=0x24, fieldStart=0x2C, eventStart=0x32,`
  `method_count=0x36, field_count=0x3C, property_count=0x40, event_count=0x42`。
- **验证**：7.1 dump md5 `e401b680…` 不变；`verify.py` **28/28 PASS**。
- **注意**：7.0 剩余 10 个字段的偏移仍是占位，dump 会读错；定位后**只改 JSON**，不用动代码。

### 15.4b typeDef 名称字段（2026-10-17）

| 字段 | 偏移 | 解码 | 怎么找到 | 验证 |
|---|---|---|---|---|
| `namespaceIndex` | `+0x08` | `^0x14BE1B80` | 7.0 导出 `fieldDecode`（`FindTypeByName2`，base `typeDef+136`）；把解出的 entry 按 `off=entry&0xFFFFFF, len=entry>>24` 解密 | **3376/3376** 可打印（`Mono`/空）|
| `nameIndex` | `+0x28` | `-0x5F8AB6E2` | 7.0 导出 `fieldDecode`（`IterNestedTypes`，base `typeDef`）；同样按打包 entry 解密 | **5000/5000** 可打印（`<Module>`/`Locale`/`Runtime`/`SR`…）|

> ⚠️ `+0x28` 在 `IterNestedTypes` 里是**嵌套类型的名字**，不是 `parentIndex`。
> `parentIndex` 仍未定位（7.1 在 +0x18，7.0 暂用占位）。

**本轮后 typeDef 剩余**：`parentIndex` / `flags` / `unknown20` / `genericContainerIndex` / `interfacesStart` / `interfaces_count` / `nestedTypesStart` / `nestedTypesCount`（8 个）。

### 15.4c typeDef 容器/接口/嵌套字段（2026-10-17，IDA 代码确认）

| 字段 | 偏移 | 解码 | 怎么找到（IDA 证据） | 置信度 |
|---|---|---|---|---|
| `genericContainerIndex` | `+0x3A` | `^0x3B64`（int16，哨兵 `0xFFFF`）| `SetupNestedLocked` 0x1404E2C3D：`*(__int16*)(70*idx + GM + (MHY[416]^0x4CE7B502) + 58) ^ 0x3B64`；随后 `v92 = GM + (MHY[280]^0x2B0F6E21) + 16*v9`，**MHY[280]=0x118 = genericContainers** | confirmed |
| `interfacesStart` | `+0x3E` | `^0x1DE4` | `SetupTypeInfoLocked` 0x1404E4019：`*(u16*)(typeDef+62) ^ 0x1DE4`；表 `v30 = GM + (MHY[188]^...)`，**MHY[188]=0xBC = interfacesTable** | confirmed |
| `nestedTypesCount` | `+0x41` | `+0x5A` | `IterNestedTypes` 0x1404EE61F：`(unsigned __int8)(*(_BYTE*)(typeDef+65) + 90)` —— 65=0x41，90=0x5A | confirmed |
| `interfaces_count` | `+0x44` | `^0xFD` | `SetupNestedLocked` 0x1404E2E95：`*(u8*)(typeDef+68) ^ 0xFD`，作为接口数组循环次数 | **likely** |
| `nestedTypesStart` | `+0x34` | `+0x66EC` | 7.0 导出 `fieldDecode`（`IterNestedTypes`）；与 `+0x41` 计数匹配 7,060/9,042（78%）| **likely**（base 可能是 runtime struct）|

**怎么验证**
- `genericContainerIndex`：`v9` 用于索引 `MHY[0x118]`（genericContainers，16B 项），哨兵 `0xFFFF`。
- `interfacesStart`：`v25 + start` 索引 `MHY[0xBC]`（interfacesTable，6B 项）。
- `nestedTypesCount`：循环上界就是 `(raw@+65 + 90)`。
- `interfaces_count` / `nestedTypesStart`：数据结构匹配 78%/20%，暂标 likely，等更强判据。

**typeDef 剩余（3 个）**：`parentIndex` / `flags` / `unknown20`。

### 15.4d typeDef 最后 3 个字段（2026-10-17，分布形状 + key 反推）

| 字段 | 偏移 | 解码 | 怎么找到 | 验证 |
|---|---|---|---|---|
| `parentIndex` | `+0x0C` | `^0x4339F98A` | 2026-10-25 按 `status.md §6/附7` 的 enum/struct 锚点重扫：父类存 **Il2CppType 索引**；枚举 7965/7965、结构体 4702/4702 全部命中 | `NEDGCCFMKBC→GlobalManager`、`GlobalManager→BaseManager`、`TimerManager→GlobalManager`；不再使用 `+0x1C/-0x6748C2A3` |
| `flags` | `+0x18` | `^0x569439D0` | 7.0 该列 **distinct=106**，与 7.1 flags 的 distinct=106 完全吻合；top raw `0x568439D1/0x568438D1/0x568438D3` 反推 key | top = `0x100001/0x100101/0x100103`，与 7.1 flags 集合 **106/106** 交集 |
| `unknown20` | `+0x10` | `-0x431A2141` | top raw `0x431A2141/0x431A218B/0x431A214D` 对应 7.1 unknown20 的 top `0/0x4a/0xc`；反推 key | distinct 44,995 ≈ 7.1 的 45,830；top 完全一致 |

**怎么找到的（可复用）**
- 先算 7.1 对应字段的 **distinct 数 + top 值频率**（`raw` 的 distinct 与 key 无关）。
- 在 7.0 所有 u32 偏移里找 **distinct/top 频率形状相同** 的列。
- 用 **top raw ↔ 已知 top decoded** 反推 op/key，再用全列分布验证。

**typeDef 18/18 个 fieldDecode 字段已全部定位**（`interfaces_count` / `nestedTypesStart` 为 likely）。

**仍缺（struct 成员，不是 fieldDecode 键）**：`bitfield`（7.1 在 +0x3A；7.0 的 +0x3A 已被 genericContainerIndex 占用）。
候选 `+0x38` / `+0x43`（u8），用 `typeIsValueType/typeIsEnum` 的 bit0/bit1 与已知值类型名（Int32/Boolean/Enum）核对。

### 15.4e typeDef `bitfield`（2026-10-17，bit 匹配）

| 版本 | 偏移 | 解码 | 说明 |
|---|---|---|---|
| 7.1 | `+0x3A` | `raw` | `typeIsValueType = raw & 1`；`typeIsEnum = ~(raw>>1) & 1` |
| **7.0** | **`+0x38`** | **`raw ^ 1`** | 同上 bit 测试，先 xor 1 |

**怎么找到的**
1. 7.1 dump 里的 `TypeDefIndex` 与 7.0 完全一致（`Boolean`=174、`Int32`=251、`ValueType`=405…）。
2. 直接读 7.1 typeDef `0x92140 + 70*i + 0x3A` 的 bit0/bit1。
3. 在 7.0 全部 u8 列里找 **bit0/bit1 匹配**（允许低 2 位 xor 常数 0..3）。
4. `+0x38` + `xor 1` → **24/24** 已知类型匹配。

**验证模式**
- enum：`0xB5`（bit0=1, bit1=0）→ `typeIsEnum=1`
- 值类型：`0xB3`（bit0=1, bit1=1）→ `typeIsEnum=0`
- 普通类：`0xB6`（bit0=0, bit1=1）→ `typeIsValueType=0`

7.1 复验：dump md5 `e401b680…` 不变；`verify.py` 28/28。

**结论：typeDef 18/18 个 fieldDecode 字段 + `bitfield` 全部完成。**

### 15.8 7.0 registration / counts（2026-10-17，部分解决）

**T1（metadata registration）布局与 7.1 完全不同**：

| 字段 | 7.1 | 7.0 | 验证 |
|---|---|---|---|
| `t1_il2CppTypes` | `0x48` | **`0x10`** | 7.0 数组 `0x142D3DED0` 前 5 项（idx 0/1/2/174/251）与 7.1 **逐字节一致**；到 idx 600,000 仍一致 |
| `t1_genericInsts` | `0x08` | **`0x30`** | `0x1422A7F10` 条目是 `{argc, argv}`（`argc=1, argv=0x1_452C1D50`）|
| `genericInstsCount` | `T1+0x50 + 0x9B1B5919` | **`T1+0x28 - 1770440218 = 219,680`** | 与 +0x30 指针相邻 |
| `typesCount` | `T1+0x54 ^ 0x6622B34E = 683574` | 静态 `+0x54 = 0`（运行时填） | 用 7.1 的 **683,574 上界 fallback** |
| `genericClassRangeCount` | `T0+0x80 ^ 0x4E013BBD` | 静态不对 | **0 fallback**（offset 也未定位）|

**怎么找到的**
1. `RuntimeInit` 0x140505BD0：`*(u64*)(g_Il2CppType_Base + 0x30)` 是类型数组指针（7.1 dumper 用 +0x48）。
2. 遍历 `T1` 的 u64 指针字段：`+0x10 → 0x1_42D3DED0`，前 5 项 type 码与 7.1 **完全一致** → `t1_il2CppTypes=0x10`。
3. `+0x30 → 0x1422A7F10`，条目 `{argc, argv}` → `t1_genericInsts=0x30`。
4. `+0x28 - 1770440218 = 219,680`，紧邻 +0x30 指针 → **genericInstsCount**。
5. typesCount 静态为 0 → 运行时才填；类型数组与 7.1 到 600k 一致，暂用 7.1 的 683,574 作上界。

**仍缺**：typesCount 精确值（运行时）、`genericClassRangeOffset/Count`、`codeRegistrationVA` / `t0_*` 字段。

### 15.9 7.0 `typesCount` 精确值（2026-10-17，数组边界法）

| 项 | 7.0 | 7.1 |
|---|---|---|
| type 数组起点 | `T1+0x10` = `0x142D3DED0` | `T1+0x48` = `0x142E1EA20` |
| 最后一个有效 type 码 | idx **677,973**（type 0x1D）| idx 683,573（type 0x1D）|
| 之后 | idx 677,974 起连续 200 个无效码（0xFF/0x00/0x5C…）| idx 683,574 type 158（下一张表）|
| **typesCount** | **677,974** | 683,574 |

**怎么找到的**
- 7.0 的 `T1+0x54` 静态是 0（运行时才填），所以不能用 7.1 的公式。
- 直接扫 `Il2CppType` 数组（16B/项，type 码在 `+0x0A`），找**第一个连续 200 个无效 type 码**的位置。
- 边界 = **677,974**；把该值作为 `typesCountFormula` 的常量（`table1Field=0x54` 静态为 0，`+677974` 即得）。

**验证**
- 字段类型索引 ~429k < 677,974，全部在界内。
- `genericInstsCount = T1+0x28 - 1770440218 = 219,680`。

**仍缺**：`genericClassRangeOffset/Count`、`codeRegistrationVA`/`t0_*`、其余 fieldDecode 字段。

### 15.10 `genericClassRange`（2026-10-17，**未定位**）

**7.1 的形状（已验证）**
- 位置：**startup** `0x23814`
- 8 字节 `{argStart, argc}`，满足累计关系 `argStart[i+1] = argStart[i] + argc[i]`
- 长度 ≈ **13,690**（count 13,671），`argc` 1..4

**7.0 的尝试**
- `genericClassRangeOffset` 槽位 `0x134 ^ 0x558E11EC` = **0x2504CC67**（621M；global body 只有 80MB）→ **槽位/密钥错**
- 7.0 startup `0x23814` 附近不是该表（`(23235,0),(19,46),(23236,22707)…`）
- 用精确累计关系扫 7.0 **startup（4MB）** 和 **global（80MB）**：**0 候选**

**结论**
- 7.0 的 `genericClassRange` **未定位**，可能是加密/移位后的表，或 7.0 改成了别的结构。
- dumper 的泛型类名解析（`GENERICINST`）会退化；`genericClassRangeCount` 暂用 **0** fallback。
- 下一步：反编译 7.0 `TypeInfoDispatcher` / 泛型类读取代码，找它的 `(slot, op, key)` 或表偏移（8B `{argStart,argc}` 的读取点）。

**当前 7.0 缺口**：`genericClassRange`、`codeRegistrationVA/t0_*`、其余 fieldDecode（method 4 / parameter 1 / genericContainer 2 / genericParameter 1 / property get+set 2）。

### 15.11 `genericClassRange` 解决（2026-10-17，**代码读取点法**）

**7.1 当初怎么找到的（`docs/PROVENANCE.md`）**
- `genericClassRangeOffset` 不是 slot 扫描出来的，是从**代码读取点**抄的：
  `0x1405367D6` = `GIMeta_RuntimeInit + 0x1C56`，代码是
  `startup + (*(u32*)(MHY + 0x134) ^ 0x558E11EC)` → startup **0x23814**。
- count 同样是代码里的公式：`*(u32*)(T0+0x80) ^ 0x4E013BBD = 13671`
  （消费者 `RuntimeInit` 的泛型注册循环，`init_534B80.c:2064`）。

**7.0 用同样的方法**
- 在 `GIMeta_RuntimeInit` 0x140505BD0 的反编译里找到同构代码（第 1475 行附近）：

```c
v173 = g_Startup_Metadata_Base + (*(int *)(g_MHY_Table + 232) ^ 0x1AEDFFE1);
while ( v175 < *(_DWORD *)&v173[8 * v171 + 4] )          // argc
    v177 = ... v173[8 * v171] ...                         // argStart
```

- **`genericClassRangeOffset` = slot `0xE8` (232) `^ 0x1AEDFFE1` → startup `0x0`**（不是 7.1 的 0x134）
- 表形状与 7.1 一致：`{0,2},{2,2},{4,2},{6,3},{9,4},{13,1}…`（8B `{argStart, argc}`，累计关系）
- **第一个断点 = 13,385 → count = 13,386**（7.1 是 13,671）
- `genericClassRangeCountFormula` = `T0+0x80 ^ (0x1B35AA27 ^ 13386)` → 13,386

**验证**：表在 startup 0x0，断点前累计 `argStart` 到 34,903；与 7.1 前 8 项逐项一致。

**统计**：confirmed **162 / 202 = 80.2%**；with likely **168 / 202 = 83.2%**。

### 15.12 `codeRegistrationVA`（2026-10-17，**结论：文件里没有静态结构**）

**7.1 当初的方法**（`docs/UPDATE.md §1`）：
> `table0VA` / `table1VA` / `codeRegistrationVA`：反编译 `GIMeta_RuntimeInit` **末尾的全局赋值**

**实测**
- 7.1 `codeRegistrationVA = 0x141F88938`：
  - IDA `lookup_funcs` → 在 **`sub_141F88920 + 0x18`**（`.text`，函数中间）
  - `docs/ANALYSIS.md §8.1` 已标 **失效**（“该地址落在 .text，是代码，非结构体”）
- `docs/UPDATE.md:1804`：**`Il2CppCodeRegistration` 运行时构造，文件镜像里没有**
- 7.0 `GIMeta_RuntimeInit`（0x140505BD0）末尾的全局赋值只有 5 个：
  - `qword_145895770 = 0x140000000 + <il2cpp 段偏移>`
  - `qword_145897A18 / qword_145897930 / qword_1458978A0 / qword_145897360 = sub_...`（运行时函数指针）
  - **没有 code registration 结构体**

**结论**
- `codeRegistrationVA` **不是能“从文件里找出来”的常量**；7.1 的 0x141F88938 是误标（函数不是结构体）。
- dumper 的 custom attribute / code registration 相关段在 7.1 和 7.0 上**同样是退化的**（`dumper.hpp` 的 `s_Il2CppCodeRegistration + 0x48/0x70/0x80/0x90` 读的是代码/垃圾）。
- 7.0 要编译只能：
  1. 用一个**有效占位地址**（不崩），或
  2. 把依赖 `s_Il2CppCodeRegistration` 的段**显式跳过**（更干净，但属于代码改动）。
- **不要**再把它当“版本常量”去扫 `.rdata` —— 它不在文件里。

**补充（2026-10-17，7.1 实测确认）**
- `customAttributeCount = int32(*(u32*)(0x141F88938 + 0x70) - 0x2F2BD0D)`
  = `int32(0x8948C433 - 0x2F2BD0D)` = **-2,041,182,426**
- `customAttr()` 的 `for (i = 0; i < count; i++)` **不执行** → 自定义属性生成器是 **no-op**
- dump 里的 `[Serializable]`（5303 处）来自 **type flags**（`TYPE_ATTRIBUTE_SERIALIZABLE`），不是 `customAttr`
- 方法 RVA 来自 method definition，不依赖 code registration
- **结论：7.1 的 `s_Il2CppCodeRegistration` 同样无用；7.0 也一样。两版的自定义属性都缺失，是共同退化。**

### 15.13 method 结构 + 字段（2026-10-17）

**7.0 `Il2CppMethodDefinition`（26B）**

| 字段 | 7.0 偏移 | 解码 | 怎么找到 |
|---|---|---|---|
| `nameIndex` | `+0x00` | `raw ^ keyMethod(i)`（`keyMethod` 已含 `^0x45E4FFC6`）| `GetMethodNameFromIndex` 0x1404E5AC0 第 56-59 行：`*(u32*)(26*i + methodsOffset) ^ (1631394208*((1147050388*((0x11C179E1B7D6*i+0x1EF8D46961E5672)>>16))>>9)) ^ 0x45E4FFC6` |
| `returnType` | `+0x04`（待确认）| 7.1 key 占位 | — |
| `declaringType` | `+0x08`（待确认）| 7.1 key 占位 | — |
| `parameterStart` | `+0x0C` | `key ^ (raw - 11222)` | 7.0 `fieldDecode` 导出 |
| `flags` | `+0x12` | `key ^ raw ^ 0xEF3B` | 同上 |
| `slot` | `+0x14` | `key ^ (raw + 11400)` | 同上（dumper 未用）|
| `iflags` | `+0x16` | `key ^ (raw - 5486)` | 同上 |
| `parameterCount` | `+0x18` | `key ^ raw ^ 0x5B` | `SetupMethodsLocked` 0x1404E59FC |

**代码改动**
- `structOffsets.Il2CppMethodDefinition`：7.1 = `0/4/8/12/16/20/22/24`；7.0 = `0/4/8/12/18/20/22/24`
- `il2cpp_image.hpp`：新增 `mdU32/mdU16/mdU8`；`methodReturnTypeIndex` 的 `md+8` 改为 JSON 偏移
- `dumper.hpp`：6 处 `methodDefinition->...` 改为 `img_.md*`
- 7.0 `fieldDecode.method.nameIndex = xor:0`、`parameterCount = xor:0x5B`；`decMethodParamCount = raw ^ 0x5B ^ keyMethod`
- **7.1 复验**：md5 `e401b680…` + `verify.py` 28/28 ✓

**仍缺**：`returnType`/`declaringType` 的 7.0 key（offset 4/8 也待确认）。

### 15.14 method `returnType` / `declaringType`（2026-10-17，**7.0 无这两个 raw 字段**）

**按 7.1 的方法验证（raw + keyMethod + 常数）**

试了：
- `raw ^ keyMethod` / `raw - keyMethod`
- 7.1 常数：`^0x3F7BDF39`（return）、`^0x59244785`（declaring）
- `raw ^ keyMethod ^ const`、`raw ^ const`

结果：**前 50,000 个方法，合法 Il2CppType/typeDef 值域命中率全部 0.000**。

**代码证据**
- `SetupMethodsLocked` 0x1404E5962：`v17[1] = a1;` → **declaringType = 当前 typeDef**，不读 method 记录
- `returnType` 在 `CreateTypeInfo`/`SetupTypeInfoLocked` 里由方法签名运行时计算
- 7.1 的 `+0x08 returnType` / `+0x0C declaringType` 是 **7.1 专属布局**，7.0 没有

**影响**
- dumper 的 `methodReturnTypeIndex` 在 7.0 读到的是 `+4`（不是 returnType）→ 越界 → `GetIl2CppTypeFromIndex` 返回 nullptr → 返回类型显示 **`?`/空**
- **不崩溃**（`typesCount` 边界保护），但 7.0 的返回类型是**退化**的（和自定义属性一样）
- `declaringType` 输出用的是**当前 type 的名字**，不依赖这个字段

**处理**
- 7.0 JSON 的 `fieldDecode.method.returnType/declaringType` 标 **unconfirmed**（不要当 7.1 值用）
- `structOffsets.Il2CppMethodDefinition.returnType/declaringType` 的 4/8 只是“记录”，不是真正的 return/declaring
- **method 的名字/参数/计数/flags/iflags 已正确**；返回类型是 7.0 的已知退化项

### 15.14b 更正：method `returnType` 已解决（2026-10-17）

**7.1 的方法（`PROVENANCE` / `status.md`）**
- returnType **不是代码读取点**，是**候选排序 + 验证**（50000/50000，void 占 50%）
- 验证法：`raw@+offset ^ keyMethod` 的众数 = `voidTypeIndex ^ C`；用 void 的 type index 反推 C

**7.0 实测**
- `raw@+4 ^ keyMethod` 众数 = **`0x4618CA82`（50.04%）**
- 7.0 void type index = **416,615**（type array 里 type code `0x01`）
- `C_ret = 0x4618CA82 ^ 416615` = **`0x461E91E5`**
- 验证：`raw@+4 ^ keyMethod ^ 0x461E91E5` → **valid 1.000**，top = void 50%、**308、70**（与 7.1 的 308/70 一致）
- 写入：`fieldDecode.method.returnType = xor:0x461E91E5`；`structOffsets.method.returnType = 4`

**`declaringType`**
- `raw@+8 ^ keyMethod` 众数 `0xBA242060`（42.2%），但前 50k 里**没有任何 typeDef 覆盖超过 441 个方法** → 不是 typeDef
- `SetupMethodsLocked` `v17[1] = a1` → 7.0 **直接取当前 typeDef**
- 7.1 的 `declaringType` 也只用于**诊断**（`declType == typeIndex`），输出用当前 type 名字
- 7.0 标 `unconfirmed`，**不影响输出**

**统计：163 / 202 = 80.7%；with likely 169 / 202 = 83.7%。**

### 15.14c declaringType 最终结论（2026-10-17，IDA + 验证）

**7.1 的验证（照 `status.md` 的方法）**
- `declaringType = keyMethod71(m) ^ raw@+0x0C ^ 0x59244785`
- 对全部方法验证：**697,727 / 697,727 = 1.000**，**每个方法都等于当前 typeDef**
- 说明 7.1 的 raw +0x0C 就是 typeDef 索引，key 正确

**7.0**
- method 记录的 +0x0C 是 `parameterStart`（`-0x2BD6`），不是 declaring
- `raw@+8 ^ keyMethod` 众数 42%，但**前 50k 没有任何 typeDef 覆盖超过 441 个方法** → +8 不是 declaring
- IDA：`SetupMethodsLocked` 0x1404E5962 `v17[1] = a1;` → **declaringType = 当前 typeDef**
- **修复**：`dumper.hpp` 的 `declType` 改为 `selfTypeIdx`（当前 typeDef）
  - 7.1 输出不变（7.1 的 declType 本来就 100% 等于 selfTypeIdx，declNote 永远为空）
  - 7.0 不再输出 `/* declaringType=<垃圾> */`
  - 复验：7.1 md5 `e401b680…` + `verify.py` 28/28 ✓

**结论：7.0 的 method 签名全部正确**（名字/参数/计数/flags/iflags/returnType/declaringType）。

### 15.15 非泛型方法验证（2026-10-17，数据级）

**method name**：`raw@+0 ^ keyMethod(i)`
- 前 5000 个方法：**4552/4552 = 100%** 可打印
- 例：`.ctor` / `GetText` / `Format` / `InstallSignalHandlers` / `Equals` / `GetHashCode` / `get_Constraints`

**完整签名样本（直接由数据拼接）**
```
Locale::.ctor                              -> void
Locale::GetText                            -> string
SR::Format                                 -> string
Mono.Runtime::mono_runtime_install_handlers-> void
Mono.Runtime::InstallSignalHandlers        -> void
Mono.Runtime::GetDisplayName               -> string
Mono.Runtime::GetNativeStackTrace          -> string
Mono.Runtime::SetGCAllowSynchronousMajor   -> bool
Mono.RuntimeClassHandle::Equals            -> bool
```

**验证**
- returnType：`raw@+4 ^ keyMethod ^ 0x461E91E5`，前 50000 valid **1.000**
- declaringType：当前 typeDef（7.1 697727/697727）

**结论**：非泛型方法的 name / returnType / declaring 全部正确；只剩泛型方法的 `genericContainer`。

### 15.16 参数类型 / 参数起始修正（2026-10-17，IDA + 全量数据）

**怎么找到的**：反编译 `GIMeta_SetupParameters` @ `0x1404F9710`（7.0）：

```c
v23 = 1631394208 * ((1147050388 * ((0x11C179E1B7D6*i + 0x9EF8D46961E5672) >> 16)) >> 9); // keyMethodParam
v20 = v16 + ((uint32_t)v23 ^ *(_DWORD *)(v10 + 8) ^ 0x3F2059);   // 方法 +8 = parameterStart
...
v22 = *(_DWORD *)(v19 + 8*v20) ^ v21 ^ 0x156CA23C;                 // v21 = keyParam(p)，参数 +0 = typeIndex
*(_QWORD *)v17 = GIMeta_DecryptString(v21 ^ *(_DWORD *)(v19 + 8*v20 + 4) ^ 0x31C2DE49); // 参数 +4 = nameIndex
```

**之前的错误**
- `parameterStart` 被当成 method `+0x0C`（`sub:11222`）
- 参数类型错用了 `keyParamType` + `0x3F2059`（那是 parameterStart 的 key）

**修复**
- `structOffsets.Il2CppMethodDefinition.parameterStart = 8`（`+0x0C` 暂记 `_pad12`）
- `fieldDecode.method.parameterStart = xor:0x3F2059`
- `decMethodParamStart = keyMethodParam(i) ^ raw ^ k`
- `decMethodParamCount = (u8)raw ^ (u8)k ^ (u8)keyMethodParam(i)`
- `fieldDecode.parameter.typeIndex = xor:0x156CA23C`，`decParamTypeIndex = keyParam(i) ^ raw ^ k`

**怎么验证的（全量数据）**
| 项 | 结果 |
|---|---|
| 无参方法与 `ps == -1` 等价 | 401636 / 401636 |
| 有参方法与 `ps != -1` 等价 | 312320 / 312320 |
| 有参方法之间 `p(m+1) == p(m)+count(m)` | **312319 / 312319** |
| 参数 typeIndex 合法（0..677974 或 -1） | **532361 / 532361 = 1.0000** |
| 参数名可打印 / 合法空名 / 解码失败 | 526849 / 5512 / **0** |

7.1 复验：md5 `e401b680248dde6714ae45eaab0b63b0`，`verify.py` **28/28**。

### 15.17 泛型容器 `genericContainer` 完全解决（2026-10-17）

**怎么找到的**：反编译 `GIMeta_SetupNestedLocked` @ `0x1404E2B30`：

```c
v92 = g_Metadata_Base + (MHY[0x118] ^ 0x2B0F6E21) + 16*c;      // genericContainers
v10 = 1461114162 * (((0x257F689DE071 * c) >> 16) ^ 0x5D221965); // keyContainer(c)
v85 = -891806131  - v10;   // 0x3527E1B3
v86 = -1623277875 - v10;   // 0x60C14133
v87 = -16692 - v10 + 1;

argc           = v85 + *(_DWORD *)(v92 + 8);    // raw@+8
parameterStart = v86 + *(_DWORD *)(v92 + 12);   // raw@+12
```

**修复**
- 7.0 `keyFormulas.containerKey` 换成上面的简单公式（原来的 murmur 公式是 7.1 的）
- `fieldDecode.genericContainer = { parameterStart: sub:0x60C14133, argc: sub:0x3527E1B3 }`
- `structOffsets.Il2CppGenericContainer = { argc: 8, parameterStart: 12 }`
- `decodeExpr`：`decGenericContainerArgc` / `decGenericContainerParameterStart` / `decGenericParameterNameIndex`
- `il2cpp_image.hpp` 的 3 个访问器改为读 `structOffsets` + `decodeExpr`（7.1 数学不变）
- 7.1：`{ argc: 8, parameterStart: 4 }`，保留原 `(raw ^ k) - key`；输出逐字节不变

**泛型参数名**
- 7.0：`nameIndex = (raw@+0 ^ 0x22857A95) ^ keyGenericParam(p)`（**XOR**，不是减）
- 7.1：`(raw ^ 0x664CCEB9) - keyGenericParam(p)`（不变）
- 7.0 应用验证：**2624 / 2669 = 98.3%** 可打印；45 个是元数据里真实存在的控制字符（`0x01/0x02`），0 个空名，0 个解码失败

**怎么验证的（全量数据）**
| 项 | 结果 |
|---|---|
| 所有容器 `argc <= 64` | **4315 / 4315** |
| 被 typeDef 引用的容器 `argc ∈ 1..8` | 1772 / 1777 |
| 容器 `[parameterStart, parameterStart+argc)` 区间重叠 | **0 / 1776** |
| 类型名 arity == argc | 696 / 705（9 个是嵌套类，argc 含外层泛型参数） |
| 渲染样本 | `List<T>`、`Dictionary<TKey, TValue>`、`ValueTuple<T1..TRest>` |

7.1 复验：md5 `e401b680248dde6714ae45eaab0b63b0`，`verify.py` **28/28**。

### 15.18 method `+0x0C` = method 级 `genericContainerIndex`（2026-10-17）

**怎么找到的**：`GIMeta_SetupMethodsLocked` @ `0x1404E5660`

```c
__int16 v32;                                  // 注意：有符号 16 位
v32 = (*(_WORD *)(v26 + 12) - 11222) ^ v25;   // v26 = method 记录，v25 = keyMethodParam(m)
*((_DWORD *)v17 + 6) = v32;                   // 存进运行时 MethodInfo +0x18
v35 = v32 == -1;                              // -1 = 非泛型方法
if ( !v35 ) *((_BYTE *)v17 + 47) |= 2;        // 泛型方法标记
```

`GIMeta_GetGenericMethodParamInfo` @ `0x1404979B0` 反向确认：

```c
v7 = *(unsigned int *)(MethodInfoFromIndex + 24);      // = 上面的 v32
v8 = genericContainers + 16 * v7;                      // 同一个 Il2CppGenericContainer
v9 = *(_DWORD *)(v8 + 8) - 891806131;                  // argc
v20 = (u16)i + (-1623277875 - key) + *(_DWORD *)(v8 + 12); // parameterStart
```

**解码**
```
genericContainerIndex(m) = (int16_t)((raw16@method+12 - 11222) ^ (keyMethodParam(m) & 0xFFFF))
```
- `-1` = 非泛型；否则是 `genericContainers[]` 的索引（**method 级**容器，不是 typeDef 的）

**怎么验证的（7.0 全量数据）**
| 项 | 结果 |
|---|---|
| `== -1`（非泛型） | 711393 / 713956 |
| `>= 0`（泛型方法） | **2563** |
| 其他负值（解码噪声） | **0** |
| 泛型方法使用的容器 | **2563 个，全部唯一** |
| 容器 `argc <= 64` | 2563 / 2563（1:2315, 2:178, 3:26 …）|
| method 容器参数区间 vs type 容器参数区间 | **交集 0** |
| 方法泛型参数名可打印 / 空名 / 解码失败 | 2940 / 0 / 36（36 个控制字符怪项）|

样本：`IfNullAndNullsAreIllegalThenThrow<T>`（container 0）。

**`+0x0E` / `+0x10`**
- 试过 `raw ^ keyMethod` / `- key` / `+ key`、`raw ^ keyMethodParam`，与 method index / token（`0x06xxxxxx`）相关度均为 0
- 暂记 `_pad14` / `_pad16`，dumper 不使用

**对输出的影响**
- 7.1 的 dumper 本来就不渲染方法级 `<T>`，7.0 保持一致；该字段只记录到 `version.json`，不改输出
- 7.1 复验：md5 `e401b680248dde6714ae45eaab0b63b0`，`verify.py` **28/28**

### 15.19 methodSpecs / genericMethodTableCount（2026-10-17，IDA 定值 + 全量校验）

**怎么找到的**：`GIMeta_RuntimeInit` @ `0x140505BD0` 的泛型方法注册循环：

```c
v611 = g_Metadata_Base + (*(int *)(g_MHY_Table + 172) ^ 0x120B7FB3);  // genericMethodTable
v321 = (*(int *)(g_MHY_Table + 116) ^ 0x3186387A) / 0xE;              // count = 548707

for (n = 0; n < v321; ++n) {
    v329 = 14 * n;
    v321 = g_Metadata_Base + *(_DWORD *)(g_MHY_Table + 176) - 388315445; // methodSpecs
    v330 = *(_DWORD *)(v321 + 12 * *(int *)(genericMethodTable + v329)); // spec[genericMethodIndex]
    v331 = *(_QWORD *)(*(_QWORD *)(qword_145897138 + 48) + 8 * methodIndex); // T0+0x30 泛型方法指针数组
}
```

**修正**
| 项 | 旧（错） | 新（IDA） | 实测 |
|---|---|---|---|
| `methodSpecs` | slot 0xB4, `-0x508E087D` → `0x1385BA8` | slot 0xB0, `-0x17253935` | **0x1F54664** |
| `genericMethodTableCount` | slot 0x1A8, `-0x4B9E6046` → 375752 | slot 0x74, `^0x3186387A`, /14 | **548707** |
| `t0_genericMethodPointers` | `0x00`（T0+0 = 0） | `0x30` | **0x30**（T0+0x30 = 0x1423AFD30）|

旧的 `0x1385BA8` 解出的 `methodDefinitionIndex` 只有 **4.6%** 合法（25,403/551,689），据此排除。

**怎么验证的**
| 项 | 结果 |
|---|---|
| genericMethodTable 548,707 条：`genericMethodIndex ∈ [0,551688]` | **548707 / 548707** |
| methodSpecs 551,689 条：`methodDefinitionIndex < 713956` | **551689 / 551689** |
| `classIndexIndex` 合法（-1 或 `<219680`） | **551689 / 551689**（460,997 个 -1）|
| `methodIndexIndex` 合法 | **551689 / 551689**（89,098 个 -1）|
| count 边界：548,707 之后 `genericMethodIndex` 合法率 | 从 100% 掉到 ~55% |
| T0+0x30 指针数组：随机 5000 个 `methodIndex` | **5000 / 5000 落在 `il2cpp` 段** |
| 随机 3000 条完整链（gmt→spec→inst→pointer） | 只有 `methodIndex=0 → 指针=0`（无编译体，dumper 会跳过），无解码错误 |

**对输出的影响**
- 修正后 7.0 的 `/* GenericInstMethod : ... */` 才能拿到正确的 spec / 实例类型 / RVA
- 7.1 复验：md5 `e401b680248dde6714ae45eaab0b63b0`，`verify.py` **28/28**

### 15.20 P1 收尾：genericTypeArgOffset / attributesInfoCount / deprecated / parametersCount（2026-10-17）

#### genericTypeArgOffset（有功能影响，已确认）

**怎么找到的**：`GIMeta_RuntimeInit` @ `0x140505BD0` v600：

```c
v600 = g_Startup_Metadata_Base + *(_DWORD *)(g_MHY_Table + 476) - 1086188179; // 0x1A250
```

**结果**
```
genericTypeArgOffset = startup + 0x1A250
                     = MHY[0x1DC] - 0x40BDEA93
                     = genericClassRangeOffset + 8 * 13386
```

**怎么验证的**
- `genericClassRange` 表在 `startup+0`，13,386 × 8 = 0x1A250，正好紧接实参表
- 实参表 34,911 个 `typeIndex`：**34911 / 34911 合法**（0..23919，无越界）
- 13,386 个 range 的实参**全部合法**：13386 / 13386
- 7.1 交叉验证：7.1 的 `genericTypeArgOffset` 解出 `startup+0`（实参表在前、range 表在 0x23814），说明两版布局不同但都自洽

> 7.1 与 7.0 的 GENERICINST 类型名都仍是 `?`（类型定义名未定位），但实参能正常解出（例：`?<void, ushort, object>`），属既有行为。

#### attributesInfoCount（未使用，保持 unconfirmed）

- 7.0 里是 7.1 残留：`slot 0x198, -1137860102`
- 常量 `0x43D25E06` 在 7.0 二进制中**不存在**
- `header.attributesInfoCount` 只被赋值，**没有任何消费者**（`customAttr()` 用的是 CR 运行时计数，7.0 的 CR 不存在）
- 结论：不影响输出，保留 `confirmed: false` + note

#### 3 张 deprecated 表（未使用）

- `interfacesOffset_deprecated` / `fieldTableOffset_deprecated` / `fieldIndexTableOffset_deprecated`
- 只被 `dumper.hpp` 的 **`#if 0`** 旧字段路径引用；活动路径用 `fieldsOffset/fieldOffset`
- 已加 note，保持 `confirmed: false`

#### parametersCount

- 实测被引用的最大参数索引：`max(parameterStart + parameterCount) = 532361`
- 已写入 `measuredCounts.parametersCount`（无消费者，仅记录）

#### 复验

- 7.1：md5 `e401b680248dde6714ae45eaab0b63b0`，`verify.py` **28/28**
- 7.0：版本头生成 + 编译通过（未运行 dump）

### 15.21 泛型名字根因：genericClasses + genericInsts（2026-10-17）

**旧逻辑错在哪**：把 `Il2CppType.data.generic_class` 当成 `genericClassRange` 的下标，再配 `genericTypeArgOffset` 猜实参 → 34,061 处输出 `?` / `?<void,...>`。

**正确结构**（`GIMeta_RuntimeInit` / `GIMeta_TypeInfoDispatcher`）：

```c
genericClasses[g] = { genericInstIndex@+0, typeDefinitionIndex@+4 }   // startup, 8B
genericInsts[gi]  = { argc@+0, pad, argv@+8 }                        // argv = Il2CppType* VA 数组
```

| 版本 | genericClassesOffset | count |
|---|---|---|
| 7.0 | startup + 0xC0830 | 398,168 |
| 7.1 | startup + 0xC5520 | 406,569 |

- 两版首项完全一致：`(0,119),(0,1251),(0,1253)...`
- 类型名 = `TypeDefinitionFullName(tdIndex)` + `<args>`（含嵌套前缀）
- 环检测：`resolvingTypes_` 防止 `Node<T> : IComparable<Node<T>>` 这类自引用无限递归

**结果（7.1）**：`?<` 34,061 → **0**；`verify.py` 28/28；新 md5 `3b5da679ee236d57ebb359d824055eb7`（旧 `e401…` 是带 34k 个 `?` 的输出，已废弃）。

### 15.22 7.0 默认值：记录顺序 + 两张表互换（2026-10-17）

**7.1 是对的**：字符串默认值格式就是 `[u32 len][bytes]`（`len=13` → `bind_rea...`；`len=5` → `ticks`）。7.1 的 1,279 条 string 默认值里 857 条 `dataIndex=-1`，其余长度 0/1 → 不会触发大 memcpy。

**7.0 的根因（不是格式，是表和顺序）**：

```c
// GIMeta_GetDefaultParameterValueObject @ 0x1404F8920
v12 = GM + (MHY[0x110] - 0x7B761D0A);   // 参数默认值表 = 0x3DCE880
v12[0] = dataIndex
v12[1] = typeIndex
v12[2] = parameterIndex                 // 二分键在 +8
```

- JSON 把 **参数表/字段表 slot 互换**了：
  - 参数表：`0x110 / -0x7B761D0A` = **0x3DCE880**
  - 字段表：`0x0C / ^0x720EB389` = **0x1022CA8**
- 两张表的记录顺序都是 `{dataIndex, typeIndex, index}`（之前写成 `{index, typeIndex, dataIndex}`）
- 修正后 7.0：`rc=0`、86,930 type、713,943 RVA、`?` 0、U+FFFD 3
- 参数默认值正确：`"True"` / `"False"` / `"ticks"`；`op_GreaterThan` 不再有假默认值

### 15.23 7.0 method flags key（IDA 确认，输出仍稀疏）

- `SetupMethodsLocked` 里 flags/iflags/slot 用的是 `v25` = **keyMethodParam**（不是 `keyMethod`）
- 已加 `decMethodFlags` / `decMethodIFlags`（7.0 = keyMethodParam，7.1 = keyMethod）
- ⚠️ 7.0 解出来大量是 `0` / `0x1000` → 方法没有 access 修饰符；7.0 元数据的 flag 可能被裁剪或另有编码，**未完全解决**
- 7.0 另外两个待办：RVA 最大共用 54,119（7.1 为 74）、部分 const 字段值/名字缺失
- **已被 §15.24（RVA）和 §15.25（flags）修正**；此处保留为当时的中间记录

### 15.24 7.0 RVA 方法指针数组：`0x48` / `0x88` 交换（补写，2026-10-17）

**怎么找到的**：`GIMeta_SetupMethodsLocked` @ `0x1404E5660`：

```c
v31 = *(_QWORD *)(v22[9] + 8 * v24);   // v24 = methodIndex，v22[9] = T0+0x48
...
v33 = *(int *)(MHY[0x130] + 4*v24);     // vtable slot
v34 = *(u64 *)(v22[1] + 8*v33);         // invoker（不是方法体）
```

**关键**：7.0 的 `T0+0x48` 才是 **il2cpp 方法体数组**（713k 项，全部落在 `il2cpp`）；
`T0+0x88` 是 **invoker/slot 表**（前 12,696 个 `.text` thunk，后面变成浮点常量）。

**错误**：JSON 里 `t0_methodPointerIndexArray=0x88`、`t0_invokerArray=0x48`（从 7.1 抄来的）——两个 offset 反了。

**修复**
- 7.0 `t0_methodPointerIndexArray = 0x48`，`t0_invokerArray = 0x88`
- `methodPointer()`：`p <= 1`（无方法体哨兵）或不在可执行段（`.text`/`il2cpp`）→ 0 → 输出 `RVA: -1`

**验收**
```
RVA 行 691,941 / 不同 691,430 / 最大共用 73   （7.1 最大 74）
```

7.1 复验：md5 `3b5da679ee236d57ebb359d824055eb7`，`verify.py` **28/28**。

### 15.25 7.0 method flags / iflags 字段交换（2026-10-17，IDA + 7.1 分布对照）

**IDA 7.0 `GIMeta_SetupMethodsLocked` @ 0x1404E5660**

```asm
movzx ecx, word ptr [r12 + 0x16]   ; +22
add   ecx, 0xffffea92              ; -5486
xor   ecx, r11d                    ; key = keyMethodParam
mov   [rbx + 0x28], cx

movzx ecx, word ptr [r12 + 0x12]   ; +18
xor   cx, r11w
xor   ecx, 0xef3b
mov   [rbx + 0x2a], cx

movzx ecx, word ptr [r12 + 0x14]   ; +20 slot
add   ecx, 0x2c88                  ; +11400
```

**IDA 7.1 `GIMeta_SetupMethodsLocked` @ 0x140514630**

```asm
movzx ecx, word ptr [r11 + 0x16]   ; +22 = MethodAttributes
xor   cx, r13w
xor   ecx, 0x8f60
mov   [rbx + 0x2c], cx

movzx ecx, word ptr [r11 + 0x10]   ; +16 = MethodImplAttributes
add   ecx, 0xffff9d00              ; -25344
```

**关键**：7.0 的 `+22` 才是 access flags，`+18` 是 impl flags。之前被 decompiler 的 `v17+20/21` 名字误导反了。

**数据判据（前 50k）**：7.0 `+22` 用 `keyMethodParam ^ (raw - 5486)`：

| | 7.0 | 7.1 |
|---|---:|---:|
| public(6) / private(1) / family(3) / assembly(4) | 28,938 / 12,543 / 6,659 / 1,833 | 28,974 / 12,507 / 6,659 / 1,833 |
| static / virtual / abstract / pinvoke | 21.6% / 29.5% / 3.0% / 0.36% | 21.5% / 29.5% / 3.0% / 0.36% |

**修复**
- `structOffsets.Il2CppMethodDefinition`: `flags: 22`, `iflags: 18`
- `fieldDecode.method`: `flags: sub:5486`, `iflags: xor:0xEF3B`
- `decMethodFlags` 改为 `keyMethodParam ^ (raw - key)`；`decMethodIFlags` 改为 `keyMethodParam ^ raw ^ key`

**验收**
```
Locale..ctor                  -> private void .ctor()
Locale.GetText                -> public static string GetText(string)
Mono.Runtime.install_handlers -> private static
```
RVA：**691,430 不同 / 最大共用 73**（7.1 为 74）。

7.1 复验：md5 `3b5da679ee236d57ebb359d824055eb7`，`verify.py` **28/28**。

### 15.26 7.0 字段 typeIndex：XOR → SUB（2026-10-17）

**问题**：`collectFields` 里 typeIndex 写死了 7.1 的 XOR：

```cpp
int32_t typeIndexDec = fieldKey(i) ^ raw ^ kFieldTypeIndex.key;   // 7.1
```

7.0 的 `fieldDecode.field.typeIndex` 是 `sub:815161169`，但 dumper 完全忽略 op，导致大量字段 typeIndex 解错 → `GetIl2CppTypeFromIndex` 失败 → **字段被跳过**（Oid 一个字段都不显示）。

**怎么找到的**：`GIMeta_SetupFieldsLocked` @ `0x1404E3850`：

```c
v34 = g_Metadata_Base + MHY[464] - 486718066;          // 字段定义表（8B）
v35 = -497750444 * ((28430 * rawFieldStart + 216525192) ^ 0x56DFA1B8) + 34757079;
v36 = v35 ^ (*(_DWORD *)(v34 + 8*v33) - 815161169);    // typeIndex = key ^ (raw - 815161169)
name = DecryptString(v35 ^ (raw@+4 - 501770607));       // name
```

**怎么验证的**：Oid 的 3 个字段：

| field | raw type | 解码 typeIndex | 名字 |
|---|---:|---:|---|
| 7703 | 0x7D2DAC4E | 429858 | `m_friendlyName` |
| 7704 | 0xCE4EAA26 | 429858 | `m_value` |
| 7705 | 0x4B4AB787 | 435577 | `m_group` |

`429858` = `System.String`，`435577` = `System.Security.Cryptography.OidGroup`。

**修复**
- 新增 `decFieldTypeIndex`：
  - 7.0：`keyField(i) ^ (raw - kFieldTypeIndex.key)`
  - 7.1：`keyField(i) ^ raw ^ kFieldTypeIndex.key`（原公式）
- `il2cpp_image.hpp` 新增 `fieldTypeIndex()` accessor
- `collectFields` 改用它，不再手写 XOR

**结果**：7.0 Oid 输出
```csharp
private string m_friendlyName; // 0x10
private string m_value;        // 0x18
private System.Security.Cryptography.OidGroup m_group; // 0x20
```
7.1 不变（`3b5da…`，28/28）。

### 15.27 7.0 字段偏移：三张表（2026-10-17）

**怎么找到的**：`GIMeta_SetupFieldsLocked` @ `0x1404E3850` 178–228 行：

```c
v46 = GM + MHY[332] - 763261186
      + 12 * *(int*)(GM + MHY[388] - 1408289675
                     + 4 * (-1963413621 * ((typeDef - typeDefsBase) >> 1)));

base = *(u32*)(v46 + 8);
v38  = *(u32*)(GM + MHY[316] - 1438178828 + 4 * (local + base));
if (v38 & 0x1000000) { v38 &= 0xFF000000; ... }   // 静态字段清掉低 24 位
```

| 表 | 来源 | 步长 | 含义 |
|---|---|---|---|
| fieldTable | `MHY[0x14C] - 763261186` | 12 | `+8` = 该 type 的偏移基址 |
| fieldIndexTable | `MHY[0x184] - 1408289675` | 4 | typeHash → fieldTable 索引 |
| fieldOffsetTable | `MHY[0x13C] - 1438178828` | 4 | 字段偏移（原始值） |

**怎么验证的**：Oid typeDef 1721：

```
typeHash = -1963413621 * ((70*1721) >> 1) = 0x6B9
index    = 37
base     = 170
raw      = 0x10 / 0x18 / 0x20     ← 和参考 dump 完全一致
```

**修复**
- 7.0 `fieldOffset` 改为 `slot 0x13C, '-', 1438178828`
- 新增 `fieldOffsetBaseTable=0x41783D4`、`fieldIndexTable=0x387F8C8`
- `fieldOffsetMask=0xFFFFFF`、`fieldStaticMask=0x1000000`、`fieldStaticValue=0x1000000`
- `collectFields` 先算 typeHash/base，再查 `fieldOffsetTable`
- 静态字段：参考 dump 偏移为 `0`；新增 `fieldStaticZero`（7.0=1，7.1=0）

**验证状态**
- 实例字段偏移：与参考匹配 **357,207** 个
- 静态字段：已验证 `type_resolve_in_progress // 0x0`、`_principal // 0x0`；实例字段 `_serialized_principal // 0x80` 与参考 `+0X080` 一致

### 15.28 7.0 属性 get/set：+4/+8 交换（已修复，2026-10-17）

**怎么找到的**：`GIMeta_SetupPropertiesLocked` @ `0x1404E6220`：

```c
v25 = GM + MHY[100] - 95851500;          // properties 表（在 0，10 字节/项）
name = DecryptString((*(u32*)(v25 + 10*v22) ^ 0x2F28B8F7) - key);
get  = (*(u16*)(v27 + 4) ^ 0x5C0A) - key;        // 0xFFFF = 无
set  = (*(u16*)(v27 + 8) - key) + 9297;          // (raw-key)==0xDBAE = 无
// +6: (raw ^ 0xEC24) - key + 2028288109（属性类型相关）
```

**当前错误**：7.0 JSON 还是 7.1 的 `get: xor:0xE5A2` / `set: sub:23324`，所以 Oid 输出：

```csharp
我们 7.0: public  FriendlyName { set; } // Setter: get_FriendlyName   ← 错
7.1:      public string FriendlyName { get; } // Getter: get_FriendlyName
```

**关键（数据验证）**：7.0 的记录和 7.1 相反，实际是 **`+4 = setter`、`+8 = getter`**。

Oid `FriendlyName`（property 1758，key=0x745AD38，raw4=0xF13D，raw8=0x88EC）：

```
getter @+8: (raw8 - key) + 9297 = 5   -> get_FriendlyName（method local 5）
setter @+4: (raw4 ^ 0x5C0A) - key = 0xFFFF -> 无 setter
```

**修复**
- `structOffsets.Il2CppPropertyDefinition`: `get: 8`, `set: 4`
- `fieldDecode.property`: `get: add:9297`, `set: xor:0x5C0A`
- `decPropertyGet`: `(raw - keyProperty(i))`；`raw-key == 0xDBAE` → 0xFFFF；否则 `+ 9297`
- `decPropertySet`: `(raw ^ 0x5C0A) - keyProperty(i)`
- 新增 `propertyNoGetter = 0xDBAE`（仅 7.0）

**结果**
```csharp
public string FriendlyName { get; } // Getter: get_FriendlyName
```

7.1 不变（`3b5da…`，28/28）。

### 15.29 与参考 dump 对比（`/home/gugugu/Music/dump.cs`）

参考是**另一个工具**的 7.0 dump：

```
md5 ef55338f4de2d8a77543e767bb974ec4
108,595,372 字节 / 3,217,898 行
格式: class X : Base { +0X010 | type field; [Flags] [ParamsCount] |RVA| ... }
无 TypeDefIndex / 无 properties/events
```

| 项 | 参考 | 我们 |
|---|---:|---:|
| 类型数 | 86,930 | **86,930** |
| 方法行 | 697,389 | 691,941 |
| 字段行 | 430,103 | 429,441 |
| 方法 RVA 完全相同 | — | **660,622** |
| RVA 不同但同方法（`.text` wrapper ↔ il2cpp body）| — | **10,226** |
| 字段偏移匹配 | — | **357,207** |
| 静态字段偏移不同 | 0 | 8/16/24（23 处，已修待重跑）|

**RVA 为什么不同**：

- 参考对部分方法用 **native `.text` wrapper**
- 我们用 **il2cpp managed body**
- 抽样证明是同一方法：
  - `RuntimeGenericParamInfoHandle.get_Constraints`
    - 参考：`add rcx,0x10 ; jmp 0x158A07F50`
    - 我们：`jmp 0x158A07F50`
  - `RuntimeClassHandle.GetTypeHandle`
    - 参考：`mov rax,[rcx+0x10] ; add rax,0x58 ; ret`
    - 我们：`mov rax,[rcx] ; add rax,0x58 ; ret`（值类型 this 偏移不同）
- 参考多出的 ~5,448 个方法 RVA 是给无 il2cpp body 的方法补了 `.text` wrapper

**字段/枚举名字**：`ExtenderType` 等枚举在参考是 `None/Simple/Voiced/...`，我们**也是**（之前逐类型脚本的 72k “缺失”是嵌套类型同名配对假象）。

**类型名约定**：参考的嵌套类型只写内层名（`class ItemInfo`），我们 `// FullName` 带外层前缀（`Outer.ItemInfo`）→ 6,825 个 key 不一致，类型总数和顺序一致。

### 15.30 当前产物与状态（2026-10-17）

| 文件 | 版本 | md5 | 说明 |
|---|---|---|---|
| `out/dump.cs` | 7.1 | `3b5da679ee236d57ebb359d824055eb7` | 基线，`verify.py` 28/28 |
| `out/dump70.cs` | 7.0 | `3517cd7283c2db5f3428da6af59d21d7` | 182,140,551 B；字段/静态偏移/属性全部修复 |

> 7.1 最初的 `e401b680…` 已因**泛型名字根因修复**（`?<` 34,061 → 0）更新为 `3b5da679…`，这是有意的正确性提升。

**已完成**
1. §15.28 属性 get/set：Oid 输出 `public string FriendlyName { get; } // Getter: get_FriendlyName`
2. §15.27 静态偏移：`type_resolve_in_progress // 0x0`、`_principal // 0x0`
3. 7.1 复验：md5 `3b5da679…`，`verify.py` 28/28

**剩余（口径，不是错位）**
- 参考对部分方法用 `.text` wrapper，我们用 il2cpp body；如需完全一致，可给无 il2cpp body 的方法加 `.text` 回退（当前输出 `RVA: -1`）

## 16. 版本更新完整操作手册（7.0 实战总结）

> 目标：以后换 7.2 / 7.3 / 8.x 时，按这个顺序定位，不靠猜、不盲扫。  
> 7.1 基线：`out/dump.cs` md5 `3b5da679ee236d57ebb359d824055eb7`，`verify.py` 28/28。  
> 7.0 最终：`out/dump70.cs` md5 `3517cd7283c2db5f3428da6af59d21d7`。  
> **RVA 口径已定：用 il2cpp managed body，不做 `.text` wrapper 回退。**

### 16.1 文件与构建

输入（每个版本一份）：

```
version/<ver>/gi.exe
version/<ver>/gi/Managed/Metadata/global-metadata.dat
version/<ver>/gi/Managed/Metadata/startup-metadata.dat
version/<ver>/version.json          ← 唯一事实来源
```

代码：

```
src/version.hpp        ← gen_version.py 生成，不要手改
src/il2cpp_image.hpp   ← 表访问 / 字段解码 / 名字解析
src/dumper.hpp         ← 输出格式
tools/gen_version.py   ← JSON -> version.hpp
tools/sig.py           ← 跨版本函数签名扫描
verify.py              ← 7.1 验收脚本（新版本另写 verify<ver>.py）
```

**构建（全自动）**：Makefile 已支持 `VERSION`：

```bash
make gen VERSION=7.2    # 只生成 src/version.hpp（不编译）
make build VERSION=7.2  # 生成头 + 只编译 gi-dump-7.2（不运行）
make run VERSION=7.2    # 生成头 + 编译 + 运行
make dump VERSION=7.2   # 生成头 + 编译 + 运行 + 保存 out/dump72.cs
make verify             # 7.1 基线：生成 7.1 头 + 运行 + verify.py
make versions           # 列出可用版本
```

规则：

- `VERSION=7.1`（默认）用**根 `version.json`**，二进制名 `gi-dump`
- 其他版本用 `version/<ver>/version.json`，二进制名 `gi-dump-<ver>`
- `gen` 是 phony：每次构建都按当前 `VERSION` 重新生成 `src/version.hpp`，不会残留上一版头文件
- `dump` 自动把 `out/dump.cs` 复制成 `out/dump<ver>.cs`（如 `out/dump72.cs`）
- `verify` 只对 7.1 有效（`verify.py` 是 7.1 验收脚本）

#### 16.1.1 `VERSION` 是怎么选 `version.json` 的

Makefile 不是自动扫描，而是**约定路径 + 显式 `VERSION`**：

```make
VERSION ?= 7.1

ifeq ($(VERSION),7.1)
VERSION_JSON := version.json                     # 7.1 特例：根目录
TARGET       := gi-dump
else
VERSION_JSON := version/$(VERSION)/version.json  # 其他版本
TARGET       := gi-dump-$(VERSION)
endif

# 路径不存在就直接报错，不会静默用错版本
ifeq ($(wildcard $(VERSION_JSON)),)
$(error version json not found: $(VERSION_JSON))
endif

gen:
	python3 tools/gen_version.py $(VERSION_JSON)
```

展开示例：

```bash
make build VERSION=7.0
# VERSION_JSON = version/7.0/version.json
# python3 tools/gen_version.py version/7.0/version.json
# 输出 gi-dump-7.0（只编译，不运行）

make verify            # VERSION 默认 7.1
# VERSION_JSON = version.json（根目录）
# python3 tools/gen_version.py（无参数 -> 根 version.json）
# 输出 gi-dump，运行 7.1 + verify.py
```

`tools/gen_version.py` 的读取规则：

```python
JSON_PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'version.json')
OUT_PATH  = os.path.join(ROOT, 'src', 'version.hpp')   # 固定输出
```

- 有参数：用参数路径
- 无参数：用根 `version.json`
- **不推断、不扫描、不自动选最新版本**

新版本目录：

```bash
mkdir -p version/7.2
cp version/7.0/version.json version/7.2/version.json
# 修改里面的常量
make build VERSION=7.2
```

找不到时的报错：

```
make: *** version json not found: version/7.2/version.json.  Stop.
```

查看可用版本：

```bash
make versions
# 7.1  (root version.json)
# version/7.0/version.json
```

> 7.1 是特例（唯一事实来源是根 `version.json`）。
> 如果以后也想让 7.1 用 `version/7.1/version.json`，把 Makefile 里的
> `ifeq ($(VERSION),7.1)` 分支去掉即可。

**已验证的自动化命令**

```bash
make build VERSION=7.0   # 只编译；out/dump.cs 不变
make gen VERSION=7.0     # 只生成 src/version.hpp
make dump VERSION=7.0    # 编译 + 跑 + 保存 out/dump70.cs
make verify              # 恢复 7.1 并验收
```

```
out/dump70.cs  3517cd7283c2db5f3428da6af59d21d7
out/dump.cs    3b5da679ee236d57ebb359d824055eb7   verify.py 28/28
```

### 16.2 工具与 IDA 入口

| 用途 | 函数 |
|---|---|
| 表槽位/计数总入口 | `GIMeta_RuntimeInit` |
| T0/T1 注册表 | `GIMeta_RegisterTables` / 静态构造器 |
| 字符串解密 | `GIMeta_DecryptString` |
| 类型字段布局 | `GIMeta_SetupTypeInfoLocked` / `SetupNestedLocked` |
| 方法 | `GIMeta_SetupMethodsLocked` |
| 参数 | `GIMeta_SetupParameters` |
| 字段 | `GIMeta_SetupFieldsLocked` |
| 属性 | `GIMeta_SetupPropertiesLocked` |
| 事件 | `GIMeta_SetupEventsLocked` |
| 泛型容器/参数 | `GIMeta_SetupNestedLocked` / `GetGenericParameterInfo` |
| 默认值 | `GIMeta_GetDefaultParameterValueObject` / `GetDefaultValue` |
| 泛型类 | `GIMeta_TypeInfoDispatcher` |
| 字符串/类型名 | `GIMeta_DecryptString` / `TypeInfoDispatcher` |

新版本先用签名找函数：

```bash
python3 tools/sig.py scan version/7.2/gi.exe --sigs tools/sigs.json
```

`sigs.json` 是 54 个函数的跨版本签名；命中后逐个反编译，**不要只看变量名**（见 §16.5）。

### 16.3 定位顺序（按依赖关系）

1. **MHY / T0 / T1**
   - `.rdata` 搜 `"MHY\0"` → `mhyTableVA`
   - `GIMeta_RegisterTables` / 静态构造器 → `table0VA`、`table1VA`
   - `codeRegistrationVA`：如果是运行时构造，`version.json` 写 `0x0`，`customAttr()` 用空指针守卫跳过
   - `globalMetadataHeaderOffset`：`0x210`（global-metadata.dat 头）

2. **字符串解密** `GIMeta_DecryptString`
   - 取 `mulA/mulB/seed/step`
   - 7.0：`key = (mulB*off + seed) ^ mulA`
   - 7.1：`key = mulA * ((mulB*off) ^ seed)`
   - 解包：`off = idx & 0xFFFFFF`，`len = idx >> 24`
   - 验证：类型/方法名可打印

3. **元数据表**（全部从 `RuntimeInit` / `Setup*` 的 `g_MHY_Table + slot` 读）
   - 每张表记录：`slot / op / key / stride / side(global|startup) / role(offset|count)`
   - 计算偏移后先读前 20 项，确认索引/长度/字符串合理
   - 7.0 已确认的表见 §16.4

4. **逐索引 key 公式**
   - 从反编译里的 `imul/shr/xor/add` 取参数
   - 每个公式配一个验证：名字可打印、typeIndex 合法、索引连续、RVA 唯一

5. **结构体字段偏移/解码**
   - 用 `structOffsets` + `decodeExpr`，不要在 dumper 里写死偏移
   - 每个字段都要有 IDA 读取点和数据验证

6. **默认值 / 泛型 / RVA / flags**（7.0 的坑集中在这里）
   - 见 §16.5

7. **构建 → 跑 dump → 验 metrics → 和参考 dump 对比**
   - 见 §16.6

### 16.4 7.0 全量常量清单（已确认）

**地址**

```
mhyTableVA 0x142720238
table0VA   0x142244C28
table1VA   0x1427B8788
codeRegistrationVA 0x0（运行时构造）
globalMetadataHeaderOffset 0x210
```

**字符串**

```
mulA 0x6E06618323D1073A
mulB 0x552E0DA77096BD68
seed 0xD7A8F7865F61DE96
step 0x31BEA5AF4493F187
key = (mulB*off + seed) ^ mulA
```

**表（global 侧，除特别标注）**

| 表 | slot | op/key | stride |
|---|---|---:|---:|
| typeDefinitionsOffset | 0x1A0 | `^0x4CE7B502` | 70 |
| typeDefinitionsCount | 0x6C | `-0x75C650E3` | /70 |
| methodsOffset | 0x18C | `^0x6ACCE7D4` | 26 |
| methodsCount | 0x98 | `^0x427E10F8` | /26 |
| parametersOffset | 0x94 | `-0x2C46EB4E` | 8 |
| fieldsOffset | 0x1D0 | `+0xE2FD458E` | 8 |
| fieldOffset | 0x13C | `-1438178828` | 4 |
| propertiesOffset | 0x64 | `+0xFA496C14` | 10 |
| eventsOffset | 0x1E8 | `^0x100547B1` | 14 |
| interfacesTable | 0x1C4 | `-1518027399` | 6 |
| nestedTypesTable | 0x17C | `^0x6EBA4F15` | 4 |
| genericContainers | 0x118 | `^0x2B0F6E21` | 16 |
| genericParameters | 0x48 | `^0x5ECCBF54` | 14 |
| **fieldDefaultValuesOffset** | 0x0C | `^0x720EB389` | 12 |
| **parameterDefaultValuesOffset** | 0x110 | `-0x7B761D0A` | 12 |
| parameterDefaultValuesCount | 0x120 | `^0x4D9E9E50` | /12 |
| defaultDataOffset | 0x1B0 | `^0x26AB5EF8` | — |
| methodSpecs | 0xB0 | `-0x17253935` | 12 |
| genericMethodTable | 0xAC | `^0x120B7FB3` | 14 |
| genericMethodTableCount | 0x74 | `^0x3186387A` | /14 |
| attributesInfoOffset | 0x80 | `^0x69D6A445` | 8 |
| attributeTypesOffset | 0x16C | `-0x225AFD44` | 4 |
| genericClassRangeOffset | 0xE8 | `^0x1AEDFFE1`（startup） | 8 |
| genericTypeArgOffset | 0x1DC | `-0x40BDEA93`（startup，legacy） | 4 |
| imagesOffset | 0x14 | `^0x495C7A75`（startup） | 40 |
| stringLiteralDataOffset | 0x174 | `^0xD1EDB05` | — |

**genericClasses（7.0）**

```
startup + 0xC0830        // MHY[0x18] - 662445654
count 398168             // (MHY[0xE0] >> 3) ^ 0x1F5F6D1
entry { genericInstIndex, typeDefinitionIndex }  // 8B
genericInsts = *(T1+0x30)  // { argc, pad, argv }
```

**T0 / T1**

| 字段 | 7.0 | 7.1 |
|---|---|---|
| T0 method body array | **0x48** | 0x88 |
| T0 invoker array | **0x88** | 0x48 |
| T0 generic method ptrs | 0x30 | 0x30 |
| T1 Il2CppTypes | 0x10 | 0x48 |
| T1 genericInsts | 0x30 | 0x08 |

**typeDef（70B，已确认 18 项）**

```
namespace@8   raw ^ 0x14BE1B80
propertyStart@32 raw - 0x6AE4E32A
methodStart@36 raw - 0x42C81546
parent@12      raw ^ 0x4339F98A
fieldStart@44  raw - 0x1E6871E4
name@40        raw - 0x5F8AB6E2
flags@24       raw ^ 0x569439D0
method_count@54 u16 + 0x28
eventStart@50  raw - 0x53B6
nestedStart@52 raw + 0x66EC
field_count@60 u16 - 0x8B
bitfield@56    bit0 valuetype / bit1 enum(反相)
interfacesStart@62 ^ 0x1DE4
genericContainerIndex@58 ^ 0x3B64（0xFFFF 无）
interfaces_count@68 ^ 0xFD
property_count@64 ^ 0xCA
event_count@66 + 0x09
nestedCount@65 + 0x5A
```

**method（26B）**

```
name@0       keyMethod ^ raw
returnType@4 keyMethod ^ raw ^ 0x461E91E5
parameterStart@8 keyMethodParam ^ raw ^ 0x3F2059
genericContainerIndex@12 (u16) (raw - 11222) ^ (keyMethodParam & 0xFFFF)
flags@22     keyMethodParam ^ (raw - 5486)     ← MethodAttributes
iflags@18    keyMethodParam ^ raw ^ 0xEF3B     ← MethodImplAttributes
slot@20      keyMethodParam ^ (raw + 11400)
parameterCount@24 raw ^ (keyMethodParam & 0xFF) ^ 0x5B
declaringType = 当前 typeDef（记录里没有）
```

**parameter**

```
typeIndex@0 keyParam ^ raw ^ 0x156CA23C
nameIndex@4 keyParam ^ raw ^ 0x31C2DE49
parameterStart = 方法 +8；无参时 -1
```

**field**

```
typeIndex@0 keyField ^ (raw - 815161169)      ← 7.0 是 SUB，不是 XOR
nameIndex@4 keyField ^ (raw - 501770607)
```

**field offset（7.0 三表）**

```
fieldBaseTable  = MHY[0x14C] - 763261186      // 12B，+8 = base
fieldIndexTable = MHY[0x184] - 1408289675     // 4B，typeHash -> index
fieldOffsetTable= MHY[0x13C] - 1438178828     // 4B，raw offset
typeHash = -1963413621 * ((70*typeDefIndex) >> 1)
base = u32(fieldBaseTable + 12*idx + 8)
raw  = u32(fieldOffsetTable + 4*(local + base))
offset = raw & 0xFFFFFF
static  = raw & 0x1000000
静态字段 offset = 0
```

**property（10B）**

```
name@0 (raw ^ 0x2F28B8F7) - keyProperty(i)
setter@4 (raw ^ 0x5C0A) - keyProperty(i)      // 0xFFFF 无
getter@8 (raw - keyProperty(i)) + 9297        // raw-key==0xDBAE 无
```

**event（14B）**：`typeIndex/name/add/remove/raise` + `eventAccessorKey`（见 §15.14）。

**genericContainer（16B）**

```
argc@8           raw - keyContainer(c) - 891806131
parameterStart@12 raw - keyContainer(c) - 1623277875
keyContainer(c) = 1461114162 * (((0x257F689DE071*c)>>16) ^ 0x5D221965)
```

**默认值**

```
parameterDefaultValue { dataIndex@0, typeIndex@4, parameterIndex@8 }
fieldDefaultValue     { dataIndex@0, typeIndex@4, fieldIndex@8 }
字符串默认值 = [u32 len][bytes]，offset = MHY[0x1B0] ^ 0x26AB5EF8 + dataIndex
```

**property/event/image 的 key**

- `keyProperty`：`A=1891780257, B=0x29296FCE4E4E, shift=16, xor=0x5C9383E5`
- `keyField`：`A=28430, add1=216525192, xor=0x56DFA1B8, B=-497750444, add2=34757079, indexBias=0x1E6871E4`
- `keyParam`：`A=0x2F41C44B80, add=0xBF6F453AB0, shift=8`
- `keyMethod`：`C=0x11C179E1B7D6, D=0x1EF8D46961E5672, inner=1147050388, outer=1631394208, shift=16/9, xor=0x45E4FFC6`
- `keyMethodParam`：同上但 `D=0x9EF8D46961E5672`，**不加 xor**
- `keyImage`：`((899978779*((18582*i)^0x1A32087B))>>11)+1714073770)^0x6688B322`

### 16.5 7.0 vs 7.1：必须记住的坑

| 项 | 7.0 | 7.1 |
|---|---|---|
| 字符串 key | `(mulB*off+seed)^mulA` | `mulA*((mulB*off)^seed)` |
| method flags | `+22`，keyParam，`-5486` | `+22`，keyMethod，`^0x8F60` |
| method iflags | `+18`，keyParam，`^0xEF3B` | `+16`，keyMethod，`-25344` |
| method RVA 数组 | T0+0x48 | T0+0x88 |
| invoker 数组 | T0+0x88 | T0+0x48 |
| parameterStart | method+8 | method+4 |
| field typeIndex | `keyField ^ (raw - 815161169)` | `keyField ^ raw ^ 0x2D27D873` |
| field offset | 三表 + typeHash | 单表 `MHY[0x204]-450622139` |
| 属性 get/set | get@8，set@4 | get@6，set@8 |
| 参数默认值表 | slot 0x110 | slot 0x104 |
| 字段默认值表 | slot 0x0C | slot 0x13C（7.1 的字段表） |
| 默认值记录顺序 | `{dataIndex,typeIndex,index}` | `{index,dataIndex,typeIndex}` |
| generic inst 名字 | genericClasses + genericInsts | genericClasses + genericInsts |
| declaringType | 记录里没有，用当前 typeDef | 记录 @+12 |

**最容易看错的地方**

1. **decompiler 的变量名不可信**：  
   `v17+20/21`、`v27+4/6/8` 经常是**移位后的基址**；以**数据分布/两条独立验证**为准。
2. **表可能互换**：参数/字段默认值表、T0 的 0x48/0x88 都实际互换过。
3. **常量的 op 不同**：同名字段可能是 `-key`、`^key`、`+key`，不要照抄上一版。
4. **哨兵不同**：`0`、`1`、`0xFFFF`、`0xDBAE`、`26229` 都出现过。
5. **静态字段没有实例偏移**；参考 dump 写 0，7.0 也要写 0。
6. **CR 是运行时构造**：`codeRegistrationVA=0`，`customAttr()` 必须空指针守卫。
7. **7.1 byte-identical**：正确性修复（如泛型名字）会让 md5 变；一旦确认是正确性提升，就记录新基线，不要为了旧 md5 保留错误路径。

### 16.6 验证配方（每个版本都跑）

**表/偏移**
- 表的前 20 项：索引单调/在范围内、count 合理
- 字符串：可打印率 100%
- typeIndex：`< typesCount` 或 `-1`
- RVA：不同 VA 数、最大共用（正常 < 100）
- 字段：名字/类型/偏移；静态字段 offset=0
- 泛型：argc ≤ 64；参数名可打印；类型名 arity 与 argc 匹配
- 默认值：type/data 合法；字符串长度合理

**输出 metrics（参考）**

```
TypeDefIndex ≈ typeDefsCount
方法 RVA 行 ≈ methodsCount - 无方法体数
不同 RVA / 最大共用：7.0 = 691,430 / 73；7.1 = 710,507 / 74
? 总数：7.0 = 0；7.1 = 3（字符串里）
U+FFFD < 200
```

**和参考 dump 对比时的正确方法**
- 两边都按 **typeDef 顺序**配对（都是 86,930 个），不要按名字（嵌套类型参考只写内层名）
- 字段/方法按 (类型, 名字, 参数数) 对比
- RVA 对比先归一化整数（`0x044FE90` vs `0x44FE90` 前导零）
- 参考的 `.text` wrapper 与我们的 il2cpp body 是同一方法，不是错位

### 16.7 新版本（7.2/8.x）操作流程

```bash
# 1) 新建版本目录
cp -r version/7.1 version/7.2        # 或只建 version/7.2
cp version/7.1/version.json version/7.2/version.json

# 2) 用签名找函数
python3 tools/sig.py scan version/7.2/gi.exe --sigs tools/sigs.json

# 3) 按 §16.3 顺序逐项定位；只改 version/7.2/version.json
#    每改一项，立刻做 §16.6 的对应数据验证

# 4) 全自动：生成头 + 编译 + 跑 + 保存 out/dump72.cs
make dump VERSION=7.2

# 5) 验收（新版本写 verify72.py；至少检查 §16.6 的 metrics）

# 6) 恢复 7.1 基线
make verify
md5sum out/dump.cs    # 3b5da679ee236d57ebb359d824055eb7
# verify.py 28/28
```

**定位顺序不要跳**：表 → key → 结构体 → 字段/方法 → 泛型 → 默认值 → RVA/flags。  
每一层都依赖上一层；跳步会把错误放大成“到处都是乱码”。

### 16.8 本次 7.0 的最终验收

```
7.0: out/dump70.cs  182,140,551 B  md5 3517cd7283c2db5f3428da6af59d21d7
     TypeDefIndex 86,930
     RVA 691,941 / 不同 691,430 / 最大共用 73
     ? 0（字符串里 15 个问号字符）
     字段段 73,626
     静态字段 offset 0
     属性: public string FriendlyName { get; } // Getter: get_FriendlyName
7.1: out/dump.cs    md5 3b5da679ee236d57ebb359d824055eb7  verify.py 28/28
```

### 16.9 自动化覆盖表：哪些不用再手找

本次 7.0 的定位里，**机械部分约 85–90% 已工具化**；剩下的是“新混淆形状”和“语义 A/B”。

| 步骤 | 工具 | 状态 |
|---|---|---|
| 54 个函数地址 | `python3 tools/sig.py scan <exe> --sigs tools/sigs.json` | **自动**（7.0 54/54） |
| MHY 表 slot/key 候选 | `tools/slot_scan.py`（capstone） | **自动** |
| 表偏移/计数/结构自证 | `tools/relocate.py <root> --scan` | **自动**（已知形状） |
| fieldDecode 42 个常数 | `tools/ida_export.py` + `tools/ida_fielddecode.py` | **自动**（旧→新匹配） |
| key 公式常数 | `tools/ida_formulas.py` / `formula_auto.py` | **半自动**（形状识别） |
| T0/T1 全局/槽位 | `tools/globals.py` | **半自动** |
| **语义 A/B**（flags/property/T0） | **`tools/semantic_ab.py`（本次新增）** | **自动**（7.0 已验证） |
| 输出验证 | `verify.py` / `verify70.py` | **自动** |
| 参考 dump 对比 | `tools/dump_diff.py` | **自动** |

#### `semantic_ab.py` 解决的三类“选反”

```bash
python3 tools/semantic_ab.py version/7.0
```

7.0 实测输出：

```
flags: off=22 key=methodParam swap=False   6/1/3/4=28938/12543/6659/1833
property get: off=8 formula=subadd (15369)
property set: off=4 formula=xor-sub (5031)
T0 method bodies: 0x48
```

它用**数据自证**，不看反编译变量名：

1. **flags / iflags**
   - 试 flags/iflags 的两个偏移、两种 key（method / methodParam）
   - 谁的 access 6/1/3/4 + static/virtual/abstract/pinvoke 分布最接近 7.1，就选谁
2. **property get / set**
   - 试 +4/+6/+8 × 5 种公式
   - 用方法名 `get_` / `set_` 前缀计分；7.0 最高是 `get@8 (raw-key)+9297`、`set@4 (raw^k)-key`
3. **T0 method body array**
   - 比较 `T0+0x48` / `T0+0x88` 的合法 RVA 与**不同地址数**
   - 7.0：0x48 = 45,566/45,566（全不同）；0x88 = 49,981 但只有 10,075 个不同 → 0x48

#### 仍然需要人工的 ~10–15%

- **新的混淆形状**：如果某个 key 从 `C/D` 形式换成全新形式，`formula_auto.py` 只能给候选，需要人确认。
- **全新的表**：`relocate.py` 的结构自证只覆盖已知表形状；新表仍要靠 `RuntimeInit` 找 slot。
- **语义边界**：例如 7.1 的 property A/B 目前 `semantic_ab.py` 只校准了 7.0（7.1 的 method-name/表读取还需微调）。
- **参考 dump 的约定差异**：`.text` wrapper vs il2cpp body、静态字段 offset 0、嵌套类型命名；这些不是解码错误，工具只报告，不自动改口径。

---

# 17. 通用换版本编排（update.py）

## 17.1 目标

以后换版本不再从零手工分析，也不再依赖“目标版本自己的 version.json”：

```
上一版 version.json（结构/字段位移/stride/role）
        +
目标版本 exe + metadata
        +
目标版本 slot_scan 缓存 + IDA 导出
        ↓
tools/update.py
        ↓
version/<ver>/version.json（目标原本没有时）
version/<ver>/version.draft.json（目标已有 JSON 时，避免覆盖）
version/<ver>/update-report.md（已自动/有候选/必须人工）
```

`slot/key` 每版都变，不能从旧 JSON 直接抄；能复用且必须复用旧 JSON 的是：

- 表名、`stride`、`role`、`countBias`
- `fieldDecode` 的字段名/位移/宽度/公式形状
- `structOffsets`、`structSizes`、`typeDefOffsets`
- `decodeExpr`、dumper 逻辑

## 17.2 新增资产

| 文件 | 作用 |
|---|---|
| `tools/update.py` | 编排：relocate + IDA 映射 + 生成 JSON + 报告 |
| `tools/learn_ida_map.py` | 从“已完成版本”的 JSON + IDA 导出学习函数读取顺序映射 |
| `tools/ida_table_map.json` | 学到的“函数 → 读取顺序 → 表名” |
| `tools/relocate.py --hint` | 指定旧 JSON 作提示（默认根 7.1） |

`learn_ida_map.py` 学的是：

```
GIMeta_SetupParameters            -> parametersOffset
GIMeta_GetDefaultParameterValue…  -> parameterDefaultValuesCount
                                     parameterDefaultValuesOffset
GIMeta_SetupFieldsLocked          -> fieldOffset
                                     registrationFields.fieldOffsetBaseTable
                                     registrationFields.fieldIndexTable
...
```

不是 slot/key；同一函数内的 MHY 读取顺序通常比 slot 稳定。

## 17.3 一条命令

```bash
# 1) 没有 slot 缓存时先扫（约 10 分钟；结果放目标目录）
python3 tools/slot_scan.py version/7.2/gi.exe \
  version/7.2/gi/Managed/Metadata/global-metadata.dat \
  --out version/7.2/slots.json

# 2) 有 IDA 导出就放 version/7.2/ida.json（先 rename function/var）
#    IDA 导出的函数名应和 tools/ida_table_map.json 里的名字一致

# 3) 生成
make update VERSION=7.2
# 等价于：
python3 tools/update.py version/7.2 --base version.json \
  --slots version/7.2/slots.json --ida version/7.2/ida.json

# 4) 目标已有 version.json、想覆盖时
python3 tools/update.py version/7.2 --base version.json --apply
```

> `--typeCount` 默认 683574（7.1 的 types 数）。如果报告里 `[⑧ 无密钥]` 没找到 typeDefs，就把 `--typeCount` 设成目标版本的 `typesCount`（用 `typesCountFormula` 在目标 T1 上算）或更大的上界再跑一次。

`update.py` 的默认行为：

- 目标 `version/<ver>/version.json` **不存在** → 直接生成它；
- 已存在 → 只写 `version.draft.json` 和 `update-report.md`，不改原 JSON；
- `--apply` 才覆盖。

## 17.4 报告怎么读

`version/<ver>/update-report.md` 分五段：

1. **自动定位（可信）**：`relocate.py` 结构自证 + 无密钥 typeDefs。7.0 实测 5 张表：
   - `attributesInfoOffset`
   - `fieldDefaultValuesOffset`
   - `methodPointerIndexOffset`
   - `methodSlotTableOffset`
   - `parameterDefaultValuesOffset`
   加上 `typeDefinitionsOffset`（无密钥基址 + slot 反查）和 typeDefs 的 `fieldStart/fieldCount` 布局。
2. **IDA 映射填充（需抽查）**：按 `ida_table_map.json` 填的新 slot/op/key；7.0 实测补了 15 项，包括 `typeDefinitionsCount`、`methodsCount`、`parametersOffset`、`methodSpecs`、`interfacesTable`、`attributeTypesOffset`、`fieldOffset`、`propertiesOffset`、`genericTypeArgOffset`、`registrationFields.fieldOffsetBaseTable/fieldIndexTable`。
3. **旧 slot 提示（默认不可信）**：`relocate.py` 的“旧 slot 唯一命中”只作参考；7.0 实测 **16 个全错**（slot 全部重排）。
4. **仍用旧值 / 必须人工**：表、`fieldDecode`、`structOffsets`、`keyFormulas`、字符串、地址。
5. **下一步**：`slot_scan`、`make dump` 等命令。

## 17.5 7.0 从 7.1 冷启动实测

条件：`--base version.json`（7.1）、7.0 的 `slots.json` + `ida70.json`、**不用 7.0 的 version.json**。

| 指标 | 结果 |
|---|---:|
| relocate 结构自证表 | 5 |
| typeDefs 基址/布局 | 1 张表 + 2 个布局 |
| IDA 映射补表 | 15 项（含 2 个 registrationFields） |
| 表 slot/op/key 完全一致 | **18 / 34** |
| 按解码后的**表值**一致 | **21 / 34** |
| 旧 slot 提示正确 | **0 / 16** |

**实际自动写入 202：54 / 202 = 26.7%**

```
17 张表 × 3（slot/op/key） = 51
typeDefs 布局（fieldStart/field_count） = 2
MHY 地址 = 1
```

另有 2 个 `registrationFields`（`fieldOffsetBaseTable` / `fieldIndexTable`）不算在 202 里。

按“草稿里的值正确”算：21/34 表 = 63 + typeDefs 2 + MHY 1 = **66 / 202 = 32.7%**；其中 4 张是旧值恰好相同，不是自动定位。

> 注意：§5.12.11 的 **107/202 = 53%** 是 **7.1 的候选口径**（relocate ∪ IDA，含 20 张表、keyFormulas 23 个系数、字符串 5、typeDefs 6 个字段），**不是当前 `update.py` 实际写进 JSON 的比例**。7.0 的 IDA 导出少了 4 个函数，且 keyFormulas/字符串还没接线，所以当前写入是 27%。

值仍不一致的 13 张（7.0 草稿仍用 7.1 值，必须人工）：

```
imagesCount, imagesOffset, stringLiteralDataOffset, methodsOffset,
fieldsOffset, eventsOffset, fieldAndParameterDefaultValueDataOffset,
nestedTypesTable, genericContainers, genericParameters,
genericClassRangeOffset, genericMethodTable, genericMethodTableCount
```

其它类别（IDA 原始候选）：

```
fieldDecode   95 条候选 → 最终需按范围/语义筛
structOffsets 34 / 43 可由 IDA disp 覆盖
keyFormulas   9 / 10 公式至少命中一个常数
```

## 17.6 反馈闭环：每版更新映射

`ida_table_map.json` 是从 7.0 学的；**函数名和读取顺序**在后续版本通常不变，但函数被优化/改名会错位。

每完成一个版本后跑一次：

```bash
python3 tools/learn_ida_map.py version/7.2/version.json version/7.2/ida.json \
  --exe version/7.2/gi.exe -o tools/ida_table_map.json
```

然后人工看一眼输出，确认没有把 `?` 错配；再提交。这样下一版可用的映射会越来越全。

## 17.7 以后版本 checklist

1. 解包到 `version/<ver>/`（`gi.exe` + `gi/Managed/Metadata/global-metadata.dat`）。
2. `slot_scan.py` → `version/<ver>/slots.json`。
3. IDA 重命名关键函数，`ida_export.py` → `version/<ver>/ida.json`。
4. `make update VERSION=<ver> BASE=version.json`。
5. 看 `update-report.md`：
   - 第 1 段可直接信；
   - 第 2 段抽查（尤其 `propertiesOffset`、`fieldOffset`、`methodsCount`）；
   - 第 3 段不要直接用；
   - 第 4 段逐项补。
6. 补 `fieldDecode`（`ida_fielddecode.py` + 范围/名字验证）、`keyFormulas`（`formula_auto.py` / `semantic_ab.py`）、字符串 key、`addresses`。
7. `make dump VERSION=<ver>`，与参考 dump/上一版比对。
8. `make verify`（7.1 基线 28/28 不能退）。
9. 完成后刷新 `ida_table_map.json`，在本文档记录新版本的“结构自证/IDA 映射”覆盖。

## 17.8 设计边界

- **不把旧 slot 当证据**：7.0 已证明 slot 全重排；弱提示只进报告。
- **不覆盖人工成果**：目标已有 JSON 时只写 draft。
- **不假装自动**：`update.py` 只填有结构证据/映射证据的项；其余明确列 TODO。
- **不写死版本号**：表名/stride/role 来自旧 JSON，slot/key 来自目标数据；新版本只换数据。
- **运行时构造的 CR/T0/T1**：文件里没有，任何离线工具都跑不出；仍按 `docs/GLOBALS.md`/IDA 处理。

# 18. 最近一次换版本的实际执行流程（6.7 冷启动）

这一节按**实际操作顺序**记录这次从 7.0/7.1 基线冷启动 6.7 的过程。
具体地址、公式和 6.7 的字段布局见 `§0.2`；自动生成和 override 的分层见 `§0.3`；
这里只记录“下一次换版本应该怎么做、哪些步骤已经不用手找、哪些必须停下来验证”。

## 18.0 总体流程（先看这里）

换版本不是先填 202 项，而是按依赖链走：

```text
准备目录 / 固定旧版基线
        ↓
sig 找函数 + MCP/IDA 归一化函数起点
        ↓
slot_scan  → version/<ver>/slots.json
ida_export → version/<ver>/ida.json + ida/decomp/
        ↓
offline_extract → ida/tables_extra.json
        ↓
update.py → relocate + IDA 读序 + 表角色
        ↓
version.draft.json
        ↓
fieldDecode / decodeExpr / 其它 override
        ↓
make dump VERSION=<ver>
        ↓
dump 统计 + RVA + 名字检查
        ↓
回归旧版本 dump md5 / verify
        ↓
记录 update-report / 学习 ida_table_map
```

对应的阶段和主要产物：

| 阶段 | 主要输入 | 主要产物 | 是否可自动 |
|---|---|---|---|
| 准备 | 新版本 `gi.exe`、metadata | `version/<ver>/` | 人工 |
| 基线 | 旧版本 dump/verify | md5、验证结果 | 人工记录 |
| 函数定位 | `sigs.json`、目标 exe | `sig_hits.json` | 自动 + 抽查 |
| slot 扫描 | 目标 exe + metadata | `slots.json` | 自动 |
| IDA 导出 | 目标 exe/i64 | `ida.json`、`ida/decomp/` | 自动 |
| 离线补表 | `ida/decomp/*.c` | `tables_extra.json` | 自动 |
| 冷启动编排 | 旧 version JSON + slots + ida | `version.draft.json`、报告 | 自动 + 人工 |
| override | 目标 decomp/证据 | `ida/*.override.json` | 人工 |
| dump | version JSON | `out/dump<ver>.cs` | 自动 |
| 验收 | dump/统计 | 通过/失败 | 半自动 |
| 回归 | 旧版本 | md5/verify 不变 | 自动 + 人工确认 |

完整命令顺序：

```bash
# 1) 准备基线（在改动前记录）
#    旧版本 dump md5、verify 结果、当前 version.json

# 2) 新版本目录
mkdir -p version/7.2
# 放入 gi.exe、gi/Managed/Metadata/*.dat

# 3) sig 锁定函数
python3 tools/sig.py scan version/7.2/gi.exe \
  --sigs tools/sigs.json --fuzzy --slow \
  --json version/7.2/sig_hits.json

# 4) slot 扫描
python3 tools/slot_scan.py \
  version/7.2/gi.exe \
  version/7.2/gi/Managed/Metadata/global-metadata.dat \
  --out version/7.2/slots.json

# 5) IDA 导出（需要 Hex-Rays）
tools/ida_headless.sh \
  version/7.2/gi.exe \
  version/7.2/ida.json \
  version/7.2/sig_hits.json

# 6) 离线补表
python3 tools/offline_extract.py version/7.2

# 7) 冷启动（目标无 version.json 时）
#    7.1 是根 version.json；如果 base 是 7.0，则写 version/7.0/version.json
python3 tools/update.py version/7.2 \
  --base version.json \
  --slots version/7.2/slots.json \
  --ida version/7.2/ida.json

# 8) 看报告，补 override，再重跑 7)
# 9) dump
make dump VERSION=7.2

# 10) 验收 + 旧版回归
# 新版本统计/RVA/名字
# 7.1 dump md5 / verify.py
```

> 这只是总览；每一步的判据、失败处理、override 写法见下面各小节。
> `update.py` 默认不会覆盖已有的目标 `version.json`，而是写 `version.draft.json`；
> 目标没有 `version.json` 时才直接写目标。

## 18.1 起点与约束

这次的目标不是只把 6.7 跑通，而是验证一条**可重复的换版本流程**：

```text
起点：7.0/7.1 已有可用的 version JSON、dump 和验证基线
目标：6.7 从 7.0 数据冷启动
约束：
  - 不使用 6.7 的目标 version.json 反填
  - 不使用 hooks_7.0.json 作为自动查找锚点
  - 不使用冻结快照/frozen JSON 伪造确定性
  - 不把版本常量写死进 C++
  - 6.7 必须能稳定重跑；7.0/7.1 不能回归
```

判断标准不是“能生成 JSON”，而是同时满足：

```text
函数/地址可解释
表内部结构自洽
dump 统计合理
RVA 唯一性合理
7.0/7.1 基线不变
```

## 18.2 实际操作顺序

实际执行顺序如下。这个顺序比“先填 202 项”更重要，因为后面的步骤依赖前面的结构验证。

### 第 0 步：准备目录和输入

新版本目录至少要有：

```text
version/<ver>/
├── gi.exe
├── gi/Managed/Metadata/global-metadata.dat
├── gi/Managed/Metadata/startup-metadata.dat
├── slots.json                  # slot_scan.py
├── ida.json                    # ida_export.py
└── ida/decomp/                 # GI_TEXT 落盘的 Hex-Rays 文本
```

检查：

```text
gi.exe 能正常打开
global-metadata.dat 大小非 0
startup-metadata.dat 大小非 0
有可用的 IDA 数据库/能生成 .i64
```

如果 `ida.json` 或 `slots.json` 不存在，后面的 `update.py` 会退化为
“只有 relocate/旧值”的冷启动，覆盖率和可信度都会下降。

### 第 1 步：先固定基线

在动 6.7 之前先记录 7.0/7.1：

```text
7.0 version.json
7.0 dump md5
7.1 dump md5
7.1 verify.py 28/28 PASS
```

本次使用的基线：

```text
7.0 dump md5: 3517cd7283c2db5f3428da6af59d21d7
7.1 dump md5: 3b5da679ee236d57ebb359d824055eb7
```

没有这份基线，后面任何“看起来成功了”的 dump 都不能算通过。

### 第 2 步：用签名找入口函数，再用 IDA 归一化

先用 `sig.py`/`sigdiff.py` 等结构签名找候选，再通过 MCP 的
`lookup_funcs` / `get_func` 把命中地址还原到函数起始地址。

6.7 实际确认的关键入口包括：

```text
GIMeta_RuntimeInit
GIMeta_SetupFieldsLocked
GIMeta_SetupMethodsLocked
GIMeta_SetupPropertiesLocked
GIMeta_RegisterTables
```

要点：

```text
sig 命中地址 != 函数起点
```

必须在目标 IDA 里检查 `start_ea`。6.7 的 `GIMeta_RegisterTables`
甚至一开始没有被 IDA 识别成函数，但反汇编确认它真实存在；这类情况不能只信
`.pdata`/函数表。

### 第 2.5 步：生成 `slots.json` 和 `ida.json`

`update.py` 的两个输入都不是手写的，必须先为目标版本单独生成。

#### 1) `slots.json`：slot_scan

先扫 MHY 槽位和 `.text` 里的 `(slot, op, key)` 候选：

```bash
# 可选：先给 sig 命中函数，后面 IDA/struct 扫描会用到
python3 tools/sig.py scan version/6.7.0/gi.exe \
  --sigs tools/sigs.json --fuzzy --slow \
  --json version/6.7.0/sig_hits.json

# 扫 MHY 槽位 + 指令里的 (slot,op,key)
python3 tools/slot_scan.py \
  version/6.7.0/gi.exe \
  version/6.7.0/gi/Managed/Metadata/global-metadata.dat \
  --out version/6.7.0/slots.json
```

产物：

```text
version/6.7.0/slots.json
  svals : MHY[slot] 的原始 4 字节
  uniq  : 全 .text 扫描得到的 (slot, op, key) 候选
```

注意：

```text
slot 跨版本不稳定
slot_scan 结果只能作为候选
真正的表地址必须由 relocate / 结构自证 / update.py 的目标数据验证
```

`slot_scan.py` 必须保留 `md.skipdata = True`；否则 capstone 遇到非法字节就停，
会得到“只扫了几 KB”的假结果。

#### 2) `ida.json`：IDA/Hex-Rays 导出

`ida_export.py` 必须在 **IDA + Hex-Rays** 里运行，不能在普通 Python 里直接跑：

```bash
# 无头模式（推荐，复用已有 .i64）
tools/ida_headless.sh \
  version/6.7.0/gi.exe \
  version/6.7.0/ida.json \
  version/6.7.0/sig_hits.json

# 也可以直接用 .i64
tools/ida_headless.sh \
  version/6.7.0/gi.exe.i64 \
  version/6.7.0/ida.json \
  version/6.7.0/sig_hits.json
```

GUI 方式：

```text
IDA → File → Script file...
选择 tools/ida_export.py
参数：
  version/6.7.0/ida.json version/6.7.0/sig_hits.json --fast
```

产物：

```json
{
  "mhy": "0x...",
  "mhy_global": "g_MHY_Table",
  "tables": [
    {"slot": "0x...", "op": "^", "key": "0x...", "funcs": ["..."], "strides": []}
  ],
  "fieldDecode": [
    {"width": "dword", "disp": 8, "op": "sub", "key": "0x...", "funcs": ["..."]}
  ],
  "formulas": [
    {"func": "...", "text": "..."}
  ]
}
```

说明：

```text
version/<ver>/ida.json          ida_export.py 的正式产物，update.py 读取
version/<ver>/ida.export.json   MCP/函数级导出，供分析用，不是 update.py 的输入
version/<ver>/ida/decomp/       GI_TEXT 落盘的反编译文本
```

`ida_export.py --fast` 只反编译 sig 命中的函数；`GI_TEXT=version/<ver>/ida/decomp`
会把 Hex-Rays 文本立即落盘，IDA 崩了也不丢。`tools/ida_wanted.txt` 里的关键函数
会通过 `sig_hits.json` 自动加入反编译列表。

#### 3) `offline_extract.py`：不启动 IDA 补漏

`ida_export.py` 的正则可能漏掉这些形态：

```text
int / unsigned / __int32 等 32 位类型
变量中转：v10 = qword_xxx; *(v10 + slot)
非 _DWORD 写法
```

所以导出后还要用 `offline_extract.py` 重扫已经落盘的 Hex-Rays 文本：

```bash
python3 tools/offline_extract.py version/6.7.0
```

默认输入/输出：

```text
输入：
  version/6.7.0/ida.json
  version/6.7.0/ida/decomp/*.c
  version/6.7.0/gi.exe

输出：
  version/6.7.0/ida.json         追加 table 候选
  version/6.7.0/ida/tables_extra.json
```

也可以显式指定：

```bash
python3 tools/offline_extract.py version/6.7.0 \
  --ida version/6.7.0/ida.json \
  --decomp version/6.7.0/ida/decomp \
  --out-extra version/6.7.0/ida/tables_extra.json
```

它做什么：

```text
1. 逐行匹配 *(type *)(g_MHY_Table + slot) op key
2. 只接受 DWORD/int/__int32 等 32 位读取
3. 用目标 gi.exe 的 MHY[slot] 复算 value
4. 把新 (slot,op,key) 合并进 ida.json 的 tables
5. 用上一版的 ida_table_map.json / table_funcs.json
   按“同一函数里的读取顺序”给表命名
6. 命名结果写到 ida/tables_extra.json
```

它**不做什么**：

```text
不验证表值一定正确
不替代 relocate 的结构自证
不直接改 version.json
不根据目标 version.json 反填
```

输出里的 `added / total / labeled` 只是数量，不是正确率：

```text
added   : 本次新补的 (slot,op,key) 条数
total   : ida.json 里 table 候选总数
labeled : 其中被赋予表名的数量
```

`tables_extra.json` 是**候选命名**，最终仍要由 `relocate.py` /
`update.py` 的值和结构验证决定是否采用。没有 `ida/decomp/*.c` 时，
先用 `GI_TEXT=version/<ver>/ida/decomp` 跑一次 `ida_export.py`。

#### 4) `tables_extra.json` 怎么被使用

`tables_extra.json` 不是单独传给 `update.py` 的参数；只要它存在于：

```text
version/<ver>/ida/tables_extra.json
```

`update.py` 就会自动读取。并且在没有加 `--no-auto` 时，`update.py` 会先自动调用
一次 `offline_extract.py`，再读这个文件。

它的结构是“表名 -> 候选”：

```json
{
  "methodsOffset": {
    "slot": "0x58",
    "op": "^",
    "key": "0x58CCB100",
    "value": "0x1970538",
    "funcs": ["GIMeta_GetMethodNameFromIndex"]
  },
  "typeDefinitionsOffset": {
    "slot": "0xA4",
    "op": "-",
    "key": "0xF0932FCE",
    "value": "0x488AC7C",
    "funcs": ["GIMeta_SetupFieldsLocked"]
  }
}
```

`update.py` 实际只取其中三个字段：

```text
slot
op
key
```

并且有一个重要限制：

```text
只有 base version.json 里已经存在的表名才会被填充
tables_extra 不能新增一个 base 里没有的表名
```

合并时它会保留原表项的其他字段（例如 `stride`），只覆盖：

```text
tables[表名].slot = extra.slot
tables[表名].op   = extra.op
tables[表名].key  = extra.key
```

应用顺序：

```text
relocate 自动定位
    ↓
IDA 读取顺序映射
    ↓
tables_extra.json 覆盖同名表
    ↓
fieldDecode / decodeExpr / 其他 override
    ↓
version.draft.json
```

因此 `tables_extra` 是“离线反编译候选”的**最后一层表覆盖**。
它可以修正 `ida.json` 里没有匹配上的表，但也可能把表名标错，所以必须检查：

```text
tables_extra 里的 value 是否落在 metadata 合法范围
是否和 relocate 的结构自证值冲突
对应表名是否在 table_funcs.json 的语义范围内
dump 后计数/边界是否仍然合理
```

跑完后看两个地方：

```text
version/<ver>/version.draft.json
  _update.extra_filled   本次被 tables_extra 填了哪些表

version/<ver>/update-report.md
  表值/候选 和仍用旧值的清单
```

如果 `extra_filled` 里出现了不该被覆盖的表，处理方式是：

```text
1. 不直接手改 tables_extra.json
2. 回到 offline_extract 的 funcs/seq 看是不是读序标错
3. 如果确实无法唯一命名，删掉该表项，让 relocate/IDA 继续处理
4. 不要用目标 version.json 反填
```

> `slots.json` / `ida.json` / `tables_extra.json` 只参与自动定位，
> 不参与 C++ 头文件生成；真正写进 C++ 的仍然是
> `version/<ver>/version.json`。

### 第 3 步：从 RegisterTables 取 T0/T1/MHY

`GIMeta_RegisterTables` 是表注册的权威入口。6.7 实际得到的全局关系：

```text
MHY = 0x142419A40
T0  = 0x141F88938
T1  = 0x1424A9F70
```

然后从消费者反编译确认字段含义，而不是只假设 7.0/7.1 的布局：

```text
T1 + 0x70  Il2CppType 数组
T1 + 0x60  genericInsts
T0 + 0x60  genericMethodPointers
T0 + 0x80  按 methodIndex 索引的方法地址表
T0 + 0x90  invoker 数组
```

T0/T1 和 MHY 的确切数值只属于 6.7；可复用的是
“找到 RegisterTables → 读它写入的全局 → 在消费者里验证字段”的过程。

### 第 4 步：先解表和字符串，再解结构体字段

顺序建议：

```text
表角色 / 表 offset / count
    ↓
字符串解密
    ↓
typeDefinitions 布局
    ↓
method/field/property/event 字段布局
```

6.7 的 `GIMeta_DecryptString` 已经不是 7.0/7.1 的旧形状，因此不能在
`stringDecrypt` 里写死旧模板。本次处理方式是：

```text
从目标 GIMeta_DecryptString 反编译/PE 提取参数
    ↓
生成 stringDecrypt.auto.json
    ↓
只有当结构和旧代码路径一致时，才走旧稳定路径
```

验证的是输出，而不是“反编译看起来像”：

```text
typeDef 名字可打印
namespace 可打印
字段名/方法名没有大面积乱码
```

### 第 5 步：跑 update 链，先看 draft，不碰目标答案

使用 7.0 作为 base，生成 6.7：

```bash
python3 tools/update.py version/6.7.0 \
  --base version/7.0/version.json \
  --slots version/6.7.0/slots.json \
  --ida version/6.7.0/ida.json \
  --emit /tmp/draft67.json \
  --report /tmp/report67.md
```

实际自动链的分层是：

```text
offline_extract.py
stringdecrypt_auto.py
fielddecode_auto.py
keyformulas_auto.py
count_auto.py
table_roles.py
regfields_auto.py
decodeexpr_auto.py
        ↓
ida/*.override.json
        ↓
最终 draft
```

这一步的原则：

```text
自动工具能给出唯一证据的项，自动写
只能给出候选/歧义的项，留 TODO 或 override
目标 version.json 不参与生成
```

### override 层具体怎么接

`update.py` 不需要手动指定 override 路径；它会在目标版本目录下自动读取：

```text
version/<ver>/ida/fieldDecode.override.json
version/<ver>/ida/decodeExpr.override.json
```

以及其它存在的 override：

```text
stringDecrypt.override.json
tables.override.json
addresses.override.json
count.override.json
registrationFields.override.json
keyformulas.values.json
```

最终顺序固定为：

```text
自动链
  ↓
fieldDecode.override / decodeExpr.override
  ↓
tables / addresses / count / registrationFields /
stringDecrypt / keyformulas.values override
  ↓
version.draft.json
```

因此 override 不是“绕过自动链”，而是**显式标注自动链无法唯一确定的项**。
每个 override 至少要有：

```text
目标版本证据
适用字段/表名
为什么自动链不能覆盖
```

6.7 最终只保留两个 override：

```text
version/6.7.0/ida/fieldDecode.override.json
version/6.7.0/ida/decodeExpr.override.json
```

它们分别处理：

```text
fieldDecode.override.json
  TypeDef / method / field / property / event / parameter /
  genericContainer / genericParameter / image 的
  structOffsets、op/key、typeDefOffsets

decodeExpr.override.json
  不能由通用模板表示的 name/type/accessor 解码表达式
  6.7 的 op 顺序与 7.0/7.1 不同，不能直接沿用旧 decodeExpr
```

什么时候应该新增 override：

```text
目标 decomp/PE 能证明值，但自动生成器没有对应模板
目标数据能通过结构/统计验证，但自动链只能给出多个候选
表/字段布局在目标版本确实变了，且变化不是通用规则
```

什么时候**不应该**新增 override：

```text
只是为了让 202 项看起来全绿
从目标 version.json 反抄答案
从 frozen JSON 拷贝整块结果
把旧版本 override 原样复制过来，没有目标证据
```

新增或删除 override 后必须做：

```bash
# 1) 重跑 draft
python3 tools/update.py version/6.7.0 \
  --base version/7.0/version.json \
  --slots version/6.7.0/slots.json \
  --ida version/6.7.0/ida.json \
  --emit /tmp/draft67.json \
  --report /tmp/report67.md

# 2) 比较 draft 的变化（新增/缺失/值不同）
# 3) 重跑 dump、统计、RVA 检查
# 4) 再跑 7.0/7.1 回归
```

6.7 这次实际删除了：

```text
stringDecrypt.override.json
tables.override.json
addresses.override.json
count.override.json
registrationFields.override.json
keyformulas.values.json
```

删除后仍能重跑，说明这些项已经由自动链 + 结构证据覆盖。
剩下的 `fieldDecode.override.json` / `decodeExpr.override.json` 不是“还没处理”，
而是当前通用模板还无法表达的部分；它们必须带着目标证据保留。

#### `fieldDecode.override.json` 怎么写

这份文件不是“整份 version.json 的备份”，而是**按结构体和字段覆盖**自动结果。
顶层只认这几块：

```json
{
  "_comment": "为什么需要这份 override",
  "fieldDecode": {
    "typeDef": {
      "nameIndex": "sub:0x6220594E",
      "methodStart": "xor:0x0DF2043C",
      "field_count": "xor:0xA791"
    },
    "method": {
      "flags": "sub:5486",
      "iflags": "xor:0xEF3B"
    }
  },
  "structOffsets": {
    "Il2CppTypeDefinition": {
      "nameIndex": 8,
      "methodStart": 20,
      "field_count": 58
    }
  },
  "typeDefOffsets": {
    "namespaceIndex": 32,
    "methodStart": 20
  }
}
```

字段含义：

```text
fieldDecode[结构体][字段] = "op:key"
  op   : xor / add / sub
  key  : 可以是 0x... 或十进制

structOffsets[结构体][字段] = 字节偏移
typeDefOffsets[字段]       = TypeDef 字段的字节偏移
```

`update.py` 的合并方式：

```text
自动结果 fieldDecode[st][field]
    ← override.fieldDecode[st][field]
自动结果 structOffsets[st][field]
    ← override.structOffsets[st][field]
自动结果 typeDefOffsets[field]
    ← override.typeDefOffsets[field]
```

没有出现在 override 里的字段保持不变，所以 override 可以只写需要修正的项。
`_comment` 不会写进最终 version JSON，但必须保留，用来说明证据来源。

推荐写法：

```json
{
  "_comment": "6.7 TypeDef 布局：反编译 + 原始 metadata 验证；method_count 总和=687467",
  "fieldDecode": {
    "typeDef": {
      "methodStart": "xor:0x0DF2043C",
      "fieldStart": "sub:0x2318D1B4",
      "method_count": "sub:0x5B59"
    }
  },
  "structOffsets": {
    "Il2CppTypeDefinition": {
      "methodStart": 20,
      "fieldStart": 40,
      "method_count": 56
    }
  }
}
```

怎么得到这些值：

```text
1. 先跑 tools/ida_export.py，得到目标版本的 fieldDecode 候选
2. 跑 tools/ida_fielddecode.py，用旧版本的已知 (op,key) 反查目标 (width,disp)
3. 唯一匹配的项可以直接作为候选
4. 同位置多个 key / 没有候选的项，回到目标 GIMeta_Setup* 反编译
5. 确认 raw 字段、op、key、width、disp 后，只把需要修正的字段写进 override
6. 用 method_count/field_count 总和、typeDef 边界、name 可打印率验证
```

`tools/ida_fielddecode.py` 的用法：

```bash
python3 tools/ida_fielddecode.py \
  --old version/7.0/ida.json \
  --new version/6.7.0/ida.json \
  --version-json version/6.7.0/version.draft.json \
  --out version/6.7.0/ida/fielddecode.auto.json
```

它输出的是**候选**，不是直接覆盖：

```text
唯一匹配 → 可参考
同位置多个 key → 歧义，必须人工
找不到 → 回到目标 decomp
```

`fieldDecode` 的最终验收不是“override 里写了多少项”，而是：

```text
typeDef name/namespace 可打印
method_count 总和 == methodsCount
field_count/property_count/event_count 总和合理
dump type 数 == typeDefinitionsCount
非法 start/越界数量为 0
```

#### `decodeExpr.override.json` 怎么写

这份文件覆盖的是**字段解码表达式**，不是字段偏移。
结构是“函数名 → 签名 + C++ 函数体”：

```json
{
  "_comment": "6.7 op 顺序与 7.0/7.1 不同，不能沿用旧 decodeExpr",
  "decTypeNameIndex": {
    "sig": "int32_t decTypeNameIndex(uint32_t raw)",
    "cpp": "return (uint32_t)(raw) - (uint32_t)kTypeDefNameIndex.key;"
  },
  "decMethodFlags": {
    "sig": "uint16_t decMethodFlags(uint16_t raw, uint32_t i)",
    "cpp": "uint32_t k = ((-9788u * i + 5882u) ^ 0xDEDu) + 15325u; return (uint16_t)(k ^ (uint32_t)(uint16_t)(raw + 13697u));"
  }
}
```

每个函数体必须满足：

```text
sig 的参数/返回类型与 C++ 调用点一致
cpp 是一个可直接编译的函数体
只使用版本 JSON 提供的 key 变量/常量
不要写 C++ 里不存在的辅助函数
```

可用的 key 变量由生成的头文件提供，例如：

```text
kTypeDefNameIndex.key
kTypeDefMethodStart.key
kTypeDefFieldStart.key
keyMethod(i)
keyProperty(i)
keyEvent(i)
keyEventAccessor(i)
keyParam(i)
keyContainer(c)
keyGenericParam(i)
keyImage(i)
```

怎么得到表达式：

```text
1. 在目标 IDA 反编译 GIMeta_SetupTypeInfoLocked /
   SetupMethodsLocked / SetupFieldsLocked / SetupPropertiesLocked /
   SetupEventsLocked / SetupParameters
2. 找到 raw -> decoded 的那一行
3. 区分：字段偏移（structOffsets）还是解码表达式（decodeExpr）
4. 把目标表达式抄成 cpp，保留位宽和类型转换
5. 同一组字段用 dump 统计验证；不能只看单个方法
```

不能这样做：

```text
直接复制 7.0 的 decodeExpr.override.json
只改版本号，不改 op 顺序
用目标 version.json 反推表达式
为了消掉编译错误随便加 cast/常量
```

改完后按顺序验证：

```bash
# 1) draft 能生成
python3 tools/update.py version/6.7.0 \
  --base version/7.0/version.json \
  --slots version/6.7.0/slots.json \
  --ida version/6.7.0/ida.json \
  --emit /tmp/draft67.json \
  --report /tmp/report67.md

# 2) 编译 + dump
make dump VERSION=6.7.0

# 3) 统计 / RVA / 名字抽查
# types / methods / fields / properties / events
# RVA distinct ratio、garbage、type name printable
```

`decodeExpr` 写错时典型症状：

```text
编译能过，但 dump 里名字/索引大面积错
method flags/iflags 看起来随机
property getter/setter 变成不对应的方法
event add/remove/raise 噪音很大
```

这时不要继续加 override；先回到目标函数，确认 raw 的位宽和 op 顺序。

### 第 6 步：生成 dump，先看统计和 RVA，不要先看名字

6.7 dump 验收结果：

```text
output: out/dump67.cs
size:   182246180
md5:    195b10ea2aea57f520f989d8b52c8354
types:  83775
methods:665827
fields: 413644
props:  108747
events: 617
garbage:0
```

RVA 唯一性：

```text
RVA 总数:       665827
不同 RVA 数:    665353
去重率:         99.9288%
单一 RVA 最大:  61
```

这两个检查能快速识别“方法地址表选错/全指向同一片区域”的假 dump。
名字乱码、字段缺失也要看，但先看统计和 RVA，能更早发现结构错误。

### 第 7 步：逐项移除 override，确认不是靠快照过关

6.7 最终只保留两个 override：

```text
version/6.7.0/ida/fieldDecode.override.json
version/6.7.0/ida/decodeExpr.override.json
```

已经移除并由自动链覆盖的：

```text
stringDecrypt.override.json
tables.override.json
addresses.override.json
count.override.json
registrationFields.override.json
keyformulas.values.json
```

移除时不是一次性删掉，而是逐项重跑：

```text
删一个 override
    ↓
重跑 update.py
    ↓
比较 draft：新增字段/缺失字段/值不同
    ↓
重跑 dump/统计/RVA
```

判定“自动覆盖”的标准是：**删掉 override 后结果仍与验证基线一致**，
而不是“自动工具输出了一个看似合理的文件”。

### 第 8 步：回归 7.0/7.1

每次工具改动后都要回到旧版本：

```text
7.0: 177/202（保持，不强行拉高）
7.1: 202/202
7.1 verify.py: 28/28 PASS
7.0/7.1 dump md5 不变
```

6.7 的当前状态：

```text
保留 fieldDecode/decodeExpr override 时：202/202
无 stringDecrypt/tables/addresses/count/registrationFields override
```

> 注意：6.7 没有目标 `version.json`，所以“202/202”是项目内验证口径；
> 它不等同于拿目标真值逐项对照。真正能说明问题的是结构自证、dump 统计、
> RVA 唯一性，以及删 override 后仍可重跑。

### 第 9 步：看报告、记录来源、学习下一版映射

`update.py` 结束后至少检查：

```text
version/<ver>/update-report.md
version/<ver>/version.draft.json
  _update.relocate_auto
  _update.ida_filled
  _update.extra_filled
  _update.fieldDecode_auto / fieldDecode_override
  _update.decodeExpr_auto / decodeExpr_override
  _update.keyFormulas_auto
  _update.registrationFields_auto
```

报告要区分：

```text
1. 结构自证（可信）
2. IDA/离线候选（需抽查）
3. 旧 slot 提示（默认不可信）
4. 仍用旧值 / 必须人工
```

如果目标版本已经有 held-out `version.json`，只用于最后对照，不参与生成：

```bash
python3 tools/json_coverage.py \
  --draft version/<ver>/version.draft.json \
  --target version/<ver>/version.json \
  --base version.json
```

新版本稳定后，把这次学到的函数读取顺序回灌：

```bash
python3 tools/learn_ida_map.py \
  version/<ver>/version.json \
  version/<ver>/ida.json \
  --exe version/<ver>/gi.exe \
  -o tools/ida_table_map.json
```

注意：

```text
learn_ida_map 只在 version.json 已经经过验证后跑
不要把 still-draft / 未确认的值学进全局 map
学完抽查函数名和读取顺序，避免把 ? 错配固化
```

### 第 10 步：提交前检查

提交前确认：

```text
[ ] 目标 version.json 不是从目标答案反填的
[ ] version.draft.json / version.json 的来源字段可解释
[ ] slots.json / ida.json / tables_extra.json 没有把错误表名硬塞进去
[ ] fieldDecode/decodeExpr override 都有目标证据和 _comment
[ ] 新版本 dump 统计/RVA/名字检查通过
[ ] 7.0/7.1 dump md5 和 verify 基线不变
[ ] 没有 frozen snapshot / 临时 dump / 个人路径被提交
[ ] docs/UPDATE.md 记录了本次新增的工具和失败点
```

如果只是做试验：

```text
不要 --apply
不要覆盖 version/<ver>/version.json
保留 version.draft.json + update-report.md
```

## 18.3 这次实际补出来的工具

| 工具/文件 | 作用 | 本次使用 |
|---|---|---|
| `tools/sig.py` | 结构签名生成/扫描；支持 section 选择 | 找入口函数候选 |
| `tools/sigdiff.py` | BinDiff-lite 签名/函数特征 | 函数归一化后的交叉验证 |
| `tools/dump_funcs.py` | 从 dump 生成函数边界表 | 给签名/对比工具提供边界 |
| `tools/dump_align.py` | 忽略混淆名的类/方法形状对齐 | 7.1→7.0 hook 候选召回（独立流程） |
| `tools/hook_resolve.py` | 调用点/修饰符/LCS/函数体证据重排 | 7.1→7.0 hook 自动补全与纠错 |
| `tools/update.py` | 冷启动编排 | 生成 6.7 draft |
| `tools/table_roles.py` | 表角色识别 | 包括 `imagesOffset` 的自动角色 |
| `tools/regfields_auto.py` | registrationFields 自动推导 | 去掉对应 override |
| `tools/count_auto.py` | count 公式自动推导 | 去掉 count override |
| `tools/stringdecrypt_auto.py` | 字符串公式自动提取 | 去掉 stringDecrypt override |

注意：`dump_align.py` 只负责**候选召回**；`hook_resolve.py` 才做最终证据重排
（调用点相对位置、caller 形状、方法修饰符、类内 LCS、函数体相似度）。两者都不应把
hook 映射写进 version JSON；高置信旧结果默认保留，只有 LCS/调用点有明确跨版本证据时才替换。

## 18.4 自动化边界（这次验证过的）

已经可以自动化的部分：

```text
签名找函数候选
RegisterTables → T0/T1/MHY
表角色/部分表 offset/count
字符串公式（从目标函数提取）
registrationFields
部分 keyFormulas
dump 生成/统计/RVA 检查
```

仍必须人工或 override 的部分：

```text
6.7 fieldDecode 的少量结构字段
6.7 decodeExpr 的非通用表达式
无法从结构唯一确定、只能靠语义判断的表项
verify.py 的版本特定检查
```

原则：

```text
唯一命中 + 结构自洽 → 自动接受
多个候选 / 只有名字像 → 拒绝或进 override
不能用目标 version.json 反填
不能用 frozen JSON 冻结结果
```

## 18.5 下一次换版本照着做

```text
1. 固定当前稳定版的 dump md5、verify 结果
2. 新版本解包，检查 gi.exe / global-metadata.dat / startup-metadata.dat
3. sig.py scan，生成 sig_hits.json
4. slot_scan.py，生成 slots.json
5. ida_export.py，生成 ida.json + ida/decomp/
6. offline_extract.py，生成 ida/tables_extra.json
7. 反编译 RegisterTables，取 T0/T1/MHY 并验证消费者字段
8. update.py --base <上一版>，生成 version.draft.json + report
9. 先看报告和 draft 的 TODO，不要先手填 202 项
10. 自动链覆盖不了的再补 fieldDecode/decodeExpr override
11. make dump VERSION=<ver>
12. dump 统计 / RVA / 名字抽查
13. 逐项删 override，确认自动链真的能复现
14. 新版本稳定后 learn_ida_map，更新全局映射
15. 回归旧版本 dump md5 / verify
```

这次最值得保留的经验：

```text
先证明“表/字段/地址是同一套结构”，再追求覆盖率
先看 dump 统计，再看名字
自动化的价值是“可重跑 + 可解释”，不是“全绿”
```

## 18.6 常见失败与处理

| 现象 | 先检查 | 处理 |
|---|---|---|
| `slot_scan` 找不到 MHY | 传的是不是 `gi.exe`；`.rdata` 是否有 `MHY\0` | 换正确 exe；不要拿 `gi-dump` 或 dll 当输入 |
| `slot_scan` 候选很少 | `md.skipdata` 是否开启；PE 段映射 | 保持 skipdata；按 PE 段表 VA→文件偏移 |
| `slots.json` 有候选但值不对 | 旧 slot 跨版本重排 | 只当候选；用 relocate 值/结构自证，不要直接采用 |
| `ida.json` 为空 | Hex-Rays 授权；i64 是否比 exe 旧；`sig_hits` 是否为空 | 用正确 IDAT/Hex-Rays；重建或更新 i64；先生成 sig_hits |
| `ida.json` 只有少量表 | `--fast` 只反编译 sig 命中；`GI_TEXT` 是否设置 | 补 `ida_wanted.txt` 函数；跑 offline_extract；必要时全量导出 |
| `update.py` 大量仍用旧值 | report 第 4 段；`ida_filled`/`extra_filled` 是否为空 | 补 `ida.json`/`tables_extra`；不要先手填 202 项 |
| `tables_extra` 表名明显错 | offline_extract 的 `funcs/seq`；`table_funcs.json` 语义 | 删掉错项；修正读序；不要用目标 version.json 反填 |
| dump 名字大面积乱码 | stringDecrypt、fieldDecode、decodeExpr、表 offset | 先验证字符串可打印率，再查字段 op/key |
| dump 统计不对/越界 | 表 offset/count、typeDef 布局、字段宽度 | 回到目标 decomp 和 metadata 边界验证；不要靠加 cast 硬过 |
| 7.0/7.1 md5 变了 | 改了生成代码或共享 JSON | 立即回退；旧版本基线不能因新版本工具改动而变 |
| override 删掉后结果不一致 | 该 override 仍是必要证据 | 保留并写清 `_comment`；不要用冻结快照替代 |

Hook 7.1→7.0 的匹配是另一条独立流程，不属于本次 6.7 版本更新链；
不要把 hook 映射结果混进 version JSON 或 dump 生成流程。

## 18.7 7.1 image `typeStart` 定位记录

这一节记录 7.1 image 头部的 `typeStart` 是怎么从“随机大数”修到
和 `out/dump-right-71.cs` 75/75 一致的。定位时用的是 7.1 IDA MCP
（`version/7.1/gi.exe`），不是拿参考 dump 反填。

### 18.7.1 IDA 里先确认 image 表

在 `GIMeta_RuntimeInit`（`0x140534B80`）里确认：

```text
imagesOffset = 0x22C5C
image 记录步长 = 40 (0x28)
imagesCount = 75
```

image 循环的核心形状：

```c
v131 = startup_metadata + MHY[0x20C] - 248195061; // 0x22C5C
v622 = 5 * imageIndex;                            // 5 * 8 = 40
v149 = &v131[8 * v622];                           // imageDefinition + 40*i
```

也就是说 image 原始记录是：

```text
imageDefinition + 0x00 .. + 0x27
```

循环会读取 `+0x00/+0x04/+0x08/+0x0C/+0x10/...+0x24`，
并用逐 image key `v134` 写入一个 88 字节的运行时 image info。

关键点：**旧代码用的 `+0x10` 不是 7.1 的 typeStart**。
`+0x10` 解码后近似常量，正是之前头部出现
`3542644948`、`3751280980` 这类随机大数的原因。

### 18.7.2 真正字段和公式

7.1 的 `typeStart` 在：

```text
imageDefinition + 0x0C
```

解码方式：

```cpp
uint32_t raw = *(uint32_t*)((uint8_t*)imageDefinition + 0x0C);
uint32_t key = keyImage(imageIndex);
uint32_t typeStart = ((raw ^ key) & 0xFFFF) ^ 0x47;
```

等价于：

```text
raw ^ key 的高 16 位是固定常量 0x73F6
低 16 位再异或 0x47，得到 image 的全局 TypeDef 起始索引
```

验证结果：

```text
Image 0 -> 0
Image 1 -> 1335
Image 2 -> 1420
Image 3 -> 2085
...
全部 75 个 image: 75/75
```

### 18.7.3 为什么一开始算错了

`keyImage()` 的中间乘法是 C++ `uint64_t` 运算，会按 64 位回绕。
如果直接用 Python 任意精度整数算，不模拟：

```python
M = (1 << 64) - 1
v = (B * inner + add) & M
```

得到的 key 是错的，后面所有 XOR 结果都会看起来像随机数。

这次修复的关键顺序是：

```text
1. 用 IDA 确认 image 表 base/stride
2. 用 C++ 的 uint64_t 语义重新算 keyImage
3. 逐个 image 对比 raw ^ key
4. 发现 +0x0C 的低 16 位与 typeStart 只差 0x47
5. 用全部 75 个 image 验证，而不是只看前几个
```

### 18.7.4 现在写在 JSON 里

结构体字段偏移：

```json
"Il2CppImageDefinition": {
  "nameIndex": 32,
  "typeStart": 12
}
```

解码公式：

```json
"decImageTypeStart": {
  "sig": "uint32_t decImageTypeStart(uint32_t raw, uint32_t key)",
  "cpp": "return ((raw ^ key) & 0xFFFF) ^ 0x47;"
}
```

`src/dumper.hpp` 只调用生成出来的函数：

```cpp
uint32_t rawTypeStart = *(const uint32_t*)(
    (const uint8_t*)imageDefinition + ver::kIl2CppImageDefinitionTypeStartOffset
);
uint32_t typeStart = ver::decImageTypeStart(rawTypeStart, key);
```

7.0/6.7 各自的 `version.json` 里保留旧偏移和旧公式，
所以不会把 7.1 的 `+0x0C/0x47` 编码套到旧版本。

### 18.7.5 7.2 / 7.3 怎么复用

不要改 `dumper.hpp`，只更新新版本目录下的 `version.json`：

```text
version/7.2/version.json
version/7.3/version.json
```

需要确认/填写：

```json
"structOffsets": {
  "Il2CppImageDefinition": {
    "nameIndex": 32,
    "typeStart": 12
  }
}
```

```json
"decodeExpr": {
  "decImageTypeStart": {
    "sig": "uint32_t decImageTypeStart(uint32_t raw, uint32_t key)",
    "cpp": "return ((raw ^ key) & 0xFFFF) ^ 0x47;"
  }
}
```

新版本如果字段或公式变了，就在 IDA 的 `GIMeta_RuntimeInit`
image 循环里重新定位，并至少验证：

```text
1. image 名字全部正确
2. typeStart 单调递增
3. 第一个 image 从 0 开始
4. 最后一个 image 的 typeStart + typeCount 不超过 typeDefinitionsCount
5. 有参考 dump 时逐行对比全部 image
```

没有参考 dump 时，不能只看前几个 image 就宣布公式正确；
这次最开始就是只验了前 10 个，后面才用 75/75 发现边界问题。

---

## §19 用 2.8 无混淆 dump 定位 7.1 字段（实例）

> 适用于游戏逻辑字段，不是 metadata 表常量。
> 2.8 dump 只提供未混淆的**类名、字段名、类型和 enum 值**；
> 7.1 的实际 offset/RVA 必须在 7.1 自己的 dump/IDA 里确认。

### 19.1 为什么不能直接抄 offset

```text
2.8 offset  != 7.1 offset
2.8 RVA     != 7.1 RVA
```

2.8 和 7.1 的字段顺序、基类大小、对齐都可能变化。
2.8 的 `_state` 在 `0x178`，7.1 的同一个语义字段可能已经移到 `0x194`。
所以只能把 2.8 当作“名字和结构参考”，不能当作“地址表”。

### 19.2 标准流程

```text
1. 在 2.8 里找到语义类，记录字段名/类型/enum/方法
2. 在 7.1 里用 7.1 自己的 RVA 找方法
3. 找到方法所属的混淆类
4. 用字段类型、顺序、nested enum 证明类匹配
5. 从 7.1 类里读取真实 offset
6. 检查对象链 v2 -> v4 -> v5，确认不是把不同对象硬串起来
7. 最后才改 hooks.json / mod 代码
```

关键点：**2.8 的 RVA 不能拿到 7.1 里搜索**。7.1 的 RVA 来自
`config/hooks.json`、IDA 或当前版本的函数定位结果。

### 19.2.1 新版本里到底怎么找字段 offset

2.8 的 offset 只用来**认出字段**，不能直接填到新版本。实际做法：

1. 在 2.8 记录字段指纹：
   - 所属类、基类
   - 字段名、字段类型
   - 前一个/后一个字段
   - 相关 enum 的名字和数值
   - 哪个方法读写它
2. 在新版本找到对应类：
   - 用新版本自己的方法 RVA（`hooks.json` / IDA）
   - 或按类结构、基类、nested enum 匹配
3. 在新版本类里找字段：
   - 把基类字段也算进去
   - 先按类型和相邻字段缩小范围
   - enum 数值是最强指纹
   - 最后看 native 代码里的 `+0x...` 访问
4. 找到后再把**新版本的 offset**写回 `hooks.json` / mod 代码。
5. 如果新旧 offset 碰巧相同，只能算巧合，不能作为证明。

例如：

```text
2.8 GadgetDataItem.gadgetState @0x60
7.1 OECHIOBHMHD.INKCGMAFJGM @0x178
```

新版本不能去搜 `0x60` 当作 gadgetState；`0x178` 是靠
`GadgetState` 的 101..106 数值和 `LCGadgetMisc._dataItem` 类型链确认的。

`dump_field_search.py --offset` 只用于列候选，不能单独证明字段身份。
简单类名重复、继承字段、泛型字段都会让它误报，必须回类定义手工核对。

### 19.3 实例：`LCSelectPickup` -> `JPJLHAEKMJD`

2.8 里：

```csharp
public sealed class MoleMole.LCSelectPickup : LCBase
{
    private BaseShape3d _inShape;          // 0x140
    private BaseShape3d _outShape;         // 0x148
    private Action<uint> _pickupCB;        // 0x170
    private LCSelectPickup.State _state;   // 0x178
}

private enum LCSelectPickup.State
{
    WaitToBegin = 0,
    BeginToCheckDisappear = 1,
    CheckingDisappear = 2,
    BeginToCheckAppear = 3,
    CheckingAppear = 4,
}
```

2.8 的方法语义：

```text
IsInPosition(BaseEntity) -> bool
IsOutPosition(BaseEntity) -> bool
AddInteeBtnByID(BaseEntity)
NeedShowPickUpBtn(BaseEntity) -> bool
```

在 7.1 里，用 7.1 的 RVA 找到：

```text
0xA9234B0  private bool GNPDFPGFPDH(JDIIHHFJKBM)  -> IsInPosition
0xA925DA0  private bool GCEOCEFIBJE(JDIIHHFJKBM)  -> IsOutPosition
0xA9242B0  private void FCLOKODIIIJ(JDIIHHFJKBM)  -> AddInteeBtnByID
```

这些方法属于：

```csharp
public sealed class JPJLHAEKMJD : IKGPCCBAMMF
{
    private List<uint> PKPLGFJIGCI;               // 0x138
    private FAFHCIIHCNN IBPHODJGDGM;              // 0x140
    private FAFHCIIHCNN GHMGBJGGODC;              // 0x148
    private List<uint> MCNDJMJLLKF;               // 0x150
    private SliceFrameWatch IGPIODHCIHA;          // 0x158
    private HashSet<uint> KHEAJBLIOIK;            // 0x160
    private KALCGFHCJFF BAMENJILIKM;              // 0x168
    private EAKBAJKBIEP EHINONDLIFN;              // 0x170
    private Action<uint> MCOKAHPKJIH;             // 0x178
    private EAKBAJKBIEP AFMNEAACLCA;              // 0x180
    private KALCGFHCJFF NKJBOLEJFMP;              // 0x188
    private float CIGJJBCLIDC;                    // 0x190
    private DOLKFDDNDAO PPGKFFDNNKK;              // 0x194
}
```

`DOLKFDDNDAO` 的枚举值同样是 `WaitToBegin=0` 到 `CheckingAppear=4`，
所以可以确认它就是 `LCSelectPickup.State`：

| 语义 | 2.8 | 7.1 |
|---|---|---|
| 进入范围 | `_inShape @ 0x140` | `IBPHODJGDGM @ 0x140` |
| 离开范围 | `_outShape @ 0x148` | `GHMGBJGGODC @ 0x148` |
| 拾取回调 | `_pickupCB @ 0x170` | `MCOKAHPKJIH @ 0x178` |
| 状态 | `_state @ 0x178` | `PPGKFFDNNKK @ 0x194` |

结论：

```text
7.1 0x148 -> LCSelectPickup._outShape   ✅
7.1 0x178 -> LCSelectPickup._pickupCB   ✅（不是 state）
7.1 0x194 -> LCSelectPickup._state      ✅
```

### 19.4 `sub_180193F40` 链已确认：LCChestPlugin -> LCGadgetMisc -> GadgetDataItem

之前把 `0x178` 和 `LCSelectPickup` 对比，结论是“0x178 不是
LCSelectPickup._state”，这是对的；但 `sub_180193F40` 读的并不是
LCSelectPickup，而是下面这条链：

```text
v2 = Entity_FindComponentByClass(entity, LCChestPlugin class)
v4 = *(v2 + 0xA0)          // LCChestPlugin._owner
v5 = *(v4 + 0x148)         // LCGadgetMisc._dataItem
state = *(v5 + 0x178)      // GadgetDataItem.gadgetState
```

2.8 名字和 7.1 混淆类的对应：

| 语义 | 2.8 字段 | 2.8 offset | 7.1 混淆类 | 7.1 字段 | 7.1 offset |
|---|---|---:|---|---|---:|
| 宝箱插件 | `LCChestPlugin` | — | `DJNFNMGHJPL` | — | — |
| 插件 owner | `LCChestPlugin._owner` | `0x58` | `DJNFNMGHJPL` | `KMAALPCPDLL` | `0xA0` |
| 宝箱逻辑 | `LCGadgetMisc` | — | `GLLEELLBINA` | — | — |
| 数据项 | `LCGadgetMisc._dataItem` | `0x148` | `GLLEELLBINA` | `MLEIJAAEJFO` | `0x148` |
| 宝箱状态 | `GadgetDataItem.gadgetState` | `0x60` | `OECHIOBHMHD` | `INKCGMAFJGM` | `0x178` |

`GadgetDataItem.gadgetState` 的 enum 值正好解释样本里的 switch：

```text
'e' = 101  ChestLocked
'f' = 102  ChestOpened
'g' = 103  ChestTrap
'h' = 104  ChestBramble
'i' = 105  ChestFrozen
'j' = 106  ChestRock
```

所以样本里的：

```text
case 'e': return 2;   // ChestLocked
case 'f': return 0;   // ChestOpened
case 'g': return 6;   // ChestTrap
case 'h': return 5;   // ChestBramble
case 'i': return 4;   // ChestFrozen
case 'j': return 3;   // ChestRock
```

不是“随手写的字符”，而是 `GadgetState` 的真实值。

结论：

```text
7.1 qword_2A2C30 -> LCChestPlugin class
7.1 qword_2A2C18 + 0xA0  -> LCChestPlugin._owner
7.1 qword_2A2C20 + 0x148 -> LCGadgetMisc._dataItem
7.1 qword_2A2C10 + 0x178 -> GadgetDataItem.gadgetState
```

因此 `AutoLoot_TreasureState = 0x178` 在**这条链里是正确的**。
它和 `LCSelectPickup._state = 0x194` 是两个完全不同的类，不能混用：

```text
LCSelectPickup._pickupCB   @ 0x178
LCSelectPickup._state      @ 0x194
GadgetDataItem.gadgetState @ 0x178   ← AutoLoot 用的是这个
```

IDA 里的对应重命名：

```text
sub_180193EC0 -> Entity_FindComponentByClass
sub_180194000 -> Component_FindPluginByClass
sub_180193F40 -> Entity_GetTreasureChestStateInternal
qword_2A2C30 -> LCChestPlugin_ClassPtr
qword_2A2C18 -> LCChestPlugin_OwnerOffset
qword_2A2C20 -> LCGadgetMisc_DataItemOffset
qword_2A2C10 -> GadgetDataItem_GadgetStateOffset
```

### 19.5 复现命令

```bash
D28=/home/gugugu/Repo/gs/dump_2.8.cs
D71=/home/gugugu/Repo/gs/dump71.cs

# 2.8 语义类
grep -a -n "class MoleMole.LCSelectPickup" "$D28"
grep -a -n "class MoleMole.LCChestPlugin" "$D28"
grep -a -n "class MoleMole.LCGadgetMisc" "$D28"
grep -a -n "class MoleMole.GadgetDataItem" "$D28"

# 7.1：用 7.1 RVA 找方法
grep -a -n -B12 -A8 "RVA: 0xA9234B0" "$D71"

# 7.1 类字段（注意同名 enum 会干扰简单名搜索）
grep -a -n -A40 "class JPJLHAEKMJD" "$D71"
grep -a -n -A30 "class DJNFNMGHJPL" "$D71"
grep -a -n -A30 "class GLLEELLBINA" "$D71"
grep -a -n -A80 "class OECHIOBHMHD" "$D71"

# offset / 类名过滤
python3 tools/dump_field_search.py "$D28" \
  --offset 0x178 --name LCSelectPickup
python3 tools/dump_field_search.py "$D71" \
  --offset 0x194 --name JPJLHAEKMJD

# 注意：--chain 只按简单类名和直接字段追踪；
# dump 里存在同名 enum/嵌套类型时，它可能误报 no chain。
python3 tools/dump_field_search.py "$D71" \
  --chain 0xA0,0x148,0x178
```

### 19.6 检查清单

```text
[ ] 2.8 类名/字段名/类型/enum 已记录
[ ] 7.1 方法用 7.1 RVA 定位，而不是 2.8 RVA
[ ] 混淆类已用字段结构确认
[ ] nested enum 值一致
[ ] offset 从 7.1 类读取
[ ] --chain 仅作辅助；同名类型/继承时要手工核对
[ ] v2/v4/v5 类型已确认
[ ] 最后才改 hooks.json / mod 代码
[ ] 构建 + 游戏内验证
```

一句话：

```text
2.8 回答“这个字段是什么”；
7.1 回答“这个字段现在在哪”。
```

