# USAGE —— 使用说明

Genshin Impact `gi.exe` 的**静态元数据 dumper**：
从 `gi.exe` + `global-metadata.dat` + `startup-metadata.dat` 还原 il2cpp 元数据，输出 `dump.cs`。

> 本项目的元数据结构与 unknowncheats 那篇文章（6.7 版）**不同**，是本样本（**7.1**）重新抄的。
> 换版本怎么做 → [`docs/UPDATE.md`](docs/UPDATE.md)；当前进度/未完成项 → [`docs/status.md`](docs/status.md)。

---

## 1. 环境要求

| 依赖 | 说明 |
|---|---|
| C++23 编译器 | GCC 13+ / Clang 16+（用到 `std::format`、`inline` 变量、`<filesystem>`）|
| [LIEF](https://github.com/lief-project/LIEF) | PE 解析（`-lLIEF`）|
| [capstone](https://github.com/capstone-engine/capstone) | 反汇编（`-lcapstone`）|
| Python 3.10+ | 验收脚本与工具（`relocate.py` 需要 `numpy`；`sig.py` 需要 `capstone` 的 python 包）|
| IDA + [ida-mcp](https://github.com/) | **可选**：只在需要重新反编译定位字段时用 |

```bash
# Debian/Ubuntu 例
sudo apt install g++-13 libcapstone-dev python3-numpy
pip install capstone
# LIEF：见 https://github.com/lief-project/LIEF 的安装说明（或 distro 包）
```

## 2. 30 秒上手

```bash
make                        # 自动生成 src/version.hpp 并构建 gi-dump
./gi-dump version/7.1       # 产出 out/dump.cs（约 177 MB / 1.4 秒）
python3 verify.py           # 28 项验收 —— 必须全 PASS
```

预期：
```
生成 src/version.hpp (201 行)
...
dump exit=0
============================================================
总计 28 项，FAIL 0 项
全部通过。
```

## 3. 目录结构

```
version.json            版本常量唯一来源（地址 / 槽位+密钥 / 公式参数 / 字段解码 / 结构尺寸）
Makefile  CMakeLists.txt
verify.py               28 项验收（换版本后跑这个）

src/
  main.cpp              入口（34 行）：MetadataFiles -> Il2CppImage -> Dumper
  version.hpp           (生成物，勿手改)
  metadata_files.hpp    MetadataFiles：装载 gi.exe/*.dat + 解析 PE（RAII）
  il2cpp_image.hpp      Il2CppImage：版本常量 + 文件字节 -> 可查询的 il2cpp 视图
  dumper.hpp            Dumper：渲染 dump.cs / stringliteral.json
  attributes.hpp        属性位掩码（ECMA-335，与版本无关）

tools/
  gen_version.py        version.json -> src/version.hpp（make 自动调用）
  sig.py                结构签名工具（gen / scan）
  slot_scan.py          全 .text 扫 MHY 槽位+密钥，得 (slot, op, key)
  relocate.py           换版本自动重定位（魔数 + 指令证据 + 结构自证）
  provenance.py         逐条溯源：扫 gi.exe 给出每个常量的代码读取点 -> docs/PROVENANCE.md
  gi_string_decrypt.py  字符串解密自检（应 75/75）
  split_main.py         一次性工具：把单文件 main.cpp 切成 src/*.hpp

docs/                   UPDATE.md / PROVENANCE.md / CROSS70.md / status.md / gi_fields.md / METHOD.md / ANALYSIS.md / mhytab_pairs.md
version/7.1/            样本：gi.exe + Managed/Metadata/*.dat + gi/Managed 软链
out/                    输出：dump.cs / stringliteral.json（gitignore）
ida/                    IDA 数据库（~10GB，gitignore）
```

## 4. 输入

`./gi-dump <game_root>` 需要这样的形状：

```
<game_root>/
├── gi.exe
└── gi/Managed/Metadata/
    ├── global-metadata.dat      （本样本 ~83 MB）
    └── startup-metadata.dat     （本样本 ~4 MB）
```

`version/7.1/` 已按此布置（`gi/Managed` 是指向 `../Managed` 的软链），所以可以直接 `./gi-dump version/7.1`。

> **在仓库根目录跑**（`gi-dump` 只生成在根目录；`make clean` 也只删根目录那份）。
> 别把二进制拷进样本目录 —— 拷过去后 `make` 不会更新它，会跑到旧版本。
>
> **stderr 里若看到 `Failed to parse PKCS9 TSTInfo`**：那是 LIEF 在解析 `gi.exe` 内嵌的
> Authenticode 时间戳签名 —— **不是错误**（`exit=0`、`out/dump.cs` 正常）。
> 新版已通过 `ParserConfig::parse_signature = false` 关掉，不再出现。

## 5. 输出

### `out/dump.cs`

```csharp
// Image 0: mscorlib.dll - 3542644948          ← 程序集（第二个数字是 typeStart 注释）

// Namespace: UnityEngine
// FullName: UnityEngine.MonoBehaviour
public class MonoBehaviour: Behaviour // TypeDefIndex: 2344
{
	// Properties
	internal System.Type[] Constraints { get; } // Getter: get_Constraints

	// Methods
// RVA: 0x19BFC4C0 Offset: 0x193B1EC0 VA: 0x159BFC4C0
	public void .ctor()
...
}
```

要点：
- `RVA` / `Offset` / `VA` 是同一个地址的三种表示（见 §8 常见问题）
- `RVA: -1` 表示**没有实体代码**（抽象/泛型共享桩/extern），不是算错
- 泛型方法会带 `/* GenericInstMethod : ... |-RVA: ... */` 块，列出各实例化
- 字段行末尾 `// 0x10` 是**字段偏移**（`static` 字段由属性 `FIELD_ATTRIBUTE_STATIC` 体现）
- 常量字段会写成 `public const int All = 32767;`

### `out/stringliteral.json`

本版本**没有独立的字面量条目表**（offset/length 打包进 nameIndex），所以固定输出 `[]`，属预期。

## 6. 命令行速查

| 命令 | 作用 |
|---|---|
| `make` | 生成 `src/version.hpp` + 构建 `gi-dump` |
| `make gen` | 只重新生成 `src/version.hpp` |
| `make run` | 等价 `./gi-dump $(SAMPLE)`（`SAMPLE ?= version/7.1`） |
| `make run ARGS=version/7.2` | 指定样本 |
| `make clean` | 删除 `gi-dump` |
| `./gi-dump <game_root>` | 产出 `out/dump.cs` |
| `python3 verify.py` | 验收默认样本（28 项） |
| `python3 verify.py version/7.2` | 验收别的样本 |
| `python3 verify.py <exe> <global.dat> <startup.dat>` | 手动指定三个文件 |

## 7. 工具说明

### `tools/gi_string_decrypt.py` —— 解密自检
```bash
python3 tools/gi_string_decrypt.py version/7.1/gi.exe \
        version/7.1/gi/Managed/Metadata/global-metadata.dat \
        version/7.1/gi/Managed/Metadata/startup-metadata.dat
```
输出所有程序集名 + `解密正确率: 75/75`。**这是最快判断「地址/密钥是否抄对」的方法。**

### `tools/slot_scan.py` —— 扫 MHY 槽位
```bash
python3 tools/slot_scan.py version/7.1/gi.exe version/7.1/gi/Managed/Metadata/global-metadata.dat
```
全 `.text` 反汇编（**几分钟**），得 3000+ 组 `(slot, op, key)`，并自带 3 条锚点自检：
```
MHY[0x13C] ^ 0x593DE464 = 0x3D00478   OK
MHY[0x0A0] ^ 0x3F525210 = 0xF1754C    OK
MHY[0x104] ^ 0x094C42AB = 0x37274C0   OK
```
结果缓存到 `slots_cache.json`（`relocate.py` 会复用）。

### `tools/relocate.py` —— 自动重定位表常量（**秒级**）
```bash
python3 tools/relocate.py version/7.1
python3 tools/relocate.py version/7.2 --scan      # 无缓存时自动跑 slot_scan
```
只靠跨版本稳定的三层锚：魔数 `"MHY\0"` → `slot_scan` 的指令证据 → **数据侧结构自证**
（12B 严格递增 / AttributeTargets 的 `[Flags]` 值签名 …）。
自测（7.1）能**在不知道旧 slot/key 的前提下**推出：
```
fieldDefaultValuesOffset = 0x3D00478   ✅ 与 version.json 一致
blob                     = 0xF1754C    ✅
```

### `tools/sig.py` —— 结构签名（找函数）+ 常量迁移
```bash
# 1) 生成 / 扫描签名
python3 tools/sig.py gen  version/7.1/gi.exe --names tools/sig_names.txt -o tools/sigs.json
python3 tools/sig.py scan version/7.2/gi.exe --sigs tools/sigs.json --fuzzy --json /tmp/h72.json

# 2) 从定位到的函数里自动迁移「字符串解密常量」
python3 tools/sig.py consts version/7.2/gi.exe \
    --func <DecryptString> --func <RuntimeInit>

# 3) 自动推导「entry 解码表达式」（**结构**是否变了）
python3 tools/sig.py entryexpr version/7.2/gi.exe \
    --decrypt <DecryptString> --caller <RuntimeInit>
```
- `gen` 会**跳过序言**、从函数中部取 8 条指令；寄存器全通配、精确保留小立即数/偏移
- `scan` 走**字节优先**（最长固定子串 `bytes.find` → 只在候选处反汇编核对）→ **0.8 秒 / 54 条**
- 自测：**54/54 命中，函数起点全部精确复原**
- `consts` 自动解出 **4/5** 个字符串密钥（`keyMulA/keyMulB/keySeed/keyStep`），
  并用「`xor reg,reg` 紧跟 `xor reg,imm32` **且之后 call 解密函数**」解出 `entryXor`
  —— 7.1 自测 **5/5**；7.0 只出 4/5（它把 entry 解码换成了 `xor K; sub key`，结构变了）
- `entryexpr` 把 entry 解码**表达式**推导出来（不是只给常数）：
  ```
  7.1:  ((raw ^ key) ^ 0x772FA51E)      形态 A（单一 xor）
  7.0:  ((raw ^ 0x1BD33CC0) - key)      形态 B（xor + sub）★ 结构不同
  ```
  两个版本都**唯一命中**（限定 `--caller RuntimeInit` + 只认 `scale=8` 的索引读取）

### `tools/dump_funcs.py` —— 从 dump 生成函数边界

```bash
python3 tools/dump_funcs.py out/dump71.cs -o /tmp/opencode/funcs71_dump.json
python3 tools/dump_funcs.py out/dump70.cs -o /tmp/opencode/funcs70_dump.json
```

它读取 dump.cs 里的 `// RVA:` 行，按地址排序，用下一个 RVA 作为当前函数结束地址；
输出 `{"funcs":[{"name","start","end","size","thunk","jmp_target","callees"}]}`。
`dump_align.py`、`sig.py`、`sigdiff.py` 都复用这份边界。

### `tools/dump_align.py` —— 混淆名类/方法候选召回

`--src-funcs` / `--dst-funcs` 不是手写的，先用 `dump_funcs.py` 从两个 dump 生成：

```bash
python3 tools/dump_funcs.py out/dump71.cs -o /tmp/opencode/funcs71_dump.json
python3 tools/dump_funcs.py out/dump70.cs -o /tmp/opencode/funcs70_dump.json
```

生成后每个文件形如：

```json
{"funcs": [{"name": "sub_...", "start": 5368715456, "end": 5368715472, "size": 16, "thunk": false, "jmp_target": null, "callees": []}]}
```

最佳候选召回命令（`hk70_best.json` 这一轮实际用的完整参数）：

```bash
python3 tools/dump_align.py \
  --from out/dump71.cs \
  --to out/dump70.cs \
  --hooks out/hk_71_all_named_map.json \
  --out out/hk70_align.json \
  --verify-disasm \
  --reselect-low \
  --reselect-medium \
  --class-score 0.58 \
  --class-margin 0.03 \
  --src-exe version/7.1/gi.exe \
  --dst-exe version/7.0/gi.exe \
  --src-funcs /tmp/opencode/funcs71_dump.json \
  --dst-funcs /tmp/opencode/funcs70_dump.json
```

说明：

```text
--reselect-low     低分候选在同一目标类内重选
--reselect-medium  中分候选也重选；漏掉它会影响 UITrigger... 等 medium 项
--src-funcs        源版本函数边界（dump_funcs.py 生成）
--dst-funcs        目标版本函数边界（dump_funcs.py 生成）
--method-aware-class  不要加；实验过，整体结果反而变差
--precision        不加；这是 candidate 召回阶段，precision 输出由 hook_resolve 负责
```

按**类/方法签名形状**对齐两个版本，忽略被混淆的名字；只负责召回候选，不负责最终判定。
`hk70_best.json` 的 95 个 key 来自 `hk_71_all_named_map.json`，不是 69 项的 `hk_71_map.json`。

### `tools/hook_resolve.py` —— 7.1→7.0 hook 自动重排

`dump_align.py` 给出候选后，用它做**证据重排**，专门处理 low / medium / ambiguous / missing：

```bash
python3 tools/hook_resolve.py \
  --src-dump out/dump71.cs \
  --dst-dump out/dump70.cs \
  --hooks out/hk_71_all_named_map.json \
  --base out/hk70_best.json \
  --src-export out/ida71_source_export.json \
  --dst-export out/ida70_group_candidates.json \
  --src-exe version/7.1/gi.exe \
  --dst-exe version/7.0/gi.exe \
  --out out/hk70_auto_resolved11.json \
  --report out/hk70_auto_resolved11_report.json \
  --max-body 300
```

这两个导出文件的来源：

```text
out/ida71_source_export.json
  tools/ida_hook_export.py 在 7.1 IDA 里生成
  内容：源 hook 的 addr/rva/name/xrefs/callees/decomp

out/ida70_group_candidates.json
  目标 7.0 候选函数的 IDA export 缓存
  候选地址来自 dump_align/hook_resolve 的类/方法筛选
  不是 ground truth，只是 xrefs/callees 缓存
```

重新生成源导出：

```bash
idat64 -A -S"tools/ida_hook_export.py out/ida71_source_export.json out/hk_71_all_named_map.json" \
  version/7.1/gi.exe.i64
```

目标候选缓存可以用 `ida_hook_export.py` 的地址模式生成：

```bash
GI_HOOK_ADDRS=0x14E645D90,0x14DF02AB0 \
GI_HOOK_OUT=out/ida70_group_candidates.json \
idat64 -A -S"tools/ida_hook_export.py" version/7.0/gi.exe.i64
```

之前那 70 个地址可以完整复现：

```bash
python3 tools/make_target_candidates.py \
  --dst-dump out/dump70.cs \
  --groups tools/hook_groups_70.json \
  --out out/ida70_group_addresses.json
```

输出：

```text
MJKBAEJOAPP    15
OADLDGCFKGG     7
BHFHBMOPLMP    48
total          70
```

这三个目标类不是手填的“目标答案”，而是 `dump_align.py` 的类形状得分 top-1：

| 源类 | 目标类 | 方法数 | class_score | 第二名 |
|---|---|---:|---:|---:|
| `BJKDIFKLEBG`（LCAvatarCombat）| `MJKBAEJOAPP` | 168 -> 168 | 0.6429 | 0.3555 |
| `JPJLHAEKMJD`（LCSelectPickup）| `OADLDGCFKGG` | 35 -> 35 | 0.7257 | 0.6172 |
| `HGPJJCNAHLB`（UITriggerHandlerUtil）| `BHFHBMOPLMP` | 323 -> 313 | 0.7060 | 0.1633 |

`class_score` 由方法形状多重集、形状序列和数量差组成；目标类名是混淆名，不能靠名字判断。
再用源 hook 的形状过滤：

```text
LCAvatar:   bool()          12 + float() 3  = 15
LCSelect:   bool(C) 5 + void(C) 2           = 7
UITrigger:  bool(C,string)                  = 48
```

所以这三个类是从**类形状**得到的候选容器，不是从 `hooks_7.0` 抄的。

然后用导出的地址列表生成 IDA export：

```bash
GI_HOOK_ADDRS=$(python3 -c \
  "import json; print(','.join(json.load(open('out/ida70_group_addresses.json'))['addrs']))") \
GI_HOOK_OUT=out/ida70_group_candidates.json \
idat64 -A -S"tools/ida_hook_export.py" version/7.0/gi.exe.i64
```

也可以完全不给 `--dst-export`：`hook_resolve.py` 会直接查
`--ida-url`（默认 `http://127.0.0.1:13337/mcp`）来取目标 xrefs。
`--dst-export` 只是缓存，方便重复跑。

更省事：让 `hook_resolve` 一边跑一边把目标候选导出成缓存：

```bash
python3 tools/hook_resolve.py   --src-dump out/dump71.cs   --dst-dump out/dump72.cs   --hooks out/hk_71_all_named_map.json   --base out/hk72_best.json   --src-export out/ida71_source_export.json   --src-exe version/7.1/gi.exe   --dst-exe version/7.2/gi.exe   --out out/hk72_auto_resolved.json   --report out/hk72_auto_resolved_report.json   --save-dst-export /tmp/ida72_candidates.json   --max-body 300
```

前提仍然是 `--ida-url` 指向 **7.2** 的 IDA MCP。  
以后复跑就直接用：

```bash
--dst-export /tmp/ida72_candidates.json
```

证据来源：

```text
方法形状 / 修饰符（private/public/static/virtual）
类内方法形状序列 LCS
源/目标直接调用点的相对位置
caller 的类/方法形状和嵌套关系
同类同形状组的顺序约束
函数体反汇编相似度
```

使用规则：

```text
--base           已有的自动结果，作为防回归基线
--src-export     源版本 IDA 导出（提供 xref）
--dst-export     目标版本 IDA 导出；缺失的 xref 会自动查 IDA MCP
--dst-xrefs      也可以传缓存的目标 xref JSON
--ida-url        默认 http://127.0.0.1:13337/mcp
--max-body       最多做多少个函数体评分；候选多时用 300
```

关键行为：

```text
不改已有 high-confidence 结果，除非类内 LCS 明确纠正了类选择
medium 结果只在调用点或 LCS 有一致证据时才替换
missing / ambiguous 才会用新候选补全
不读取 hooks_7.0.json 作为生成输入
不修改 version.json / dump / 基线文件
```

每条结果还会输出：

```json
{
  "confidence": "auto-evidence",
  "confidence_level": "high|medium|low",
  "confidence_score": 0.87,
  "confidence_reasons": ["call_delta=0.0007", "class_lcs=1", "body=0.844"],
  "review_required": false
}
```

`confidence_score` 是证据评分，不是概率；`confidence_level` 是规则等级。
`review_required=true` 表示还需要目标侧人工/额外权威对照，尤其是：

```text
目标类型名被混淆，且没有直接 call-site
源/目标返回类型或参数类型明显不一致
候选分差很小（如同形状 getter）
```

本次 7.1→7.0 的结果：

```text
67 / 67 有效 hook 正确
输出: out/hk70_auto_resolved11.json
报告: out/hk70_auto_resolved11_report.json
```

> `hooks_7.0.json` 只能用于最后的独立对照，不能作为自动查找的锚点。

### 新版本怎么用

假设源 hook 仍然是 7.1，新目标是 7.2：

```bash
# 1) 先有 7.2 的 dump
./gi-dump version/7.2
# 输出 out/dump.cs；按项目约定保存为 out/dump72.cs

# 2) 生成 7.1 / 7.2 函数边界
python3 tools/dump_funcs.py out/dump71.cs -o /tmp/opencode/funcs71_dump.json
python3 tools/dump_funcs.py out/dump72.cs -o /tmp/opencode/funcs72_dump.json

# 3) 生成 7.1 -> 7.2 的初始候选
python3 tools/dump_align.py \
  --from out/dump71.cs \
  --to out/dump72.cs \
  --hooks out/hk_71_all_named_map.json \
  --out out/hk72_best.json \
  --verify-disasm \
  --reselect-low \
  --reselect-medium \
  --class-score 0.58 \
  --class-margin 0.03 \
  --src-exe version/7.1/gi.exe \
  --dst-exe version/7.2/gi.exe \
  --src-funcs /tmp/opencode/funcs71_dump.json \
  --dst-funcs /tmp/opencode/funcs72_dump.json

# 4) 目标 7.2 IDA 打开，证据重排
python3 tools/hook_resolve.py \
  --src-dump out/dump71.cs \
  --dst-dump out/dump72.cs \
  --hooks out/hk_71_all_named_map.json \
  --base out/hk72_best.json \
  --src-export out/ida71_source_export.json \
  --src-exe version/7.1/gi.exe \
  --dst-exe version/7.2/gi.exe \
  --out out/hk72_auto_resolved.json \
  --report out/hk72_auto_resolved_report.json \
  --max-body 300
```

新版本不需要手动维护那 70 个类名：

```text
hook_resolve 会按源类形状重新搜索目标类
-> 目标方法的 shape 过滤
-> 目标 IDA xrefs/callees
-> 函数体评分
```

如果新目标 IDA 没有打开，可以预先准备 `--dst-export` 或 `--dst-xrefs`；
否则默认查 `http://127.0.0.1:13337/mcp`。

### `tools/gen_version.py` —— 生成版本头
```bash
python3 tools/gen_version.py        # version.json -> src/version.hpp（make 会调）
```

### `tools/provenance.py` —— 逐条溯源（每个常量从哪来）
**直接扫 `gi.exe`**（不读 `slots_cache.json`），给出 `version.json` 里每条偏移/密钥的
**代码读取点（指令地址 + 函数名）**，输出 `docs/PROVENANCE.md`。
```bash
python3 tools/provenance.py version/7.1/gi.exe
python3 tools/provenance.py version/7.0/gi.exe --out /tmp/P70.md
# 迭代格式时可复用上次扫描：--hits-in/--hits-out
```
「未命中」不是错误 —— 说明那条是**结构自证 / 公式 / 反解**来的（见 `docs/UPDATE.md` §5.7）。

### `tools/split_main.py` —— 一次性工具
把单文件 `main.cpp` 机械切分成 `src/*.hpp`。**只在需要重新搬运代码时用**，平时不用。

## 8. 常见任务

**① 换版本（→ 详见 `docs/UPDATE.md`）**
```bash
python3 tools/sig.py scan version/7.2/gi.exe --sigs tools/sigs.json   # 找函数（秒级）
python3 tools/relocate.py version/7.2                                  # 推表常量
vim version.json                                                       # 填回常量
make && ./gi-dump version/7.2 && python3 verify.py version/7.2         # 28 项拍板
```

**② 崩溃了怎么查**
```bash
make clean && make OPT="-O0 -g"
gdb -batch -ex run -ex "bt 12" --args ./gi-dump version/7.1
```
本项目历史崩溃都发生在：读越界/野指针。**先看 §9**。

**③ 只想快速判断「常量抄对没有」**
```bash
python3 tools/gi_string_decrypt.py ...    # 75/75 ？
python3 tools/relocate.py version/7.1     # fDV / blob 是否推出已知值？
```

**④ 输出里出现大量相同 RVA**
→ 说明用错了方法地址表（见 §9 第 3 条）。`verify.py` 的「方法 RVA 去重率」会报 FAIL。

**⑤ RVA / Offset / VA 的区别**
```
VA     = 运行时地址 = ImageBase(0x140000000) + RVA
RVA    = 相对基址的偏移（内存，按 0x1000 段对齐）
Offset = 文件里的字节位置（按 0x200 文件对齐）
换算式（**必须按段**）：Offset = 段.PointerToRawData + (RVA - 段.VirtualAddress)
```
例：`VA 0x1402F2B00` → `RVA 0x2F2B00` → `Offset 0x2F1F00`（.text 段）

**⑥ 重新生成签名（比如改过 `sig_names.txt` 后）**
```bash
python3 tools/sig.py gen version/7.1/gi.exe -o tools/sigs.json
python3 tools/sig.py scan version/7.1/gi.exe --sigs tools/sigs.json   # 自测应 54/54
```

**⑦ 7.1→7.0 hook 自动迁移**
```bash
# 1) 生成函数边界（dump_align 的 --src-funcs/--dst-funcs 用）
python3 tools/dump_funcs.py out/dump71.cs -o /tmp/opencode/funcs71_dump.json
python3 tools/dump_funcs.py out/dump70.cs -o /tmp/opencode/funcs70_dump.json

# 2) 已有候选（可选，hook_resolve 也会自己召回）
python3 tools/dump_align.py \
  --from out/dump71.cs --to out/dump70.cs \
  --hooks out/hk_71_all_named_map.json \
  --out out/hk70_align.json \
  --verify-disasm --reselect-low --reselect-medium \
  --class-score 0.58 --class-margin 0.03 \
  --src-exe version/7.1/gi.exe --dst-exe version/7.0/gi.exe \
  --src-funcs /tmp/opencode/funcs71_dump.json \
  --dst-funcs /tmp/opencode/funcs70_dump.json

# 3) 证据重排 + 补 missing
python3 tools/hook_resolve.py \
  --src-dump out/dump71.cs --dst-dump out/dump70.cs \
  --hooks out/hk_71_all_named_map.json \
  --base out/hk70_best.json \
  --src-export out/ida71_source_export.json \
  --dst-export out/ida70_group_candidates.json \
  --src-exe version/7.1/gi.exe --dst-exe version/7.0/gi.exe \
  --out out/hk70_auto_resolved11.json \
  --report out/hk70_auto_resolved11_report.json \
  --max-body 300

# 4) 只做独立验证，不参与查找
python3 - <<'PY'
import json
R = json.load(open('out/hk70_auto_resolved11.json'))
H = {x['name']: x for x in json.load(open('out/hooks_7.0.json'))['hooks']}
ok = bad = miss = 0
for n, h in H.items():
    a = int(h['rva_7_0'], 16)
    t = R.get(n, {}).get('target_rva')
    if t is None:
        miss += 1
    elif int(t, 16) == a:
        ok += 1
    else:
        bad += 1
print('same=%d diff=%d missing=%d' % (ok, bad, miss))
PY
```

目标 xref 优先从 `--dst-export` 读取；没有导出的候选会自动通过 IDA MCP
（默认 `127.0.0.1:13337`）查询。没有 IDA 时，预先准备 `--dst-xrefs` 缓存也能跑。

## 9. 排错（症状 → 原因 → 处理）

| 症状 | 原因 | 处理 |
|---|---|---|
| 程序直接 `std::length_error` | 文件打不开（路径不对）| 检查 `<root>/gi/Managed/Metadata/*.dat` 与 `<root>/gi.exe` |
| SIGSEGV 在解引用处 | 把镜像 **VA** 当宿主指针用了 | 必须 `exe.data() + pe->va_to_offset(VA)` |
| 某些字段类型只剩 `[]` / `*` | VA 与宿主指针**混用**（算索引要减**镜像 VA**）| 见 `UPDATE.md` §9 陷阱 5 |
| **大量方法 RVA 相同**（几十万次）| 用错方法地址表：`*(T0+0x60)` 是**泛型**方法指针表 | 非泛型用 `*(T0+0x88)[methodIndex]` |
| 属性访问器名全空 / 事件 0 个 | 结构体**字段顺序**抄错（get/set、typeIndex/nameIndex）| 以反编译的读取点为准 |
| 名字正确但**带垃圾尾巴** | 逐索引 key 用了 32 位乘法（会回绕）| **一律 64 位** |
| 签名**到处匹配** | 取到了序言（`push`/`movaps` 刷栈）| 已自动跳过；若仍弱，该函数退回字符串锚 |
| `verify.py` 某项 FAIL | 见该项名字 | 回 `UPDATE.md` §5/§6 找它的重定位方法 |

## 10. 已知限制（不会因为"再努力一点"就消失的）

| 缺 | 原因 |
|---|---|
| 自定义属性的**值** | `Il2CppCodeRegistration` 是**运行时构造**的，文件镜像里不存在 |
| `attributesInfo` 的 `token` 语义 | 非标准 ECMA token（被重映射）→ 属性**名字**也挂不回成员 |
| 泛型**实例**的类型名 | `type->data.generic_class` 指向的表未定位（输出 `?<...>` 占位）|
| 泛型参数的 `in`/`out` 变体 | 14 字节参数项整体加密，变体 flags 偏移未定 |
| 少数中文/韩文默认值截断（~29 处）| 字符串常量路径的长度少算 1 字节 |

完整清单见 [`docs/status.md`](docs/status.md) §5。

## 11. 文档索引

| 文档 | 内容 |
|---|---|
| [`docs/UPDATE.md`](docs/UPDATE.md) | **版本更新维护手册**：三层锚、逐项重定位方法、14 条陷阱 |
| [`docs/status.md`](docs/status.md) | 当前进度、已验证字段、**失败记录**（避免重复踩）|
| [`docs/gi_fields.md`](docs/gi_fields.md) | 结构体字段偏移与逐索引 key 速查 |
| [`docs/METHOD.md`](docs/METHOD.md) | 文章方法整理（中文）|
| [`docs/ANALYSIS.md`](docs/ANALYSIS.md) | 总报告（部分章节已过期，以 `status.md` 为准）|
| [`docs/mhytab_pairs.md`](docs/mhytab_pairs.md) | MHY 槽位配对表（含「槽位是字节偏移」的更正）|

### `tools/ida_hook_export.py` —— 导出 hook 函数/xref/callees

`hook_resolve.py` 需要源版本的 `functions[name].xrefs/callees`。这个脚本在 IDA 内运行，
不会修改数据库：

**源版本（7.1），按 hook 名字/RVA：**

```bash
idat64 -A -S"tools/ida_hook_export.py /tmp/ida71_source_export.json out/hk_71_all_named_map.json" \
  version/7.1/gi.exe.i64
```

或者在 IDA GUI 里：

```text
File -> Script file... -> tools/ida_hook_export.py
```

GUI 没有命令行参数时，用环境变量：

```text
GI_HOOK_OUT=/tmp/ida71_source_export.json
GI_HOOKS=out/hk_71_all_named_map.json
```

**目标版本（7.0），按候选地址：**

```bash
GI_HOOK_ADDRS=0x14E645D90,0x14DF02AB0 \
GI_HOOK_OUT=/tmp/ida70_candidates.json \
idat64 -A -S"tools/ida_hook_export.py" version/7.0/gi.exe.i64
```

如果地址已经自己整理在文件里：

```text
# /tmp/addrs.txt，一行一个，允许空行和 # 注释
0x14E645D90
0x14DF02AB0
```

则：

```bash
GI_HOOK_ADDRS_FILE=/tmp/addrs.txt \
GI_HOOK_OUT=/tmp/ida70_candidates.json \
idat64 -A -S"tools/ida_hook_export.py" version/7.0/gi.exe.i64
```

也支持 JSON：

```json
{"addrs": ["0x14E645D90", "0x14DF02AB0"]}
```

`GI_HOOK_ADDRS_FILE` 会从 `addrs` / `target_va` 读取；如果 JSON 只是数组，
会按普通地址数组处理。

导出的 JSON 直接作为：

```bash
--dst-export /tmp/ida70_candidates.json
```

它只包含你指定的地址，不会自动扩展；缺少的候选仍会由 `hook_resolve` 查 IDA MCP。

输出格式：

```json
{
  "source": "ida-hook-export-hooks",
  "image_base": "0x140000000",
  "functions": {
    "HookName": {
      "addr": "0x14...",
      "rva": "0x...",
      "name": "sub_...",
      "size": "0x...",
      "lookup": {"addr": "...", "name": "...", "size": "..."},
      "callees": [{"addr": "...", "name": "...", "type": "internal"}],
      "xrefs": [{"addr": "...", "type": "code", "fn": {...}}],
      "decomp": "..."
    }
  }
}
```

地址模式输出 `functions` 为 list，`hook_resolve.py --dst-export` 两种格式都接受。
`decomp` 可能为空，超大函数会返回空但 xrefs/callees 仍然有效。

### `tools/ida_export.py` + `ida_apply.py` —— 在 IDA 里导出常量（替代手抄）
```bash
# ① IDA 里：File → Script file… 选 tools/ida_export.py  → /tmp/ida_export.json
# ② 配对到表名
python3 tools/ida_apply.py /tmp/ida_export.json --out /tmp/tables.json
```
`ida_export.py` 用 Hex-Rays 的表达式（`global + *(MHY+SLOT) OP KEY`）+ IDA 的真实函数边界，
把 `tables` 的 slot/op/key **连值一起**导出；`ida_apply.py` 按 `tools/table_funcs.json`
的「函数→表」映射配对，单表函数直接确定，多表函数给候选。

### 无头模式（不打开 IDA 界面）
```bash
tools/ida_headless.sh version/7.0/gi.i64 /tmp/ida70.json /tmp/h70.json   # 可直接给 .i64
# 等价：idat64 -A -S"tools/ida_export.py <out> <hits>" <exe>
```
`-A` 自动跑完退出；**首次自动分析 431MB 的 gi.exe 是小时级**，有分析好的 `.i64` 才快。
需要 Hex-Rays 授权（脚本要调 `decompile()`）。
