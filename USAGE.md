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

### `tools/sig.py` —— 结构签名（找函数）
```bash
python3 tools/sig.py gen  version/7.1/gi.exe --names tools/sig_names.txt -o tools/sigs.json
python3 tools/sig.py scan version/7.2/gi.exe --sigs tools/sigs.json
```
- `gen` 会**跳过序言**、从函数中部取 8 条指令；寄存器全通配、精确保留小立即数/偏移
- `scan` 走**字节优先**（最长固定子串 `bytes.find` → 只在候选处反汇编核对）→ **0.6 秒 / 36 条**
- 自测：`36/36 命中，函数起点全部精确复原`
- 生成时打印**弱签名警告**（区分度 <4 的函数，如 `movaps` 刷栈的）—— 那些不可靠，换版本时该退回字符串/调用图锚

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
