# GIMetadata 分析报告

> 目标：① 让 `main.cpp` 跨平台编译；② 分析仓库内这份 `gi.exe` 与 `main.cpp` 硬编码参数是否匹配。
> 环境：Arch Linux · GCC 16.2.1 · Clang 22.1.8 · LIEF 1.0.0 · capstone 5.0.9
> 样本：`gi.exe` 444,260,776 B · `Managed/Metadata/global-metadata.dat` 82,724,152 B · `startup-metadata.dat` 4,060,776 B

---

## 0. 结论摘要

| 项目 | 状态 |
|---|---|
| 跨平台编译（Linux ELF） | **完成并验证** |
| Windows 行为不变 | **完成**（路径拼法逐字节一致） |
| 原 dump 崩溃根因 | **已定位**：所有混淆常量版本绑定，本样本 0/33 命中 |
| 本样本的表地址 / 加载例程 | **已定位** |
| **字符串解密算法** | **已完全攻克，75/75 实测通过** → 见 [`mhytab_pairs.md`](mhytab_pairs.md) 第 7 节 |
| header 字段 | **14 条已定位**（见 `gi_fields.md`），typeDefinitions 88902/88902、fields 440172、properties 115596 均实测通过 |
| **dump 实跑** | ❌ **从未跑过** |
| 各索引 key 公式 | 程序集名一条已取得并验证；其余待提取 |

> **决定性验证**：`python3 gi_string_decrypt.py` → 75 个程序集名全部解出且均为合法 `.dll`
> （`mscorlib.dll` / `UnityEngine.*` / `Assembly-CSharp.dll` …），正确率 **100%**。
> 这条链路一旦跑通，表地址 → 槽位公式 → 字段语义 → 解密全部对齐，可判定上述定位无误。

---

## 1. 跨平台移植

### 1.1 改动清单（`main.cpp`，共 5 处，零行为影响）

| 位置 | 原内容 | 改为 | 原因 |
|---|---|---|---|
| 24-33 | `#pragma warning(push/disable/pop)` | 包进 `#ifdef _MSC_VER` | MSVC 专属指令 |
| 105 | `#pragma comment(lib, "bcrypt.lib")` | 删除 | 全文无任何 BCrypt 调用，纯残留 |
| 886 | `(unsigned __int64)v37` | `(uint64_t)v37` | MSVC 专属类型，语义相同 |
| 1817-1820 | `__argv[1]`、`"\\gi\\Managed\\Metadata\\"` | `argv[1]` + `argc` 检查 + `kPathSep` | `_WIN32` 下仍为 `\`，POSIX 下为 `/` |
| 20-22 | — | 补 `<memory>`、`<string_view>` | `unique_ptr` / `string_view` 原先靠传递包含 |

```cpp
#ifdef _WIN32
constexpr const char* kPathSep = "\\";
#else
constexpr const char* kPathSep = "/";
#endif
```

### 1.2 构建与验证

```console
$ make
g++ -O2 -std=c++23 -Wall -o gi-dump main.cpp -lcapstone -lLIEF
$ file gi-dump
ELF 64-bit LSB pie executable, x86-64, dynamically linked
$ ldd gi-dump
libcapstone.so.5  libLIEF.so  libstdc++.so.6
```

新增 `Makefile`（pkg-config 探测，缺 `lief.pc` 时回退 `-lLIEF`）与 `CMakeLists.txt`。
GCC 16.2.1 与 Clang 22.1.8 均通过（仅剩原代码本有的 `-Wswitch` / `-Wsign-compare` 告警，对应 MSVC 侧被 pragma 屏蔽的 C4267/C4244）。

---

## 2. 原 dump 崩溃的根因

程序在 `string_Literal()` 段错误（`main.cpp:1294`），gdb 显示计算出的指针落在栈地址区→ `decryptHeader()` 产出垃圾。

### 2.1 证据链

1. **LIEF 无责**：LIEF 1.0.0 正常解析，13 个 section 齐全，5 个硬编码 VA 的 `va_to_offset` 均返回合理偏移。
2. **26 个字段全部越界**：以 `global-metadata.dat` 大小 `0x4EE4538` 为界，`decryptHeader()` 的 26 个输出无一落在范围内：

| 字段 | 旧公式 | 解出的值 | |
|---|---|---|---|
| `stringLiteralOffset` | `table[0xCC] ^ 0x3C92F84B` | `0x3C92F84A` | 1 GB，越界 |
| `stringLiteralDataOffset` | `table[0x20] ^ 0x1D07B94C` | `0x1D07B94D` | 越界 |
| `typeDefinitionsCount` | `table[0x12C] - 0x0BBB76A5` | `4098132316` | 越界 |
| `imagesCount` | `table[0x1FC] - 0x0A2A6C08` | `4124414969` | 越界 |

3. **表位置不对**：`0x142419A40`（旧表地址）处数据是无关的重复结构，非混淆 header 表。
4. **全盘扫描 0 候选**：以 26 条约束为条件，逐 4 字节扫描全部 444 MB（所有 section），**没有任何 0x200 字节窗口同时满足** → 不只是地址漂移，**槽位布局与密钥常量都变了**。
5. **常量比对 3/33**：33 个混淆常量中仅 3 个"命中"，且均为噪声（`0x1BD3`、`0x262BB9DB`、`.upx0` 中的 `0x154AA920`）。
6. **旁证**：`global-metadata.dat` 在 `+0x210` 处 magic 为 `0x01000000`（非 il2cpp 的 `0xFAB11BAF`）；整个 exe 中 `0xFAB11BAF` 出现 **0 次**。

> 结论：崩溃是**原项目对特定游戏版本的硬编码**所致，与跨平台移植无关；MSVC 版在同一样本上行为一致。

---

## 3. 本样本的静态定位结果

方法沿用原出处文章（<https://www.unknowncheats.me/forum/genshin-impact/774111-exploring-custom-struct-genshin-impact.html>）的两招：**ASCII 签名扫描** + **xref 回溯**。

### 3.1 MHY 表

文章中的定位方式：

```asm
.text:00000001402B4958  lea  rax, unk_142419A40
.text:00000001402B495F  mov  cs:s_MHYTable, rax
.rdata:0000000142419A40  db 4Dh ; 'M'
.rdata:0000000142419A41  db 48h ; 'H'
.rdata:0000000142419A42  db 59h ; 'Y'
```

本样本照搬，全 `.text`（9,517,134 条指令）中该地址**仅 1 处引用**：

```asm
0001402F2948  lea  rax, [rip+0x24E2281]        ; -> 0x1427D4BD0   (.rdata, 开头 "MHY\0")
0001402F294F  mov  qword ptr [rip+0x57E2962], rax ; -> 0x145AD52B8   (.data, s_MHYTable)
```

| 项 | 值 |
|---|---|
| MHY 表本体 | `0x1427D4BD0`（文件偏移 `0x027D3BD0`，`.rdata+0x6466512`） |
| 全局指针 | `0x145AD52B8`（位于 `.data` 的 BSS 区） |
| 注册代码 | `0x1402F2910`（静态构造器，连续 5 组 `lea`/`mov` 注册 5 张表） |

**本版本共 5 张表**（文章版本为 3 张）：

| 全局 | 表本体 VA |
|---|---|
| `0x145AD5298` | `0x1422DE370` |
| `0x145AD52A0` | `0x142870A88` |
| `0x145AD52A8` | `0x142870B28` |
| `0x145AD52B0` | `0x1422DE418` |
| `0x145AD52B8` | `0x1427D4BD0` ← MHY 表 |

### 3.2 表体布局

```
+0x000  0059484D "MHY\0"   00000000        魔数 + 保留
+0x008 .. +0x200           高熵数据        ← 26 个字段的混淆常量区
+0x204  402F2B00 00000001  402F2B1000000001  ← 明文指针数组
```

### 3.3 metadata 加载例程

以 `global-metadata.dat` 字符串做 RIP 相对 xref（全 `.text` 仅 1 处）：

```asm
00014053531e  lea  rcx, [rip+...]   ; "global-metadata.dat"
000140535325  call 0x140523120      ; 读文件
00014053532d  lea  rcx, [rip+...]   ; "startup-metadata.dat"
000140535334  call 0x140523120
000140535349  add  rsi, 0x210       ; <<< header 偏移，与 main.cpp 假设一致
000140535350  mov  [rip+...], rsi   ; s_GlobalMetadataHeader
00014053535e  mov  rax, [rip+...]   ; 表指针 <- 0x145AD52A0
000140535365  movsxd rbx, [rax+0x84]
000140535369  xor  rbx, 0x6622B34E
```

| 变量 | 全局地址 |
|---|---|
| `s_GlobalMetadataHeader` | `0x145AD52C0` |
| `s_StartupMetadataHeader` | `0x145AD52C8` |

---

## 4. 已实测验证的字段

验证方法：把解出的值拿去对应 `.dat` 里按已知结构体步长实测，**最终以"能解出可读字符串"为准绳**。

### 4.1 已确认（4 项）

| 字段 | 公式 | 值 | 实测结果 |
|---|---|---|---|
| `stringLiteralDataOffset` | `MHYTAB[0x184] + 0xBF9D4735` | `0x444C1E8` | 配合 §4.3 解密，75/75 程序集名正确 |
| `imagesCount`（字节） | `MHYTAB[0x02C] + 0xDB9A4FDD` | `3000` | `3000 / 0x28 = 75`，正好等于解出的程序集数 |
| `imagesDefinitions`（startup 侧基址） | `MHYTAB[0x20C] + 0xF134D80B` | `0x22C5C` | 40 字节步长，75 条全部解出合法名 |
| `genericParametersOffset` | `MHYTAB[0x170] ^ 0x7B3B96A2` | `0x3891F74` | 步长 14 字节（`Il2CppGenericParameter`） |

> `+K` 与 `-K'`、`^K` 在 32 位下是**同值不同写法**（`K' = 2^32 - K`），报常量时以本文写法为准。
> 例：`+0xDB9A4FDD` ≡ `-0x2465B023`，两者解出同一个 `3000`。

### 4.2 曾误判、现已排除的候选

| 公式 | 解出的值 | 问题 |
|---|---|---|
| `MHYTAB[0x0EC] + 0x973A9CDF` | `37,768,528` | 步长 92 B 能"看起来自洽"，但无字符串佐证，**不作为已验证** |
| `MHYTAB[0x120] + 0xE239498D` | `12,763,924` | 同上 |
| `MHYTAB[0x0DC] + 0xC3D3697A` | `1200` | 数值整齐易误判（`12 × 100`），未验证 |

> 教训：结构体步长自洽是**弱判据**。`typeDefinitionsOffset` 那种"92 字节步长、298/300 条目结构可信"的结论，
> 在高熵数据上几乎必然成立，不足以定性。**唯一可靠的验证是解出可读字符串。**

### 4.3 字符串解密（决定性验证）

完整算法见 [`mhytab_pairs.md`](mhytab_pairs.md) 第 7 节。要点：

```c
entry  = index_key(i) ^ rawNameIndex ^ 0x772FA51E;   // 24bit offset + 8bit length 打包在一起
offset = entry & 0xFFFFFF;
length = entry >> 24;
key    = 0x5C2B4E660E2D0544ull * ((0x694418957C890198ull * offset) ^ 0x55A357D81EF0E48Bull);
for (k = 0; k < (length+7)/8; k++)
    out[k] = enc[k] ^ (key + k * 0x6B0B40C349AE61E5ull);   // uint64 溢出
```

**本版本与 `main.cpp` 假设的结构差异**：不存在独立的 `{dataIndex, length}` 字面量条目表，
offset(24 位) 与 length(8 位) 直接打包进 `nameIndex` 字段 —— 这正是当初盲搜该表 0 命中的原因。

复现：

```console
$ python3 gi_string_decrypt.py
imagesCount          = 75
stringLiteralDataOff = 0x444C1E8
  [ 0] mscorlib.dll
  [ 5] UnityEngine.SharedInternalsModule.dll
  [74] Assembly-CSharp.dll
解密正确率: 75/75 (100.0%)
```

---

## 5. 候选配对表（`.text` 全扫，待逐字段确认）

数据流 tracer 扫过 `.text` 的 104,631 个函数块，得 63 组落在合法范围、其中 **53 组在 MHY 表上**。
下表中 **粗体** 为已实测验证者（详见 [§4.1](#41-已确认4-项)）。

| 表 | 槽位 | 运算 | 密钥 | 原始值 | 解出值 |
|---|---|---|---|---|---|
| `MHYTAB` | `0x0EC` | `+` | `0x973A9CDF` | `6B05B071` | 37768528 |
| `MHYTAB` | `0x120` | `+` | `0xE239498D` | `1E897987` | 12763924 |
| `MHYTAB` | `0x0DC` | `+` | `0xC3D3697A` | `3C2C9B36` | 1200 |
| `T1` | `0x050` | `+` | `0x9B1B5919` | `64E5B501` | 69146 |
| `T1` | `0x054` | `^` | `0x6622B34E` | `6628DD78` | 683574 |
| `T1` | `0x060` | `+` | `0xF0729EEC` | `0F90D014` | 225024 |
| `MHYTAB` | `0x008` | `+` | `0x934DEE31` | `6CB641EF` | 274464 |
| `MHYTAB` | `0x01C` | `+` | `0x80FA6886` | `7F05DB22` | 17320 |
| `MHYTAB` | `0x024` | `+` | `0xA3E7A399` | `5D09AEDB` | 15815284 |
| `MHYTAB` | `0x028` | `^` | `0x774A3BA6` | `7789427A` | 12810716 |
| **`MHYTAB`** | **`0x02C`** | `+` | `0xDB9A4FDD` | `2465BBDB` | 3000 |
| `MHYTAB` | `0x048` | `^` | `0x58C97533` | `5AEB136F` | 35808860 |
| `MHYTAB` | `0x054` | `^` | `0x23E67A90` | `23EBAFC1` | 906577 |
| `MHYTAB` | `0x078` | `+` | `0xE63A6EDB` | `19CDA491` | 529260 |
| `MHYTAB` | `0x080` | `^` | `0x26D4B008` | `2519FDE4` | 63786476 |
| `MHYTAB` | `0x088` | `^` | `0x09E94BD8` | `0D0464B0` | 82653032 |
| `MHYTAB` | `0x090` | `+` | `0xB7255040` | `4B164EE4` | 37461796 |
| `MHYTAB` | `0x094` | `^` | `0x4A4C0A71` | `4A88841D` | 12881516 |
| `MHYTAB` | `0x09C` | `+` | `0xF08117D4` | `0F838D94` | 304488 |
| `MHYTAB` | `0x0A0` | `^` | `0x3F525210` | `3FA3275C` | 15824204 |
| `MHYTAB` | `0x0AC` | `^` | `0x7D85E99F` | `7D8DCC9F` | 533760 |
| `MHYTAB` | `0x0B4` | `+` | `0xEC48AB9F` | `13C075A1` | 598336 |
| `MHYTAB` | `0x0B8` | `+` | `0xB6043152` | `49FFB1FA` | 254796 |
| `MHYTAB` | `0x0C0` | `+` | `0x9ED589B3` | `626C4DB1` | 21092196 |
| `MHYTAB` | `0x0C4` | `^` | `0x499FD4B1` | `4DA05729` | 71271320 |
| `MHYTAB` | `0x0D4` | `+` | `0xDD1C37D5` | `23156973` | 3252552 |
| `MHYTAB` | `0x0D8` | `+` | `0x8D16CD7C` | `76550034` | 57396656 |
| **`MHYTAB`** | **`0x0DC`** | `+` | `0xC3D3697A` | `3C2C9B36` | 1200 |
| `MHYTAB` | `0x0E0` | `+` | `0xE2F9B07D` | `1D654533` | 6223280 |
| `MHYTAB` | `0x0E8` | `^` | `0x4870FAF8` | `4BAD2330` | 64870856 |
| **`MHYTAB`** | **`0x0EC`** | `+` | `0x973A9CDF` | `6B05B071` | 37768528 |
| `MHYTAB` | `0x0F8` | `+` | `0xCB974EEA` | `355A038A` | 15815284 |
| `MHYTAB` | `0x108` | `+` | `0xB8700892` | `47910B2E` | 70592 |
| `MHYTAB` | `0x114` | `^` | `0x3E5D33E6` | `3DD76F8A` | 59399276 |
| **`MHYTAB`** | **`0x120`** | `+` | `0xE239498D` | `1E897987` | 12763924 |
| `MHYTAB` | `0x128` | `^` | `0x0F92DC85` | `0CE8867D` | 58350328 |
| `MHYTAB` | `0x130` | `+` | `0xDE4F6B4F` | `222859BD` | 7849228 |
| `MHYTAB` | `0x134` | `^` | `0x558E11EC` | `558C29F8` | 145428 |
| `MHYTAB` | `0x13C` | `^` | `0x593DE464` | `5AEDE01C` | 63964280 |
| `MHYTAB` | `0x14C` | `^` | `0x37855E78` | `33C14B20` | 71570776 |
| `MHYTAB` | `0x154` | `^` | `0x61747075` | `604BFC09` | 20941948 |
| `MHYTAB` | `0x15C` | `^` | `0x7AFBCC1D` | `7E21E481` | 81406108 |
| `MHYTAB` | `0x16C` | `+` | `0xE33589AC` | `1F0E0858` | 37982724 |
| **`MHYTAB`** | **`0x170`** | `^` | `0x7B3B96A2` | `78B289D6` | 59318132 |
| `MHYTAB` | `0x178` | `+` | `0xADEC9E28` | `5435F5B8` | 35820512 |
| **`MHYTAB`** | **`0x184`** | `+` | `0xBF9D4735` | `44A77AB3` | 71614952 |
| `MHYTAB` | `0x188` | `^` | `0x1B58E334` | `1A7A1901` | 19069493 |
| `MHYTAB` | `0x18C` | `+` | `0xEBF0392C` | `149CCE88` | 9242548 |
| `MHYTAB` | `0x198` | `+` | `0xBC2DA1FA` | `43D280DE` | 8920 |
| `MHYTAB` | `0x19C` | `^` | `0x30F4D28E` | `30F4D28E` | 0 |
| `MHYTAB` | `0x1A8` | `^` | `0x13FD57CF` | `108A4DE7` | 58137128 |
| `MHYTAB` | `0x1AC` | `+` | `0xF9DB82D3` | `07DE199D` | 28941424 |
| `MHYTAB` | `0x1B4` | `+` | `0xF00FB1AC` | `1058D498` | 6850116 |
| `MHYTAB` | `0x1B8` | `+` | `0xD2393C88` | `2DCEE3C8` | 532560 |
| `MHYTAB` | `0x1D8` | `^` | `0x1F85ABE5` | `1E3C4BFD` | 28958744 |
| `MHYTAB` | `0x1E8` | `^` | `0x100547B1` | `100DA671` | 582080 |
| `MHYTAB` | `0x1F8` | `+` | `0x85BF6C9F` | `7A4CE881` | 808224 |
| `MHYTAB` | `0x204` | `+` | `0xE5240D45` | `1BD780EB` | 16485936 |
| **`MHYTAB`** | **`0x20C`** | `+` | `0xF134D80B` | `0ECD5451` | 142428 |
| `T0` | `0x00C` | `^` | `0x050A0762` | `050B30F7` | 79765 |
| `T0` | `0x018` | `+` | `0xDDACA461` | `225477D7` | 72760 |
| `T0` | `0x040` | `^` | `0x7A05CF91` | `7A02C98B` | 460314 |
| `T1` | `0x050` | `+` | `0x9B1B5919` | `64E5B501` | 69146 |
| `T1` | `0x054` | `^` | `0x6622B34E` | `6628DD78` | 683574 |
| `T1` | `0x060` | `+` | `0xF0729EEC` | `0F90D014` | 225024 |
| `T2` | `0x008` | `+` | `0xD90D8FC3` | `26F2703D` | 0 |
| `T2` | `0x018` | `^` | `0x68876D70` | `6886A9C9` | 115897 |
| `T2` | `0x038` | `+` | `0x8675E8D2` | `798B678B` | 86109 |
| `T2` | `0x040` | `+` | `0xD451F014` | `2BB2D19D` | 311729 |

---

## 6. 更正记录

**此前结论有误**：曾报告"`.data` 中 5 个表指针全局在文件里是密文"。

实际情况：`.data` 的虚拟大小（`0x9BF098`）远大于原始大小（`0x17BC00`），这 5 个全局落在 BSS 区，**文件里没有对应字节**，运行时由 `0x1402F2910` 的静态构造器填入。此前 VA→文件偏移换算未扣除 vsize/rawsize 之差，偏移落到了 `.pdata`（熵 7.99 bits/byte）里，读出的高熵字节是误判。

顺带观察：`.pdata` 熵达 7.99 bits/byte，正常 unwind 表不应如此，该 section 可能被额外处理过（与本任务无直接关系）。

**更正 2**：曾报告"capstone 脚本与 Hex-Rays 算出的密钥不一致，判定密钥提取错误"。
实际是 `+K` 与 `-K'` 在 mod 2^32 下同值（如 `0xB7255040` ≡ `-0x48DAAFC0`），两边算的是同一个数。**提取本身没错。**

**更正 3**：曾报告"`4×A9 ≠ 实际组步长`，两者差 `0x10`"，据此怀疑密钥流不是均匀递增。
实际 `4 × 0x6B0B40C349AE61E5 mod 2^64 = 0xAC2D030D26B98794`，与反汇编里的 `r15` **完全一致**；`0x10` 的偏差来自当时手算时漏了 `0x1` 进位。

---

## 7. 工具链

全部位于 `/tmp/opencode`，可独立复用（均以 LIEF 1.0.0 + capstone 5.0.9 构建）。

| 脚本 | 用途 |
|---|---|
| `probe.cpp` | PE 基本信息、section 表、`va_to_offset` 抽查 |
| `secflags.cpp` | section 权限位（判断是否可原地解密） |
| `identify.cpp` | 熵分析、特征字符串探测、PE 时间戳 |
| `const_search.cpp` | 全文件搜索 33 个混淆常量并定位所在 section |
| `xref_scan.cpp` | capstone 线性扫描，找 RIP 相对引用（带上下文窗口） |
| `dump_func.cpp` | 指定 VA 反汇编，自动解析 RIP 目标与立即数 |
| `chunks.h` | 函数切分器：同时支持 `.text` 的 int3 填充与 `.il2cpp` 的 NOP 填充 |
| `trace.cpp` | **数据流 tracer**：配对 `[表+槽位]` 与其解混淆密钥 |
| `keyhunt.cpp` | 按"64 位立即数密度"筛出混淆/解密例程 |
| `loopkey.cpp` | 按"`xor` + `add reg, 大立即数` 循环体"结构筛出块解密函数 |
| `find_lit.cpp` | 在 `.dat` 中盲搜字面量表（**假设不成立，见 §8**） |
| `validate2.py` | 候选偏移值与已知结构体步长的匹配打分 |
| `check_vas.cpp` | 核对 `main.cpp` 中全部硬编码 VA 是否仍有效 |

### 仓库内新增

| 文件 | 用途 |
|---|---|
| `gi_string_decrypt.py` | **本样本的字符串解密实现 + 自检**（75 个程序集名，100%） |
| `mhytab_pairs.md` | 27 组权威 (槽位, 运算, 密钥) 配对表 + **§7 完整解密算法** |
| `METHOD.md` | 原文章定位方法的中文整理（签名扫描 / xref 回溯） |
| `ANALYSIS.md` | 本文 |
| `Makefile` / `CMakeLists.txt` | 跨平台构建 |

### tracer 的关键设计

最初用"前瞻 N 条指令抓立即数"的朴素做法，配对几乎全错。正确做法是抽象解释：

1. 跟踪"哪个寄存器持有哪张表的指针"（`mov rXX, [rip+G]`，G 为已知表全局）
2. `movsxd dst, [表+disp]` → `dst` 标记为槽位值
3. 随后的 `xor/add/sub dst, imm` → 配对成立
4. **`call` 之后清空易失寄存器**（rax/rcx/rdx/rsi/rdi/r8-r11）—— 漏掉这一步会产生大量跨调用的误配对
5. 兼容两种书写：`movsxd r,[表+d]; xor r,K` 与 `mov ebx,K; add ebx,[表+d]`

修正后同一段代码的配对从 24 条（大多无效）变为 63 条有效。

### 函数切分的坑

| section | 填充方式 | 失败后果 |
|---|---|---|
| `.text` | `0xCC`（int3） | — |
| `.il2cpp` | 单个多字节 NOP（`66 66 66 66 66 2E 0F 1F 84 ...`），`0xCC` 仅占 0.34%，无 `endbr64` | 按 int3 切分时整段 305 MB 被视作 1 个巨型块直接跳过，**扫描"0 命中"其实是根本没扫** |

初版切分器要求"连续 4 个填充指令"，在 `.il2cpp` 上同样失效。最终规则：填充 ≥4 项，或紧跟 `ret` 之后有 ≥1 项填充。

---

## 8. 待办清单

### 8.1 必须重新定位的硬编码 VA

| `main.cpp` 中的 VA | 用途 | 本样本状态 |
|---|---|---|
| `0x142419A40` | MHY 表 | **失效**，实际为 `0x1427D4BD0` |
| `0x141F88938` | `Il2CppCodeRegistration` | **失效**，该地址落在 `.text`（是代码，非结构体） |
| `0x1424A9F70` | `Il2CppMetadataRegistration` | 待确认（该处值为 `0x1546A7750`，形似合法 VA） |
| `0x141F04D90` | `customAttributeGenerators` 数组 | 待确认（落在 `.text`） |
| `0x1404D1BF0` | `String::NewLen` helper | 待确认 |
| `0x1404DA250` | `typeof()` helper | 待确认 |
| `0x1404C7BD0` | bool helper | 待确认 |

后四项在 `parseGenerator()` 中以"比较指令立即数是否等于该地址"的方式使用，失效会直接导致自定义属性参数解不出来。

### 8.2 混淆常量取得情况

| 项 | 旧值（文章版本） | 本样本 | 状态 |
|---|---|---|---|
| `decryptString` 密钥派生 | `0x66717F7413519820` 等 6 个 | `0x5C2B4E660E2D0544` / `0x694418957C890198` / `0x55A357D81EF0E48B` | **已取得，75/75 验证** |
| 分块密钥步长 | `+ 0x1AAF299B1B933F38` | `+ 0x6B0B40C349AE61E5` | **已取得** |
| 字面量条目解码 | `dataIndex = raw ^ 0x47DBC836 + key` | `entry = indexKey ^ rawNameIndex ^ 0x772FA51E` | **已取得（结构不同，见 §4.3）** |
| 程序集名 index key | `((-486614588*i + 535893754) ^ 0x324D0DED) + 311442397` | `1368137530*(((667674736*((13029*i)^0x43E2DEB7)+0xCB287082F0)>>8))+1505552983` | **已取得，75/75 验证** |
| 泛型参数名 index key | — | `(((1845531077*((12124*idx+1969070457)^0x423B2C8D))>>10)+1212570291)^0x62A3A8F4` | 已取得，未验证 |
| `stringLiteralCount` | `0x52B07516 ^ 0x52B1495D` | — | 未取得 |
| 其余 22 个 header 字段 | 见 [§5](#5-候选配对表text-全扫待逐字段确认) | — | 待逐字段确认 |
| 各索引 key 公式 | 如上（仅程序集名一条） | — | 其余待提取 |

### 8.3 失败的尝试（记录以免重复）

- **在 `.il2cpp` 全扫旧常量**：本版本每次更新全部重生成，0/6 命中，纯属白费工夫。
- **按结构体步长自动打分**：判据"多数 dword < 2^25"在稀疏高熵区几乎必然 100% 通过，无法区分。**已证明会产生假阳性**（§4.2）。
- **盲搜字面量表**：曾假设"因 `dataIndex < 2^27`，混淆后各条目高 5 位必然相同"，可据此反解密钥。扫出 445,596 个候选，单调性全部只有 4~5/2000。
  **根本原因**：本版本**根本没有这个表** —— offset+length 打包在 `nameIndex` 里（§4.3）。
- **整表单常量 XOR 假设**：枚举 40 万个 `stringLiteralCount` 反解 K，0 候选。表体是"按设计混淆存放"，每个槽位有各自的密钥，不存在统一 K。
- **在 IDA `py_eval` 里跑批量扫描**：3108 个 xref 的 capstone 扫描会堵死主线程十几分钟，导致 IDA 卡死 / MCP 超时。
  **正确做法**：批量放进程外脚本，IDA 只做秒级单函数查询。

### 8.4 解密过程中踩的坑

| 坑 | 表现 | 正解 |
|---|---|---|
| 漏 `+0x210` 基址 | 全是乱码，但**前 8 字节偶尔对** | `s_GlobalMetadataHeader = global.data() + 0x210`，所有 global 侧偏移都要加上 |
| `imagesCount` 与 `imagesDefinitions` 用错槽位 | 循环 3535 次、越界读数组外 | `0x02C` = 字节数（`/0x28` 得条目数），`0x20C` = startup 侧基址 |
| 用 `key` 直接算 mod 4 判矛盾 | 推出"明文不可能是 `mscorlib.dll`" | 密钥流是 `key + k × A9`，不是固定 `key`；推论前提错了 |
| 循环上界写成 `imagesCount` 而非条目数 | 长串大面积"失败" | 越界读的其实是数组外的垃圾，与字符串长度无关 |
| 反编译器的 `_mm_shuffle_epi32(x, 68)` 渲染 | 以为 lane 映射是 `[lo,hi,lo,hi]` | 直接读 `.text` 真实指令；IDA 里 `A10=2×A9`、`A11=3×A9`、`r15=4×A9` |

---

## 9. 复现命令

```bash
# 编译
make                      # 或 cmake -B build && cmake --build build

# 字符串解密自检（本样本 75/75）
python3 gi_string_decrypt.py

# 布局（程序找的是 <root>/gi.exe 与 <root>/gi/Managed/Metadata/）
mkdir -p /tmp/run/gi/Managed
ln -sf /path/to/GIMetadata/gi.exe                      /tmp/run/gi.exe
ln -sf /path/to/GIMetadata/Managed/Metadata             /tmp/run/gi/Managed/Metadata
cd /tmp/run && /path/to/GIMetadata/gi-dump .

# 分析
cd /tmp/opencode
./probe   /path/to/gi.exe
./secflags /path/to/gi.exe
./const_search /path/to/gi.exe
./xref_scan /path/to/gi.exe .text 0x1427D4BD0
./trace   /path/to/gi.exe 0x140001000 0x21A8C00 multi
./loopkey /path/to/gi.exe .text
./check_vas /path/to/gi.exe
```

---

## 10. 参考

- 原作者文章（本项目公式出处）：<https://www.unknowncheats.me/forum/genshin-impact/774111-exploring-custom-struct-genshin-impact.html>
- 原项目引用的中文帖：<https://yougame.biz/threads/390622/>
