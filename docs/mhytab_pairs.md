# MHY 表配对表（本样本，从 IDA Hex-Rays 伪代码提取）

> 提取函数：`0x140534B80`（内含 metadata 加载例程 `0x14053531E`）
> 提取方式：IDA `py_eval` → `ida_hexrays.decompile()` → 正则匹配 `*(TYPE *)(qword_<全局> + slot) OP key`
> 本表为**权威值**，覆盖了此前脚本推测版本的大部分错误配对。

## 全局符号对照

| 伪代码符号 | 地址 | 说明 |
|---|---|---|
| `qword_145AD5298` | `0x145AD5298` | 表 T0 |
| `qword_145AD52A0` | `0x145AD52A0` | 表 T1（字面量缓存等） |
| `qword_145AD52A8` | `0x145AD52A8` | 表 T2 |
| `qword_145AD52B0` | `0x145AD52B0` | 表 T3 |
| `qword_145AD52B8` | `0x145AD52B8` | **表 MHYTAB**（本文重点） |
| `qword_145AD52C0` | `0x145AD52C0` | `s_GlobalMetadataHeader` |
| `qword_145AD52C8` | `0x145AD52C8` | `s_StartupMetadataHeader` |

表本体：`MHYTAB = 0x1427D4BD0`（`.rdata`，开头 `"MHY\0"`）。

---

## 语义判读规则

伪代码里下一行就带用途，可直接分类：

| 形态 | 含义 |
|---|---|
| `+ qword_145AD52C0 + <value>` | 该值是 **global-metadata.dat 内的偏移** |
| `+ qword_145AD52C8 + <value>` | 该值是 **startup-metadata.dat 内的偏移** |
| 之后跟 `/ 0x28`、`>> 3`、`>> 4`、`/ 0xE`、`* 8 * N` | 该值是**元素计数**（除数/移位即元素大小） |
| 参与指针运算 `ptr + val * 8` | 该值是**索引/下标** |

---

## 27 组配对（`0x140534B80`）

| 全局 | 槽位 | 运算 | 密钥 | 原语句 | 用途线索 |
|---|---|---|---|---|---|
| `T0` | `0x050` | `-` | `0x50F53991` | `while (v510 < (unsigned)(*(DWORD*)(qword_145AD5298 + 80) - 1358248337))` | 循环上界 → 计数 |
| `T0` | `0x088` | `+` | `0x00000008` | `v300 = *(_QWORD *)(*(_QWORD *)(qword_145AD5298 + 136) + 8 * v299)` | 8 字节元素数组指针 |
| `T0` | `0x098` | `+` | `0x00000008` | `v526 = *(_QWORD *)(*(_QWORD *)(qword_145AD5298 + 152) + 8 * v158)` | 8 字节元素数组指针 |
| `T1` | `0x008` | `+` | `0x00000010` | `*(QWORD*)(v67+8) = *(QWORD*)(qword_145AD52A0 + 8) + 16LL * *(int*)(v68 + 8LL*v61)` | 基址 + 16 字节步长索引 |
| `T1` | `0x048` | `+` | `0x00000010` | `v165 = *(_QWORD *)(qword_145AD52A0 + 72) + 16 * v164` | 同上 |
| `T1` | `0x050` | `-` | `0x64E4A6E7` | `if (*(DWORD*)(qword_145AD52A0 + 80) - 1692706535 > 0)` | 计数（>0 判断） |
| `T1` | `0x054` | `^` | `0x6622B34E` | `v40 = *(int*)(qword_145AD52A0 + 84) ^ 0x6622B34E` → `sub_1404FF510(qword_145AD4E90, 8 * v40)` | **字面量缓存计数**（8 字节/项） |
| `T1` | `0x060` | `-` | `0x0F8D6114` | `v366 = *(DWORD*)(qword_145AD52A0 + 96) - 260923668` → `off_1455B2FC8(1, v366)` | 计数 |
| `MHYTAB` | `0x008` | `-` | `0x6CB211CF` | `v528 = qword_145AD52C0 + *(DWORD*)(qword_145AD52B8 + 144) - 12…` | **global-metadata 偏移** |
| `MHYTAB` | `0x02C` | `-` | `0x2465B023` | `v49 = (*(DWORD*)(qword_145AD52B8 + 44) - 610644003) / 0x28uLL` | **计数，元素 40 B**（ImageDefinition） |
| `MHYTAB` | `0x090` | `-` | `0x48DAAFC0` | `v528 = qword_145AD52C0 + *(_DWORD*)(qword_145AD52B8 + 144) - 1222291392` | **global-metadata 偏移** |
| `MHYTAB` | `0x0AC` | `^` | `0x7D85E99F` | `v533 = qword_145AD52C8 + (*(int*)(qword_145AD52B8 + 172) ^ 0x7D85E99F)` | **startup-metadata 偏移** |
| `MHYTAB` | `0x0B4` | `-` | `0x13B75461` | `*(_DWORD *)(qword_145AD52C0 + *(_DWORD*)(qword_145AD52B8 + 180) - 330781793 + 70LL*v402)` | **global 偏移，70 B 步长**（TypeDefinition） |
| `MHYTAB` | `0x0B8` | `-` | `0x49FBCEAE` | `v534 = qword_145AD52C8 + *(DWORD*)(qword_145AD52B8 + 184) - 1241239214` | **startup-metadata 偏移** |
| `MHYTAB` | `0x0C0` | `-` | `0x612A764D` | `v544 = qword_145AD52C0 + *(DWORD*)(qword_145AD52B8 + 192) - 1630172749` | **global-metadata 偏移** |
| `MHYTAB` | `0x0D4` | `-` | `0x22E3C82B` | `v60 = *(DWORD*)(qword_145AD52B8 + 212) - 585353259; LODWORD(v544) = v60 >> 3;` | **计数，8 B 元素** |
| `MHYTAB` | `0x0DC` | `-` | `0x3C2C9686` | `v53 = *(DWORD*)(qword_145AD52B8 + 220) - 1009555078; dword_145AD5300 = v53 >> 4;` | **计数，16 B 元素** |
| `MHYTAB` | `0x0E0` | `-` | `0x1D064F83` | `v42 = *(DWORD*)(qword_145AD52B8 + 224) - 486952835` → `sub_1404FF510(…)` | 分配大小 → 计数 |
| `MHYTAB` | `0x0EC` | `-` | `0x68C56321` | `v535 = qword_145AD52C0 + *(_DWORD*)(qword_145AD52B8 + 236) - 1757766433` | **global-metadata 偏移** |
| `MHYTAB` | `0x120` | `-` | `0x1DC6B673` | `v330 = *(DWORD*)(qword_145AD52B8 + 288) - 499562099` → `qword_145AD52C0 + v330` | **global-metadata 偏移** |
| `MHYTAB` | `0x130` | `-` | `0x21B094B1` | `v546 = (*(DWORD*)(qword_145AD52B8 + 304) - 565220529) / 0xEuLL` | **计数，14 B 元素**（GenericMethodFnDef） |
| `MHYTAB` | `0x134` | `^` | `0x558E11EC` | `v160 = qword_145AD52C8 + (*(int*)(qword_145AD52B8 + 308) ^ 0x558E11EC)` | **startup-metadata 偏移** |
| `MHYTAB` | `0x188` | `^` | `0x1B58E334` | `v44 = *(_DWORD*)(qword_145AD52B8 + 392) ^ 0x1B58E334` → `(0x4EC4…CC5 * x) >> 64` | 计数（26 B 元素，MethodDefinition） |
| `MHYTAB` | `0x1A8` | `^` | `0x13FD57CF` | `v410 = *(unsigned *)(qword_145AD52C0 + (*(int*)(qword_145AD52B8 + 424) ^ 0x13FD57CF) + 4LL*…)` | **global-metadata 偏移**（TypeDefinition 表内寻址） |
| `MHYTAB` | `0x1B4` | `-` | `0x0FF04E54` | `v47 = (0xAAAA…AAAB * (u128)(*(DWORD*)(qword_145AD52B8 + …) - 267406932)) >> 64` | 计数 |
| `MHYTAB` | `0x1D8` | `^` | `0x1F85ABE5` | `+ (*(int*)(qword_145AD52B8 + 472) ^ 0x1F85ABE5)` 出现在 `qword_145AD52C0 + … + 12LL*idx` | **global-metadata 偏移** |
| `MHYTAB` | `0x20C` | `-` | `0x0ECB27F5` | `v113 = *(DWORD*)(qword_145AD52B8 + 524) - 248195061 + qword_145AD52C8` | **startup-metadata 偏移** |

---

## 与脚本推测版的差异（重要）

脚本版（`/tmp/opencode/trace.cpp` 产出）**多数密钥是错的**，Hex-Rays 已推翻：

| 槽位 | 脚本推测 | Hex-Rays 权威 | 结论 |
|---|---|---|---|
| `0x02C` | `+ 0xDB9A4FDD` | `- 0x2465B023` | ❌ 运算与密钥都错 |
| `0x0DC` | `+ 0xC3D3697A` | `- 0x3C2C9686` | ❌ |
| `0x0E0` | `+ 0xE2F9B07D` | `- 0x1D064F83` | ❌ |
| `0x0EC` | `+ 0x973A9CDF` | `- 0x68C56321` | ❌ |
| `0x120` | `+ 0xE239498D` | `- 0x1DC6B673` | ❌ |
| `0x134` | `^ 0x558E11EC` | `^ 0x558E11EC` | ✅ |
| `0x188` | `^ 0x1B58E334` | `^ 0x1B58E334` | ✅ |
| `T1 0x054` | `^ 0x6622B34E` | `^ 0x6622B34E` | ✅ |

**推论**：此前 `ANALYSIS.md` §4 中"已验证"的两个字段
（`typeDefinitionsOffset = MHYTAB[0x0EC] + 0x973A9CDF`、
`methodsOffset = MHYTAB[0x120] + 0xE239498D`）
虽然当时在 `.dat` 里确实匹配到了结构步长（`0x5C` / `0x46`），但**与 IDA 给出的公式不一致**，属于巧合命中或偏移错配，需按本表重新核对。

---

## 尚未提取

| 项 | 状态 |
|---|---|
| 其余 ~2470 个引用 MHYTAB 的函数 | 待提取（**不得在 IDA 主线程内批量跑**） |
| `decryptString` 的 6 个 64 位常数 | 未取得 |
| 字面量条目 XOR 密钥 | 未取得 |
| main.cpp 中 7 个硬编码 VA | 待重新定位 |

---

## 7. 字符串解密：已完全攻克（75/75 验证）

### 7.1 定位链（按文章方法）

```
xref "global-metadata.dat" → sub_1408AF790（纯读文件 + 末尾资产块解密，与 il2cpp 头无关）
                          → 0x140534B80 巨型 init 函数（分配各缓存、填 s_GlobalMetadataHeader）
xref 字面量缓存 qword_145AD52D0 → 仅 2 个引用 → sub_140524E80（实为类型缓存）
从 init 的汇编循环里抓到 GetStringFromIndex 调用点
                          → sub_14050F280  ← 解密函数本体
```

### 7.2 本版本的结构差异（与 main.cpp 假设不同）

| | main.cpp（原版） | 本版本 |
|---|---|---|
| 字面量条目 | 独立数组 `{dataIndex, length}`，8 字节/项 | **不存在** —— offset(24位)+length(8位) **打包进 nameIndex** |
| 条目解密 | `dataIndex = raw ^ 0x47DBC836 + key` | `entry = indexKey ^ rawNameIndex ^ 0x772FA51E` |
| 分块密钥步长 | `+ 0x1AAF299B1B933F38` | `+ 0x6B0B40C349AE61E5` |

这解释了为什么在 `.dat` 里搜不到 `{dataIndex, length}` 数组 —— **根本没有这个数组**。

### 7.3 完整算法（已验证）

```c
// ① 逐索引 key
uint32_t index_key(uint32_t i) {
    return 1368137530u * (((667674736u * ((13029u * i) ^ 0x43E2DEB7u) + 0xCB287082F0u) >> 8))
           + 1505552983u;
}

// ② 条目解码
uint32_t entry = index_key(i) ^ rawNameIndex ^ 0x772FA51E;
uint32_t offset = entry & 0xFFFFFF;        // 24 位：字面量数据块内偏移
uint32_t length = (entry >> 24) & 0xFF;    //  8 位：长度

// ③ 密钥派生（用的是 offset，不是索引）
uint64_t key = 0x5C2B4E660E2D0544ull * ((0x694418957C890198ull * offset) ^ 0x55A357D81EF0E48Bull);

// ④ 分块解密：每 8 字节一块，密钥每块递增
uint64_t qwords = (length + 7) / 8;
for (uint32_t k = 0; k < qwords; k++)
    out_qword[k] = enc_qword[k] ^ (key + k * 0x6B0B40C349AE61E5ull);   // uint64 溢出
```

密钥流**均匀递增**。IDA 里那段 4 路展开的 SSE/标量代码，`A10 = 2×A9`、`A11 = 3×A9`、`r15 = 4×A9`，全是同一步长的倍数。

### 7.4 新确认的字段

| 字段 | 公式 | 值 | 验证 |
|---|---|---|---|
| `imagesCount` | `MHYTAB[44] - 610644003` | `3000` | `/0x28 = 75` 个程序集 |
| `imagesDefinitions`（startup 侧基址） | `MHYTAB[524] - 248195061` | `0x22C5C` | 40 字节步长，75 条全部解出合法名 |
| `stringLiteralDataOffset`（global 侧） | `MHYTAB[388] - 1080211659` | `0x444C1E8` | 配合上述解密 75/75 |
| `genericParameters`（global 侧） | `MHYTAB[368] ^ 0x7B3B96A2` | — | 步长 14 字节 |
| 泛型参数名 key | `(((1845531077*((12124*idx+1969070457)^0x423B2C8D))>>10)+1212570291)^0x62A3A8F4` | — | `sub_14050D9C0` case 0x13/0x1E |

> 注：global-metadata 侧的偏移需再加 `0x210`（`s_GlobalMetadataHeader = global.data() + 0x210`）；startup 侧不加。

### 7.5 复现

```bash
python3 gi_string_decrypt.py            # 自检 75 个程序集名
```

```
imagesCount          = 75
stringLiteralDataOff = 0x444C1E8
  [ 0] mscorlib.dll
  [ 5] UnityEngine.SharedInternalsModule.dll
  [74] Assembly-CSharp.dll
解密正确率: 75/75 (100.0%)
```

---

## 方法备注

`py_eval` 在 IDA 主线程同步执行，单次调用应控制在 **1~2 秒内**。
批量提取的正确做法：

1. 用 IDA 导出的 xref / 函数列表（或进程外脚本）确定候选函数集合
2. 在**进程外**用 capstone 做快速预筛
3. 只把少量候选函数送进 IDA 逐个反编译

（本表 27 组即按此法，从单个函数 `0x140534B80` 一次取得。）
---

## 补充配对（本轮新增，来源：全 `.text` capstone 线性扫描 + 读取点验证）

> 方法：capstone 线性反汇编 `.text`（**必须 `md.skipdata=True`**，否则遇非法字节即停），
> 匹配 `mov reg,[base+disp]`（`disp < 0x300`）后 8 条指令内的 `op reg,imm`，
> 再算 `MHY[disp] op imm`，与已知表自检。共得 3269 个唯一组合，其中落进元数据偏移范围 295 个。

| 全局 | 槽位 | 运算 | 密钥 | 解出值 | 用途 |
|---|---|---|---|---|---|
| `MHYTAB` | `0x09C` | `-` | `259975212` | 304488 | **parameterDefaultValuesCount（字节数）** |
| `MHYTAB` | `0x104` | `^` | `0x094C42AB` | `0x37274C0` | **parameterDefaultValues 基址** |
| `MHYTAB` | `0x13C` | `^` | `0x593DE464` | `0x3D00478` | **fieldDefaultValues 基址** |
| `MHYTAB` | `0x0A0` | `^` | `0x3F525210` | `0xF1754C` | **常量值 blob**（字段与参数共用）|

**读取点（权威）**：
- `fieldDefaultValues`/blob：`0x1404C6E76` / `0x1404C6F1F`
- `parameterDefaultValues`/blob/count/methods：`GetDefaultParameterValueObject` @ **`0x140529DC0`**

### ⚠️ 表内前几行的「槽位」列是**字节偏移**（`qword_145AD52B8 + N`）
`8 + 144` 这类写法里 `144` 就是字节偏移；`0x008` 行是 `0x090` 行的重复，标错了。
