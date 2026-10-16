# mHoYo il2cpp 元数据定位方法

> 原文：<https://www.unknowncheats.me/forum/genshin-impact/774111-exploring-custom-struct-genshin-impact.html>
> 本文是原文定位方法的**中文整理**，按原文的推进顺序，把「怎么找到」「找到后怎么读出公式」写清楚。
> 配套：本仓库 `ANALYSIS.md` 记录了在另一游戏版本上重新走这套流程的实测结果。

---

## 0. 方法的核心前提

原文作者在开头就把整个方法的根基讲明了，有两条，缺一不可：

> **"Since it's a static dumper, the runtime approach where we could rely on initialized structures won't work for us, and we will need to replicate the game's data processing logic."**
> （因为是静态 dumper，不能依赖运行时已初始化的结构，必须复刻游戏自己的数据处理逻辑。）

> **"At the time of writing, the game version is 6.7, but from version to version only the keys and fields may change."**
> （写作时是 6.7 版，版本之间**只有 key 和字段会变**。）

第二条是整套方法可以复用的根本原因：**程序结构稳定，变的只是混淆密钥**。所以换版本不需要重新逆全部流程，只要重新抄一遍常量。

由此推出方法的本质，原文自称 **"look here, click here"**：

> 手上有**对应版本的 il2cpp 源码**当地图 → 在二进制里找到编译后变形的对应物 → 把里面的混淆公式抄出来。

---

## 1. 先拿到对应版本的 il2cpp 源码

原文的做法是：先从 `globalgamemanagers` 里读出 build method（原文样本为 `2017.4.30f1`），据此下载**该精确版本**的 il2cpp 源码。

因为后面每一步都是"拿源码片段去和二进制对照"，源码版本必须对得上，否则结构体字段偏移全错。

接下来要关注的结构（原文列出的清单）：

```
ImageDefinition / TypeDefinition / FieldDefinition / MethodDefinition
PropertyDefinition / EventDefinition / StringLiteral / CustomAttribute
Generics (GenericInst, GenericContainers)
```

---

## 2. 定位加载入口

### 2.1 从源码片段开始

源码里最靠前的初始化函数：

```cpp
void MetadataCache::Initialize() {
    s_GlobalMetadata = vm::MetadataLoader::LoadMetadataFile("global-metadata.dat");
    s_GlobalMetadataHeader = (const Il2CppGlobalMetadataHeader*)s_GlobalMetadata;
    IL2CPP_ASSERT(s_GlobalMetadataHeader->sanity == 0xFAB11BAF);   // 0xFAB11BAF = il2cpp 元数据 magic
    IL2CPP_ASSERT(s_GlobalMetadataHeader->version == 24);
}
```

对应的编译结果：

```c
char __fastcall Runtime::Init(char* a1) {
    ...
    GlobalMetadataBuffer_ptr   = LoadMetadataFile("global-metadata.dat");
    StartupMetadataBuffer_ptr = LoadMetadataFile("startup-metadata.dat");
    dword_14536E820 = *(_DWORD*)(qword_145370490 + 4);
    s_GlobalMetadataHeader   = GlobalMetadataBuffer_ptr   + 0x210;
    s_StartupMetadataHeader = StartupMetadataBuffer_ptr;
}
```

### 2.2 怎么找到这段代码

**用文件名字符串做交叉引用。** 在二进制里找 `global-metadata.dat` / `startup-metadata.dat` 的字符串，搜谁引用它 —— 引用处就是加载代码。

### 2.3 从这段代码能直接得到的结论

| 结论 | 依据 |
|---|---|
| 头指针要 `+0x210` | `s_GlobalMetadataHeader = GlobalMetadataBuffer_ptr + 0x210` |
| 存在多个全局指针 | `qword_145370490`、`qword_145370478`、`qword_145370488`… |
| 后续所有计算以"这张表"为基准 | 原文：「There are no other transformations, so we can proceed to the next step.」 |

dump 侧就照抄：

```cpp
std::string metaDir = (std::string)__argv[1] + "\\GenshinImpact_Data\\Managed\\Metadata\\";
std::string dllDir  = (std::string)__argv[1] + "\\";
auto global  = readFile(metaDir + "global-metadata.dat");
auto startup = readFile(metaDir + "startup-metadata.dat");
il2cpp::s_GlobalMetadataHeader = global.data() + 0x210;
```

两个 `.dat` 的分工：
- `global-metadata.dat` —— 字段、方法、属性、事件等主要信息
- `startup-metadata.dat` —— 泛型等附加结构

---

## 3. 定位混淆表（MHY 表）—— 本文最关键的一招

这张表承载了**所有被混淆的常量**（偏移、计数、密钥相关）。原文自己强调：

> **It holds encrypted const, offsets, sizes, etc. That's why in the code you can see it being used as an "offset + deobf key" pair.**
> （它装着被加密的常量、偏移、大小。所以你在代码里会看到它总是以 **"偏移 + 解混淆密钥"** 成对出现。）

### 3.1 定位过程

原文先从 `Runtime::Init` 里的 calloc 序列入手：

```c
typesCount          = *(_DWORD*)(s_Il2CppMetadataRegistration + 80) - 1683598852;
typeDefinitionsCount = *(_DWORD*)(s_MHYTable + 300) - 196834981;
methodsCount        = *(_DWORD*)(s_MHYTable + 192) - 2104354401;
methodSpecsCount    = ... *(_DWORD*)(s_MHYTable + 156) ^ 0x5E648680u ...
imagesCount         = (*(_DWORD*)(s_MHYTable + 0x1FC) - 0xA2A6C08) / 0x28uLL;
```

原文对这个 `calloc/memset` 串的解释：

> **"the macro has expanded into a series of calloc/memset calls"** —— `IL2CPP_CALLOC` 宏在编译后展开成一串 calloc/memset。

关键是原文下一句 —— `s_MHYTable` **是作者自己起的名字**：

> **"You have probably noticed that the runtime fills it via s_MHYTable — that's just a name I made up."**

那么真实的表在哪？原文给出的定位证据是这三行：

```asm
.text:00000001402B4958  lea     rax, unk_142419A40
.text:00000001402B495F  mov     cs:s_MHYTable, rax
.rdata:0000000142419A40 unk_142419A40 db 4Dh ; 'M'
.rdata:0000000142419A41             db 48h ; 'H'
.rdata:0000000142419A42             db 59h ; 'Y'
```

**两个可迁移的判据：**

1. **静态构造器模式**：在启动代码里找 `lea rax, <rdata 地址>` 紧跟 `mov cs:<某个 .data 全局>, rax` 的成对序列 —— 被 `mov` 进去的那个 `.rdata` 地址就是表本体。这是**最可靠**的判据，因为它不依赖任何字符串/常量。
2. **ASCII 签名**：表本体开头三个字节是 `M` `H` `Y`（即 `"MHY"`），可直接在 `.rdata` 里扫。

### 3.2 表的使用形态

拿到表之后，所有字段读取都是这一种形状：

```c
某字段 = *(_DWORD*)(s_MHYTable + 槽位)  OP  密钥
```

其中 `OP` 可能是 `^`（异或）、`-`（减）、`+`（加）。抄的时候要连**槽位**和**密钥**一起抄，缺一不可。

---

## 4. 逐个结构提取公式

拿到表之后，原文按"源码片段 → 二进制对应物 → 抄公式"的节奏逐个结构推进。

### 4.1 通用技巧：用除法魔数反推结构体大小

这是原文反复使用、最值得单独拎出来的一招：

```c
typeDefinitionsCount = *(_DWORD*)(s_MHYTable + 0x12C) - 0xBBB76A5;
// 编译后：
typeDefinitionsCount = (*(_DWORD*)(s_MHYTable + 0x12C) - 0xBBB76A5) / 70;
```

原文：

> **"(x * M) >> k is the compiler's optimization of the x / d case, so it's easy to guess that 70 is sizeof(Il2CppTypeDefinition)"**
> （`(x * M) >> k` 是编译器对 `x / d` 的优化，所以很容易猜出 70 就是 `sizeof(Il2CppTypeDefinition)`。）

即：**看到结尾的除法，就知道这个结构体多大**。同样的手法原文用在：

| 结构 | 除数 | 推得步长 |
|---|---|---|
| `Il2CppImageDefinition` | `0x28` | 40 字节 |
| `Il2CppTypeDefinition` | `70` (`0x46`) | 92 字节 |
| `Il2CppMethodDefinition` | `26` (`0x1A`) | 38 字节 |

### 4.2 各结构定位锚点

| 目标 | 源码锚点 | 定位方式 |
|---|---|---|
| ImageDefinition | `MetadataCache::Initialize()` 的 assembly 处理循环 | 原文：**"the assembly processing loop is located near the .dat file loading code"**（就在 `.dat` 加载代码附近），之后再用 **xref to `s_ImagesCount`** 精确锁定循环 |
| TypeDefinition | `GetTypeInfoFromTypeDefinitionIndex()` | 先由类型索引拿到类型信息的调用链；`nameIndex` 在结构 `+0x08` |
| MethodDefinition | 方法索引 → 方法定义 | 与 TypeDefinition 同链条往下；`flags`/`iflags`/`parameterStart` 等字段各自有 key 公式 |
| FieldDefinition | `GetFieldDefaultValueForField()` | 按 `fieldIndex` 查 `Il2CppFieldDefaultValue` 数组（步长 `0x0C`） |
| PropertyDefinition | `get`/`set` 方法索引 `0xFFFF` 哨兵 | 从属性索引取 getter/setter 索引 |
| EventDefinition | `add`/`remove`/`raise` 索引 | 同上 |

### 4.3 一个很实用的思路：从"魔数哨兵"反查

原文在 PropertyDefinition 处展示了这种技巧：属性索引取出的 `get`/`set` 字段，若为 `0xFFFF` 表示不存在某个访问器。这个**固定哨兵值**可以作为特征，用来在二进制里快速认出对应的读取代码。

同样的哨兵在原文的 `GetStringFromIndex` 里也出现：

```c
if (index == -1) return "";
```

---

## 5. 字符串字面量与解密函数

这一节原文写得最细，因为它同时要解决"在哪"和"怎么解"两个问题。

### 5.1 定位加载函数

源码：

```cpp
Il2CppString* GetStringLiteralFromIndex(uint32_t index) {
    if (index == kStringLiteralIndexInvalid) return NULL;
    if (s_StringLiteralTable[index]) return s_StringLiteralTable[index];      // 先查缓存
    const Il2CppStringLiteral* stringLiteral =
        (const Il2CppStringLiteral*)((const char*)s_GlobalMetadata + s_GlobalMetadataHeader->stringLiteralOffset) + index;
    s_StringLiteralTable[index] = String::NewLen(
        (const char*)s_GlobalMetadata + s_GlobalMetadataHeader->stringLiteralDataOffset + stringLiteral->dataIndex,
        stringLiteral->length);
    return s_StringLiteralTable[index];
}
```

定位手段（原文）：

> **"GetStringLiteralFromIndex can be reached via an xref to InitializeMethodMetadata"**
> （`GetStringLiteralFromIndex` 可以通过对 `InitializeMethodMetadata` 的交叉引用到达。）

原文还指出这类 init 函数都集中在 `Runtime::Init` 附近。

### 5.2 关键：字数与 data 块

`Il2CppStringLiteral` 只有两个字段：`dataIndex` 和 `length`。用 `length` 从 data 块切出字节，再**解密**。

> **"the function itself decrypts strings from that chunk"**

### 5.3 字面量数量：一个"同时拿到槽位和密钥"的模式

原文在 `RuntimeInit` 里找到这么一段：

```c
v478 = *(int*)(qword_145370488 + 0x4C);
if (v478 != 0x52B1495D) {
    v479 = v478 ^ 0x52B1495D;   // stringLiteralCount
    if ((_DWORD)v479) {
        sub_140500670(*(_QWORD*)(qword_145370488 + 56), 8 * v479, 2);   // 分配 8 字节/项的缓存数组
        v477 = qword_145370488;
    }
}
```

**这个 `if (v != CONST)` 的模式一次给出两个信息**：槽位 `0x4C` 和密钥 `0x52B1495D`。dump 侧于是写成硬编码：

```cpp
uint32_t string_count = /*string+0x4c*/ 0x52B07516 ^ 0x52B1495D;   // = 80971
```

这个"用哨兵常量做自校验"的写法在 mHoYo 的混淆里反复出现，遇到 `if (x != K)` 就应该警觉：**K 很可能就是密钥**。

### 5.4 解密函数本体

原文指出解密函数 `sub_1404D19E0` **自己不读 metadata**，签名是 `(index, 加密数据指针, 长度)`，解密在函数内部完成：

```cpp
const char* decryptString(uint32_t idx, uint64_t enc, uint32_t len) {
    uint32_t q = (len + 7) / 8;
    char* buf = (char*)calloc(q * 8 + 1, 1);
    if (!q) return buf;
    uint64_t key = (0x6CDEF0503D2BE717ULL * ((0x66717F7413519820ULL * idx ^ 0x27BE59F824C59557ULL))
                    + 0x5A4B3FE621B87A13ULL) ^ 0x5648341351EAF534ULL;
    for (uint32_t i = 0; i < q; i++) {
        uint64_t c; memcpy(&c, (void*)(enc + i * 8), 8);
        uint64_t d = c ^ key;
        memcpy(buf + i * 8, &d, 8);
        key += 0x1AAF299B1B933F38ULL;
    }
    buf[len] = 0; return buf;
}
```

结构拆解：

| 片段 | 作用 |
|---|---|
| `(len + 7) / 8` | 按 8 字节分块 |
| `key = (K1 * ((K2 * idx ^ K3)) + K4) ^ K5` | 用**索引**派生每条字面量的密钥 |
| `d = c ^ key` | XOR 解密 |
| `key += K6` | 每块密钥递增 |

**6 个 64 位常数全部版本相关**，换版本必须重抄。

---

## 6. 自定义属性：用 capstone 模拟生成器

自定义属性的值不在 metadata 里，而是存在一段**生成器代码**里 —— 需要反汇编 + 符号执行还原。

### 6.1 定位路径

原文的调用链：

```
MonoGetCustomAttributesDataInternal
  └─ ReflectionGetCustomAttrsInfo        // 用 token 做 bsearch 找到 attribute 索引
       └─ GenerateCustomAttributesCache  // 真正填值的地方
```

### 6.2 结构与打包技巧

```cpp
struct Il2CppCustomAttributeTypeRange {
    int32_t start;   // 低 24 位 = start， 高 8 位 = count
    int32_t count;
    int32_t token;   // 归属 owner 的 token
};
```

原文强调 start/count **打包在第一个 DWORD 里**：`count = v9 >> 24`，`start = v9 & 0xFFFFFF`。

token 的构成（原文列举）：

| token | 含义 |
|---|---|
| `0x02xxxxxx` | TypeDefIndex |
| `0x04xxxxxx` | FieldIndex |
| `0x06xxxxxx` | MethodIndex |
| `0x17xxxxxx` | PropertyIndex |
| `0x14xxxxxx` | EventIndex |
| `0x08xxxxxx` | ParameterIndex |
| `0x20xxxxxx` | AssemblyIndex |

`ReflectionGetCustomAttrsInfo` 拿 token 在 8 字节一项的数组里 `bsearch`，**比较每项的第二个 DWORD**。

### 6.3 值是怎么来的

```c
(*(void (**)(signed __int64))(*(_QWORD*)(s_Il2CppCodeRegistration + 88) + 8 * v5))(v8);
```

即 `customAttributeGenerators[index](cache)` —— 用 index 取一个**函数指针**再调用。这个生成器会把常量写进 cache 里的对象字段。

### 6.4 capstone 还原实参

原文用三个符号容器跟踪寄存器状态：

```cpp
std::unordered_set<unsigned int> arrays;                       // 持有 cache->attributes 的寄存器
std::unordered_map<unsigned int, uint32_t> objects;            // 寄存器 → attributes[i] 下标
std::unordered_map<unsigned int, uint64_t> values;             // 寄存器 → 已知数值
```

处理的指令模式（前 4 类）：

| 模式 | 例子 | 含义 |
|---|---|---|
| 取 attributes 数组 | `mov rax, [rcx+8]` | `rax = cache->attributes` |
| 取数组元素 | `mov rcx, [rax]` / `mov rdi, [rax+8]` | `rcx = attributes[0]` / `[1]` |
| 载常量 | `mov reg, 4` | 寄存器值已知 |
| 寄存器间移动 | `mov a, b` | 继承状态 |

第二部分处理**反向写入**（值写进对象字段）：

```
mov [rcx+14h], 4
mov [rdi+10h], 1
```

最后把 offset 和收集到的属性字段对起来，按字段类型转成 C# 字面量输出：

```cpp
[System.AttributeUsageAttribute(m_attributeTarget = Interface(1024), m_inherited = false)]
[System.Runtime.InteropServices.ComVisibleAttribute(_val = true)]
public sealed class InterfaceTypeAttribute: Attribute { }
```

---

## 7. 泛型

### 7.1 两条分支

`Type::GetGenericArgumentsInternal`：

- **开放泛型**：`klass->genericContainerIndex` → 取 `Il2CppGenericContainer` → 按 `type_argc` 遍历 `Il2CppGenericParameter`
- **封闭泛型**：`klass->generic_class` → `Il2CppGenericClass` → 按 index 取 `Il2CppGenericInst` → 输出 `Name<args>`

```cpp
struct Il2CppGenericParameter {
    GenericContainerIndex ownerIndex;
    StringIndex nameIndex;                              // ← GetStringFromIndex(param->nameIndex)
    GenericParameterConstraintIndex constraintsStart;
    int16_t constraintsCount;
    uint16_t num;
    uint16_t flags;                                     // bit0 = out, bit1 = in
};
```

注意源码里名字直接是 `GetStringFromIndex(param->nameIndex)`（无 key），但编译后变成：

```c
*(_QWORD*)&v23 = ((0x65DE21D74280LL * v22) ^ 0x154AA920) + 1912316114;
*((_QWORD*)&v23 + 1) = v20 + 14LL * v22;   // GetGenericParameter
```

—— **索引乘一个常数再异或/加**，就是 nameIndex 的 key 公式。抄的时候要连这个乘法一起抄。

### 7.2 泛型实例注册表

原文从 `MetadataCache::Register` 里读出注册逻辑（这部分在游戏里被**内联**进 `Runtime::Init`）：

```cpp
for (int32_t j = 0; j < metadataRegistration->genericClassesCount; j++)
    if (metadataRegistration->genericClasses[j]->typeDefinitionIndex != kTypeIndexInvalid)
        GenericMetadata::RegisterGenericClass(metadataRegistration->genericClasses[j]);
for (int32_t i = 0; i < metadataRegistration->genericInstsCount; i++)
    s_GenericInstSet.insert(metadataRegistration->genericInsts[i]);
```

泛型方法表则用 **xref to `s_Il2CppCodeRegistration`** 定位：

```c
v575 = s_GlobalMetadataHeader + *(_DWORD*)(s_MHYTable + 84) - 287570307;    // genericMethodTableOffset
v577 = (*(_DWORD*)(s_MHYTable + 0xB0) - 0x56CF1181) / 0xEu;                 // genericMethodTableCount
```

结构：

```cpp
struct Il2CppGenericMethodFunctionsDefinitions {
    int32_t genericMethodIndex;
    Il2CppGenericMethodIndices indices;   // { methodIndex, invokerIndex }
};
```

---

## 8. 手法总结

把原文用到的定位手段归类，实际逆向时按这个顺序找：

| # | 手法 | 用途 | 可靠性 |
|---|---|---|---|
| 1 | **对应版本 il2cpp 源码当地图** | 一切的前提 | 基础 |
| 2 | **文件名字符串 xref** | 找 metadata 加载入口 | 高 |
| 3 | **静态构造器模式**<br>`lea rax, <rdata>` + `mov cs:<全局>, rax` | 找混淆表本体 | **最高** |
| 4 | **ASCII 签名扫描**（`"MHY"`） | 快速找表 | 中（易误命中） |
| 5 | **全局变量 xref** | 顺着调用链找函数 | 高 |
| 6 | **除法魔数反推** `(x*M)>>k` → 除数 | 推结构体步长 | 高 |
| 7 | **固定哨兵值**（`0xFFFF`、`-1`、`if (x != K)`） | 认出读取代码 / 顺带拿到密钥 | 高 |
| 8 | **"邻近"定位**<br>"汇编循环就在 .dat 加载代码附近" | 粗定位函数 | 中 |
| 9 | **capstone + 符号执行** | 还原生成器实参 | 需要自己实现 |

原文一句总结值得记住：

> **"It's hard to get lost here"** —— 只要手里有源码地图，就不会迷路。

---

## 9. 换版本的操作清单

基于"版本之间只有 key 和字段会变"，换版本时按此顺序重做：

1. 读 `globalgamemanagers` 的 build method → 下对应版本 il2cpp 源码
2. 文件名字符串 xref → 重新确认 `+0x210` 之类的固定偏移是否仍成立
3. 找静态构造器 `lea`/`mov` 对 → 重新定位混淆表
4. 按结构顺序逐个抄 `(槽位, 运算, 密钥)`：
   - `ImageDefinition` → `TypeDefinition` → `MethodDefinition` → `FieldDefinition`
   - `PropertyDefinition` → `EventDefinition` → `StringLiteral` → `CustomAttribute` → `Generics`
5. 重抄 `decryptString` 的 6 个 64 位常数
6. 用 `decryptString` 解第一条字面量 → **能解出可读字符串即全部正确**（最强的验证点）
7. 重抄 3 个 helper 函数的地址（自定义属性模拟器要比较指令立即数）

> 第 6 步是关键的验收环节：只要能解出可读的字符串，就说明槽位、密钥、偏移全都对上了。

---

## 附录：原文版本（6.7）的常量一览

供对照参考，**换版本后全部失效**：

| 项 | 槽位 | 运算 | 密钥 |
|---|---|---|---|
| `stringLiteralCount` | `0x4C` | `^` | `0x52B1495D`（`if (v != K)` 模式） |
| `imagesCount` | `0x1FC` | `-` | `0x0A2A6C08`，再 `/0x28` |
| `imagesOffset` | `0x160` | `-` | `0x4F3E2863` |
| `typeDefinitionsCount` | `0x12C` | `-` | `0x0BBB76A5`，再 `/70` |
| `typeDefinitionsOffset` | `0x138` | `-` | `0x3D9122A9` |
| `interfacesOffset` | `0x19C` | `-` | `0x698BED19` |
| `stringLiteralOffset` | `51*4` | `^` | `0x3C92F84B` |
| `stringLiteralDataOffset` | `8*4` | `^` | `0x1D07B94C` |
| `attributesInfoOffset` | `20` | `^` | `0x6582BCC1` |
| `attributeTypesOffset` | `0x70` | `+` | `0xAA7DCAA0` |
| `genericClasses` | `0xF8` | `^` | `0x262BB9DB` |
| `methodSpecs` | `0x18` | `-` | `0x0099C699` |
| `methodSpecsCount` | `0x9C` | `^` | `0x5E648680` |
| `genericMethodTable` | `0x54` | `-` | `287570307` |
| `genericMethodTableCount` | `0xB0` | `-` | `0x56CF1181`，再 `/0xE` |
| `methodsOffset` | `88` | `^` | `0x58CCB100` |
| `fieldTableOffset` | `0x30` | `^` | `0x72BDC288` |
| `fieldDefaultValuesOffset` | `440` | `^` | `0x67F4AD86` |
| `fieldDefaultValuesCount` | `60` | `^` | `0x3682EBE4`，再 `/0xC` |
| `fieldAndParamDefaultValueData` | `0x184` | `^` | `0x4FC504B5` |
| `genericContainers` | `276` | `^` | `0x4F78036A` |
| `genericParameters` | `364` | `^` | `0x41F55180` |

索引类 key 公式（示例）：

```cpp
// 方法名
key = (((-486614588 * index + 535893754) ^ 0x324D0DED) + 311442397);
name = GetStringFromIndex((methodDefinition->nameIndex - 0x33F32D77) ^ key);

// 泛型参数名
nameKey = (0x65DE21D74280ULL * (genericParameterStart + i)) ^ 0x154AA920 + 1912316114;
name = GetStringFromIndex((parameter->nameIndex ^ 0x2DD1C9C6u) - nameKey);
```

`decryptString` 的 6 个常数：

```cpp
0x6CDEF0503D2BE717ULL * ((0x66717F7413519820ULL * idx ^ 0x27BE59F824C59557ULL))
  + 0x5A4B3FE621B87A13ULL) ^ 0x5648341351EAF534ULL
key += 0x1AAF299B1B933F38ULL
```

---

## 相关文件

| 文件 | 内容 |
|---|---|
| `ANALYSIS.md` | 在另一游戏版本上重走这套流程的实测结果（含失效的硬编码 VA 清单） |
| `main.cpp` | 按上述方法抄出来的 dumper |