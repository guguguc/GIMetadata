// ============================================================================
//  Il2CppImage —— il2cpp 元数据的「对象视图」
//
//  职责：把「版本常量(ver::) + 文件字节(MetadataFiles)」变成可查询的镜像视图：
//        - 表定位（MHY 槽位 -> 元数据偏移 / 条目数）
//        - 逐索引 key 与字段解码
//        - 名字解析（字符串 / Il2CppType，带缓存）
//  不负责：任何输出格式（那是 Dumper 的事）。
//
//  ⚠️ 本文件由 tools/split_main.py 从原 main.cpp 机械搬运，代码体逐字一致。
// ============================================================================
#pragma once

#include "version.hpp"
#include "metadata_files.hpp"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 泛型参数名兜底：本版本的 genericParamKey 公式未完全验证，个别参数名会解出控制字符。
// 这不是真实名字，但比输出 \x01 安全：按 IL2CPP 惯例回落为 T / T1 / T2 ...
inline std::string SanitizeGenericName(const std::string& s, uint32_t idx)
{
    bool bad = s.empty();
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7F) { bad = true; break; }
    }
    if (!bad) return s;
    return idx ? ("T" + std::to_string(idx)) : std::string("T");
}

class Il2CppImage {
public:
    explicit Il2CppImage(MetadataFiles& files) : files_(files) {
        // 基址指针（地址来自 version.json -> ver::）
        s_GlobalMetadataHeader = (uint8_t*)files.global() + ver::kGlobalMetadataHeaderOffset;   // +0x210
        metadataSize           = files.globalSize();
        s_StartupMetadataHeader = (uint8_t*)files.startup();
        s_MHYTable = (uint8_t*)files.at(ver::kMhyTableVA);
        s_Table1   = (uint8_t*)files.at(ver::kTable1VA);
        s_Table0   = (uint8_t*)files.at(ver::kTable0VA);
        s_Il2CppCodeRegistration = (uint8_t*)files.at(ver::kCodeRegistrationVA);
    }

    // 把版本常量 + 派生指针全部装载进来（换版本改 version.json，不改这里）

void decryptHeader() 
{
    // ⚠️ 本函数**只有一行逻辑**：把版本常量表（src/version.hpp，由 version.json 生成）读进来。
    //    换游戏版本时**不要改这里**，改 version.json 然后 make。
        header.imagesCount        = tableBytes(ver::kImagesCount);
    header.imagesOffset       = tableOffset(ver::kImagesOffset);
    header.stringLiteralDataOffset = tableOffset(ver::kStringLiteralDataOffset);
    header.typeDefinitionsOffset = tableOffset(ver::kTypeDefinitionsOffset);
    header.typeDefinitionsCount  = tableCount(ver::kTypeDefinitionsCount);
    header.methodsOffset = tableOffset(ver::kMethodsOffset);
    header.methodsCount  = tableCount(ver::kMethodsCount);
    header.typesCount    = (uint32_t)regRaw(ver::kTypesCountFormula);
    header.methodPointerIndexOffset = tableOffset(ver::kMethodPointerIndexOffset);
    header.methodSlotTableOffset = tableOffset(ver::kMethodSlotTableOffset);
    header.methodSlotCount       = tableCount(ver::kMethodSlotCount);
    header.parametersOffset = tableOffset(ver::kParametersOffset);
    header.propertiesOffset = tableOffset(ver::kPropertiesOffset);
    header.fieldsOffset     = tableOffset(ver::kFieldsOffset);
    header.eventsOffset     = tableOffset(ver::kEventsOffset);
    header.fieldOffset      = tableOffset(ver::kFieldOffset);
    header.fieldOffsetBaseTable = (uint32_t)ver::kFieldOffsetBaseTable;
    header.fieldIndexTable      = (uint32_t)ver::kFieldIndexTable;
    header.interfacesTable  = tableOffset(ver::kInterfacesTable);
    header.nestedTypesTable = tableOffset(ver::kNestedTypesTable);
    header.genericContainers = tableOffset(ver::kGenericContainers);
    header.genericParameters = tableOffset(ver::kGenericParameters);
    header.genericParameterCount = 0;            // ❌ 仍未定位（勿误用 0x130）
    header.interfacesOffset       = tableOffset(ver::kInterfacesOffsetDeprecated);
    header.fieldTableOffset       = tableOffset(ver::kFieldTableOffsetDeprecated);
    header.fieldIndexTableOffset  = tableOffset(ver::kFieldIndexTableOffsetDeprecated);
    header.fieldDefaultValuesOffset = tableOffset(ver::kFieldDefaultValuesOffset);
    // ⚠️ fieldDefaultValuesCount **不写死**：表按 fieldIndex 严格递增（il2cpp 不变量）→ 扫到断点即条目数。
    //    随版本自动正确，且自带校验（断了说明表结构变了）。
    header.fieldDefaultValuesCount = 0;
    {
        const uint32_t fdvOff = tableOffset(ver::kFieldDefaultValuesOffset);
        const uint8_t* fdv = s_GlobalMetadataHeader + fdvOff;
        int32_t prev = -1;
        while ((uint64_t)fdvOff + 12ull * (header.fieldDefaultValuesCount + 1) <= metadataSize) {
            const auto* ent = (const Il2CppFieldDefaultValue*)(fdv + 12ull * header.fieldDefaultValuesCount);
            const int32_t v = fdvFieldIndex(ent);
            if (v <= prev) break;
            prev = v;
            header.fieldDefaultValuesCount++;
        }
    }
    header.fieldAndParameterDefaultValueDataOffset = tableOffset(ver::kFieldAndParameterDefaultValueDataOffset);
    header.parameterDefaultValuesOffset = tableOffset(ver::kParameterDefaultValuesOffset);
    header.parameterDefaultValuesCount  = tableBytes(ver::kParameterDefaultValuesCount);  // 字节数，读取处 /12
    header.stringLiteralOffset = 0;              // 本版本无独立字面量条目表
    header.attributesInfoOffset = tableOffset(ver::kAttributesInfoOffset);
    header.attributesInfoCount  = tableCount(ver::kAttributesInfoCount);
    header.attributeTypesOffset = tableOffset(ver::kAttributeTypesOffset);
    header.methodSpecs      = tableOffset(ver::kMethodSpecs);
    // ⚠️ methodSpecsCount **不写死**：唯一用途是守卫 specs[genericMethodIndex]，
    //    所以“必要且充分”的取值 = 泛型方法表里实际引用到的 max(genericMethodIndex) + 1（从数据推出）。
    header.methodSpecsCount = 0;
    {
        // ⚠️ 直接用 ver:: 取表，别依赖 header 字段（本块在它们赋值之前）
        const uint8_t* gmt = s_GlobalMetadataHeader + tableOffset(ver::kGenericMethodTable);
        const uint32_t gcnt = tableCount(ver::kGenericMethodTableCount);
        uint32_t mx = 0;
        for (uint32_t i = 0; i < gcnt; i++) {
            const int32_t g = *(const int32_t*)(gmt + 14ull * i);
            if (g >= 0 && (uint32_t)g > mx) mx = (uint32_t)g;
        }
        header.methodSpecsCount = mx ? mx + 1 : 0;
    }
    header.genericInstsCount = (uint32_t)regRaw(ver::kGenericInstsCountFormula);  // 当前无调用者，保留备用
    header.genericClassRangeOffset = tableOffset(ver::kGenericClassRangeOffset);
    header.genericTypeArgOffset    = tableOffset(ver::kGenericTypeArgOffset);
    // ✅ 也是公式（T0 侧）：消费者是 RuntimeInit 的泛型注册循环（init_534B80.c:2064）
    header.genericClassRangeCount  = (uint32_t)tableRawAt(s_Table0, ver::kGenericClassRangeCountFormula);
    header.genericClasses          = (uint32_t)ver::kGenericClassesOffset;
    header.genericClassesCount     = (uint32_t)ver::kGenericClassesCount;
    header.genericMethodTable      = tableOffset(ver::kGenericMethodTable);
    header.genericMethodTableCount = tableCount(ver::kGenericMethodTableCount);
    s_Il2CppMetadataRegistration = s_Table1;   // == T1

    // ---- T0 / T1 派生指针（偏移见 version.json 的 registrationFields）----
    s_GenericInsts         = files_.exe().data() + files_.pe()->va_to_offset(*(uint64_t*)(s_Table1 + ver::kT1GenericInsts));
    s_Il2CppTypesVA        = *(uint64_t*)(s_Table1 + ver::kT1Il2CppTypes);
    s_Il2CppTypes          = files_.exe().data() + files_.pe()->va_to_offset(s_Il2CppTypesVA);
    s_MethodPointerArray   = files_.exe().data() + files_.pe()->va_to_offset(*(uint64_t*)(s_Table0 + ver::kT0GenericMethodPointers));
    s_MethodPointerByIndex = files_.exe().data() + files_.pe()->va_to_offset(*(uint64_t*)(s_Table0 + ver::kT0MethodPointerIndexArray));
    s_InvokerArray         = files_.exe().data() + files_.pe()->va_to_offset(*(uint64_t*)(s_Table0 + ver::kT0InvokerArray));
}




    uint8_t* s_GlobalMetadataHeader = nullptr;
    uint64_t metadataSize = 0;              // = global-metadata.dat 文件大小（越界保护用）
    uint8_t* s_StartupMetadataHeader = nullptr;
    uint8_t* s_MHYTable = nullptr;
    uint8_t* s_Table0 = nullptr;   // 0x1422DE370（静态构造器注册）
    uint8_t* s_Table1 = nullptr;   // 0x142870A88（静态构造器 0x1402F2910 注册的运行时数组总表）
    uint8_t* s_GenericInsts = nullptr;     // [V] = *(T1+0x08)，16 字节项 {argc@+0, pad, Il2CppType** argv@+8}
    uint8_t* s_Il2CppTypes = nullptr;      // [V] = *(T1+0x48) 转成 host 指针；16 字节项 Il2CppType
    uint64_t s_Il2CppTypesVA = 0;          // 同一数组的**镜像 VA**。type->data.type/array 是 VA，
                                           // 算索引时必须减 VA，不能减 host 指针（混用会得到野索引）。
    uint8_t* s_GenericClasses = nullptr;   // ❌ 未定位（genericClasses 另找）
    uint8_t* s_MethodPointerArray = nullptr; // = *(T0+0x60) == **genericMethodPointers**（文章：CR+0x60）。
                                             //   只给泛型实例用（按 entry.indices.methodIndex 直接索引）✓
    uint8_t* s_MethodPointerByIndex = nullptr; // = *(T0+0x88)，按 methodIndex **直接**索引的非泛型方法地址表。
                                             //   文章 §methodPointer：非虚走 `+0x80[index]`；本版本对应 `*(T0+0x88)[methodIndex]`。
                                             //   实测 711021/733442 落在镜像内，其余为 0（无实体方法）。
    uint8_t* s_InvokerArray = nullptr;       // = *(T0+0x48)，8 字节项，按 slot 索引；12827 项
    uint8_t* s_Il2CppMetadataRegistration = nullptr;  // == s_Table1
    uint8_t* s_Il2CppCodeRegistration = nullptr;     // 旧地址，未使用
    uint8_t* metadataUsages = nullptr;
    // ---- 从「表描述」(src/version.hpp) 取值：换版本只改 version.json ----
    inline uint64_t tableRawAt(const uint8_t* base, const ver::Table& t) {
        const uint32_t v = *(const uint32_t*)(base + t.slot);
        switch (t.op) {
        case '-': return (uint32_t)(v - (uint32_t)t.key);
        case '^': return (uint32_t)(v ^ (uint32_t)t.key);
        default:  return (uint32_t)(v + (uint32_t)t.key);
        }
    }
    inline uint64_t tableRaw(const ver::Table& t)   { return tableRawAt(s_MHYTable, t); }
    inline uint64_t regRaw(const ver::Table& t)     { return tableRawAt(s_Table1, t); }
    inline uint32_t tableOffset(const ver::Table& t){ return (uint32_t)tableRaw(t); }
    inline uint32_t tableBytes(const ver::Table& t) { return (uint32_t)tableRaw(t); }
    inline uint32_t tableCount(const ver::Table& t) {
        const uint32_t st = t.stride ? t.stride : 1;
        return (uint32_t)(tableRaw(t) / st) + (uint32_t)t.countBias;
    }

    enum class Il2CppTypeEnum : uint8_t
    {
        IL2CPP_TYPE_END = 0x00,
        IL2CPP_TYPE_VOID = 0x01,
        IL2CPP_TYPE_BOOLEAN = 0x02,
        IL2CPP_TYPE_CHAR = 0x03,
        IL2CPP_TYPE_I1 = 0x04,
        IL2CPP_TYPE_U1 = 0x05,
        IL2CPP_TYPE_I2 = 0x06,
        IL2CPP_TYPE_U2 = 0x07,
        IL2CPP_TYPE_I4 = 0x08,
        IL2CPP_TYPE_U4 = 0x09,
        IL2CPP_TYPE_I8 = 0x0a,
        IL2CPP_TYPE_U8 = 0x0b,
        IL2CPP_TYPE_R4 = 0x0c,
        IL2CPP_TYPE_R8 = 0x0d,
        IL2CPP_TYPE_STRING = 0x0e,
        IL2CPP_TYPE_PTR = 0x0f,       /* arg: <type> token */
        IL2CPP_TYPE_BYREF = 0x10,       /* arg: <type> token */
        IL2CPP_TYPE_VALUETYPE = 0x11,       /* arg: <type> token */
        IL2CPP_TYPE_CLASS = 0x12,       /* arg: <type> token */
        IL2CPP_TYPE_VAR = 0x13,       /* Generic parameter in a generic type definition, represented as number (compressed unsigned integer) number */
        IL2CPP_TYPE_ARRAY = 0x14,       /* type, rank, boundsCount, bound1, loCount, lo1 */
        IL2CPP_TYPE_GENERICINST = 0x15,     /* <type> <type-arg-count> <type-1> \x{2026} <type-n> */
        IL2CPP_TYPE_TYPEDBYREF = (uint32_t)ver::kTypeDefPropertyCount.key,
        IL2CPP_TYPE_I = 0x18,
        IL2CPP_TYPE_U = 0x19,
        IL2CPP_TYPE_FNPTR = 0x1b,        /* arg: full method signature */
        IL2CPP_TYPE_OBJECT = 0x1c,
        IL2CPP_TYPE_SZARRAY = 0x1d,       /* 0-based one-dim-array */
        IL2CPP_TYPE_MVAR = 0x1e,       /* Generic parameter in a generic method definition, represented as number (compressed unsigned integer)  */
        IL2CPP_TYPE_CMOD_REQD = 0x1f,       /* arg: typedef or typeref token */
        IL2CPP_TYPE_CMOD_OPT = 0x20,       /* optional arg: typedef or typref token */
        IL2CPP_TYPE_INTERNAL = 0x21,       /* CLR internal type */

        IL2CPP_TYPE_MODIFIER = 0x40,       /* Or with the following types */
        IL2CPP_TYPE_SENTINEL = 0x41,       /* Sentinel for varargs method signature */
        IL2CPP_TYPE_PINNED = 0x45,       /* Local var that points to pinned object */

        IL2CPP_TYPE_ENUM = 0x55        /* an enumeration */
    };


    struct Il2CppImageDefinition
    {
        uint8_t _pad0[0x10];
        int32_t typeStart;  // 0x10
        uint8_t _pad1[0x0C]; // 0x14..0x1F
        int32_t nameIndex;  // 0x20（此前误写成 0x24 -> 图像名解出垃圾，string 越界崩溃）
        uint8_t _pad2[0x04]; // 0x24..0x27，凑满 0x28
    };

    // 本版本布局，70 字节。
    // 步长由 init 里 memset 快速路径的 `if (count >= 0x46)` 守卫反推（0x46 = 70）。
    // [V] = 已实测验收（见 gi_fields.md §3）；未定位的用 _pad 占位。
#pragma pack(push,1)
    struct Il2CppTypeDefinition {
        int32_t  namespaceIndex;   // 0x00 [V] - (uint32_t)ver::kTypeDefNamespaceIndex.key
        uint8_t  _pad04[0x04];     // 0x04
        int32_t  propertyStart;    // 0x08 [V] - (uint32_t)ver::kTypeDefPropertyStart.key
        int32_t  methodStart;      // 0x0C [V] ^ (uint32_t)ver::kTypeDefMethodStart.key
        uint8_t  _pad10[0x08];     // 0x10..0x17
        // [V] parentIndex：存的是 **Il2CppType 索引**，解码 `raw - (uint32_t)ver::kTypeDefParentIndex.key`；-1 = 无父类。
        //   验收：枚举→System.Enum(Il2CppType 401709)、结构体→System.ValueType(425583)、
        //         MonoBehaviour→Behaviour、String/Exception→Object、FileStream→Stream、Object→-1。
        int32_t  parentIndex;      // 0x18
        int32_t  fieldStart;       // 0x1C [V] ^ (uint32_t)ver::kTypeDefFieldStart.key
        int32_t  _f20;             // 0x20     ^ (uint32_t)ver::kTypeDefUnknown20.key 语义未确认（索引另一张 4 字节表）
        int32_t  nameIndex;        // 0x24 [V] - (uint32_t)ver::kTypeDefNameIndex.key
        uint32_t flags;            // 0x28 [V] - (uint32_t)ver::kTypeDefFlags.key（TYPE_ATTRIBUTE）
        uint8_t  _pad2C[0x04];     // 0x2C
        uint16_t method_count;     // 0x30 [V] - (uint32_t)ver::kTypeDefMethodCount.key
        uint8_t  _pad32[0x02];     // 0x32
        int16_t  eventStart;       // 0x34 [V] + (uint32_t)ver::kTypeDefEventStart.key
        int16_t  nestedTypesStart; // 0x36 [V] + (uint32_t)ver::kTypeDefNestedTypesStart.key
        uint16_t field_count;      // 0x38 [V] ^ (uint32_t)ver::kTypeDefFieldCount.key
        uint8_t  bitfield;         // 0x3A [V] bit0=valuetype, bit1=enum(反相)
        uint8_t  _pad3B;           // 0x3B
        uint16_t interfacesStart;  // 0x3C [V] ^ (uint32_t)ver::kTypeDefInterfacesStart.key
        // [V] genericContainerIndex（int16）：`raw - (uint32_t)ver::kTypeDefGenericContainerIndex.key`，哨兵 26229 = 无泛型。
        //   来源 sub_140511DB0（读 typeDef 70*idx + 62）。验收见 status.md §6 附 9。
        int16_t  genericContainerIndex; // 0x3E
        uint8_t  interfaces_count; // 0x40 [V] + 56（0xC8 编码 0）
        uint8_t  _pad41[0x02];     // 0x41
        uint8_t  property_count;   // 0x43 [V] ^ (uint32_t)ver::kTypeDefPropertyCount.key
        uint8_t  event_count;      // 0x44 [V] + 113   (0x8F 编码 0)
        uint8_t  nestedTypesCount; // 0x45 [V] ^ (uint32_t)ver::kTypeDefNestedTypesCount.key（(uint32_t)ver::kTypeDefNestedTypesCount.key 编码 0）
    };

    // 字段统一按 version.json 的 structOffsets 读取（7.0/7.1 偏移不同，不要直接用成员）
    static int32_t  tdI32(const Il2CppTypeDefinition* td, uint32_t off) { return *(const int32_t*)((const uint8_t*)td + off); }
    static uint32_t tdU32(const Il2CppTypeDefinition* td, uint32_t off) { return *(const uint32_t*)((const uint8_t*)td + off); }
    static int16_t  tdI16(const Il2CppTypeDefinition* td, uint32_t off) { return *(const int16_t*)((const uint8_t*)td + off); }
    static uint16_t tdU16(const Il2CppTypeDefinition* td, uint32_t off) { return *(const uint16_t*)((const uint8_t*)td + off); }
    static uint8_t  tdU8 (const Il2CppTypeDefinition* td, uint32_t off) { return *(const uint8_t* )((const uint8_t*)td + off); }

    struct Il2CppType;
    struct Il2CppArrayType { 
        const Il2CppType* etype; 
        uint8_t rank; // 0x08
        uint8_t numsizes; 
        uint8_t numlobounds; 
        uint8_t _pad1; 
    };

    struct Il2CppType {
        union {
            void* dummy;
            int32_t klassIndex;           // CLASS/VALUETYPE
            const Il2CppType* type;       // PTR/BYREF/SZARRAY
            Il2CppArrayType* array;                  // ARRAY
            int32_t genericParameterIndex; // VAR/MVAR
            void* generic_class;          // GENERICINST
        } data;
        uint16_t attrs;
        Il2CppTypeEnum type; // 0x0A
        uint8_t _pad1[0x05];
    };
    
    
    struct Il2CppFieldDefinition {
        int32_t typeIndex; // 0x00
        int32_t nameIndex; // 0x04
    };

    struct Il2CppFieldDefaultValue {
        int32_t fieldIndex;
        int32_t dataIndex;
        int32_t typeIndex;
    };

    // 26 字节；**布局随版本变化，字段一律通过 version.json 的 structOffsets + md* 读取**。
    //   7.1: name@0, parameterStart@4, returnType@8, declaringType@12, iflags@16, token@20, flags@22, count@24
    //   7.0: name@0, returnType@4, parameterStart@8(_pad12@12), flags@18, slot@20, iflags@22, count@24
    // 下面的成员名/偏移只用于 7.1 的旧 #if 0 代码，活动路径不要直接访问成员。
    struct Il2CppMethodDefinition {
        int32_t  nameIndex;       // 0x00  [V]
        int32_t  parameterStart;  // 0x04
        int32_t  returnType;      // 0x08 [V] (raw ^ key) ^ (uint32_t)ver::kMethodReturnType.key
        int32_t  declaringType;   // 0x0C [V] key ^ raw ^ (uint32_t)ver::kMethodDeclaringType.key（typeDefinition 索引）
        uint16_t iflags;          // 0x10  [V] key ^ (raw - (uint32_t)ver::kMethodIflags.key)
        uint16_t _f12;            // 0x12      (多为 0xFFFF，语义未定)
        uint16_t token;           // 0x14      key ^ raw ^ 0xD73C
        uint16_t flags;           // (uint32_t)ver::kTypeDefPropertyCount.key  [V] key ^ raw ^ (uint32_t)ver::kMethodFlags.key
        uint8_t  parameterCount;  // 0x18  [V] (sub_140528560 在 +0x18 取参数个数)
        uint8_t  _pad19;          // 0x19
    };

    // 方法字段按 version.json 的 structOffsets 读取（7.0/7.1 偏移不同）
    static uint32_t mdU32(const Il2CppMethodDefinition* m, uint32_t off) { return *(const uint32_t*)((const uint8_t*)m + off); }
    static uint16_t mdU16(const Il2CppMethodDefinition* m, uint32_t off) { return *(const uint16_t*)((const uint8_t*)m + off); }
    static uint8_t  mdU8 (const Il2CppMethodDefinition* m, uint32_t off) { return *(const uint8_t* )((const uint8_t*)m + off); }

    struct Il2CppParameterDefinition {
        int32_t typeIndex;
        int32_t nameIndex;
    };

    // ⚠️ 本版本的字段顺序与文章/6.7 版不同！
    //    实测（GetDefaultParameterValueObject @0x140529DC0）:
    //      +0 = parameterIndex（搜索键，线性查找 while(v != *v8) v8+=3）
    //      +4 = dataIndex（-1 表示无默认值，否则加 blob 基址）
    //      +8 = typeIndex（*(T1+0x48) + 16*idx，Il2CppType 索引）
    //    与 fieldDefaultValues 的 {index, dataIndex, typeIndex} 顺序一致。
    struct Il2CppParameterDefaultValue {
        int32_t parameterIndex;
        int32_t dataIndex;
        int32_t typeIndex;
    };

    // 默认值表字段偏移由 version.json -> structOffsets 决定（7.0/7.1 顺序不同）
    static int32_t fdvFieldIndex(const Il2CppFieldDefaultValue* e) {
        return *(const int32_t*)((const uint8_t*)e + ver::kIl2CppFieldDefaultValueFieldIndexOffset);
    }
    static int32_t fdvDataIndex(const Il2CppFieldDefaultValue* e) {
        return *(const int32_t*)((const uint8_t*)e + ver::kIl2CppFieldDefaultValueDataIndexOffset);
    }
    static int32_t fdvTypeIndex(const Il2CppFieldDefaultValue* e) {
        return *(const int32_t*)((const uint8_t*)e + ver::kIl2CppFieldDefaultValueTypeIndexOffset);
    }
    static int32_t pdvParameterIndex(const Il2CppParameterDefaultValue* e) {
        return *(const int32_t*)((const uint8_t*)e + ver::kIl2CppParameterDefaultValueParameterIndexOffset);
    }
    static int32_t pdvDataIndex(const Il2CppParameterDefaultValue* e) {
        return *(const int32_t*)((const uint8_t*)e + ver::kIl2CppParameterDefaultValueDataIndexOffset);
    }
    static int32_t pdvTypeIndex(const Il2CppParameterDefaultValue* e) {
        return *(const int32_t*)((const uint8_t*)e + ver::kIl2CppParameterDefaultValueTypeIndexOffset);
    }

    // ⚠️ 字段顺序按 sub_1405151D0 实测：getter 在 +6、setter 在 +8。
    //    此前 set/get 写反 -> get 读到的是 setter 字段 -> 全部越界（属性类型/访问器全空）。
    struct Il2CppPropertyDefinition {
        int32_t nameIndex;
        uint16_t token; 
        uint16_t get;   // 0x06 -> key ^ raw ^ (uint32_t)ver::kPropertyGet.key
        uint16_t set;   // 0x08 -> (raw - (uint32_t)ver::kPropertySet.key) ^ key
    };

    // ⚠️ 字段顺序按 sub_140514CF0 实测：typeIndex 在 +0（解码 `key ^ (raw - (uint32_t)ver::kEventTypeIndex.key)`），
    //    nameIndex 在 +4。此前写反 -> 事件 typeIndex 628/628 全不合法 -> 事件全部被 continue。
    struct Il2CppEventDefinition {
        int32_t typeIndex; // 0x0  -> key ^ (raw - (uint32_t)ver::kEventTypeIndex.key)
        int32_t nameIndex; // 0x4  -> key ^ (raw - (uint32_t)ver::kEventNameIndex.key)
        uint16_t add; // 0x8
        uint16_t remove; // 0xA
        uint16_t raise; // 0xC
    };

    struct Il2CppStringLiteral {
        int32_t dataIndex;
        int32_t length;
    };

    struct Il2CppCustomAttributeTypeRange {
        int32_t start_сount;
        int32_t token;
    };

    // 16 字节；字段偏移走 structOffsets（7.1: argc@+8/pStart@+4；7.0: argc@+8/pStart@+12）
    struct Il2CppGenericContainer {
        int32_t ownerIndex;
        int32_t is_method;
        int32_t type_argc;
        int32_t genericParameterStart;
    };

    // 14 字节；已确认 nameIndex@+0、flags@+6（IDA 0x1404E2B30 用 14*p+6 读方差位）
    struct Il2CppGenericParameter {
        int32_t nameIndex; // 0x00
        uint8_t _pad[4];
        uint16_t flags;    // 0x08（占位注释；实际 +6，活动路径只读 nameIndex）
        uint8_t _pad2[4];
    };

    struct Il2CppGenericInst {
        uint32_t type_argc;
        uint32_t _pad;
        const Il2CppType** type_argv;
    };

    struct Il2CppMethodSpec {
        int32_t methodDefinitionIndex;
        int32_t classIndexIndex;
        int32_t methodIndexIndex;
    };

    struct Il2CppGenericMethodIndices
    {
        int32_t methodIndex;
        int32_t invokerIndex;
    };

    struct Il2CppGenericMethodFunctionsDefinitions
    {
        int32_t genericMethodIndex;
        Il2CppGenericMethodIndices indices;
        uint16_t ktoprochitaltothoroshiymalchik;
    };
    #pragma pack(pop)

    

    static_assert(sizeof(Il2CppImageDefinition) == ver::kSize_Il2CppImageDefinition);
    static_assert(sizeof(Il2CppTypeDefinition) == ver::kSize_Il2CppTypeDefinition);
    static_assert(sizeof(Il2CppType) == ver::kSize_Il2CppType);
    static_assert(sizeof(Il2CppFieldDefinition) == ver::kSize_Il2CppFieldDefinition);
    static_assert(sizeof(Il2CppFieldDefaultValue) == ver::kSize_Il2CppFieldDefaultValue);
    static_assert(sizeof(Il2CppMethodDefinition) == ver::kSize_Il2CppMethodDefinition);
    static_assert(sizeof(Il2CppParameterDefinition) == ver::kSize_Il2CppParameterDefinition);
    static_assert(sizeof(Il2CppParameterDefaultValue) == ver::kSize_Il2CppParameterDefaultValue);
    static_assert(sizeof(Il2CppPropertyDefinition) == ver::kSize_Il2CppPropertyDefinition);
    static_assert(sizeof(Il2CppEventDefinition) == ver::kSize_Il2CppEventDefinition);
    static_assert(sizeof(Il2CppStringLiteral) == ver::kSize_Il2CppStringLiteral);
    static_assert(sizeof(Il2CppCustomAttributeTypeRange) == ver::kSize_Il2CppCustomAttributeTypeRange);
    static_assert(sizeof(Il2CppGenericContainer) == ver::kSize_Il2CppGenericContainer);
    static_assert(sizeof(Il2CppGenericParameter) == ver::kSize_Il2CppGenericParameter);
    static_assert(sizeof(Il2CppGenericInst) == ver::kSize_Il2CppGenericInst);
    static_assert(sizeof(Il2CppMethodSpec) == ver::kSize_Il2CppMethodSpec);
    static_assert(sizeof(Il2CppGenericMethodIndices) == ver::kSize_Il2CppGenericMethodIndices);
    static_assert(sizeof(Il2CppGenericMethodFunctionsDefinitions) == ver::kSize_Il2CppGenericMethodFunctionsDefinitions);

    struct metadataHeader {
        uint32_t imagesOffset;
        uint32_t imagesCount;

        uint32_t typeDefinitionsCount;
        uint32_t typeDefinitionsOffset;

        uint32_t interfacesOffset;

        uint32_t fieldTableOffset;
        uint32_t fieldIndexTableOffset;
        uint32_t fieldOffset;

        uint32_t fieldsOffset;
        uint32_t fieldOffsetBaseTable;     // 7.0: 字段偏移基址表；0 = 用 7.1 简单路径
        uint32_t fieldIndexTable;          // 7.0: typeHash -> 基址表索引
        uint32_t interfacesTable;
        uint32_t nestedTypesTable;   // 4 字节/项

        uint32_t fieldDefaultValuesOffset;
        uint32_t fieldDefaultValuesCount;
        uint32_t fieldAndParameterDefaultValueDataOffset;

        uint32_t methodsOffset;
        uint32_t methodsCount;
        uint32_t typesCount;               // Il2CppType 数组项数 = regRaw(typesCountFormula)；0 = 未初始化（边界检查会失败关闭）
        // ⚠️ MHY[0x94] ^ 0x4A4C0A71：**每方法 -> genericMethodPointers 的下标**（不是方法地址表！）。
        //    游戏用它填 MethodInfo 的 +0x20 字段（sub_140514630: v16[4] = *(*(T0+0x60) + 8*ptrIndex)）。
        //    方法地址请用 methodPointer()（= *(T0+0x88)[methodIndex]）。详见 status.md §6 附 8。
        uint32_t methodPointerIndexOffset;
        uint32_t methodSlotTableOffset;    // = MHY[0x140] - 1832561230，6 字节项 {methodIndex, slot}
        uint32_t methodSlotCount;          // = (MHY[0x1FC] - 127184164)/6 = 12827

        uint32_t parametersOffset;
        uint32_t parameterDefaultValuesOffset;
        uint32_t parameterDefaultValuesCount;

        uint32_t propertiesOffset;
        uint32_t eventsOffset;

        uint32_t stringLiteralOffset;
        uint32_t stringLiteralDataOffset;

        uint32_t attributesInfoOffset;
        uint32_t attributesInfoCount;
        uint32_t attributeTypesOffset;

        uint32_t methodSpecs;              // MHY[0x1D8] ^ 0x1F85ABE5，步长 12
        uint32_t methodSpecsCount;         // 实测边界 610109（表里无此计数，见下）

        uint32_t genericInstsCount;       // [V] (T1+0x50) + 0x9B1B5919 = 69146
        uint32_t genericClassRangeOffset; // [V] MHY[0x134] ^ 0x558E11EC（startup, 8B {argStart, argc}）
        uint32_t genericTypeArgOffset;    // [V] MHY[0x180] - 898198093（= startup+0, 4B 类型索引, -1 哨兵）
        uint32_t genericClassRangeCount;  // 实测 13671（start 严格无缝累计）
        // [V] generic class 表（startup，8 字节 {genericInstIndex@+0, typeDefinitionIndex@+4}）。
        //   来源 GIMeta_RuntimeInit：v610 = startup + MHY[0x18] - 662445654；count = (MHY[0xE0] >> 3) ^ 0x1F5F6D1。
        //   7.0: startup+0xC0830 / 398168；7.1: startup+0xC5520 / 406569（两版同一套读取逻辑）。
        uint32_t genericClasses;
        uint32_t genericClassesCount;
        uint32_t genericMethodTable;       // MHY[0xC0] - 1630172749，步长 14
        uint32_t genericMethodTableCount;  // (MHY[0x130] - 565220529)/14 = 560659

        uint32_t genericParameters;
        uint32_t genericParameterCount;   // 未验证
        uint32_t genericContainers;
    }header;


    // ========== 解密 / 表访问 / 逐索引 key / 名字解析（原 namespace utils）==========


        std::unordered_map<int32_t, std::string> stringCache;
        std::unordered_map<const Il2CppType*, std::string> typeNameCache;
        std::unordered_set<const Il2CppType*> resolvingTypes_;   // 环检测（NameFromIl2CppType 递归）

        // ================= 本版本字符串解密（已实测 75/75 通过）=================
        // 见 ANALYSIS.md §4.3。本版本与旧版有两处结构差异：
        //   1) 没有独立的 {dataIndex, length} 字面量条目表
        //   2) offset(24 位) 与 length(8 位) 直接打包在 nameIndex 字段里
        static constexpr uint32_t kStringEntryXor = ver::kEntryXor;      // 条目解码 XOR
        static constexpr uint64_t kKeyMulA      = ver::kKeyMulA;
        static constexpr uint64_t kKeyMulB      = ver::kKeyMulB;
        static constexpr uint64_t kKeySeed      = ver::kKeySeed;
        static constexpr uint64_t kKeyStep      = ver::kKeyStep;   // 每 8 字节递增

        // 图像名解码（7.0/7.1 形状不同，由 version.json 的 decodeExpr 决定）
        inline uint32_t DecodeImageName(uint32_t raw, uint32_t imageIndex)
        {
            return ver::decImageNameIndex(raw, imageIndex);
        }

        // 条目解码：entry -> (24 位偏移, 8 位长度)
        inline uint32_t DecodeStringEntry(uint32_t raw, uint32_t indexKey)
        {
            return raw ^ indexKey ^ kStringEntryXor;
        }

        inline void SplitStringEntry(uint32_t entry, uint32_t& offset, uint32_t& length)
        {
            offset = entry & 0xFFFFFFu;
            length = (entry >> 24) & 0xFFu;
        }

        // 逐索引 key —— 程序集名（imagesDefinitions[].nameIndex）用，已验证
        // ⚠️ 必须 64 位精确运算！已验收的 Python 版（gi_string_decrypt.py，75/75）中间量是精确整数。
        //    写成 `667674736u * X`（32 位）会在乘后立刻回绕，>>8 放大误差 →
        //    低 24 位（offset）仍对、高 8 位（length）错 → 名字正确但带垃圾尾巴。
        inline uint32_t ImageIndexKey(uint32_t index)
        {
            return ver::keyImage(index);
        }

        // 按 (offset, length) 解密一段字符串；offset 相对 stringLiteralDataOffset
        std::string DecryptStringAt(uint32_t offset, uint32_t length)
        {
            if (!length) return std::string();
            // 越界保护：解出垃圾 index 时不要直接 segfault
            if ((uint64_t)header.stringLiteralDataOffset + offset + length + 8 > metadataSize)
                return std::string();

            // 版本相关：7.1 = mulA * ((mulB*off) ^ seed)；7.0 = (mulB*off + seed) ^ mulA
            const uint64_t keyBase = ver::decStringKey(offset);
            const uint8_t* ptr = s_GlobalMetadataHeader + header.stringLiteralDataOffset + offset;

            std::string value((length + 7) & ~7u, '\0');
            uint64_t key = keyBase;
            const uint32_t qwords = (length + 7) / 8;
            for (uint32_t i = 0; i < qwords; i++)
            {
                uint64_t chunk;
                memcpy(&chunk, ptr + i * 8, 8);
                uint64_t dec = chunk ^ key;
                memcpy(value.data() + i * 8, &dec, 8);
                key += kKeyStep;
            }
            value.resize(length);
            return value;
        }

        const char* GetStringFromIndex(int32_t index)
        {
            if (index == -1) return "";

            auto cached = stringCache.find(index);
            if (cached != stringCache.end()) return cached->second.c_str();

            uint32_t offset = (uint32_t)index & 0xFFFFFF;
            uint32_t length = (uint32_t)index >> 24;

            auto inserted = stringCache.emplace(index, DecryptStringAt(offset, length));
            return inserted.first->second.c_str();
        }

        // ---- 各结构 nameIndex 的解码（gi_fields.md §3/§4，均已验收）----
        // 这些是对原始字节的解码，不依赖 Il2CppTypeDefinition 的成员名，
        // 所以即使结构体成员名与本版本布局不同也能用。
        inline int32_t typeNameIndex(uint32_t raw)      { return ver::decTypeNameIndex(raw); }
        inline int32_t typeNamespaceIndex(uint32_t raw) { return ver::decTypeNamespaceIndex(raw); }
        inline int32_t typeMethodStart(uint32_t raw)    { return ver::decTypeMethodStart(raw); }
        inline int32_t typeFieldStart(uint32_t raw)     { return ver::decTypeFieldStart(raw); }
        inline int32_t typePropertyStart(uint32_t raw)  { return ver::decTypePropertyStart(raw); }
        // [V] parentIndex（Il2CppType 索引）：`raw - (uint32_t)ver::kTypeDefParentIndex.key`，-1 = 无父类
        inline int32_t typeParentIndex(uint32_t raw)    { return ver::decTypeParentIndex(raw); }
        // [V] 泛型容器索引：`(int16)(raw16 - (uint32_t)ver::kTypeDefGenericContainerIndex.key)`；26229 是「无泛型」哨兵（sub_140511DB0）
        inline int32_t typeGenericContainerIndex(uint16_t raw) {
            return ver::decTypeGenericContainerIndex(raw);
        }
        // [V] 容器表每索引 key（sub_140511DB0 / sub_14050E030 两处互证）
        inline uint64_t genericContainerKey(uint32_t c) {
            return ver::keyContainer(c);
        }
        // 容器布局按 version.json 的 structOffsets 读取（7.1: argc@+8, pStart@+4；7.0: argc@+8, pStart@+12）
        inline uint32_t genericContainerArgc(uint32_t c) {
            const uint8_t* b = s_GlobalMetadataHeader + header.genericContainers + 16ull * c;
            return ver::decGenericContainerArgc(*(const uint32_t*)(b + ver::kIl2CppGenericContainerArgcOffset), c);
        }
        inline uint32_t genericParameterStart(uint32_t c) {
            const uint8_t* b = s_GlobalMetadataHeader + header.genericContainers + 16ull * c;
            return ver::decGenericContainerParameterStart(*(const uint32_t*)(b + ver::kIl2CppGenericContainerParameterStartOffset), c);
        }
        // [V] 泛型参数名：7.1 = (raw ^ k) - key_p；7.0 = (raw ^ k) ^ key_p（见 version.json 的 decodeExpr）
        inline uint64_t genericParameterKey(uint32_t p) {
            return ver::keyGenericParam(p);
        }
        inline int32_t genericParameterNameIndex(uint32_t p) {
            // 越界保护：VAR/MVAR 的索引在异常数据里可能不是全局下标（实测见过 0x4313ac60）。
            const uint64_t off = (uint64_t)header.genericParameters + 14ull * p;
            if (off + 14 > metadataSize) return -1;
            const uint8_t* e = s_GlobalMetadataHeader + off;
            return ver::decGenericParameterNameIndex(*(const uint32_t*)e, p);
        }
        inline uint16_t typeMethodCount(uint16_t raw)   { return ver::decTypeMethodCount(raw); }
        inline uint16_t typeFieldCount(uint16_t raw)    { return ver::decTypeFieldCount(raw); }
        inline uint8_t  typePropertyCount(uint8_t raw)  { return ver::decTypePropertyCount(raw); }
        inline int16_t  typeEventStart(int16_t raw)     { return ver::decTypeEventStart(raw); }
        // [V] flags = +0x28 - (uint32_t)ver::kTypeDefFlags.key。验收：106 个不同值（全在 TYPE_ATTRIBUTE 掩码内）；
        //   BeforeFieldInit 87%、Public 84%、Sealed 50%、NestedPublic 29%、Abstract 8.8%、
        //   Serializable 5.7%、Interface 1.8%、**SpecialName 0%**（该标志本就罕见，用错常量时是 54%）。
        inline uint32_t typeFlags(uint32_t raw) { return ver::decTypeFlags(raw); }
        // [V] type kind bitfield：7.x +0x3A；6.7 +0x36（decode 见 version.json）。
        inline uint8_t typeIsValueType(uint8_t raw) { return (uint8_t)(ver::decTypeBitfield(raw) & 1u); }
        inline uint8_t typeIsEnum(uint8_t raw)      { uint8_t b = ver::decTypeBitfield(raw); return (uint8_t)((~b >> 1) & 1u); }
        inline uint16_t typeInterfacesStart(uint16_t raw){ return ver::decTypeInterfacesStart(raw); }
        // ⚠️ 必须按 8 位截断：0xC8 编码 0 -> (uint8_t)(0xC8 + 56) = 0。
        //    返回 uint32 不截断会得到 256 -> 读 256 个接口 -> 越界野指针（实测崩溃）。
        inline uint8_t  typeInterfacesCount(uint8_t raw) { return ver::decTypeInterfacesCount(raw); }  // 0xC8 编码 0
        inline int16_t  typeNestedStart(int16_t raw)     { return ver::decTypeNestedStart(raw); }
        inline uint32_t typeNestedCount(uint8_t raw)     { return ver::decTypeNestedCount(raw); }
        inline uint8_t  typeEventCount(uint8_t raw)     { return (uint8_t)(raw + (uint32_t)ver::kTypeDefEventCount.key); } // 0x8F 编码 0（同样必须 8 位截断）

        // 方法名：逐索引 key，与 raw 异或后再减去常数
        // 见 sub_140514A70 / sub_140528080（两个独立读取点互证）
        inline int32_t methodNameIndex(uint32_t raw, uint32_t methodIndex)
        {
            return (int32_t)(ver::keyMethod(methodIndex) ^ (raw - (uint32_t)ver::kMethodNameIndex.key));
        }

        // flags / iflags：与方法名同一个逐索引 key（sub_140514630 的循环体）。
        // 验收：flags 的 METHOD_ATTRIBUTE 位分布呈教科书形态
        //       （access=6/1/3 为主，static 29%、virtual 31%、abstract 2.5%、pinvoke 0.3%）；
        //       iflags 只取 0 与 0x1000（IL/Managed 与 InternalCall）。
        inline uint16_t methodFlags(uint16_t raw, uint32_t methodIndex)
        {
            return ver::decMethodFlags(raw, methodIndex);
        }
        inline uint16_t methodIFlags(uint16_t raw, uint32_t methodIndex)
        {
            return ver::decMethodIFlags(raw, methodIndex);
        }

        // [V] returnType：methodDefinition +0x08，解码 `(raw ^ key) ^ (uint32_t)ver::kMethodReturnType.key`。
        //   key 与方法名同；末尾那个常量是关键（少了它就会得到 0x3F78xxxx 窄带）。
        //   验收：前 50000 个方法索引全部合法（0/越界），type 分布合理
        //   （void 50%、bool、class、I4、string、valuetype、szarray、genericinst…）。
        static constexpr uint32_t kReturnTypeXor = (uint32_t)ver::kMethodReturnType.key;
        // [V] declaringType = key ^ raw ^ (uint32_t)ver::kMethodDeclaringType.key（typeDefinition 索引）；
        //   来源 GIMeta_GetMethodInfoFromIndex：拿到后交给 GetTypeInfoByIndex。
        inline int32_t methodDeclaringType(uint32_t raw, uint32_t methodIndex)
        {
            uint32_t key = ver::keyMethod(methodIndex);
            return (int32_t)(key ^ raw ^ (uint32_t)ver::kMethodDeclaringType.key);
        }
        inline int32_t methodReturnTypeIndex(uint32_t methodIndex)
        {
            const uint8_t* md = s_GlobalMetadataHeader + header.methodsOffset + 26 * (size_t)methodIndex;
            uint32_t raw = *(const uint32_t*)(md + ver::kIl2CppMethodDefinitionReturnTypeOffset);
            const uint32_t opKey = (uint32_t)ver::kMethodReturnType.key;
            // 通用：returnType 的 op 由 fieldDecode.method.returnType 决定。
            // 7.0/7.1 是 xor，6.7 是 sub，最后再与方法级 keyMethod 异或。
            switch (ver::kMethodReturnType.op) {
            case '-': raw -= opKey; break;
            case '+': raw += opKey; break;
            default:  raw ^= opKey; break;
            }
            return (int32_t)(raw ^ ver::keyMethod(methodIndex));
        }

        // [V] 方法指针索引表 = MHY[0x94] ^ 0x4A4C0A71（4 字节/方法，-1 = 无实现）。
        //   来源 GIMeta_SetupMethodsLocked：`ptr = *(T0+0x60)[ MHY[0x94][methodIndex] ]`。
        inline int32_t methodPointerIndex(uint32_t methodIndex)
        {
            if (methodIndex >= header.methodsCount) return -1;
            return *(const int32_t*)(s_GlobalMetadataHeader + header.methodPointerIndexOffset + 4 * methodIndex);
        }
        // [V] 虚/重写方法的 invoker：在 6 字节表里按 methodIndex 二分，取 slot，再 *(T0+0x48)[slot]
        inline uint64_t methodInvoker(uint32_t methodIndex)
        {
            uint32_t lo = 0, hi = header.methodSlotCount;
            while (lo < hi)
            {
                uint32_t mid = (lo + hi) / 2;
                int32_t mi = *(const int32_t*)(s_GlobalMetadataHeader + header.methodSlotTableOffset + 6 * mid);
                if ((int32_t)methodIndex <= mi) hi = mid; else lo = mid + 1;
            }
            if (lo >= header.methodSlotCount) return 0;
            const uint8_t* e = s_GlobalMetadataHeader + header.methodSlotTableOffset + 6 * lo;
            if (*(const int32_t*)e != (int32_t)methodIndex) return 0;
            uint16_t slot = *(const uint16_t*)(e + 4);
            if (slot >= header.methodSlotCount) return 0;
            return *(const uint64_t*)(s_InvokerArray + 8 * (uint64_t)slot);
        }

        // 方法指针（.text VA）；无实现返回 0
        // [V] 非泛型方法地址：按 **methodIndex 直接索引** `*(T0+0x88)`。
        //   文章 §methodPointer 原文：非虚走 `+0x80[index]`，虚/重写走 `+0x90[slot]`（本版本 `*(T0+0x48)[slot]`）。
        //   ⚠️ 之前用 `*(T0+0x60)[ ptrIndex ]` 是错的：`*(T0+0x60)` 是 **genericMethodPointers**
        //      （文章 CR+0x60，只服务泛型实例）。后果：718552 条 RVA 只有 16217 个不同值、
        //      单一地址被 216261 个方法共用（诱饵表污染）。
        inline uint64_t methodPointer(uint32_t methodIndex)
        {
            if (methodIndex >= header.methodsCount) return 0;
            uint64_t p = *(const uint64_t*)(s_MethodPointerByIndex + 8 * (uint64_t)methodIndex);
            if (p <= 1) return 0;   // 0/1 = 无方法体哨兵
            const uint64_t base = files_.pe()->optional_header().imagebase();
            if (p < base) return 0;
            const uint64_t rva = p - base;
            for (const auto& sec : files_.pe()->sections())
            {
                if (rva >= sec.virtual_address() && rva < (uint64_t)sec.virtual_address() + sec.virtual_size())
                {
                    // 只有可执行段才是方法体；.data/.rdata 里的值不是函数地址
                    return (sec.name() == ".text" || sec.name() == "il2cpp") ? p : 0;
                }
            }
            return 0;
        }

        // returnType 不在 26 字节方法结构里，而在并行的 4 字节表（sub_140514630）。
        // 实测：取值 0..527，其中约 12% 为 -1（void）。
        // [V] 参数：count/start 与方法同一个 key，但 count 是**字节**运算。
        //   parameterStart = key ^ (raw@+4 - (uint32_t)ver::kMethodParameterStart.key)（全局索引，实测累计递增）
        //   parameterCount = ((raw@+0x18 - 31) & 0xFF) ^ (key & 0xFF)   <- 字节 XOR
        inline uint32_t methodParamStart(uint32_t raw_pstart, uint32_t methodIndex)
        {
            return ver::decMethodParamStart(raw_pstart, methodIndex);
        }
        inline uint8_t methodParamCount(uint8_t raw_pcount, uint32_t methodIndex)
        {
            return ver::decMethodParamCount(raw_pcount, methodIndex);
        }
        // 参数名/类型：逐索引 key（sub_140528560）
        // ⚠️ 必须 64 位不回绕！`41617*paramIndex + 1219887025` 在 paramIndex≈73891 处首次超过 2^32，
        //    用 uint32 回绕会让「索引 ≥ 73891 的参数」名/类型全错（实测合法率 4.81% → 修后 100%）。
        inline uint32_t paramKey(uint32_t paramIndex)
        {
            return ver::keyParam(paramIndex);
        }
        inline int32_t paramNameIndex(uint32_t raw, uint32_t paramIndex)
        {
            return ver::decParamNameIndex(raw, paramIndex);
        }
        inline int32_t paramTypeIndex(uint32_t raw, uint32_t paramIndex)
        {
            return ver::decParamTypeIndex(raw, paramIndex);
        }

        // 属性名：逐索引 key（sub_1405151D0）
        inline uint32_t propertyKey(uint32_t propertyIndex)
        {
            return ver::keyProperty(propertyIndex);
        }
        inline int32_t propertyNameIndex(uint32_t raw, uint32_t propertyIndex)
        {
            return ver::decPropertyNameIndex(raw, propertyIndex);
        }
        inline uint16_t propertyGet(uint32_t raw, uint32_t propertyIndex)
        {
            return ver::decPropertyGet(raw, propertyIndex);
        }
        inline uint16_t propertySet(uint32_t raw, uint32_t propertyIndex)
        {
            return ver::decPropertySet(raw, propertyIndex);
        }

        // 字段名：逐索引 key（sub_14051CB80 / sub_140512870）
        // ⚠️ 同 paramKey：必须 64 位不回绕（`34782*fieldIndex` 在 fieldIndex≈123482 处超过 2^32）。
        //    实测 fields[].typeIndex 合法率：32 位 123483/440172 → 64 位 440172/440172。
        inline uint32_t fieldKey(uint32_t fieldIndex)
        {
            return ver::keyField(fieldIndex);
        }
        inline int32_t fieldNameIndex(uint32_t raw, uint32_t fieldIndex)
        {
            return ver::decFieldNameIndex(raw, fieldIndex);
        }
        inline int32_t fieldTypeIndex(uint32_t raw, uint32_t fieldIndex)
        {
            return ver::decFieldTypeIndex(raw, fieldIndex);
        }

        // 事件名：逐索引 key（sub_140514CF0）
        inline uint32_t eventKey(uint32_t eventIndex)
        {
            return ver::keyEvent(eventIndex);
        }
        inline int32_t eventNameIndex(uint32_t raw, uint32_t eventIndex)
        {
            return ver::decEventNameIndex(raw, eventIndex);
        }
        inline int32_t eventTypeIndex(uint32_t raw, uint32_t eventIndex)
        {
            return ver::decEventTypeIndex(raw, eventIndex);
        }
        inline uint16_t eventAdd(uint32_t raw, uint32_t eventIndex)
        {
            return ver::decEventAdd(raw, eventIndex);
        }
        inline uint16_t eventRemove(uint32_t raw, uint32_t eventIndex)
        {
            return ver::decEventRemove(raw, eventIndex);
        }
        inline uint16_t eventRaise(uint32_t raw, uint32_t eventIndex)
        {
            return ver::decEventRaise(raw, eventIndex);
        }

        const Il2CppType* GetIl2CppTypeFromIndex(int32_t index) {
            if (index == -1) return nullptr;
            // ⚠️ *(T1+0x48) 是**镜像里的 VA**，必须先 va_to_offset 转成宿主指针再解引用。
            //    直接用 VA 会得到野地址 -> SIGSEGV（实测）。
            const Il2CppType* types = (const Il2CppType*)s_Il2CppTypes;
            if (!types) return nullptr;
            // 合法域保护：Il2CppType 数组共 683574 项（T1+0x54 ^ 0x6622B34E，已验收）。
            // 个别字段解码出越界索引时，直接返回 nullptr，避免野指针。
            if (index < 0 || !header.typesCount || (uint32_t)index >= header.typesCount) return nullptr;

            return types + index;
        }

        const Il2CppType* GetInterfaceFromIndex(int32_t index) {
            if (index == -1) return nullptr;
            // [V] 接口表 = MHY[0x1C4] - 1518027399，步长 6；每项 +0 是 Il2CppType 索引
            const uint8_t* interfaceIndices = (const uint8_t*)((const char*)s_GlobalMetadataHeader + header.interfacesTable);
            return GetIl2CppTypeFromIndex(*(const int32_t*)(interfaceIndices + 6LL * index));
        }

        const Il2CppFieldDefinition* GetFieldDefinitionFromIndex(int32_t index)
        {
            const Il2CppFieldDefinition* fields = (const Il2CppFieldDefinition*)((const char*)s_GlobalMetadataHeader + header.fieldsOffset);
            return fields + index;
        }

        const Il2CppTypeDefinition* GetTypeDefinitionFromIndex(int32_t index)
        {
            const Il2CppTypeDefinition* typeDefinitions = (const Il2CppTypeDefinition*)(s_GlobalMetadataHeader + header.typeDefinitionsOffset);
            return typeDefinitions + index;
        }

        const Il2CppGenericContainer* GetGenericContainerFromIndex(int32_t genericContainerIndex)
        {
            // [V] 槽位已换版本：6.7 用 0x114，本版本 genericContainers 在 0x28（= header.genericContainers）
            auto base = (const Il2CppGenericContainer*)(s_GlobalMetadataHeader + header.genericContainers);
            return (genericContainerIndex == 0xFFFF) ? nullptr : base + genericContainerIndex;
        }

        const Il2CppGenericParameter* GetGenericParameter(uint32_t genericParameterStart, uint16_t index) {
            // [V] 槽位已换版本：6.7 用 364，本版本 genericParameters 在 0x170（= header.genericParameters）
            return (const Il2CppGenericParameter*)(s_GlobalMetadataHeader + header.genericParameters) + (genericParameterStart + index);
        }

        // ---- typeDef 全名（namespace + 嵌套链 + 自身名），供 generic inst 名字使用 ----
        //   genericClasses 表给出 typeDefinitionIndex，必须能还原出 `Outer.Inner`。
        void ensureNestingMap()
        {
            if (nestingMapBuilt_) return;
            nestingMapBuilt_ = true;
            if (!header.nestedTypesTable || !header.typeDefinitionsCount) return;
            const uint32_t* tbl = (const uint32_t*)(s_GlobalMetadataHeader + header.nestedTypesTable);
            const Il2CppTypeDefinition* tds = (const Il2CppTypeDefinition*)(s_GlobalMetadataHeader + header.typeDefinitionsOffset);
            for (uint32_t t = 0; t < header.typeDefinitionsCount; ++t)
            {
                int32_t st = typeNestedStart(tdI16(&tds[t], ver::kIl2CppTypeDefinitionNestedTypesStartOffset));
                uint32_t cnt = typeNestedCount(tdU8(&tds[t], ver::kIl2CppTypeDefinitionNestedTypesCountOffset));
                if (st < 0 || cnt == 0) continue;
                for (uint32_t i = 0; i < cnt; ++i)
                {
                    uint32_t child = tbl[st + i];
                    if (child < header.typeDefinitionsCount) nestingMap_[(int32_t)child] = (int32_t)t;
                }
            }
        }

        std::string typeDefFullName(int32_t idx)
        {
            if (idx < 0 || (uint32_t)idx >= header.typeDefinitionsCount) return {};
            auto cached = typeDefNameCache_.find(idx);
            if (cached != typeDefNameCache_.end()) return cached->second;

            ensureNestingMap();
            const Il2CppTypeDefinition* tds = (const Il2CppTypeDefinition*)(s_GlobalMetadataHeader + header.typeDefinitionsOffset);
            auto nameOf = [&](int32_t t) {
                std::string n{ GetStringFromIndex(typeNameIndex((uint32_t)tdI32(&tds[t], ver::kIl2CppTypeDefinitionNameIndexOffset))) };
                if (size_t p = n.find('`'); p != std::string::npos) n.resize(p);
                return n;
            };
            auto nsOf = [&](int32_t t) {
                return std::string{ GetStringFromIndex(typeNamespaceIndex((uint32_t)tdI32(&tds[t], ver::kIl2CppTypeDefinitionNamespaceIndexOffset))) };
            };

            std::vector<std::string> chain;
            int32_t cur = idx, outermost = -1;
            for (int depth = 0; depth < 16; ++depth)
            {
                auto it = nestingMap_.find(cur);
                if (it == nestingMap_.end()) break;
                cur = it->second;
                outermost = cur;
                chain.push_back(nameOf(cur));
            }
            std::string ns = nsOf(idx);
            if (ns.empty() && outermost >= 0) ns = nsOf(outermost);
            std::string out;
            if (!ns.empty()) out = ns + ".";
            for (auto it = chain.rbegin(); it != chain.rend(); ++it) out += *it + ".";
            out += nameOf(idx);
            return typeDefNameCache_.emplace(idx, std::move(out)).first->second;
        }

        std::unordered_map<int32_t, int32_t> nestingMap_;
        std::unordered_map<int32_t, std::string> typeDefNameCache_;
        bool nestingMapBuilt_ = false;

        std::string NameFromIl2CppType(const Il2CppType* type) 
        {
            if (!type) return "";

            auto cached = typeNameCache.find(type);
            if (cached != typeNameCache.end()) return cached->second;

            // 环检测：泛型实参可以自引用（class Node<T> : IComparable<Node<T>>）。
            // 正在解析的 type 再次进入时返回 "?"，既避免死循环，也保留外层的真实类型名。
            if (!resolvingTypes_.insert(type).second) return "?";
            struct ResolveGuard {
                std::unordered_set<const Il2CppType*>& set;
                const Il2CppType* key;
                ~ResolveGuard() { set.erase(key); }
            } resolveGuard{resolvingTypes_, type};

            std::string result;

            switch (type->type) 
            {
            case Il2CppTypeEnum::IL2CPP_TYPE_VOID:       result = "void"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN:    result = "bool"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_CHAR:       result = "char"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_I1:         result = "sbyte"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_U1:         result = "byte"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_I2:         result = "short"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_U2:         result = "ushort"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_I4:         result = "int"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_U4:         result = "uint"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_I8:         result = "long"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_U8:         result = "ulong"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_R4:         result = "float"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_R8:         result = "double"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_STRING:     result = "string"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:     result = "object"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_I:          result = "IntPtr"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_U:          result = "UIntPtr"; break;
            case Il2CppTypeEnum::IL2CPP_TYPE_TYPEDBYREF: result = "TypedReference"; break;
            }

            if (!result.empty()) return typeNameCache.emplace(type, std::move(result)).first->second;

            if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type->type == Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE)
            {
                if (type->data.klassIndex < 0 || type->data.klassIndex >= 88902) return "";  // 非法 klassIndex 保护
                const Il2CppTypeDefinition* typeDefinitions = GetTypeDefinitionFromIndex(type->data.klassIndex);
                std::string name{ GetStringFromIndex(typeNameIndex((uint32_t)tdI32(typeDefinitions, ver::kIl2CppTypeDefinitionNameIndexOffset))) };
                if (size_t p = name.find('`'); p != std::string::npos) name.resize(p);
;
                std::string ns{ GetStringFromIndex(typeNamespaceIndex((uint32_t)tdI32(typeDefinitions, ver::kIl2CppTypeDefinitionNamespaceIndexOffset))) };
                // declaringTypeIndex 未定位 -> 不输出 declaring 前缀
                std::string declaring;

                result = declaring.empty() ? (ns.empty() ? "" : ns + ".") + name : declaring + name;
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST) {
                
                // [V] type->data.generic_class 是 genericClasses 表的**索引**（不是指针）：
                //   genericClasses[g] = {genericInstIndex@+0, typeDefinitionIndex@+4}（startup，8 字节）
                //   genericInsts[gi]  = {argc@+0, pad, argv@+8}；argv 是 Il2CppType* 的 VA 数组
                //   来源 GIMeta_RuntimeInit / GIMeta_TypeInfoDispatcher（见 UPDATE.md §15.21）。
                uint32_t gcIndex = (uint32_t)(uintptr_t)type->data.generic_class;
                if (header.genericClasses && header.genericClassesCount && gcIndex < header.genericClassesCount)
                {
                    const uint8_t* e = s_StartupMetadataHeader + header.genericClasses + 8ull * gcIndex;
                    uint32_t ginstIndex = *(const uint32_t*)e;
                    uint32_t tdIndex    = *(const uint32_t*)(e + 4);
                    if (tdIndex < header.typeDefinitionsCount && ginstIndex < header.genericInstsCount)
                    {
                        std::string gargs;
                        const uint8_t* inst = s_GenericInsts + 16ull * ginstIndex;
                        uint32_t argc = *(const uint32_t*)inst;
                        if (argc > 64) argc = 64;
                        // inst+8 是 **argv 数组的指针字段**；先取出指针，再逐个读 type VA。
                        uint64_t argvVA = *(const uint64_t*)(inst + 8);
                        const uint64_t* argv = argvVA ? (const uint64_t*)files_.at(argvVA) : nullptr;
                        for (uint32_t k = 0; k < argc; ++k)
                        {
                            if (!argv || !argv[k]) continue;
                            const Il2CppType* at = (const Il2CppType*)files_.at(argv[k]);
                            if (!at) continue;
                            if (!gargs.empty()) gargs += ", ";
                            gargs += NameFromIl2CppType(at);
                        }
                        std::string gname = typeDefFullName((int32_t)tdIndex);
                        if (!gname.empty())
                        {
                            result = gargs.empty() ? gname : gname + "<" + gargs + ">";
                            return typeNameCache.emplace(type, std::move(result)).first->second;
                        }
                    }
                }
                // fallback：旧版 genericClassRange 路径（genericClasses 缺失时才会走到）
                uint64_t genericIndex = (uint64_t)type->data.generic_class;
                std::string gname;
                std::string gargs;
                if (genericIndex < header.genericClassRangeCount)
                {
                    const uint8_t* rng = s_StartupMetadataHeader
                                       + header.genericClassRangeOffset + 8 * genericIndex;
                    uint32_t argStart = *(const uint32_t*)rng;
                    uint32_t argCount = *(const uint32_t*)(rng + 4);
                    if (argCount > 64) argCount = 64;
                    for (uint32_t k = 0; k < argCount; k++)
                    {
                        int32_t ti = *(const int32_t*)(s_StartupMetadataHeader
                                     + header.genericTypeArgOffset + 4 * (argStart + k));
                        if (ti == -1) continue;
                        const Il2CppType* at = GetIl2CppTypeFromIndex(ti);
                        if (!at) continue;
                        if (!gargs.empty()) gargs += ", ";
                        gargs += NameFromIl2CppType(at);
                    }
                }
                std::string fullName = gname.empty() ? std::string("?") : gname;
                result = gargs.empty() ? fullName : fullName + "<" + gargs + ">";
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_PTR || type->type == Il2CppTypeEnum::IL2CPP_TYPE_BYREF || type->type == Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY)
            {
                // ⚠️ 基址必须用运行时的 s_Il2CppTypes（= *(T1+0x48) = 0x142E1EA20）。
                //    此前的硬编码 0x1429FB1E0 是**旧版本**的 Il2CppType 数组地址，
                //    用它算出的索引全错 -> 野指针（实测 400 项里只有 64 个 type 字节合法）。
                uint64_t index = ((uint64_t)(uintptr_t)type->data.type - s_Il2CppTypesVA) / 16;
                const Il2CppType* elementType = GetIl2CppTypeFromIndex((int32_t)index);
                std::string rcx = NameFromIl2CppType(elementType);

                if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_PTR)     result = rcx + "*";
                if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_BYREF)   result = rcx + "&";
                if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY) result = rcx + "[]";
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_ARRAY)
            {
                // 同上：data.array 是镜像 VA，直接 va_to_offset 得到宿主指针。
                auto* a = (Il2CppArrayType*)(files_.exe().data() + files_.pe()->va_to_offset((uint64_t)type->data.array));
                if (!a) return typeNameCache.emplace(type, std::string{}).first->second;
                std::string e = NameFromIl2CppType(GetIl2CppTypeFromIndex((int32_t)(((uint64_t)(uintptr_t)a->etype - s_Il2CppTypesVA) / 16)));
                if (e.empty()) result = std::string("?");
                result = e + (a->rank == 1 ? "[*]" : "[" + std::string(a->rank - 1, ',') + "]");
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_VAR || type->type == Il2CppTypeEnum::IL2CPP_TYPE_MVAR)
            {
                // ⚠️ 必须用**本版本**的泛型参数名公式。旧版（6.7）的
                //    `(nameIndex ^ 0x2DD1C9C6) - ((0x65DE21D74280*p) ^ 0x154AA920) + 1912316114`
                //    在本版本会解出**乱码**（实测 2787 个方法签名被污染）。
                uint32_t gp = (uint32_t)type->data.genericParameterIndex;
                int32_t gpName = genericParameterNameIndex(gp);
                result = SanitizeGenericName(gpName >= 0 ? GetStringFromIndex(gpName) : std::string(), gp);
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            return typeNameCache.emplace(type, std::string{}).first->second;
        }

        const Il2CppFieldDefaultValue* GetDefaultValueForField(int32_t index)
        {
            const Il2CppFieldDefaultValue* start = (const Il2CppFieldDefaultValue*)(s_GlobalMetadataHeader + header.fieldDefaultValuesOffset);
            // 表按 fieldIndex **严格递增**（已验收 155..440164）-> 二分（原为线性，O(4.4e5 x 7.5e4)）。
            int32_t lo = 0, hi = (int32_t)header.fieldDefaultValuesCount - 1;
            while (lo <= hi)
            {
                int32_t mid = lo + ((hi - lo) >> 1);
                int32_t v = fdvFieldIndex(start + mid);
                if (v == index) return start + mid;
                if (v < index) lo = mid + 1; else hi = mid - 1;
            }
            return nullptr;
        }

        std::string GetConstantValueFromBlob(Il2CppTypeEnum type, uint8_t* blob)
        {
            if (!blob)
            {
                if (type == Il2CppTypeEnum::IL2CPP_TYPE_STRING || type == Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type == Il2CppTypeEnum::IL2CPP_TYPE_OBJECT || type == Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST || type == Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY)
                    return "null";
                return "";
            }

            switch (type)
            {
            case Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN: return *blob ? "true" : "false";
            case Il2CppTypeEnum::IL2CPP_TYPE_I1:      return std::to_string((int)*(int8_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_U1:      return std::to_string((unsigned)*(uint8_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
            case Il2CppTypeEnum::IL2CPP_TYPE_I2:      return std::to_string((int)*(int16_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_U2:      return std::to_string((unsigned)*(uint16_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_I4:      return std::to_string(*(int32_t*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_U4:      return std::to_string(*(uint32_t*)blob) + "u";
            case Il2CppTypeEnum::IL2CPP_TYPE_I8:      return std::to_string(*(int64_t*)blob) + "L";
            case Il2CppTypeEnum::IL2CPP_TYPE_U8:      return std::to_string(*(uint64_t*)blob) + "UL";
            case Il2CppTypeEnum::IL2CPP_TYPE_R4:      return std::to_string(*(float*)blob) + "f";
            case Il2CppTypeEnum::IL2CPP_TYPE_R8:      return std::to_string(*(double*)blob);
            case Il2CppTypeEnum::IL2CPP_TYPE_STRING:
            {
                uint32_t len = *(uint32_t*)blob;
                // 字符串默认值格式（两版一致）：[u32 len][bytes]。
                // 这里只做元数据边界保护，避免损坏文件造成超大 memcpy。
                const uint64_t off = (uint64_t)(blob - s_GlobalMetadataHeader);
                if (off + 4ull + len > metadataSize) return "\"\"";
                return "\"" + std::string((char*)blob + 4, len) + "\"";
            }
            case Il2CppTypeEnum::IL2CPP_TYPE_CLASS:
            case Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:
            case Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST:
            case Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY:
                return "null";
            default:
                return "";
            }
        }

        const Il2CppMethodDefinition* GetMethodDefinitionFromIndex(int32_t index)
        {
            const Il2CppMethodDefinition* methods = (const Il2CppMethodDefinition*)((const char*)s_GlobalMetadataHeader + header.methodsOffset);
            return methods + index;
        }

        const Il2CppParameterDefinition* GetParameterDefinitionFromIndex(uint32_t index)
        {
            const Il2CppParameterDefinition* parameters = (const Il2CppParameterDefinition*)((const char*)s_GlobalMetadataHeader + header.parametersOffset);
            return parameters + index;
        }

        const Il2CppParameterDefaultValue* GetParamDefault(uint32_t parameterIndex) {
            const Il2CppParameterDefaultValue* start = (const Il2CppParameterDefaultValue*)(s_GlobalMetadataHeader + header.parameterDefaultValuesOffset);
            const int32_t count = (int32_t)(header.parameterDefaultValuesCount / sizeof(Il2CppParameterDefaultValue));
            // 表按 parameterIndex **严格递增**（已验收 4868..548362）-> 二分。
            // 原实现是线性扫描：25374 项 x 548400 个参数 = O(1.4e10)，会非常慢。
            int32_t lo = 0, hi = count - 1;
            while (lo <= hi)
            {
                int32_t mid = lo + ((hi - lo) >> 1);
                int32_t v = pdvParameterIndex(start + mid);
                if (v == (int32_t)parameterIndex) return start + mid;
                if (v < (int32_t)parameterIndex) lo = mid + 1; else hi = mid - 1;
            }
            return nullptr;
        }

        std::string GetDefaultValueData(int32_t typeIndex, int32_t dataIndex) {
            if (dataIndex == -1) return "null";
            const auto* t = GetIl2CppTypeFromIndex(typeIndex);
            if (!t) return "";
            uint8_t* blob = s_GlobalMetadataHeader + dataIndex + header.fieldAndParameterDefaultValueDataOffset;
            return GetConstantValueFromBlob(t->type, blob);
        }

        const Il2CppPropertyDefinition* GetPropertyDefinitionFromIndex(int32_t index)
        {
            const Il2CppPropertyDefinition* properties = (const Il2CppPropertyDefinition*)((const char*)s_GlobalMetadataHeader + header.propertiesOffset);
            return properties + index;
        }

        const Il2CppEventDefinition* GetEventDefinitionFromIndex(int32_t index)
        {
            const Il2CppEventDefinition* events = (const Il2CppEventDefinition*)((const char*)s_GlobalMetadataHeader + header.eventsOffset);
            return events + index;
        }

        // 旧接口保留，内部改走本版本的 (offset, length) 解密。
        // 注意：本版本没有独立的字面量条目表，offset/length 打包在 nameIndex 里，
        // 因此调用方必须自己先 SplitStringEntry 拿到 offset，不能像旧版那样传索引。
        std::string decryptString(uint32_t offset, uint32_t len) {
            return DecryptStringAt(offset, len);
        }


private:
    MetadataFiles& files_;
};
