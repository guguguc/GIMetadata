// https://yougame.biz/threads/390622/

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <limits>
#include <cmath>
#include <locale>
#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstdint>
#include <format>
#include <memory>
#include <span>
#include <string_view>
#include <capstone/capstone.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4267 4244)
#endif
#include <LIEF/PE.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef _WIN32
constexpr const char* kPathSep = "\\";
#else
constexpr const char* kPathSep = "/";
#endif

#define TYPE_ATTRIBUTE_VISIBILITY_MASK       0x00000007
#define TYPE_ATTRIBUTE_NOT_PUBLIC            0x00000000
#define TYPE_ATTRIBUTE_PUBLIC                0x00000001
#define TYPE_ATTRIBUTE_NESTED_PUBLIC         0x00000002
#define TYPE_ATTRIBUTE_NESTED_PRIVATE        0x00000003
#define TYPE_ATTRIBUTE_NESTED_FAMILY         0x00000004
#define TYPE_ATTRIBUTE_NESTED_ASSEMBLY       0x00000005
#define TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM  0x00000006
#define TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM   0x00000007
#define TYPE_ATTRIBUTE_LAYOUT_MASK           0x00000018
#define TYPE_ATTRIBUTE_AUTO_LAYOUT           0x00000000
#define TYPE_ATTRIBUTE_SEQUENTIAL_LAYOUT     0x00000008
#define TYPE_ATTRIBUTE_EXPLICIT_LAYOUT       0x00000010
#define TYPE_ATTRIBUTE_CLASS_SEMANTIC_MASK   0x00000020
#define TYPE_ATTRIBUTE_CLASS                 0x00000000
#define TYPE_ATTRIBUTE_INTERFACE             0x00000020
#define TYPE_ATTRIBUTE_ABSTRACT              0x00000080
#define TYPE_ATTRIBUTE_SEALED                0x00000100
#define TYPE_ATTRIBUTE_SPECIAL_NAME          0x00000400
#define TYPE_ATTRIBUTE_SERIALIZABLE          0x00002000
#define TYPE_ATTRIBUTE_BEFORE_FIELD_INIT     0x00100000

#define FIELD_ATTRIBUTE_FIELD_ACCESS_MASK    0x0007
#define FIELD_ATTRIBUTE_PRIVATE              0x0001
#define FIELD_ATTRIBUTE_FAM_AND_ASSEM        0x0002
#define FIELD_ATTRIBUTE_ASSEMBLY             0x0003
#define FIELD_ATTRIBUTE_FAMILY               0x0004
#define FIELD_ATTRIBUTE_FAM_OR_ASSEM         0x0005
#define FIELD_ATTRIBUTE_PUBLIC               0x0006
#define FIELD_ATTRIBUTE_STATIC               0x0010
#define FIELD_ATTRIBUTE_INIT_ONLY            0x0020
#define FIELD_ATTRIBUTE_LITERAL              0x0040
#define FIELD_ATTRIBUTE_NOT_SERIALIZED       0x0080
#define FIELD_ATTRIBUTE_HAS_DEFAULT          0x8000

#define METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK  0x0007
#define METHOD_ATTRIBUTE_PRIVATE_SCOPE       0x0000
#define METHOD_ATTRIBUTE_PRIVATE             0x0001
#define METHOD_ATTRIBUTE_FAM_AND_ASSEM       0x0002
#define METHOD_ATTRIBUTE_ASSEM               0x0003
#define METHOD_ATTRIBUTE_FAMILY              0x0004
#define METHOD_ATTRIBUTE_FAM_OR_ASSEM        0x0005
#define METHOD_ATTRIBUTE_PUBLIC              0x0006
#define METHOD_ATTRIBUTE_STATIC              0x0010
#define METHOD_ATTRIBUTE_FINAL               0x0020
#define METHOD_ATTRIBUTE_VIRTUAL             0x0040
#define METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK  0x0100
#define METHOD_ATTRIBUTE_REUSE_SLOT          0x0000
#define METHOD_ATTRIBUTE_NEW_SLOT            0x0100
#define METHOD_ATTRIBUTE_ABSTRACT            0x0400
#define METHOD_ATTRIBUTE_PINVOKE_IMPL        0x2000
#define METHOD_IMPL_ATTRIBUTE_INTERNAL_CALL        0x1000

#define PARAM_ATTRIBUTE_IN                    0x0001
#define PARAM_ATTRIBUTE_OUT                   0x0002
#define PARAM_ATTRIBUTE_OPTIONAL               0x0010
#define PARAM_ATTRIBUTE_HAS_DEFAULT            0x1000

#define GENERIC_PARAMETER_ATTRIBUTE_VARIANCE_MASK              0x0003
#define GENERIC_PARAMETER_ATTRIBUTE_COVARIANT                  0x0001
#define GENERIC_PARAMETER_ATTRIBUTE_CONTRAVARIANT              0x0002
#define GENERIC_PARAMETER_ATTRIBUTE_REFERENCE_TYPE_CONSTRAINT  0x0004
#define GENERIC_PARAMETER_ATTRIBUTE_NOT_NULLABLE_VALUE_TYPE_CONSTRAINT 0x0008
#define GENERIC_PARAMETER_ATTRIBUTE_DEFAULT_CONSTRUCTOR_CONSTRAINT 0x0010

std::ofstream out("dump.cs");
std::ofstream стрингиойой("stringliteral.json");
std::unique_ptr<LIEF::PE::Binary> pe;
std::vector<uint8_t> exe;
namespace il2cpp
{
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
        IL2CPP_TYPE_TYPEDBYREF = 0x16,
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
        int32_t  namespaceIndex;   // 0x00 [V] - 1145778368
        uint8_t  _pad04[0x04];     // 0x04
        int32_t  propertyStart;    // 0x08 [V] - 1995389561
        int32_t  methodStart;      // 0x0C [V] ^ 0x4D8127F2
        uint8_t  _pad10[0x08];     // 0x10..0x17
        // [V] parentIndex：存的是 **Il2CppType 索引**，解码 `raw - 0x3D74901F`；-1 = 无父类。
        //   验收：枚举→System.Enum(Il2CppType 401709)、结构体→System.ValueType(425583)、
        //         MonoBehaviour→Behaviour、String/Exception→Object、FileStream→Stream、Object→-1。
        int32_t  parentIndex;      // 0x18
        int32_t  fieldStart;       // 0x1C [V] ^ 0x29010897
        int32_t  _f20;             // 0x20     ^ 0x2E8C0EB8 语义未确认（索引另一张 4 字节表）
        int32_t  nameIndex;        // 0x24 [V] - 72511848
        uint32_t flags;            // 0x28 [V] - 0x4159BB8E（TYPE_ATTRIBUTE）
        uint8_t  _pad2C[0x04];     // 0x2C
        uint16_t method_count;     // 0x30 [V] - 0xED3A
        uint8_t  _pad32[0x02];     // 0x32
        int16_t  eventStart;       // 0x34 [V] + 3330
        int16_t  nestedTypesStart; // 0x36 [V] + 6631
        uint16_t field_count;      // 0x38 [V] ^ 0x51A8
        uint8_t  bitfield;         // 0x3A [V] bit0=valuetype, bit1=enum(反相)
        uint8_t  _pad3B;           // 0x3B
        uint16_t interfacesStart;  // 0x3C [V] ^ 0x43DA
        // [V] genericContainerIndex（int16）：`raw - 26230`，哨兵 26229 = 无泛型。
        //   来源 sub_140511DB0（读 typeDef 70*idx + 62）。验收见 status.md §6 附 9。
        int16_t  genericContainerIndex; // 0x3E
        uint8_t  interfaces_count; // 0x40 [V] + 56（0xC8 编码 0）
        uint8_t  _pad41[0x02];     // 0x41
        uint8_t  property_count;   // 0x43 [V] ^ 0x16
        uint8_t  event_count;      // 0x44 [V] + 113   (0x8F 编码 0)
        uint8_t  nestedTypesCount; // 0x45 [V] ^ 0xBA（0xBA 编码 0）
    };

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

    // 本版本布局，26 字节（守卫 >= 0x1A）。nameIndex 在 +0x00（不是旧版的 +0x04）。
    // 见 gi_fields.md §4；nameIndex 的解码见 utils::methodNameIndex()
    struct Il2CppMethodDefinition {
        int32_t  nameIndex;       // 0x00  [V]
        int32_t  parameterStart;  // 0x04
        int32_t  returnType;      // 0x08 [V] (raw ^ key) ^ 0x3F7BDF39
        int32_t  declaringType;   // 0x0C [V] key ^ raw ^ 0x59244785（typeDefinition 索引）
        uint16_t iflags;          // 0x10  [V] key ^ (raw - 25344)
        uint16_t _f12;            // 0x12      (多为 0xFFFF，语义未定)
        uint16_t token;           // 0x14      key ^ raw ^ 0xD73C
        uint16_t flags;           // 0x16  [V] key ^ raw ^ 0x8F60
        uint8_t  parameterCount;  // 0x18  [V] (sub_140528560 在 +0x18 取参数个数)
        uint8_t  _pad19;          // 0x19
    };

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

    // ⚠️ 字段顺序按 sub_1405151D0 实测：getter 在 +6、setter 在 +8。
    //    此前 set/get 写反 -> get 读到的是 setter 字段 -> 全部越界（属性类型/访问器全空）。
    struct Il2CppPropertyDefinition {
        int32_t nameIndex;
        uint16_t token; 
        uint16_t get;   // 0x06 -> key ^ raw ^ 0xE5A2
        uint16_t set;   // 0x08 -> (raw - 23324) ^ key
    };

    // ⚠️ 字段顺序按 sub_140514CF0 实测：typeIndex 在 +0（解码 `key ^ (raw - 452544412)`），
    //    nameIndex 在 +4。此前写反 -> 事件 typeIndex 628/628 全不合法 -> 事件全部被 continue。
    struct Il2CppEventDefinition {
        int32_t typeIndex; // 0x0  -> key ^ (raw - 452544412)
        int32_t nameIndex; // 0x4  -> key ^ (raw - 1037298109)
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

    struct Il2CppGenericContainer {
        int32_t ownerIndex;
        int32_t is_method;
        int32_t type_argc;
        int32_t genericParameterStart;
    };

    struct Il2CppGenericParameter {
        int32_t nameIndex; // 0x00
        uint8_t _pad[4];
        uint16_t flags;    // 0x08
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

    

    static_assert(sizeof(Il2CppImageDefinition) == 0x28);
    static_assert(sizeof(Il2CppTypeDefinition) == 0x46);
    static_assert(sizeof(Il2CppType) == 0x10);
    static_assert(sizeof(Il2CppFieldDefinition) == 0x08);
    static_assert(sizeof(Il2CppFieldDefaultValue) == 0xC);
    static_assert(sizeof(Il2CppMethodDefinition) == 0x1A);
    static_assert(sizeof(Il2CppParameterDefinition) == 0x08);
    static_assert(sizeof(Il2CppParameterDefaultValue) == 0xC);
    static_assert(sizeof(Il2CppPropertyDefinition) == 0xA);
    static_assert(sizeof(Il2CppEventDefinition) == 0xE);
    static_assert(sizeof(Il2CppStringLiteral) == 0x08);
    static_assert(sizeof(Il2CppCustomAttributeTypeRange) == 0x08);
    static_assert(sizeof(Il2CppGenericContainer) == 0x10);
    static_assert(sizeof(Il2CppGenericParameter) == 0xE);
    static_assert(sizeof(Il2CppGenericInst) == 0x10);
    static_assert(sizeof(Il2CppMethodSpec) == 0xC);
    static_assert(sizeof(Il2CppGenericMethodIndices) == 0x08);
    static_assert(sizeof(Il2CppGenericMethodFunctionsDefinitions) == 0x0E);

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
        uint32_t interfacesTable;
        uint32_t nestedTypesTable;   // 4 字节/项

        uint32_t fieldDefaultValuesOffset;
        uint32_t fieldDefaultValuesCount;
        uint32_t fieldAndParameterDefaultValueDataOffset;

        uint32_t methodsOffset;
        uint32_t methodsCount;
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
        uint32_t genericMethodTable;       // MHY[0xC0] - 1630172749，步长 14
        uint32_t genericMethodTableCount;  // (MHY[0x130] - 565220529)/14 = 560659

        uint32_t genericParameters;
        uint32_t genericParameterCount;   // 未验证
        uint32_t genericContainers;
    }header;


    namespace utils 
    {
        std::unordered_map<int32_t, std::string> stringCache;
        std::unordered_map<const Il2CppType*, std::string> typeNameCache;

        // ================= 本版本字符串解密（已实测 75/75 通过）=================
        // 见 ANALYSIS.md §4.3。本版本与旧版有两处结构差异：
        //   1) 没有独立的 {dataIndex, length} 字面量条目表
        //   2) offset(24 位) 与 length(8 位) 直接打包在 nameIndex 字段里
        constexpr uint32_t kStringEntryXor = 0x772FA51E;      // 条目解码 XOR
        constexpr uint64_t kKeyMulA      = 0x5C2B4E660E2D0544ull;
        constexpr uint64_t kKeyMulB      = 0x694418957C890198ull;
        constexpr uint64_t kKeySeed      = 0x55A357D81EF0E48Bull;
        constexpr uint64_t kKeyStep      = 0x6B0B40C349AE61E5ull;   // 每 8 字节递增

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
            return (uint32_t)(1368137530ull * ((667674736ull * (((13029ull * index) ^ 0x43E2DEB7ull)) + 0xCB287082F0ull) >> 8)
                   + 1505552983ull);
        }

        // 按 (offset, length) 解密一段字符串；offset 相对 stringLiteralDataOffset
        std::string DecryptStringAt(uint32_t offset, uint32_t length)
        {
            if (!length) return std::string();
            // 越界保护：解出垃圾 index 时不要直接 segfault
            if ((uint64_t)header.stringLiteralDataOffset + offset + length + 8 > metadataSize)
                return std::string();

            const uint64_t keyBase = kKeyMulA * ((kKeyMulB * offset) ^ kKeySeed);
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
        inline int32_t typeNameIndex(uint32_t raw)      { return (int32_t)(raw - 72511848u); }
        inline int32_t typeNamespaceIndex(uint32_t raw) { return (int32_t)(raw - 1145778368u); }
        inline int32_t typeMethodStart(uint32_t raw)    { return (int32_t)(raw ^ 0x4D8127F2u); }
        inline int32_t typeFieldStart(uint32_t raw)     { return (int32_t)(raw ^ 0x29010897u); }
        inline int32_t typePropertyStart(uint32_t raw)  { return (int32_t)(raw - 1995389561u); }
        // [V] parentIndex（Il2CppType 索引）：`raw - 0x3D74901F`，-1 = 无父类
        inline int32_t typeParentIndex(uint32_t raw)    { return (int32_t)(raw - 0x3D74901FU); }
        // [V] 泛型容器索引：`(int16)(raw16 - 26230)`；26229 是「无泛型」哨兵（sub_140511DB0）
        inline int32_t typeGenericContainerIndex(uint16_t raw) {
            if (raw == 26229) return -1;
            return (int16_t)(uint16_t)(raw - 26230u);
        }
        // [V] 容器表每索引 key（sub_140511DB0 / sub_14050E030 两处互证）
        inline uint64_t genericContainerKey(uint32_t c) {
            return (1714760523ull * ((1015151837ull * ((10661ull * c + 1371718001ull) ^ 0x146D2C3Dull)) ^ 0x5D7F95E0ull)) >> 19;
        }
        inline uint32_t genericContainerArgc(uint32_t c) {
            const uint8_t* b = s_GlobalMetadataHeader + header.genericContainers + 16ull * c;
            return *(const uint32_t*)(b + 8) - (uint32_t)genericContainerKey(c) - 1053517166u;
        }
        inline uint32_t genericParameterStart(uint32_t c) {
            const uint8_t* b = s_GlobalMetadataHeader + header.genericContainers + 16ull * c;
            return (*(const uint32_t*)(b + 4) ^ 0x138FD4C7u) - (uint32_t)genericContainerKey(c);
        }
        // [V] 泛型参数：nameIndex = (raw@+0 ^ 0x664CCEB9) - key_p
        inline uint64_t genericParameterKey(uint32_t p) {
            return (((1845531077ull * ((12124ull * p + 1969070457ull) ^ 0x423B2C8Dull)) >> 10) + 1212570291ull) ^ 0x62A3A8F4ull;
        }
        inline int32_t genericParameterNameIndex(uint32_t p) {
            const uint8_t* e = s_GlobalMetadataHeader + header.genericParameters + 14ull * p;
            return (int32_t)((*(const uint32_t*)e ^ 0x664CCEB9u) - (uint32_t)genericParameterKey(p));
        }
        inline uint16_t typeMethodCount(uint16_t raw)   { return (uint16_t)(raw - 0xED3A); }
        inline uint16_t typeFieldCount(uint16_t raw)    { return (uint16_t)(raw ^ 0x51A8); }
        inline uint8_t  typePropertyCount(uint8_t raw)  { return (uint8_t)(raw ^ 0x16); }
        inline int16_t  typeEventStart(int16_t raw)     { return (int16_t)(raw + 3330); }
        // [V] flags = +0x28 - 0x4159BB8E。验收：106 个不同值（全在 TYPE_ATTRIBUTE 掩码内）；
        //   BeforeFieldInit 87%、Public 84%、Sealed 50%、NestedPublic 29%、Abstract 8.8%、
        //   Serializable 5.7%、Interface 1.8%、**SpecialName 0%**（该标志本就罕见，用错常量时是 54%）。
        inline uint32_t typeFlags(uint32_t raw) { return raw - 0x4159BB8Eu; }
        // [V] bitfield = +0x3A。验收：valuetype 全量 88884/88884；enum 用 13 枚举 + 11 struct 锚点全对。
        inline uint8_t typeIsValueType(uint8_t raw) { return raw & 1u; }
        inline uint8_t typeIsEnum(uint8_t raw)      { return (uint8_t)((~raw >> 1) & 1u); }
        inline uint16_t typeInterfacesStart(uint16_t raw){ return (uint16_t)(raw ^ 0x43DAu); }
        // ⚠️ 必须按 8 位截断：0xC8 编码 0 -> (uint8_t)(0xC8 + 56) = 0。
        //    返回 uint32 不截断会得到 256 -> 读 256 个接口 -> 越界野指针（实测崩溃）。
        inline uint8_t  typeInterfacesCount(uint8_t raw) { return (uint8_t)(raw + 56u); }  // 0xC8 编码 0
        inline int16_t  typeNestedStart(int16_t raw)     { return (int16_t)(raw + 6631); }
        inline uint32_t typeNestedCount(uint8_t raw)     { return (uint32_t)(raw ^ 0xBAu); }
        inline uint8_t  typeEventCount(uint8_t raw)     { return (uint8_t)(raw + 113u); } // 0x8F 编码 0（同样必须 8 位截断）

        // 方法名：逐索引 key，与 raw 异或后再减去常数
        // 见 sub_140514A70 / sub_140528080（两个独立读取点互证）
        inline int32_t methodNameIndex(uint32_t raw, uint32_t methodIndex)
        {
            uint32_t key = ((860405619u * methodIndex) ^ 0x73758947u) + 1547935323u;
            return (int32_t)(key ^ (raw - 1524016681u));
        }

        // flags / iflags：与方法名同一个逐索引 key（sub_140514630 的循环体）。
        // 验收：flags 的 METHOD_ATTRIBUTE 位分布呈教科书形态
        //       （access=6/1/3 为主，static 29%、virtual 31%、abstract 2.5%、pinvoke 0.3%）；
        //       iflags 只取 0 与 0x1000（IL/Managed 与 InternalCall）。
        inline uint16_t methodFlags(uint16_t raw, uint32_t methodIndex)
        {
            uint32_t key = ((860405619u * methodIndex) ^ 0x73758947u) + 1547935323u;
            return (uint16_t)(key ^ raw ^ 0x8F60u);
        }
        inline uint16_t methodIFlags(uint16_t raw, uint32_t methodIndex)
        {
            uint32_t key = ((860405619u * methodIndex) ^ 0x73758947u) + 1547935323u;
            return (uint16_t)(key ^ (uint32_t)(uint16_t)(raw - 25344u));
        }

        // [V] returnType：methodDefinition +0x08，解码 `(raw ^ key) ^ 0x3F7BDF39`。
        //   key 与方法名同；末尾那个常量是关键（少了它就会得到 0x3F78xxxx 窄带）。
        //   验收：前 50000 个方法索引全部合法（0/越界），type 分布合理
        //   （void 50%、bool、class、I4、string、valuetype、szarray、genericinst…）。
        static constexpr uint32_t kReturnTypeXor = 0x3F7BDF39u;
        // [V] declaringType = key ^ raw ^ 0x59244785（typeDefinition 索引）；
        //   来源 GIMeta_GetMethodInfoFromIndex：拿到后交给 GetTypeInfoByIndex。
        inline int32_t methodDeclaringType(uint32_t raw, uint32_t methodIndex)
        {
            uint32_t key = ((860405619u * methodIndex) ^ 0x73758947u) + 1547935323u;
            return (int32_t)(key ^ raw ^ 0x59244785u);
        }
        inline int32_t methodReturnTypeIndex(uint32_t methodIndex)
        {
            const uint8_t* md = s_GlobalMetadataHeader + header.methodsOffset + 26 * (size_t)methodIndex;
            uint32_t key = ((860405619u * methodIndex) ^ 0x73758947u) + 1547935323u;
            return (int32_t)((*(const uint32_t*)(md + 8)) ^ key ^ kReturnTypeXor);
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
            return *(const uint64_t*)(s_MethodPointerByIndex + 8 * (uint64_t)methodIndex);
        }

        // returnType 不在 26 字节方法结构里，而在并行的 4 字节表（sub_140514630）。
        // 实测：取值 0..527，其中约 12% 为 -1（void）。
        // [V] 参数：count/start 与方法同一个 key，但 count 是**字节**运算。
        //   parameterStart = key ^ (raw@+4 - 257927898)（全局索引，实测累计递增）
        //   parameterCount = ((raw@+0x18 - 31) & 0xFF) ^ (key & 0xFF)   <- 字节 XOR
        inline uint32_t methodParamStart(uint32_t raw_pstart, uint32_t methodIndex)
        {
            uint32_t key = ((860405619u * methodIndex) ^ 0x73758947u) + 1547935323u;
            return key ^ (raw_pstart - 257927898u);
        }
        inline uint8_t methodParamCount(uint8_t raw_pcount, uint32_t methodIndex)
        {
            uint32_t key = ((860405619u * methodIndex) ^ 0x73758947u) + 1547935323u;
            return (uint8_t)(((uint8_t)(raw_pcount - 31u)) ^ ((uint8_t)key));
        }
        // 参数名/类型：逐索引 key（sub_140528560）
        // ⚠️ 必须 64 位不回绕！`41617*paramIndex + 1219887025` 在 paramIndex≈73891 处首次超过 2^32，
        //    用 uint32 回绕会让「索引 ≥ 73891 的参数」名/类型全错（实测合法率 4.81% → 修后 100%）。
        inline uint32_t paramKey(uint32_t paramIndex)
        {
            return (uint32_t)(((1457992407ull * ((41617ull * paramIndex + 1219887025ull) ^ 0x19E1D47Aull)) >> 21) + 2068375556u);
        }
        inline int32_t paramNameIndex(uint32_t raw, uint32_t paramIndex)
        {
            return (int32_t)(paramKey(paramIndex) ^ (raw - 1764493660u) ^ 0x4CDBD093u);
        }
        inline int32_t paramTypeIndex(uint32_t raw, uint32_t paramIndex)
        {
            return (int32_t)(paramKey(paramIndex) ^ raw ^ 0x31BF59F3u);
        }

        // 属性名：逐索引 key（sub_1405151D0）
        inline uint32_t propertyKey(uint32_t propertyIndex)
        {
            return (uint32_t)((((976451930ull * ((0x17A5419F8A28ull * propertyIndex) >> 9)) >> 12)) ^ 0x70BE4B04u);
        }
        inline int32_t propertyNameIndex(uint32_t raw, uint32_t propertyIndex)
        {
            return (int32_t)((raw - 1953953095u) ^ propertyKey(propertyIndex));
        }

        // 字段名：逐索引 key（sub_14051CB80 / sub_140512870）
        // ⚠️ 同 paramKey：必须 64 位不回绕（`34782*fieldIndex` 在 fieldIndex≈123482 处超过 2^32）。
        //    实测 fields[].typeIndex 合法率：32 位 123483/440172 → 64 位 440172/440172。
        inline uint32_t fieldKey(uint32_t fieldIndex)
        {
            return (uint32_t)(((1824013172ull * ((34782ull * fieldIndex) ^ 0x59B1DB19ull)) >> 16) + 1410079245u);
        }
        inline int32_t fieldNameIndex(uint32_t raw, uint32_t fieldIndex)
        {
            return (int32_t)((raw - 1475293452u) ^ fieldKey(fieldIndex) ^ 0x2D027B84u);
        }

        // 事件名：逐索引 key（sub_140514CF0）
        inline uint32_t eventKey(uint32_t eventIndex)
        {
            return (uint32_t)(((-1599256506 * (int32_t)eventIndex + 1725894951) ^ 0x1B23E40F));
        }
        inline int32_t eventNameIndex(uint32_t raw, uint32_t eventIndex)
        {
            return (int32_t)(eventKey(eventIndex) ^ (raw - 1037298109u));
        }

        const Il2CppType* GetIl2CppTypeFromIndex(int32_t index) {
            if (index == -1) return nullptr;
            // ⚠️ *(T1+0x48) 是**镜像里的 VA**，必须先 va_to_offset 转成宿主指针再解引用。
            //    直接用 VA 会得到野地址 -> SIGSEGV（实测）。
            const Il2CppType* types = (const Il2CppType*)il2cpp::s_Il2CppTypes;
            if (!types) return nullptr;
            // 合法域保护：Il2CppType 数组共 683574 项（T1+0x54 ^ 0x6622B34E，已验收）。
            // 个别字段解码出越界索引时，直接返回 nullptr，避免野指针。
            if (index < 0 || index >= 683574) return nullptr;

            return types + index;
        }

        const Il2CppType* GetInterfaceFromIndex(int32_t index) {
            if (index == -1) return nullptr;
            // [V] 接口表 = MHY[0x1C4] - 1518027399，步长 6；每项 +0 是 Il2CppType 索引
            const uint8_t* interfaceIndices = (const uint8_t*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.interfacesTable);
            return GetIl2CppTypeFromIndex(*(const int32_t*)(interfaceIndices + 6LL * index));
        }

        const Il2CppFieldDefinition* GetFieldDefinitionFromIndex(int32_t index)
        {
            const Il2CppFieldDefinition* fields = (const Il2CppFieldDefinition*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.fieldsOffset);
            return fields + index;
        }

        const il2cpp::Il2CppTypeDefinition* GetTypeDefinitionFromIndex(int32_t index)
        {
            const il2cpp::Il2CppTypeDefinition* typeDefinitions = (const il2cpp::Il2CppTypeDefinition*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset);
            return typeDefinitions + index;
        }

        const Il2CppGenericContainer* GetGenericContainerFromIndex(int32_t genericContainerIndex)
        {
            // [V] 槽位已换版本：6.7 用 0x114，本版本 genericContainers 在 0x28（= header.genericContainers）
            auto base = (const Il2CppGenericContainer*)(s_GlobalMetadataHeader + il2cpp::header.genericContainers);
            return (genericContainerIndex == 0xFFFF) ? nullptr : base + genericContainerIndex;
        }

        const Il2CppGenericParameter* GetGenericParameter(uint32_t genericParameterStart, uint16_t index) {
            // [V] 槽位已换版本：6.7 用 364，本版本 genericParameters 在 0x170（= header.genericParameters）
            return (const Il2CppGenericParameter*)(s_GlobalMetadataHeader + il2cpp::header.genericParameters) + (genericParameterStart + index);
        }

        std::string NameFromIl2CppType(const Il2CppType* type) 
        {
            if (!type) return "";

            auto cached = typeNameCache.find(type);
            if (cached != typeNameCache.end()) return cached->second;

            std::string result;

            switch (type->type) 
            {
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VOID:       result = "void"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN:    result = "bool"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:       result = "char"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I1:         result = "sbyte"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U1:         result = "byte"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I2:         result = "short"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U2:         result = "ushort"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I4:         result = "int"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U4:         result = "uint"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I8:         result = "long"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U8:         result = "ulong"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_R4:         result = "float"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_R8:         result = "double"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_STRING:     result = "string"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:     result = "object"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I:          result = "IntPtr"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U:          result = "UIntPtr"; break;
            case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_TYPEDBYREF: result = "TypedReference"; break;
            }

            if (!result.empty()) return typeNameCache.emplace(type, std::move(result)).first->second;

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE)
            {
                if (type->data.klassIndex < 0 || type->data.klassIndex >= 88902) return "";  // 非法 klassIndex 保护
                const il2cpp::Il2CppTypeDefinition* typeDefinitions = GetTypeDefinitionFromIndex(type->data.klassIndex);
                std::string name{ il2cpp::utils::GetStringFromIndex(il2cpp::utils::typeNameIndex((uint32_t)typeDefinitions->nameIndex)) };
                if (size_t p = name.find('`'); p != std::string::npos) name.resize(p);
;
                std::string ns{ GetStringFromIndex(il2cpp::utils::typeNamespaceIndex((uint32_t)typeDefinitions->namespaceIndex)) };
                // declaringTypeIndex 未定位 -> 不输出 declaring 前缀
                std::string declaring;

                result = declaring.empty() ? (ns.empty() ? "" : ns + ".") + name : declaring + name;
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST) {
                
                // [V] 泛型实参：metadata 侧表（init:1447-1465 那条链，已验收）
                //   range[gi] = {argStart@+0, argc@+4}（startup，8 字节）
                //   实参 = typeIndex[startup + 4*(argStart+k)]（4 字节，-1 哨兵）
                //   经 GetIl2CppTypeFromIndex 取 Il2CppType。
                //   ⚠️ 泛型**类型定义**名仍缺：type->data.generic_class 实测范围 0..406568，
                //      大于 range 表项数(13671)，故不是它的索引；索引语义未定。
                uint64_t genericIndex = (uint64_t)type->data.generic_class;
                std::string gname;   // 类型定义名未定位
                std::string gargs;
                if (genericIndex < il2cpp::header.genericClassRangeCount)
                {
                    const uint8_t* rng = il2cpp::s_StartupMetadataHeader
                                       + il2cpp::header.genericClassRangeOffset + 8 * genericIndex;
                    uint32_t argStart = *(const uint32_t*)rng;
                    uint32_t argCount = *(const uint32_t*)(rng + 4);
                    if (argCount > 64) argCount = 64;   // 防越界
                    for (uint32_t k = 0; k < argCount; k++)
                    {
                        int32_t ti = *(const int32_t*)(il2cpp::s_StartupMetadataHeader
                                     + il2cpp::header.genericTypeArgOffset + 4 * (argStart + k));
                        if (ti == -1) continue;
                        const il2cpp::Il2CppType* at = il2cpp::utils::GetIl2CppTypeFromIndex(ti);
                        if (!at) continue;
                        if (!gargs.empty()) gargs += ", ";
                        gargs += NameFromIl2CppType(at);
                    }
                }
                // 泛型类型定义名 gname 未定位 -> 用占位 `?` 保留参数列表（不假称类型名）
                std::string fullName = gname.empty() ? std::string("?") : gname;
                result = gargs.empty() ? fullName : fullName + "<" + gargs + ">";
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_PTR || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BYREF || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY)
            {
                // ⚠️ 基址必须用运行时的 s_Il2CppTypes（= *(T1+0x48) = 0x142E1EA20）。
                //    此前的硬编码 0x1429FB1E0 是**旧版本**的 Il2CppType 数组地址，
                //    用它算出的索引全错 -> 野指针（实测 400 项里只有 64 个 type 字节合法）。
                uint64_t index = ((uint64_t)(uintptr_t)type->data.type - il2cpp::s_Il2CppTypesVA) / 16;
                const Il2CppType* elementType = GetIl2CppTypeFromIndex((int32_t)index);
                std::string rcx = NameFromIl2CppType(elementType);

                if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_PTR)     result = rcx + "*";
                if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BYREF)   result = rcx + "&";
                if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY) result = rcx + "[]";
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_ARRAY)
            {
                // 同上：data.array 是镜像 VA，直接 va_to_offset 得到宿主指针。
                auto* a = (Il2CppArrayType*)(exe.data() + pe->va_to_offset((uint64_t)type->data.array));
                if (!a) return typeNameCache.emplace(type, std::string{}).first->second;
                std::string e = NameFromIl2CppType(GetIl2CppTypeFromIndex((int32_t)(((uint64_t)(uintptr_t)a->etype - il2cpp::s_Il2CppTypesVA) / 16)));
                if (e.empty()) result = std::string("?");
                result = e + (a->rank == 1 ? "[*]" : "[" + std::string(a->rank - 1, ',') + "]");
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VAR || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_MVAR)
            {
                // ⚠️ 必须用**本版本**的泛型参数名公式。旧版（6.7）的
                //    `(nameIndex ^ 0x2DD1C9C6) - ((0x65DE21D74280*p) ^ 0x154AA920) + 1912316114`
                //    在本版本会解出**乱码**（实测 2787 个方法签名被污染）。
                uint32_t gp = (uint32_t)type->data.genericParameterIndex;
                result = GetStringFromIndex(genericParameterNameIndex(gp));
                return typeNameCache.emplace(type, std::move(result)).first->second;
            }

            return typeNameCache.emplace(type, std::string{}).first->second;
        }

        const Il2CppFieldDefaultValue* GetDefaultValueForField(int32_t index)
        {
            const Il2CppFieldDefaultValue* start = (const il2cpp::Il2CppFieldDefaultValue*)(s_GlobalMetadataHeader + il2cpp::header.fieldDefaultValuesOffset);
            // 表按 fieldIndex **严格递增**（已验收 155..440164）-> 二分（原为线性，O(4.4e5 x 7.5e4)）。
            int32_t lo = 0, hi = (int32_t)il2cpp::header.fieldDefaultValuesCount - 1;
            while (lo <= hi)
            {
                int32_t mid = lo + ((hi - lo) >> 1);
                int32_t v = start[mid].fieldIndex;
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
            const Il2CppMethodDefinition* methods = (const Il2CppMethodDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.methodsOffset);
            return methods + index;
        }

        const Il2CppParameterDefinition* GetParameterDefinitionFromIndex(uint32_t index)
        {
            const Il2CppParameterDefinition* parameters = (const Il2CppParameterDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.parametersOffset);
            return parameters + index;
        }

        const Il2CppParameterDefaultValue* GetParamDefault(uint32_t parameterIndex) {
            const Il2CppParameterDefaultValue* start = (const Il2CppParameterDefaultValue*)(s_GlobalMetadataHeader + il2cpp::header.parameterDefaultValuesOffset);
            const int32_t count = (int32_t)(il2cpp::header.parameterDefaultValuesCount / sizeof(Il2CppParameterDefaultValue));
            // 表按 parameterIndex **严格递增**（已验收 4868..548362）-> 二分。
            // 原实现是线性扫描：25374 项 x 548400 个参数 = O(1.4e10)，会非常慢。
            int32_t lo = 0, hi = count - 1;
            while (lo <= hi)
            {
                int32_t mid = lo + ((hi - lo) >> 1);
                int32_t v = (int32_t)start[mid].parameterIndex;
                if (v == (int32_t)parameterIndex) return start + mid;
                if (v < (int32_t)parameterIndex) lo = mid + 1; else hi = mid - 1;
            }
            return nullptr;
        }

        std::string GetDefaultValueData(int32_t typeIndex, int32_t dataIndex) {
            if (dataIndex == -1) return "null";
            const auto* t = il2cpp::utils::GetIl2CppTypeFromIndex(typeIndex);
            if (!t) return "";
            uint8_t* blob = il2cpp::s_GlobalMetadataHeader + dataIndex + il2cpp::header.fieldAndParameterDefaultValueDataOffset;
            return il2cpp::utils::GetConstantValueFromBlob(t->type, blob);
        }

        const Il2CppPropertyDefinition* GetPropertyDefinitionFromIndex(int32_t index)
        {
            const Il2CppPropertyDefinition* properties = (const Il2CppPropertyDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.propertiesOffset);
            return properties + index;
        }

        const Il2CppEventDefinition* GetEventDefinitionFromIndex(int32_t index)
        {
            const Il2CppEventDefinition* events = (const Il2CppEventDefinition*)((const char*)s_GlobalMetadataHeader + il2cpp::header.eventsOffset);
            return events + index;
        }

        // 旧接口保留，内部改走本版本的 (offset, length) 解密。
        // 注意：本版本没有独立的字面量条目表，offset/length 打包在 nameIndex 里，
        // 因此调用方必须自己先 SplitStringEntry 拿到 offset，不能像旧版那样传索引。
        std::string decryptString(uint32_t offset, uint32_t len) {
            return utils::DecryptStringAt(offset, len);
        }

        
    }

}
namespace {
    struct MethodEntry { std::string name, ret, attrs, valueType; uint64_t ptr; uint16_t flags, iflags; };
    std::vector<MethodEntry> methods;
    const MethodEntry emptyMethod{};   // 越界时的占位（属性/事件的 getter/setter 索引偶尔解出异常值）

    std::unordered_map<uint32_t, std::string> attrMap;
    std::string getcustomattr(int32_t token, bool block = false)
    {
        auto it = attrMap.find(token);
        if (it == attrMap.end() || it->second.empty()) return "";
        if (!block) return it->second;
        std::string r = "\t" + it->second;
        for (size_t p = 0; (p = r.find('\n', p)) != std::string::npos && p + 1 < r.size(); )
            r.insert(p + 1, "\t"), p += 2;
        return r;
    }

    std::vector<uint8_t> readFile(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);
        if (!f)
        {
            std::cerr << "error: cannot open file: " << path << std::endl;
            std::exit(1);
        }
        f.seekg(0, std::ios::end);
        std::streamoff end = f.tellg();
        if (end < 0)
        {
            std::cerr << "error: cannot determine size of: " << path << std::endl;
            std::exit(1);
        }
        f.seekg(0);
        std::vector<uint8_t> buf((size_t)end);
        f.read((char*)buf.data(), (std::streamsize)buf.size());
        return buf;
    }
}

void imageDef()
{
    uint32_t s_ImagesCount = il2cpp::header.imagesCount / sizeof(il2cpp::Il2CppImageDefinition);
    const il2cpp::Il2CppImageDefinition* imagesDefinitions = (const il2cpp::Il2CppImageDefinition*)(il2cpp::s_StartupMetadataHeader + il2cpp::header.imagesOffset);
    for (uint32_t imageIndex = 0; imageIndex < s_ImagesCount; imageIndex++)
    {
        const il2cpp::Il2CppImageDefinition* imageDefinition = imagesDefinitions + imageIndex;
        // 本版本的逐索引 key（解密用；已验证 75/75）
        uint32_t key = il2cpp::utils::ImageIndexKey(imageIndex);

        // typeStart 的混淆公式仍是旧版本的常量，未重新定位 —— 保持原样不动
        uint32_t typeStart = (imageDefinition->typeStart ^ 0x5AF8F775) - key - 0x605F970E - 290428500;

        // nameIndex 属于解密部分：本版本改为 offset(24)+length(8) 打包格式
        uint32_t nameIndex = il2cpp::utils::DecodeStringEntry((uint32_t)imageDefinition->nameIndex, key);

        std::string name{il2cpp::utils::GetStringFromIndex(nameIndex)};

        out << "// Image " << imageIndex << ": " << name << " - " << typeStart << std::endl;
    }
    out << std::endl;
}

struct FieldInfo
{
    int32_t index;
    std::string name;
    const il2cpp::Il2CppType* type;
    std::string typeName;
    uint32_t offset;
};

std::vector<FieldInfo> collectFields(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    std::vector<FieldInfo> out;

    // [V] fieldStart +0x1C ^ 0x29010897 ; field_count +0x38 ^ 0x51A8
    //     fields 数组 MHY[0x18C] - 336578260，步长 8，nameIndex @ +4
    //     字段偏移 MHY[0x204] - 450622139，步长 4
    int32_t трушный_старт = il2cpp::utils::typeFieldStart((uint32_t)typeDefinition->fieldStart);
    int32_t count = il2cpp::utils::typeFieldCount((uint16_t)typeDefinition->field_count);
    if (count <= 0 || count > 4096) return out;
    int32_t end = трушный_старт + count;

    for (int32_t j = 0; j < count; ++j)
    {
        uint32_t fieldIndex = (uint32_t)(трушный_старт + j);
        const il2cpp::Il2CppFieldDefinition* fieldDefinition = il2cpp::utils::GetFieldDefinitionFromIndex((int32_t)fieldIndex);

        // 字段偏移表：低 29 位是偏移，高 3 位是静态标志
        uint32_t v35 = *(uint32_t*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.fieldOffset + 4 * (fieldIndex - (uint32_t)трушный_старт));

        std::string name{ il2cpp::utils::GetStringFromIndex(
            il2cpp::utils::fieldNameIndex((uint32_t)fieldDefinition->nameIndex, fieldIndex)) };

        // typeIndex 在字段条目 +0，与 nameIndex 同一个 key（sub_140512870）
        int32_t typeIndexDec = (int32_t)(il2cpp::utils::fieldKey(fieldIndex)
            ^ (uint32_t)fieldDefinition->typeIndex ^ 0x2D27D873u);
        if (typeIndexDec == -1) continue;
        const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeIndexDec);
        if (!type) continue;

        std::string typeName{ il2cpp::utils::NameFromIl2CppType(type) };

        // 低 29 位 = 实例内偏移；0xC0000000 标记 static
        uint32_t offset = (v35 & 0x1FFFFFFF);
        bool isStatic = (v35 & 0xE0000000u) == 0xC0000000u;

        out.push_back({ fieldIndex, std::move(name), type, std::move(typeName), offset });
    }

    return out;

#if 0
    // ===== 上一版（本样本之前）的实现，原样保留，等 fieldTableOffset / fieldIndexTableOffset
    // 在本版本验证后放开。它走的是 typeIndex -> fieldTableOffset/fieldIndexTableOffset 的
    // 两级间接，而上面那条路径是直接用 typeDefinition 的 fieldStart + 字段偏移表。 =====
    int32_t start = typeFieldStart((uint32_t)typeDefinition->fieldStart);
    int32_t tr_start = start - 0x2318D1B4;
    int32_t count_old = typeFieldCount((uint16_t)typeDefinition->field_count);
    if (count_old == 0) return out;

    int32_t end_old = tr_start + count_old;

    const uint8_t* typeDefinitions = il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset;
    uint32_t typeIndex = (uint32_t)(-1963413621 * (((uint64_t)((const uint8_t*)typeDefinition - typeDefinitions)) >> 1));
    uint64_t v42 = (uint64_t)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.fieldTableOffset + 12LL * *(uint32_t*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.fieldIndexTableOffset + 4LL * typeIndex));

    for (int32_t fieldIndex = tr_start; fieldIndex < end_old; ++fieldIndex)
    {
        const il2cpp::Il2CppFieldDefinition* fieldDefinition = il2cpp::utils::GetFieldDefinitionFromIndex(fieldIndex);
        uint32_t v35 = *(uint32_t*)(il2cpp::s_GlobalMetadataHeader + (*(uint32_t*)(il2cpp::s_MHYTable + 372) ^ 0x369C42D5u) + 4 * ((fieldIndex - tr_start) + (*(uint32_t*)(v42 + 8))));
        uint32_t key = (uint32_t)((((uint64_t)0xA3D685EE8C0ULL * fieldIndex >> 13) + 0x6C43549A) ^ 0x7B227EB7);

        std::string name{ il2cpp::utils::GetStringFromIndex((fieldDefinition->nameIndex ^ 0x2C9F4153u) - key) };

        if (((uint32_t)fieldDefinition->typeIndex - key) == 0x5422128A) continue;
        const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(fieldDefinition->typeIndex - key - 0x5422128B);
        if (!type) continue;

        std::string typeName{ il2cpp::utils::NameFromIl2CppType(type) };

        uint32_t offset = (v35 & 0x01000000) ? (v35 & 0xFFFFFF) : v35;

        // Il2CppObject
        bool isValueType = il2cpp::utils::typeIsValueType(typeDefinition->bitfield) != 0;
        if (isValueType && offset > 0x0 && !(type->attrs & (FIELD_ATTRIBUTE_STATIC | FIELD_ATTRIBUTE_LITERAL))) offset -= 0x10;

        out.push_back({ fieldIndex, std::move(name), type, std::move(typeName), offset });
    }
#endif
}

std::string fieldDef(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    auto fields = collectFields(typeDefinition);
    if (fields.empty()) return "";

    std::string full{};
    for (const auto& field : fields)
    {
        std::string flags{};
        switch (field.type->attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK)
        {
        case FIELD_ATTRIBUTE_PUBLIC:        flags += "public "; break;
        case FIELD_ATTRIBUTE_PRIVATE:       flags += "private "; break;
        case FIELD_ATTRIBUTE_FAMILY:        flags += "protected "; break;
        case FIELD_ATTRIBUTE_ASSEMBLY:      flags += "internal "; break;
        case FIELD_ATTRIBUTE_FAM_OR_ASSEM:  flags += "protected internal "; break;
        case FIELD_ATTRIBUTE_FAM_AND_ASSEM: flags += "private protected "; break;
        }
        if (field.type->attrs & FIELD_ATTRIBUTE_NOT_SERIALIZED) full += "\t[NonSerialized]\n";
        if (field.type->attrs & FIELD_ATTRIBUTE_LITERAL) flags += "const ";
        else
        {
            if (field.type->attrs & FIELD_ATTRIBUTE_STATIC) flags += "static ";
            if (field.type->attrs & FIELD_ATTRIBUTE_INIT_ONLY) flags += "readonly ";
        }

        std::string constValue{};
        const il2cpp::Il2CppFieldDefaultValue* entry = il2cpp::utils::GetDefaultValueForField(field.index);
        if (entry != NULL && entry->dataIndex != -1)
        {
            auto* consttype = il2cpp::utils::GetIl2CppTypeFromIndex(entry->typeIndex);
            uint8_t* defaultValuesData = (uint8_t*)((const char*)il2cpp::s_GlobalMetadataHeader + entry->dataIndex + il2cpp::header.fieldAndParameterDefaultValueDataOffset);
            il2cpp::Il2CppTypeEnum code = consttype ? consttype->type : il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_END;
            constValue = il2cpp::utils::GetConstantValueFromBlob(code, defaultValuesData);
        }

        full += getcustomattr(0x04000000 | field.index, true) + "\t" + flags + field.typeName + " " + field.name + (constValue.empty() ? "" : " = " + constValue) + "; // 0x" + std::format("{:X}", field.offset) + "\n";
    }

    return "\t// Fields\n" + full + "\n";
}


std::string methodDef(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    static bool genericIndexBuilt = false;
    static std::unordered_map<int32_t, std::vector<uint32_t>> genericEntriesByMethod;

    std::string full{};
    // 已验证：methodStart ^ 0x4D8127F2，method_count - 0xED3A
    int32_t start = il2cpp::utils::typeMethodStart((uint32_t)typeDefinition->methodStart);
    int32_t count = (int32_t)((uint16_t)((uint16_t)typeDefinition->method_count - 0xED3A));
    if (start < 0) start = 0;
    if (count <= 0 || count > (int32_t)il2cpp::header.methodsCount) return "";

    int32_t end = start + count;

    for (int32_t index = start; index < end; ++index)
    {
        const il2cpp::Il2CppMethodDefinition* methodDefinition = il2cpp::utils::GetMethodDefinitionFromIndex(index);

        // 已验证：methodDefinition.nameIndex 在 +0x00，逐索引 key 后解包 entry
        std::string name{il2cpp::utils::GetStringFromIndex(
            il2cpp::utils::methodNameIndex((uint32_t)methodDefinition->nameIndex, (uint32_t)index))};

        // [V] flags / iflags（先算，方法指针要用到 VIRTUAL 位）
        uint16_t flags  = il2cpp::utils::methodFlags((uint16_t)methodDefinition->flags, (uint32_t)index);
        uint16_t iflags = il2cpp::utils::methodIFlags((uint16_t)methodDefinition->iflags, (uint32_t)index);

        // [V] 方法地址双路径（文章：虚/重写取 +0x90[slot]，其余取 +0x80[index]）：
        //   非虚     = *(T0+0x60)[ MHY[0x94][methodIndex] ]
        //   虚/重写  = *(T0+0x48)[ MHY[0x140] 里查到的 slot ]
        uint64_t mptr = il2cpp::utils::methodPointer((uint32_t)index);
        if ((flags & METHOD_ATTRIBUTE_VIRTUAL) && !(flags & METHOD_ATTRIBUTE_ABSTRACT))
        {
            uint64_t inv = il2cpp::utils::methodInvoker((uint32_t)index);
            if (inv) mptr = inv;
        }
        std::string vaInfo;
        if (mptr)
        {
            uint64_t off = pe->va_to_offset(mptr);
            vaInfo = std::format("// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}\n",
                                 mptr - pe->optional_header().imagebase(), off, mptr);
        }
        // [V] returnType
        std::string retType;
        {
            int32_t rti = il2cpp::utils::methodReturnTypeIndex((uint32_t)index);
            if (rti >= 0 && rti < 683574)
            {
                const il2cpp::Il2CppType* rt = il2cpp::utils::GetIl2CppTypeFromIndex(rti);
                if (rt) { retType = il2cpp::utils::NameFromIl2CppType(rt); if (!retType.empty()) retType += " "; }
            }
        }

        std::string attrs;
        switch (flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) {
        case METHOD_ATTRIBUTE_PUBLIC:        attrs += "public "; break;
        case METHOD_ATTRIBUTE_PRIVATE:       attrs += "private "; break;
        case METHOD_ATTRIBUTE_FAMILY:        attrs += "protected "; break;
        case METHOD_ATTRIBUTE_ASSEM:         attrs += "internal "; break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:  attrs += "protected internal "; break;
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM: attrs += "private protected "; break;
        }
        if (flags & METHOD_ATTRIBUTE_STATIC)   attrs += "static ";
        if (flags & METHOD_ATTRIBUTE_ABSTRACT) attrs += "abstract ";
        else if (flags & METHOD_ATTRIBUTE_VIRTUAL) attrs += "virtual ";
        if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) attrs += "extern ";

        // 泛型方法实例（已接，见下）；旧版整段保留在 #if 0。
        // [V] 参数列表
        std::string params;
        std::string lastParamType;   // 最后一个参数的类型（属性 setter / 事件用）
        {
            uint32_t c = il2cpp::utils::methodParamCount(methodDefinition->parameterCount, (uint32_t)index);
            if (c > 32) c = 32;
            uint32_t ps = il2cpp::utils::methodParamStart((uint32_t)methodDefinition->parameterStart, (uint32_t)index);
            const uint8_t* pbase = il2cpp::s_GlobalMetadataHeader + il2cpp::header.parametersOffset;
            for (uint32_t k = 0; k < c; k++)
            {
                uint32_t pi = ps + k;
                int32_t pni = il2cpp::utils::paramNameIndex(*(const uint32_t*)(pbase + 8 * pi + 4), pi);
                std::string pn{ il2cpp::utils::GetStringFromIndex(pni) };
                int32_t pti = il2cpp::utils::paramTypeIndex(*(const uint32_t*)(pbase + 8 * pi), pi);
                std::string pt;
                if (pti != -1) { const il2cpp::Il2CppType* t = il2cpp::utils::GetIl2CppTypeFromIndex(pti); if (t) pt = il2cpp::utils::NameFromIl2CppType(t); }
                if (k) params += ", ";
                params += pt + " " + pn;
                lastParamType = pt;
                // 参数默认值：表已定位并验证（25374 项）。原文这行在旧版的 #if 0 里，漏接了。
                if (auto* dv = il2cpp::utils::GetParamDefault(pi))
                {
                    std::string cv = il2cpp::utils::GetDefaultValueData(dv->typeIndex, dv->dataIndex);
                    if (!cv.empty()) params += " = " + cv;
                }
            }
        }
        // [V] 泛型方法实例（数据链已独立验证：classIndexIndex/methodIndexIndex 索引 genericInsts 20319/0）
        {
            static bool gBuilt = false;
            static std::unordered_map<int32_t, std::vector<uint32_t>> gByMethod;
            const auto* specs = (const il2cpp::Il2CppMethodSpec*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.methodSpecs);
            const auto* gInsts = (const il2cpp::Il2CppGenericInst*)il2cpp::s_GenericInsts;
            const auto* gmTab = (const il2cpp::Il2CppGenericMethodFunctionsDefinitions*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.genericMethodTable);
            const uint64_t* gmPtrs = (const uint64_t*)il2cpp::s_MethodPointerArray;
            if (!gBuilt)
            {
                for (uint32_t t = 0; t < il2cpp::header.genericMethodTableCount; ++t)
                {
                    const auto& e = gmTab[t];
                    if (e.genericMethodIndex < 0 || (uint32_t)e.genericMethodIndex >= il2cpp::header.methodSpecsCount) continue;
                    if (e.indices.methodIndex < 0) continue;
                    gByMethod[specs[e.genericMethodIndex].methodDefinitionIndex].push_back(t);
                }
                gBuilt = true;
            }
            auto instName = [&](const il2cpp::Il2CppGenericInst* inst) -> std::string
            {
                if (!inst || inst->type_argc == 0 || inst->type_argc > 64) return "";
                const uint64_t* argv = (const uint64_t*)(exe.data() + pe->va_to_offset((uint64_t)inst->type_argv));
                std::string r = "<";
                for (uint32_t k = 0; k < inst->type_argc; ++k)
                {
                    if (k) r += ", ";
                    uint64_t o = pe->va_to_offset(argv[k]);
                    if (o < exe.size()) r += il2cpp::utils::NameFromIl2CppType((const il2cpp::Il2CppType*)(exe.data() + o));
                }
                return r + ">";
            };
            auto it = gByMethod.find(index);
            if (it != gByMethod.end())
            {
                std::string ownerName{ il2cpp::utils::GetStringFromIndex(il2cpp::utils::typeNameIndex((uint32_t)typeDefinition->nameIndex)) };
                if (size_t q = ownerName.find('`'); q != std::string::npos) ownerName.resize(q);
                std::string instances;
                for (uint32_t t : it->second)
                {
                    const auto& e = gmTab[t];
                    const auto& sp = specs[e.genericMethodIndex];
                    const auto* ci = sp.classIndexIndex == -1 ? nullptr : gInsts + sp.classIndexIndex;
                    const auto* mi = sp.methodIndexIndex == -1 ? nullptr : gInsts + sp.methodIndexIndex;
                    uint64_t va = gmPtrs[e.indices.methodIndex];
                    if (va) instances += std::format("\n\t|-RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}", va - pe->optional_header().imagebase(), pe->va_to_offset(va), va);
                    instances += "\n\t|-" + ownerName + instName(ci) + "." + name + instName(mi) + "\n\t|";
                }
                if (!instances.empty()) full += "\t/* GenericInstMethod :" + instances + "\n\t*/\n";
            }
        }
        // [V] declaringType 一致性诊断：methodDefinition+0x0C 解出的声明类型应等于当前类型索引。
        //   不一致说明该方法在元数据里被挂到了别的类型下（正常不应发生）-> 输出标注。
        int32_t declType = il2cpp::utils::methodDeclaringType(
            (uint32_t)methodDefinition->declaringType, (uint32_t)index);
        std::string declNote;
        const int32_t selfTypeIdx = (int32_t)(((const uint8_t*)typeDefinition
                                  - (il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset)) / 70);
        if (declType != selfTypeIdx) declNote = std::format("/* declaringType={} */ ", declType);

        // ⚠️ 这条赋值原本在下面的 #if 0 里（旧版遗留），而活动路径在它之前就 continue 了
        //    -> methods 向量**永远是空的** -> 属性的 getter/setter 名、事件 add/remove/raise 名全丢。
        {
            if (methods.size() <= (size_t)index) methods.resize((size_t)index + 1);
            std::string retTrim = retType;
            while (!retTrim.empty() && retTrim.back() == ' ') retTrim.pop_back();
            methods[index] = { name, retTrim, attrs, lastParamType, mptr, flags, iflags };
        }
        full += vaInfo + "\t" + attrs + declNote + retType + name + "(" + params + ")\n";
        continue;
#if 0
        uint32_t key = (((-486614588 * index + 535893754) ^ 0x324D0DED) + 311442397);
        const il2cpp::Il2CppType* returnType = il2cpp::utils::GetIl2CppTypeFromIndex((methodDefinition->returnType - 978518114) ^ key);
        if (!returnType) continue;
        std::string typeName {il2cpp::utils::NameFromIl2CppType(returnType)};

        uint16_t flags = key ^ (methodDefinition->flags + 0x3581);
        uint16_t iflags = key ^ (methodDefinition->iflags ^ 0xDECB);

        std::string attrs;
        switch (flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) {
        case METHOD_ATTRIBUTE_PUBLIC:        attrs += "public "; break;
        case METHOD_ATTRIBUTE_PRIVATE:       attrs += "private "; break;
        case METHOD_ATTRIBUTE_FAMILY:        attrs += "protected "; break;
        case METHOD_ATTRIBUTE_ASSEM:         attrs += "internal "; break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:  attrs += "protected internal "; break;
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM: attrs += "private protected "; break;
        }
        if (flags & METHOD_ATTRIBUTE_STATIC) attrs += "static ";
        if (flags & METHOD_ATTRIBUTE_ABSTRACT) attrs += "abstract ";
        else if (flags & METHOD_ATTRIBUTE_VIRTUAL)
        if (!(flags & METHOD_ATTRIBUTE_FINAL) && (flags & METHOD_ATTRIBUTE_NEW_SLOT)) attrs += (flags & METHOD_ATTRIBUTE_NEW_SLOT) ? "virtual " : "override ";
        if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) attrs += "extern ";

       
        int32_t v23 = index;
        uint64_t methodPointer = 0;
        uint64_t v30 = 0;

        if (((typeDefinition->bitfield << 6) & 0x40) != 0)
        {
            uint8_t* v27 = il2cpp::s_GlobalMetadataHeader + (*(uint32_t*)(il2cpp::s_MHYTable + 126 * 4) - 2095267037u);
            uint8_t* v28 = v27;
            if ((*(uint32_t*)(il2cpp::s_MHYTable + 66 * 4) ^ 0x3D054A4Cu) >= 6)
            {
                uint64_t v36 = (*(uint32_t*)(il2cpp::s_MHYTable + 66 * 4) ^ 0x3D054A4CuLL) / 6;
                v28 = v27;
                uint64_t v37 = v36;
                do
                {
                    v37 = (uint64_t)v37 >> 1;
                    uint64_t v38 = 3 * v37;
                    if (v23 > *(int32_t*)(v28 + 6 * v37))
                    {
                        v37 = v36 + ~v37;
                        v28 = v28 + 2 * v38 + 6;
                    }
                    v36 = v37;
                } while (v37 > 0);
            }
            uint8_t* v29 = v27 + 6 * ((*(uint32_t*)(il2cpp::s_MHYTable + 66 * 4) ^ 0x3D054A4CuLL) / 6);
            if (v28 != v29 && v23 >= *(int32_t*)v28)
            {
                v30 = *(uint64_t*)(*(uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 144) + 8ULL * *(uint16_t*)(v28 + 4));
                if (v30)
                    goto LABEL_25;
            }
        }
        v30 = *(uint64_t*)(*(uint64_t*)(il2cpp::s_Il2CppCodeRegistration + 0x80) + 8ULL * (uint32_t)v23);
LABEL_25:
        methodPointer = v30;

        if (!methodPointer) full += "\n\t// RVA: -1 Offset: -1 VA: -1\n";
        else {
            uint64_t rva = methodPointer - pe->optional_header().imagebase();
            uint64_t off = pe->va_to_offset(methodPointer);
            full += std::format("\n\t// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}\n", rva, off, methodPointer);
        }

        uint8_t v9 = (uint8_t)(((0xC4 * index - 6) ^ 0xED) - 0x23);
        uint8_t parameter_count = v9 ^ methodDefinition->parameterCount ^ 0xE1;
        int32_t paramStartDec = (key ^ methodDefinition->parameterStart ^ 0x5A970208);

        std::string params;
        std::string lastParamType;
        for (uint16_t paramIndex = 0; paramIndex < parameter_count; ++paramIndex)
        {
            const il2cpp::Il2CppParameterDefinition* parameterDefinition = il2cpp::utils::GetParameterDefinitionFromIndex(paramStartDec + paramIndex);
            uint32_t parameter_key = (uint32_t)((-2072089200LL * (paramStartDec + paramIndex) - 1328203725) ^ 0xACC85C96);

            std::string parameter_name{ il2cpp::utils::GetStringFromIndex(parameterDefinition->nameIndex + parameter_key - 0x5D4A021B) };

            const il2cpp::Il2CppType* parameter_type = nullptr;
            if (parameter_key + (uint32_t)(parameterDefinition->typeIndex ^ 0x326A9F52) != 1109209749)
                parameter_type = il2cpp::utils::GetIl2CppTypeFromIndex((parameter_key + (parameterDefinition->typeIndex ^ 0x326A9F52) - 1109209750));
            uint16_t paramAttrs = parameter_type ? parameter_type->attrs : 0;

            if (!params.empty()) params += ", ";
            
            if (parameter_type && parameter_type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BYREF) {
                if (paramAttrs & PARAM_ATTRIBUTE_IN) params += "in ";
                else if (paramAttrs & PARAM_ATTRIBUTE_OUT) params += "out ";
                else params += "ref ";
            } else {
                if (paramAttrs & PARAM_ATTRIBUTE_IN) params += "in ";
                if (paramAttrs & PARAM_ATTRIBUTE_OUT) params += "out ";
            }
            
            params += [](auto s) { return s.back() == '\n' ? s.back() = ' ', s : s; }(getcustomattr(0x08000000 | (paramStartDec + paramIndex))) + il2cpp::utils::NameFromIl2CppType(parameter_type) + " " + parameter_name;
            lastParamType = il2cpp::utils::NameFromIl2CppType(parameter_type);

            std::string constValue;
            if (auto* data = il2cpp::utils::GetParamDefault(paramStartDec + paramIndex)) 
            constValue = (data->dataIndex == -1) ? "null" : il2cpp::utils::GetDefaultValueData(data->typeIndex, data->dataIndex);
            
            params += (constValue.empty() ? "" : " = " + constValue);
        }

        if (methods.size() <= (size_t)index) methods.resize(index + 1);
        methods[index] = { name, typeName, attrs, lastParamType, methodPointer, flags, iflags };
        

        full += getcustomattr(0x06000000 | index, true) + "\t" + attrs + typeName + " " + name + "(" + params + ")" + " { }\n";
        {
            // [V] methodSpecs：12 字节 {methodDefinitionIndex, classIndexIndex, methodIndexIndex}
            const auto* specs = (const il2cpp::Il2CppMethodSpec*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.methodSpecs);
            uint32_t specCount = il2cpp::header.methodSpecsCount;          // 已是条目数（实测 610109）
            // [V] genericInsts = *(T1+0x08)，16 字节 {argc@+0, pad, Il2CppType** argv@+8}
            const auto* genericInsts = (const il2cpp::Il2CppGenericInst*)il2cpp::s_GenericInsts;

            // [V] genericMethodTable：14 字节 {genericMethodIndex, methodIndex, invokerIndex, w}
            const auto* genericMethodTable = (const il2cpp::Il2CppGenericMethodFunctionsDefinitions*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.genericMethodTable);
            uint32_t genericMethodTableCount = il2cpp::header.genericMethodTableCount;   // 560659（条目数）
            // [V] 方法指针数组 = *(T0+0x60)，按 methodIndex 索引
            const auto* genericMethodPointers = (const uint64_t*)il2cpp::s_MethodPointerArray;

            if (!genericIndexBuilt)
            {
                for (uint32_t tableIndex = 0; tableIndex < genericMethodTableCount; ++tableIndex)
                {
                    const auto& tableEntry = genericMethodTable[tableIndex];
                    if (tableEntry.genericMethodIndex < 0 || (uint32_t)tableEntry.genericMethodIndex >= specCount) continue;

                    const auto& spec = specs[tableEntry.genericMethodIndex];
                    if (tableEntry.indices.methodIndex >= 0)  genericEntriesByMethod[spec.methodDefinitionIndex].push_back(tableIndex);
                }
                genericIndexBuilt = true;
            }

            auto instName = [&](const il2cpp::Il2CppGenericInst* inst) -> std::string
                {
                    if (!inst) return "";
                    const uint64_t* argv = (const uint64_t*)(exe.data() + pe->va_to_offset((uint64_t)inst->type_argv));
                    std::string result = "<";
                    for (uint32_t k = 0; k < inst->type_argc; ++k)
                    {
                        if (k) result += ", ";
                        result += il2cpp::utils::NameFromIl2CppType((const il2cpp::Il2CppType*)(exe.data() + pe->va_to_offset(argv[k])));
                    }
                    return result + ">";
                };

            std::string ownerName{ il2cpp::utils::GetStringFromIndex(il2cpp::utils::typeNameIndex((uint32_t)typeDefinition->nameIndex)) };
            if (size_t p = ownerName.find('`'); p != std::string::npos) ownerName.resize(p);
            std::string instances;

            auto genericEntries = genericEntriesByMethod.find(index);
            if (genericEntries != genericEntriesByMethod.end())
            {
                for (uint32_t tableIndex : genericEntries->second)
                {
                const auto& entry = genericMethodTable[tableIndex];
                const auto& spec = specs[entry.genericMethodIndex];

                const auto* classInst = spec.classIndexIndex == -1 ? nullptr : genericInsts + spec.classIndexIndex;
                const auto* methodInst = spec.methodIndexIndex == -1 ? nullptr : genericInsts + spec.methodIndexIndex;
                uint64_t va = genericMethodPointers[entry.indices.methodIndex];

                instances += std::format("\n\t|-RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}", va - pe->optional_header().imagebase(), pe->va_to_offset(va), va);
                instances += "\n\t|-" + ownerName + instName(classInst) + "." + name + instName(methodInst) + "\n\t|";
                }
            }
            if (!instances.empty()) full += "\t/* GenericInstMethod :" + instances + "\n\t*/\n";
        }
        
    }
#endif
    }   // for
    return "\t// Methods\n" + full;
}

std::string propDef(const il2cpp::Il2CppTypeDefinition* typeDefinition)
{
    std::string full{};
    // [V] propertyStart +0x08 - 1995389561 ; property_count +0x43 ^ 0x16
    //     properties 数组 MHY[0x150] - 0x1C3D5389，步长 10
    //     name@+0 / token@+4 / get@+6 / set@+8（0xFFFF = 无该访问器）
    uint32_t start = il2cpp::utils::typePropertyStart((uint32_t)typeDefinition->propertyStart);
    uint32_t count = il2cpp::utils::typePropertyCount(typeDefinition->property_count);

    if (count == 0) return "";

    uint32_t end = start + count;

    for (uint32_t propertyIndex = start; propertyIndex < end; ++propertyIndex)
    {
        const il2cpp::Il2CppPropertyDefinition* propertyDefinition = il2cpp::utils::GetPropertyDefinitionFromIndex((int32_t)propertyIndex);
        uint32_t key = il2cpp::utils::propertyKey(propertyIndex);

        std::string name {il2cpp::utils::GetStringFromIndex(
            il2cpp::utils::propertyNameIndex((uint32_t)propertyDefinition->nameIndex, propertyIndex))};

        // get @+6: key ^ raw ^ 0xE5A2 ; set @+8: (raw-23324) ^ key ；0xFFFF = 无
        uint16_t get = (uint16_t)(key ^ propertyDefinition->get ^ 0xE5A2);
        uint16_t set = (uint16_t)(((uint16_t)propertyDefinition->set - 23324) ^ key);   // sub_1405151D0: - 23324
        bool hasGet = get != 0xFFFF;
        bool hasSet = set != 0xFFFF;

        int32_t methodStartDec = il2cpp::utils::typeMethodStart((uint32_t)typeDefinition->methodStart);
        std::string getterName, setterName;
        std::string propType;
        std::string propAttrs;
        if (hasGet && (size_t)methodStartDec + get < methods.size()) {
            const auto& ge = methods[methodStartDec + get];
            getterName = ge.name;
            propType = ge.ret;
            propAttrs = ge.attrs;
        }
        if (hasSet && (size_t)methodStartDec + set < methods.size()) {
            const auto& se = methods[methodStartDec + set];
            setterName = se.name;
            if (propAttrs.empty()) {
                propAttrs = se.attrs;
                propType = se.valueType;
            }
        }
        std::string acc;
        if (hasGet) acc += " // Getter: " + getterName;
        if (hasSet) acc += (acc.empty() ? " // " : "; ") + std::string("Setter: ") + setterName;
        full += getcustomattr(0x17000000 | propertyIndex, true) + "\t" + propAttrs + propType + " " + name + " { " + (hasGet ? "get; " : "") + (hasSet ? "set; " : "") + "}" + acc + "\n";

    }

    return "\t// Properties\n" + full + "\n";
    return "";
}

std::string eventDef(const il2cpp::Il2CppTypeDefinition* typeDefinition) 
{
    std::string full{};
    // [V] eventStart +0x34 + 3330 ; event_count +0x44 + 113（0x8F 编码 0）
    //     events 数组 MHY[0x1E8] ^ 0x100547B1，步长 14，name@+4
    //     typeIndex@+0 / add@+8 / remove@+10 / raise@+12（0xFFFF = 无）
    int32_t start = il2cpp::utils::typeEventStart(typeDefinition->eventStart);
    uint32_t count = il2cpp::utils::typeEventCount(typeDefinition->event_count);

    if (count == 0) return "";

    int32_t end = start + count;

    for (int32_t eventIndex = start; eventIndex < end; ++eventIndex)
    {
        const il2cpp::Il2CppEventDefinition* eventDefinition = il2cpp::utils::GetEventDefinitionFromIndex(eventIndex);
        uint32_t key = il2cpp::utils::eventKey((uint32_t)eventIndex);

        std::string name {il2cpp::utils::GetStringFromIndex(
            il2cpp::utils::eventNameIndex((uint32_t)eventDefinition->nameIndex, (uint32_t)eventIndex))};
        // sub_140514CF0: v28 = v26 ^ (*(DWORD*)v27 - 452544412)
        int32_t typeIndex = (int32_t)((uint32_t)eventDefinition->typeIndex - 452544412u) ^ (int32_t)key;
        if (typeIndex == -1) continue;
        const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeIndex);
        if (!type) continue;
        std::string type_name {il2cpp::utils::NameFromIl2CppType(type)};

        // [V] add/remove/raise 是**相对 methodStart 的局部索引**，解出后还要 +
        // typeMethodStart(typeDefinition) 才是全局方法索引（文章：methods[methodStartDec + add]）。
        // 实测偏移与标签：+0x0C -> add_X（^0xBEA7）、+0x08 -> remove_X（^0xEE66）、
        //                 +0x0A -> raise_X（(raw-30703)^key）；0xFFFF = 无。
        uint16_t evAdd    = (uint16_t)(key ^ eventDefinition->raise  ^ 0xBEA7);   // +0x0C
        uint16_t evRemove = (uint16_t)(key ^ eventDefinition->add    ^ 0xEE66);   // +0x08
        uint16_t evRaise  = (uint16_t)(((uint16_t)eventDefinition->remove - 30703) ^ key); // +0x0A
        uint16_t add = evAdd, remove = evRemove, raise = evRaise;
        bool hasRemove = remove != 0xFFFF;
        bool hasAdd = add != 0xFFFF;
        bool hasRaise = raise != 0xFFFF;

        int32_t methodStartDec = il2cpp::utils::typeMethodStart((uint32_t)typeDefinition->methodStart);
        std::string evAttrs;
        std::string acc;
        if (hasAdd) {
            const auto& e = ((size_t)methodStartDec + add < methods.size()) ? methods[methodStartDec + add] : emptyMethod;
            evAttrs = e.attrs;
            acc += " // Add: " + e.name;
        }
        if (hasRemove) {
            const auto& e = ((size_t)methodStartDec + remove < methods.size()) ? methods[methodStartDec + remove] : emptyMethod;
            if (evAttrs.empty()) evAttrs = e.attrs;
            acc += (acc.empty() ? " // " : "; ") + std::string("Remove: ") + e.name;
        }
        if (hasRaise) {
            const auto& e = ((size_t)methodStartDec + raise < methods.size()) ? methods[methodStartDec + raise] : emptyMethod;
            if (evAttrs.empty()) evAttrs = e.attrs;
            acc += (acc.empty() ? " // " : "; ") + std::string("Raise: ") + e.name;
        }
        full += getcustomattr(0x14000000 | eventIndex, true) + "\t" + evAttrs + "event " + type_name + " " + name + " {" + (hasAdd ? "add; " : "") + (hasRemove ? "remove; " : "") + (hasRaise ? "raise; " : "") + " }" + acc + "\n";
    }

    return "\t// Events\n" + full + "\n";
    return "";
}


// 嵌套类：用 nestedTypes 表反推「子 -> 父」映射（declaringTypeIndex 未定位的替代方案）。
//   表 = MHY[0x05C] - 381850355，步长 4；typeDef +0x36 +6631 = start，+0x45 ^0xBA = count。
//   已验收：9310 个父类型 / 25981 条目；起点互不重叠、恰好铺满整表、条目全为合法 TypeDefIndex。
static std::unordered_map<int32_t, int32_t> buildNestingMap()
{
    std::unordered_map<int32_t, int32_t> m;
    if (!il2cpp::header.nestedTypesTable || !il2cpp::header.typeDefinitionsCount) return m;
    const uint32_t* tbl = (const uint32_t*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.nestedTypesTable);
    const il2cpp::Il2CppTypeDefinition* tds =
        (const il2cpp::Il2CppTypeDefinition*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset);
    const uint32_t nTypes = il2cpp::header.typeDefinitionsCount;
    for (uint32_t t = 0; t < nTypes; t++)
    {
        int32_t st = il2cpp::utils::typeNestedStart(tds[t].nestedTypesStart);
        uint32_t cnt = il2cpp::utils::typeNestedCount(tds[t].nestedTypesCount);
        for (uint32_t i = 0; i < cnt; i++)
        {
            uint32_t child = tbl[st + i];
            if (child < nTypes) m[(int32_t)child] = (int32_t)t;
        }
    }
    return m;
}

void typeDef() 
{
    // decryptHeader() 里已经把字节数换算成条目数了（(表值/70)-2），这里不能再除
    int32_t typeDefinitionsCount = (int32_t)il2cpp::header.typeDefinitionsCount;
    const il2cpp::Il2CppTypeDefinition* typeDefinitions = (const il2cpp::Il2CppTypeDefinition*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.typeDefinitionsOffset);
    
    const auto childToParent = buildNestingMap();   // 一次预扫，供声明前缀使用
    for (int32_t typeIndex = 0; typeIndex < typeDefinitionsCount; typeIndex++)
    {
        const il2cpp::Il2CppTypeDefinition* typeDefinition = typeDefinitions + typeIndex;
        std::string name{ il2cpp::utils::GetStringFromIndex(
            il2cpp::utils::typeNameIndex((uint32_t)typeDefinition->nameIndex)) };
        if (size_t p = name.find('`'); p != std::string::npos) name.resize(p);

        // [V] flags = +0x28 - 0x4159BB8E（TYPE_ATTRIBUTE）。
        //   bitfield = +0x3A（见 utils::typeIsValueType / typeIsEnum）
        uint32_t flags = il2cpp::utils::typeFlags((uint32_t)typeDefinition->flags);
        uint8_t valuetype = il2cpp::utils::typeIsValueType(typeDefinition->bitfield);
        uint8_t enumtype  = il2cpp::utils::typeIsEnum(typeDefinition->bitfield);
        uint32_t token = 0x02000000 | typeIndex;

        std::string serializableAttr{};
        if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) serializableAttr = "[Serializable]\n";

        std::string visibility;
        switch (flags & TYPE_ATTRIBUTE_VISIBILITY_MASK)
        {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:       visibility = "public ";             break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:     visibility = "internal ";           break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:      visibility = "private ";            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:       visibility = "protected ";          break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM: visibility = "protected internal "; break;
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:visibility = "private protected";   break;
        }

        std::string typeAttr{};
        if (flags & TYPE_ATTRIBUTE_INTERFACE)                                          typeAttr = "interface ";
        else if (enumtype)                                                             typeAttr = "enum ";
        else if (valuetype)                                                            typeAttr = "struct ";
        else if ((flags & TYPE_ATTRIBUTE_ABSTRACT) && (flags & TYPE_ATTRIBUTE_SEALED)) typeAttr = "static class ";
        else if (flags & TYPE_ATTRIBUTE_ABSTRACT)                                      typeAttr = "abstract class ";
        else if (flags & TYPE_ATTRIBUTE_SEALED)                                        typeAttr = "sealed class ";
        else                                                                           typeAttr = "class ";

        std::string interfaces{};
        // [V] interfaces：start +0x3C ^ 0x43DA；count +0x40 + 56（0xC8 编码 0）
        //     实测：SafeGPtrArrayHandle→System.IDisposable、SecurityParser→IContentHandler、
        //           PKCS12→System.ICloneable。
        uint16_t interfacesStart = il2cpp::utils::typeInterfacesStart((uint16_t)typeDefinition->interfacesStart);
        uint32_t interfaces_count = il2cpp::utils::typeInterfacesCount(typeDefinition->interfaces_count);
        if (interfaces_count > 256) interfaces_count = 256;   // 防越界
        for (uint32_t i = 0; i < interfaces_count; i++)
        {
            const il2cpp::Il2CppType* type = il2cpp::utils::GetInterfaceFromIndex(interfacesStart + i);
            if (!type) continue;
            if (!interfaces.empty()) interfaces += ", ";
            interfaces += il2cpp::utils::NameFromIl2CppType(type);
        }

        std::string parent{};
        // [V] 基类：parentIndex -> Il2CppType -> 父类型。逻辑照抄 6.7 版（只换常量）。
        {
            int32_t pIdx = il2cpp::utils::typeParentIndex((uint32_t)typeDefinition->parentIndex);
            if (pIdx != -1)
            {
                const il2cpp::Il2CppType* ptype = il2cpp::utils::GetIl2CppTypeFromIndex(pIdx);
                if (ptype && !valuetype && !enumtype)
                {
                    auto typeCode = ptype->type;
                    if (typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
                    {
                        parent = il2cpp::utils::NameFromIl2CppType(ptype);
                    }
                    else if (typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS
                             && ptype->data.klassIndex != 405 && ptype->data.klassIndex != 204)
                    {
                        parent = il2cpp::utils::GetStringFromIndex(
                            il2cpp::utils::typeNameIndex((uint32_t)typeDefinitions[ptype->data.klassIndex].nameIndex));
                    }
                }
            }
        }
        std::string namespaze{ il2cpp::utils::GetStringFromIndex(
            il2cpp::utils::typeNamespaceIndex((uint32_t)typeDefinition->namespaceIndex)) };

        std::string fullName{};
        std::string declaringType{};
#if 0
        if (typeDefinition->parentIndex != 0xC52CB9C) 
        {
            const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeDefinition->parentIndex - 0xC52CB9D);
            auto typeCode = type->type;

            if (!valuetype && !enumtype)
            {
                if (typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
                {
                    parent = il2cpp::utils::NameFromIl2CppType(type);
                }
                else if ((typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS /*|| typeCode == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT*/) && type->data.klassIndex != 405 && type->data.klassIndex != 204)
                {
                    parent = il2cpp::utils::GetStringFromIndex(
                        il2cpp::utils::typeNameIndex((uint32_t)typeDefinitions[type->data.klassIndex].nameIndex));
                }
            }

        }

        if (typeDefinition->declaringTypeIndex != 0x5C0F5BCB) 
        {
            const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeDefinition->declaringTypeIndex - 0x5C0F5BCC);
            fullName = il2cpp::utils::NameFromIl2CppType(type);
            if (!fullName.empty()) fullName += ".";

            declaringType = il2cpp::utils::GetStringFromIndex(
                il2cpp::utils::typeNameIndex((uint32_t)typeDefinitions[type->data.klassIndex].nameIndex));
            if (size_t p = declaringType.find('`'); p != std::string::npos) declaringType.resize(p);
        }
        else
#endif
        // 嵌套类前缀：沿「子->父」往上走，拼成 Outer.Inner（不含尾点）。
        {
            std::vector<std::string> chain;
            int32_t cur = typeIndex;
            int32_t outermost = -1;
            for (int depth = 0; depth < 16; depth++)
            {
                auto it = childToParent.find(cur);
                if (it == childToParent.end()) break;
                cur = it->second;
                outermost = cur;
                std::string pn{ il2cpp::utils::GetStringFromIndex(
                    il2cpp::utils::typeNameIndex((uint32_t)typeDefinitions[cur].nameIndex)) };
                if (size_t q = pn.find('`'); q != std::string::npos) pn.resize(q);
                chain.push_back(std::move(pn));
            }
            for (auto it = chain.rbegin(); it != chain.rend(); ++it)
            {
                if (!declaringType.empty()) declaringType += ".";
                declaringType += *it;
            }
            // 嵌套类型的 namespaceIndex 为空 -> 继承最外层父类型的命名空间
            if (namespaze.empty() && outermost >= 0)
                namespaze = il2cpp::utils::GetStringFromIndex(
                    il2cpp::utils::typeNamespaceIndex((uint32_t)typeDefinitions[outermost].namespaceIndex));
        }
        if (!namespaze.empty())
        {
            fullName = namespaze + ".";
        }
        if (!declaringType.empty()) fullName += declaringType + ".";
        fullName += name;


        std::string typeGenerics{};
#if 0   // 6.7 版原始实现（常量不同），保留作为对照
        {
            uint16_t genericContainerIndex = (typeDefinition->genericContainerIndex ^ 0x1BD3u);
            const auto* container = il2cpp::utils::GetGenericContainerFromIndex(genericContainerIndex);
            if (container)
            {
                uint32_t key = (269045474 * ((1724555473 * ((59131LL * genericContainerIndex) ^ 0x13149C18)) ^ 0x26CF5EFDuLL) + 0x1272614D2E8ALL) >> 16;
                uint32_t count = key ^ 0x1CACE492 ^ container->type_argc;
                if (count != 0 && count <= 32)
                {
                    uint32_t genericParameterStart = key ^ (container->genericParameterStart - 283689125);
                    for (uint32_t i = 0; i < count; ++i)
                    {
                        const auto* parameter = il2cpp::utils::GetGenericParameter(genericParameterStart, i);
                        uint32_t nameKey = (uint32_t)(((0x65DE21D74280ull * (genericParameterStart + i)) ^ 0x154AA920) + 1912316114);
                        if (i) typeGenerics += ", ";

                        uint16_t pflags = parameter->flags;
                        if (pflags & 1) typeGenerics += "out ";
                        else if (pflags & 2) typeGenerics += "in ";
                        typeGenerics += il2cpp::utils::GetStringFromIndex((parameter->nameIndex ^ 0x2DD1C9C6u) - nameKey);
                    }
                }
            }
        }
#endif
        // [V] 类泛型参数：typeDef+0x3E -> 容器 -> (argc, parameterStart) -> genericParameters[]
        //   逻辑照抄 6.7 版，常量全部换成本版本的（sub_140511DB0 / sub_14050E030 / sub_1404B7B20）。
        {
            int32_t cIdx = il2cpp::utils::typeGenericContainerIndex((uint16_t)typeDefinition->genericContainerIndex);
            if (cIdx >= 0)
            {
                uint32_t count = il2cpp::utils::genericContainerArgc((uint32_t)cIdx);
                uint32_t pStart = il2cpp::utils::genericParameterStart((uint32_t)cIdx);
                if (count != 0 && count <= 32)
                {
                    for (uint32_t i = 0; i < count; ++i)
                    {
                        if (i) typeGenerics += ", ";
                        typeGenerics += il2cpp::utils::GetStringFromIndex(
                            il2cpp::utils::genericParameterNameIndex(pStart + i));
                    }
                }
            }
        }
        out << "// Namespace: " << namespaze << "\n// FullName: " << fullName << "\n" << getcustomattr(token) << serializableAttr << visibility << typeAttr << (declaringType.empty() ? "" : declaringType + ".") << name << (typeGenerics.empty() ? "" : "<" + typeGenerics + ">") /*блатной*/
            << (parent.empty() ? "" : ": " + parent)
            << (interfaces.empty() ? "" : (parent.empty() ? ": " : ", ") + interfaces) << " // TypeDefIndex: " << typeIndex << std::endl;
        
        std::string v = methodDef(typeDefinition);
        out << "{\n" 
            << fieldDef(typeDefinition) << propDef(typeDefinition) << eventDef(typeDefinition) << v;
        out << "}\n\n";
    }
}

void string_Literal() {
    // ⚠️ 本版本**没有独立的字面量条目表**（offset/length 打包进 nameIndex，见 decryptHeader），
    //    header.stringLiteralOffset == 0。若仍按「条目表」遍历，stringLiteral 指针会落在
    //    元数据头上，dataIndex/length 解出垃圾 → DecryptStringAt 越界读 → SIGSEGV。
    //    所以本版本直接输出空数组并返回（字符串仍可经 GetStringFromIndex 正常取到）。
    if (il2cpp::header.stringLiteralOffset == 0)
    {
        стрингиойой << "[]\n";
        return;
    }
    int32_t stringLiteralCount = /*string+0x4c*/ 0x52B07516 ^ 0x52B1495D;

    auto format = [](std::string_view in) -> std::string
        {
            std::string out;
            out.reserve(in.size() + 8);
            for (unsigned char c : in)
            {
                switch (c)
                {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20) out += std::format("\\u{:04x}", c);
                    else out += (char)c;
                }
            }
            return out;
        };

    стрингиойой << "[\n";
    for (uint32_t index = 0; index < (uint32_t)stringLiteralCount; ++index)
    {
        const auto* stringLiteral = (const il2cpp::Il2CppStringLiteral*)((const char*)il2cpp::s_GlobalMetadataHeader + il2cpp::header.stringLiteralOffset + 4ull * index);

        uint32_t datakey = ((-242635478LL * (int64_t)index + 2077684850) ^ 0xBD35B71B);
        uint32_t lengthKey = (uint32_t)((-242635478LL * (int64_t)index + 1835049372) ^ 0xBD35B71B);

        int32_t dataIndex = (stringLiteral->dataIndex ^ 0x47DBC836) + datakey;
        uint32_t length = (stringLiteral->length ^ 0x47DBC836) + lengthKey - dataIndex;

        uint8_t* stringLiteralData = il2cpp::s_GlobalMetadataHeader + il2cpp::header.stringLiteralDataOffset;

        // 解密部分已更新为本版本算法（已验证）；dataIndex/length 的读取逻辑未验证，保持原样
        std::string s = il2cpp::utils::decryptString((uint32_t)dataIndex, length);
        uint64_t addr = (uint64_t)(stringLiteralData + dataIndex) - (uint64_t)il2cpp::s_GlobalMetadataHeader + 0x210;
        стрингиойой << "  {\"value\": \"" << format(s) << "\", \"address\": \"" << std::format("0x{:X}", addr) << "\"}" << (index + 1 < (uint32_t)stringLiteralCount ? "," : "") << "\n";

    }
    стрингиойой << "]\n";
    стрингиойой.flush();
}

struct GenWrite { uint32_t obj; uint32_t off; uint32_t size; uint64_t value; std::string str; uint64_t high = 0; };
std::vector<GenWrite> parseGenerator(uint8_t* code_, size_t len, uint64_t va) 
{
    std::vector<GenWrite> writes;
    auto normalize = [](x86_reg reg) {
        switch (reg) {
        case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX: return X86_REG_RAX;
        case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX: return X86_REG_RBX;
        case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX: return X86_REG_RCX;
        case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX: return X86_REG_RDX;
        case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI: case X86_REG_RSI: return X86_REG_RSI;
        case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI: case X86_REG_RDI: return X86_REG_RDI;
        case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8: return X86_REG_R8;
        case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9: return X86_REG_R9;
        default: return reg;
        }
        };

    std::unordered_set<unsigned int> arrays;
    std::unordered_map<unsigned int, uint32_t> objects;
    std::unordered_map<unsigned int, uint64_t> values;
    std::unordered_map<uint32_t, std::string> strings;
    std::unordered_map<uint32_t, std::pair<uint64_t, uint64_t>> xmm;
    std::unordered_map<int64_t, std::pair<uint64_t, uint32_t>> stackValues;
    std::unordered_map<uint32_t, int64_t> stackPtrs;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return {};
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = cs_malloc(handle);
    const uint8_t* code = code_;
    size_t size = len;
    uint64_t addr = va;

    while (cs_disasm_iter(handle, &code, &size, &addr, insn))
    {
        if (insn->id == X86_INS_RET) break;

        cs_x86& x = insn->detail->x86;
        if (insn->id == X86_INS_CALL && x.op_count == 1 && x.operands[0].type == X86_OP_IMM && (uint64_t)x.operands[0].imm == 0x1404D1BF0)
        {
            std::string result;
            if (values.contains(X86_REG_RCX) && values.contains(X86_REG_RDX))
            {
                uint64_t stringVA = values[X86_REG_RCX];
                uint64_t length = values[X86_REG_RDX];

                if (stringVA < 0x140001200) continue;
                else
                {
                    uint64_t fileOffset = stringVA - 0x140001200;

                    if (fileOffset <= exe.size() && length <= exe.size() - fileOffset)
                    {
                        result = std::string((const char*)exe.data() + fileOffset, (size_t)length);
                    }
                }
            }

            for (auto r : { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9 }) {
                arrays.erase((uint32_t)r); objects.erase((uint32_t)r);
                values.erase((uint32_t)r); strings.erase((uint32_t)r); stackPtrs.erase((uint32_t)r);
            }
            if (!result.empty()) strings[X86_REG_RAX] = std::move(result);
            continue;
        }

        if ((insn->id == X86_INS_CALL || insn->id == X86_INS_JMP) && x.op_count == 1 && x.operands[0].type == X86_OP_IMM && (uint64_t)x.operands[0].imm == 0x1404DA250)
        {
            std::string result;
            auto itV = values.find((uint32_t)X86_REG_RCX);
            if (itV != values.end() && !(itV->second & 0xF))
            {
                uint64_t typePtr = (uint64_t)(il2cpp::s_Il2CppTypes) + itV->second;   // 同样必须转 host 指针
                std::string tname = il2cpp::utils::NameFromIl2CppType((const il2cpp::Il2CppType*)typePtr);
                if (!tname.empty()) result = "typeof(" + tname + ")";
            }
            for (auto r : { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9 }) {
                arrays.erase((uint32_t)r); objects.erase((uint32_t)r);
                values.erase((uint32_t)r); strings.erase((uint32_t)r); stackPtrs.erase((uint32_t)r);
            }
            if (!result.empty())
            {
                if (insn->id == X86_INS_JMP) writes.push_back({ 0, UINT32_MAX, 8, 0, std::move(result) });
                else strings[X86_REG_RAX] = std::move(result);
            }
            if (insn->id == X86_INS_JMP) break;
            continue;
        }

        if (insn->id == X86_INS_CALL && x.op_count == 1 && x.operands[0].type == X86_OP_IMM && (uint64_t)x.operands[0].imm == 0x1404C7BD0)
        {
            std::string result;
            auto itP = stackPtrs.find((uint32_t)X86_REG_RDX);
            if (itP != stackPtrs.end())
            {
                auto itS = stackValues.find(itP->second);
                if (itS != stackValues.end())
                    result = itS->second.second == 1 ? (itS->second.first ? "true" : "false") : std::to_string((int32_t)itS->second.first);
            }
            for (auto r : { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9 }) {
                arrays.erase((uint32_t)r); objects.erase((uint32_t)r);
                values.erase((uint32_t)r); strings.erase((uint32_t)r); stackPtrs.erase((uint32_t)r);
            }
            if (!result.empty()) strings[X86_REG_RAX] = std::move(result);
            continue;
        }


        if (x.op_count != 2) continue;
        cs_x86_op& dst = x.operands[0];
        cs_x86_op& src = x.operands[1];

        if (insn->id == X86_INS_MOV && dst.type == X86_OP_REG)
        {
            uint32_t dstReg = (uint32_t)normalize(dst.reg);

            if (src.type == X86_OP_MEM && src.mem.index == X86_REG_INVALID)
            {
                uint32_t baseReg = (uint32_t)normalize(src.mem.base);
                // mov reg, [rcx+8]
                if (baseReg == X86_REG_RCX && src.mem.disp == 8) { arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg); arrays.insert(dstReg); }
                // mov reg, [arr+8*i]
                else if (arrays.contains(baseReg) && src.mem.disp >= 0 && !(src.mem.disp & 7)) { uint32_t objIdx = (uint32_t)(src.mem.disp / 8); arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg); objects[dstReg] = objIdx; }
                else { arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg); }
                continue;
            }

            // mov reg, imm
            if (src.type == X86_OP_IMM)
            {
                arrays.erase(dstReg); objects.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
                values[dstReg] = (uint64_t)src.imm;
                continue;
            }

            // mov reg, reg
            if (src.type == X86_OP_REG)
            {
                uint32_t srcReg = (uint32_t)normalize(src.reg);
                if (dstReg == srcReg) continue;
                bool isArr = arrays.contains(srcReg);
                auto itO = objects.find(srcReg);
                auto itV = values.find(srcReg);
                auto itS = strings.find(srcReg);
                auto itP = stackPtrs.find(srcReg);
                arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
                if (isArr) arrays.insert(dstReg);
                else if (itO != objects.end()) objects[dstReg] = itO->second;
                else if (itS != strings.end()) strings[dstReg] = itS->second;
                else if (itV != values.end()) values[dstReg] = itV->second;
                else if (itP != stackPtrs.end()) stackPtrs[dstReg] = itP->second;
                continue;
            }
        }



        // lea reg, [rip+disp]
        if (insn->id == X86_INS_LEA && dst.type == X86_OP_REG && src.type == X86_OP_MEM && src.mem.base == X86_REG_RIP)
        {
            uint32_t dstReg = (uint32_t)normalize(dst.reg);
            uint64_t va = insn->address + insn->size + src.mem.disp;
            arrays.erase(dstReg); objects.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
            values[dstReg] = va;
            continue;
        }

        // lea reg, [rsp+disp]
        if (insn->id == X86_INS_LEA && dst.type == X86_OP_REG && src.type == X86_OP_MEM && src.mem.base == X86_REG_RSP && src.mem.index == X86_REG_INVALID)
        {
            uint32_t dstReg = (uint32_t)normalize(dst.reg);
            arrays.erase(dstReg); objects.erase(dstReg); values.erase(dstReg); strings.erase(dstReg); stackPtrs.erase(dstReg);
            stackPtrs[dstReg] = src.mem.disp;
            continue;
        }

        // xmmreg, [rip]
        if ((insn->id == X86_INS_MOVAPS || insn->id == X86_INS_MOVUPS || insn->id == X86_INS_MOVSS || insn->id == X86_INS_MOVSD)
            && dst.type == X86_OP_REG && src.type == X86_OP_MEM && src.mem.base == X86_REG_RIP)
        {
            uint64_t va = insn->address + insn->size + src.mem.disp;
            uint64_t off = pe->va_to_offset(va);
            if (off < exe.size() && 16 <= exe.size() - off)
            {
                uint64_t lo = 0, hi = 0;
                memcpy(&lo, exe.data() + off, 8);
                memcpy(&hi, exe.data() + off + 8, 8);
                xmm[(uint32_t)dst.reg] = { lo, hi };
            }
            continue;
        }
        if (insn->id == X86_INS_XORPS && dst.type == X86_OP_REG && src.type == X86_OP_REG && dst.reg == src.reg)
        {
            xmm[(uint32_t)dst.reg] = { 0, 0 };
            continue;
        }
        // [obj+disp], xmm
        if ((insn->id == X86_INS_MOVAPS || insn->id == X86_INS_MOVUPS || insn->id == X86_INS_MOVSS || insn->id == X86_INS_MOVSD)
            && dst.type == X86_OP_MEM && src.type == X86_OP_REG)
        {
            if (dst.mem.base == X86_REG_INVALID || dst.mem.index != X86_REG_INVALID) continue;
            auto o = objects.find((uint32_t)normalize(dst.mem.base));
            auto x = xmm.find((uint32_t)src.reg);
            if (o == objects.end() || x == xmm.end()) continue;
            writes.push_back({ o->second, (uint32_t)dst.mem.disp, 16, x->second.first, "", x->second.second });
            continue;
        }

        // mov [rsp+disp], imm
        if (insn->id == X86_INS_MOV && dst.type == X86_OP_MEM && src.type == X86_OP_IMM
            && dst.mem.base == X86_REG_RSP && dst.mem.index == X86_REG_INVALID)
        {
            uint64_t v = (uint64_t)src.imm;
            if (dst.size < 8) v &= (1ull << (dst.size * 8)) - 1;
            stackValues[dst.mem.disp] = { v, dst.size };
            continue;
        }

        // mov [reg+disp], imm
        if (dst.type != X86_OP_MEM || dst.mem.base == X86_REG_INVALID || dst.mem.index != X86_REG_INVALID) continue;
        uint32_t baseReg = (uint32_t)normalize(dst.mem.base);
        auto object = objects.find(baseReg);
        if (object == objects.end()) continue;

        uint64_t value = 0;
        std::string str;
        if (src.type == X86_OP_IMM && (insn->id == X86_INS_MOV || insn->id == X86_INS_OR)) { value = (uint64_t)src.imm; }
        else if (src.type == X86_OP_REG && insn->id == X86_INS_MOV) {
            uint32_t srcReg = (uint32_t)normalize(src.reg);
            auto itV = values.find(srcReg);
            auto itS = strings.find(srcReg);
            if (itS != strings.end()) str = itS->second;
            else if (itV != values.end()) value = itV->second;
            else continue;
        }
        else continue;

        writes.push_back({ object->second, (uint32_t)dst.mem.disp, dst.size, value, str });
    }


    cs_free(insn, 1);
    cs_close(&handle);

    return writes;
}

static std::string format(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\b': o += "\\b";  break;
        case '\f': o += "\\f";  break;
        case '\n': o += "\\n";  break;
        case '\r': o += "\\r";  break;
        case '\t': o += "\\t";  break;
        default:
            if (c < 0x20) o += std::format("\\u{:04x}", c);
            else o += (char)c;
        }
    }
    return o;
}

static std::string formatEnum(const il2cpp::Il2CppType* enumType, uint64_t raw)
{
    if (!enumType) return std::to_string(raw);
    if (enumType->type != il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE) return std::to_string(raw);
    const il2cpp::Il2CppTypeDefinition* enumDef = il2cpp::utils::GetTypeDefinitionFromIndex(enumType->data.klassIndex);
    // bitfield = +0x3A（已定位）：enumtype = ~(raw>>1)&1
    if (!enumDef) return std::to_string(raw);
    return std::to_string(raw);

    auto fields = collectFields(enumDef);
    std::vector<std::pair<uint64_t, std::string>> vals;
    for (auto& f : fields)
    {
        if (!(f.type->attrs & FIELD_ATTRIBUTE_LITERAL)) continue;
        const il2cpp::Il2CppFieldDefaultValue* d = il2cpp::utils::GetDefaultValueForField(f.index);
        if (!d || d->dataIndex == -1) continue;
        const il2cpp::Il2CppType* ct = il2cpp::utils::GetIl2CppTypeFromIndex(d->typeIndex);
        uint8_t* blob = il2cpp::s_GlobalMetadataHeader + d->dataIndex + il2cpp::header.fieldAndParameterDefaultValueDataOffset;
        uint64_t v = 0;
        auto code = ct ? ct->type : il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_END;
        switch (code)
        {
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN:
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I1: v = (uint64_t)(int64_t)(int8_t)*blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U1: v = *blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I2: v = (uint64_t)(int64_t)*(int16_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U2: v = *(uint16_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I4: v = (uint64_t)(int64_t)*(int32_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U4: v = *(uint32_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I8: v = *(uint64_t*)blob; break;
        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U8: v = *(uint64_t*)blob; break;
        default: continue;
        }
        vals.push_back({ v, f.name });
    }
    for (auto& p : vals)
        if (p.first == raw) return p.second + "(" + std::to_string(p.first) + ")";

    std::sort(vals.begin(), vals.end(), [](auto& a, auto& b) { return a.first > b.first; });
    uint64_t rem = raw;
    std::string out;
    for (auto& p : vals)
    {
        if (p.first && ((rem & p.first) == p.first))
        {
            if (!out.empty()) out += " | ";
            out += p.second + "(" + std::to_string(p.first) + ")";
            rem &= ~p.first;
        }
    }
    if (!out.empty() && rem == 0) return out;
    return std::to_string(raw);
}

void customAttr()
{
    const il2cpp::Il2CppCustomAttributeTypeRange* attributeTypeRange = (const il2cpp::Il2CppCustomAttributeTypeRange*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.attributesInfoOffset);

    int32_t customAttributeCount = *(int32_t*)(il2cpp::s_Il2CppCodeRegistration + 0x70) - 0x2F2BD0D;
    for (int32_t i = 0; i < customAttributeCount; i++)
    {
        uint32_t count = attributeTypeRange[i].start_сount >> 24;
        if (count == 0) continue;

        uint32_t start = attributeTypeRange[i].start_сount & 0xFFFFFF;
        uint32_t token = attributeTypeRange[i].token;

        uint64_t genVA = *(uint64_t*)(exe.data() + pe->va_to_offset(/*s_Il2CppCodeRegistration + 0x58*/0x141F04D90 + 8ULL * i));
        auto writes = parseGenerator(exe.data() + pe->va_to_offset(genVA), std::min<size_t>(0x1000, exe.size() - pe->va_to_offset(genVA)), genVA);

        for (int32_t index = 0; index < count; index++)
        {
            uint32_t typeIndex = *(uint32_t*)(il2cpp::s_GlobalMetadataHeader + il2cpp::header.attributeTypesOffset + 4 * (start + index));
            const il2cpp::Il2CppType* type = il2cpp::utils::GetIl2CppTypeFromIndex(typeIndex);

            std::string attrName{ il2cpp::utils::NameFromIl2CppType(type) };
            std::vector<std::string> args;

            if (type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE)
            {
                const il2cpp::Il2CppTypeDefinition* attrTypeDef = il2cpp::utils::GetTypeDefinitionFromIndex(type->data.klassIndex);
                auto fields = collectFields(attrTypeDef);
                std::sort(fields.begin(), fields.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });

                for (auto& w : writes)
                {
                    if (w.obj != (uint32_t)index) continue;

                    auto it = std::find_if(fields.begin(), fields.end(), [&](const FieldInfo& f) { return f.offset == w.off; });
                    if (it == fields.end()) continue;

                    if (w.size == 16 && it->typeName == "Decimal")
                    {
                        uint32_t flags = (uint32_t)w.value, hi = (uint32_t)(w.value >> 32);
                        uint32_t lo = (uint32_t)w.high, mid = (uint32_t)(w.high >> 32);
                        args.push_back(std::to_string((flags >> 16) & 0x7F));
                        args.push_back(std::to_string(flags >> 24));
                        args.push_back(std::to_string(hi) + "U");
                        args.push_back(std::to_string(mid) + "U");
                        args.push_back(std::to_string(lo) + "U");
                        continue;
                    }

                    std::string value;

                    if (!w.str.empty())
                    {
                        if (w.str.starts_with("typeof("))
                        {
                            args.push_back(w.str);
                            continue;
                        }
                        if (it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT ||
                            it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS ||
                            it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY ||
                            it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
                        {
                            if (w.str == "true" || w.str == "false")
                            {
                                args.push_back(w.str);
                                continue;
                            }
                            bool isInt = !w.str.empty() && (w.str[0] == '-' || (w.str[0] >= '0' && w.str[0] <= '9'));
                            if (isInt)
                            {
                                bool ok = true;
                                for (size_t k = (w.str[0] == '-' ? 1 : 0); k < w.str.size(); ++k)
                                    if (w.str[k] < '0' || w.str[k] > '9') { ok = false; break; }
                                if (ok && w.str.size() > (size_t)(w.str[0] == '-' ? 1 : 0)) { args.push_back(w.str); continue; }
                            }
                            args.push_back("\"" + format(w.str) + "\"");
                            continue;
                        }
                        if (it->type->type == il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_STRING)
                        {
                            value = "\"" + format(w.str) + "\"";
                        }
                        else continue;
                    }
                    else
                    {
                        value = il2cpp::utils::GetConstantValueFromBlob(it->type->type, (uint8_t*)&w.value);

                        switch (it->type->type)
                        {
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN: value = w.value ? "true" : "false"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I1:  value = std::to_string((int)(int8_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U1:  value = std::to_string((unsigned)(uint8_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I2:  value = std::to_string((int)(int16_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U2:  value = std::to_string((unsigned)(uint16_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I4:  value = std::to_string((int32_t)w.value); break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U4:  value = std::to_string((uint32_t)w.value) + "u"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_I8:  value = std::to_string((int64_t)w.value) + "L"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_U8:  value = std::to_string(w.value) + "UL"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_STRING: value = w.value ? "\"...\"" : "null"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_CLASS:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY:
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST: value = w.value ? "\"...\"" : "null"; break;
                        case il2cpp::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE:
                        {
                            const il2cpp::Il2CppTypeDefinition* fieldTypeDef = il2cpp::utils::GetTypeDefinitionFromIndex(it->type->data.klassIndex);
                            bool isEnum = il2cpp::utils::typeIsEnum(fieldTypeDef->bitfield) != 0;
                            if (isEnum)
                            {
                                uint64_t ev = w.value;
                                if (w.size == 1) ev &= 0xFF;
                                else if (w.size == 2) ev &= 0xFFFF;
                                else if (w.size == 4) ev &= 0xFFFFFFFF;
                                value = formatEnum(it->type, ev);
                            }
                            else continue;
                            break;
                        }
                        default: continue;
                        }
                    }

                    args.push_back(it->name + " = " + value);
                }
            }
            std::string argsStr;
            for (size_t k = 0; k < args.size(); ++k) argsStr += (k ? ", " : "") + args[k];
            attrMap[token] += std::format("[{}{}] /* VA: 0x{:X} */\n", attrName, argsStr.empty() ? "" : "(" + argsStr + ")", genVA);
        }
    }
}

void decryptHeader() 
{
    // --- 以下 4 项已实测验证（ANALYSIS.md §4.1），75/75 程序集名正确 ---
    // ===== 已验收字段（见 gi_fields.md §2）=====
    // 步长由 init 里 memset 快速路径的 `if (count >= sizeof(Struct))` 守卫反推
    il2cpp::header.imagesCount        = *(uint32_t*)(il2cpp::s_MHYTable + 0x02C) - 0x2465B023u;   // 字节数，/0x28 = 75
    il2cpp::header.imagesOffset       = *(uint32_t*)(il2cpp::s_MHYTable + 0x20C) - 0x0ECB27F5u;   // startup 侧，步长 40
    il2cpp::header.stringLiteralDataOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x184) + 0xBF9D4735u;

    // 守卫 >= 0x46(70)：typeDefinitions 步长 70；表里存的是字节数，代码里再 -2
    il2cpp::header.typeDefinitionsCount = (*(uint32_t*)(il2cpp::s_MHYTable + 0x0E0) - 0x1D064F83u) / 70 - 2;
    il2cpp::header.typeDefinitionsOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x0B4) - 0x13B75461u;

    // 守卫 >= 0x1A(26)：methods 步长 26；表里存字节数
    il2cpp::header.methodsOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x16C) - 0x1CCA7654u;
    il2cpp::header.methodsCount  = (*(uint32_t*)(il2cpp::s_MHYTable + 0x188) ^ 0x1B58E334u) / 26;
    // returnType 索引表：sub_140514630 中 `*(int*)(global + (slot148 ^ 0x4A4C0A71) + 4*methodIndex)`
    // [V] 方法指针索引表（原被我误标为 returnType）：来源 GIMeta_SetupMethodsLocked。
    il2cpp::header.methodPointerIndexOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x94) ^ 0x4A4C0A71u;
    // [V] methodIndex -> slot 表：6 字节项 {int32 methodIndex, uint16 slot}，methodIndex 严格递增。
    il2cpp::header.methodSlotTableOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x140) - 1832561230u;
    il2cpp::header.methodSlotCount       = ((*(uint32_t*)(il2cpp::s_MHYTable + 0x1FC) - 127184164u) / 6);

    il2cpp::header.parametersOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x114) ^ 0x3E5D33E6u;   // 步长 8，name@+4
    il2cpp::header.propertiesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x150) - 0x1C3D5389u;   // 步长 10，name@+0
    il2cpp::header.fieldsOffset     = *(uint32_t*)(il2cpp::s_MHYTable + 0x18C) - 336578260u;    // 步长 8，name@+4
    il2cpp::header.eventsOffset     = *(uint32_t*)(il2cpp::s_MHYTable + 0x1E8) ^ 0x100547B1u;    // 步长 14，name@+4
    il2cpp::header.fieldOffset      = *(uint32_t*)(il2cpp::s_MHYTable + 0x204) - 450622139u;    // 步长 4，(off&0x1FFFFFFF)/静态位
    il2cpp::header.interfacesTable  = *(uint32_t*)(il2cpp::s_MHYTable + 0x1C4) - 1518027399u;   // 步长 6
    il2cpp::header.nestedTypesTable = *(uint32_t*)(il2cpp::s_MHYTable + 0x05C) - 381850355u;    // 步长 4

    il2cpp::header.genericContainers = *(uint32_t*)(il2cpp::s_MHYTable + 0x28) ^ 0x774A3BA6u;    // 步长 16
    il2cpp::header.genericParameters = *(uint32_t*)(il2cpp::s_MHYTable + 0x170) ^ 0x7B3B96A2u;   // 步长 14
    il2cpp::header.genericParameterCount = 0;   // ❌ 未定位（0x130 实为 genericMethodTableCount，勿再误用）

    // ================================================================================
    // ⚠️⚠️  以下字段**未在本版本定位**。旧版公式保留，但本版本这些槽位的含义已变，
    //       读到的值**是错的**。启用前必须先按 status.md §6 的方法重新定位槽位。
    //       影响面：常量默认值、自定义属性值（均属尚未接通的功能）。
    //       另注：本版本结构**多出** nestedTypesStart/Count（原版没有），布局是重排过的，
    //       不能按原版字段一一对应。
    // ================================================================================

    // ❌ 已被 interfacesTable（槽位 0x1C4，已验证）取代，本版本**无任何调用者**
    il2cpp::header.interfacesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x1F8) - 0x7A409361u;

    // ❌ 仅被上面 `#if 0` 的旧 collectFields 引用（字段已用新路径走通，实际不需要）
    il2cpp::header.fieldTableOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x30) ^ 0x72BDC288;
    il2cpp::header.fieldIndexTableOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0xA4) - 0x0F6CD032;
#if 0   // 旧公式会覆盖上面已验证的 fieldOffset(0x204)，故禁用；保留仅为不丢信息
    il2cpp::header.fieldOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0xE4) - 0x409D95E9;
#endif

    // [V-实测] fieldDefaultValues：12 字节 {fieldIndex@0, dataIndex@4, typeIndex@8}。
    //   靠结构自证：meta 0x3D00688 处 fieldIndex 严格递增（535..440164）且 < 440172（字段数），
    //   dataIndex 4 字节对齐递增（176..661724），typeIndex 全为合法 Il2CppType 索引
    //   （大量 = 70 = Il2CppType[70] = Int32），共 75504 项。
    //   ⚠️ 槽位+密钥公式未解（读者不在已反编译的 49 个函数里），故此处直接用实测地址；
    //      版本更新后必须重新定位。
    il2cpp::header.fieldDefaultValuesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x13C) ^ 0x593DE464u;
    il2cpp::header.fieldDefaultValuesCount  = 75548;
    // [V-实测] 常量值 blob：fieldDefaultValues[i].dataIndex 相对于它。
    //   定位法：AttributeTargets 是 [Flags] 枚举、值确定（Field=256, Event=512, ... All=32767），
    //   用这 8 个值的 4 字节 LE 序列在全 .dat 搜 -> 唯一命中；再用该类型 17 个字段反验证全对。
    //   ⚠️ 槽位+密钥公式未解（同 fieldDefaultValues），故直接写实测地址。
    il2cpp::header.fieldAndParameterDefaultValueDataOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x0A0) ^ 0x3F525210u;

    // 实测自 GetDefaultParameterValueObject(@0x140529DC0):
    //   base  = MHY[0x104] ^ 0x094C42AB        （注意：不是 6.7 的 0x98）
    //   count = (MHY[0x9C] - 259975212) / 12   （0x9C 是字节大小槽位）
    //   struct 为 {parameterIndex, dataIndex, typeIndex}，线性查找（未排序）
    il2cpp::header.parameterDefaultValuesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x104) ^ 0x094C42ABu;
    il2cpp::header.parameterDefaultValuesCount = *(uint32_t*)(il2cpp::s_MHYTable + 0x09C) - 259975212u;

#if 0   // 旧公式会覆盖上面已验证的 eventsOffset(0x1E8)，故禁用；保留仅为不丢信息
    il2cpp::header.eventsOffset = *(int32_t*)(il2cpp::s_MHYTable + 0xF4) - 0x542B037D;
#endif

    // ❌ 本版本没有独立的字面量条目表（offset/length 打包进 nameIndex）-> 无此字段
    il2cpp::header.stringLiteralOffset = 0;

    // [V-struct] attributesInfo：8 字节项 {customAttributeIndex@+0, range@+4}；
    //   range 打包 count=>24 / start=&0xFFFFFF，实测区间无缝平铺。
    //   注意：本版本表按 customAttributeIndex 排序（非 6.7 的 token），
    //   所以 customAttr() 的 token 查找逻辑需要改，不仅是换常量。
    il2cpp::header.attributesInfoOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x024) - 1545100391u;
    il2cpp::header.attributesInfoCount  = ((*(uint32_t*)(il2cpp::s_MHYTable + 0x198) - 1137860102u) >> 3);

    // [V] attributeTypes：4 字节项，**带 tag**，取 `v & 0xFFFFFF` 才是 Il2CppType 索引
    //   （实测全部 < 683574 = typesCount，解出的类型名正确；同名混淆项属预期）。
    il2cpp::header.attributeTypesOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x0D8) - 1927885444u;

    // [V] methodSpecs：12 字节项 {methodDefinitionIndex, classIndexIndex, methodIndexIndex}；
    //   来源 init:2256 `methodSpecs[genericMethodIndex]`（GenericMetadata::Register 内联）。
    il2cpp::header.methodSpecs = *(uint32_t*)(il2cpp::s_MHYTable + 0x1D8) ^ 0x1F85ABE5u;
    // methodSpecsCount：**表里没有对应槽位**（init 三处用法都只读 +0/+4/+8，无计数）。
    // 用实测边界：第 610109 条起 methodDefinitionIndex 越界。
    // 安全下界 = max(genericMethodIndex)+1 = 563653（游戏从不超过它）。
    il2cpp::header.methodSpecsCount = 610109;

    il2cpp::header.genericInstsCount = *(uint32_t*)(il2cpp::s_Table1 + 0x50) + 0x9B1B5919u;
    // [V] 泛型实例表（文章 MetadataCache::Register 内联，init:1447-1465）：
    //   8 字节项 {argStart@+0, argc@+4}；类型参数在 4 字节数组里（-1 哨兵），
    //   取到后经 GetIl2CppTypeFromIndex。start 严格无缝累计是强验证。
    il2cpp::header.genericClassRangeOffset = *(uint32_t*)(il2cpp::s_MHYTable + 0x134) ^ 0x558E11ECu;
    il2cpp::header.genericTypeArgOffset    = *(uint32_t*)(il2cpp::s_MHYTable + 0x180) - 898198093u;
    il2cpp::header.genericClassRangeCount  = 13671;   // 实测（start 重新归 0 处即为表尾）
    // [V] genericMethodTable：14 字节项 {genericMethodIndex, methodIndex, invokerIndex, w=0xFFFF}；
    //   来源 init:2243 `v571 = globalBase + (MHY[0xC0] - 1630172749)`，步长 14*n。
    il2cpp::header.genericMethodTable = *(uint32_t*)(il2cpp::s_MHYTable + 0xC0) - 1630172749u;
    il2cpp::header.genericMethodTableCount = ((*(uint32_t*)(il2cpp::s_MHYTable + 0x130) - 565220529u) / 14);

    // Il2CppType 数组：旧版是 Il2CppMetadataRegistration+0x70，本版本该结构搬到运行时
    // 数组总表 T1（0x142870A88，由静态构造器 0x1402F2910 注册），且偏移改成 +0x48。
    // 实测：T1+0x48 = 0x142E1EA20（16 字节/项，类型码在项内 +0x0A）；
    //       T1+0x70 = 0，所以旧偏移在任何基址上都读不到 —— 必须同时换基址和偏移。
    il2cpp::s_Il2CppMetadataRegistration = il2cpp::s_Table1;   // 指向 T1
    // [V] genericInsts = *(T1+0x08)：16 字节 {argc@+0, pad, Il2CppType** argv@+8}。
    //   验证：argv[0]/argv[1] 指向 Il2CppType 数组内的项（0x142E1EA30 = Il2CppType[1]）。
    il2cpp::s_GenericInsts = exe.data() + pe->va_to_offset(*(uint64_t*)(il2cpp::s_Table1 + 0x08));
    // [V] Il2CppType 数组 = *(T1+0x48)。同 GenericInsts：VA -> host 指针。
    il2cpp::s_Il2CppTypesVA = *(uint64_t*)(il2cpp::s_Table1 + 0x48);
    il2cpp::s_Il2CppTypes = exe.data() + pe->va_to_offset(il2cpp::s_Il2CppTypesVA);
    // [V] 方法指针数组 = *(T0+0x60)。表 T0 的全局是 qword_145AD5298 = 0x1422DE370；
    //   实测 3000/3000 项落在 .text，且 79765 项后正好紧接表 T1 起始（边界吻合）。
    // [V] 泛型方法指针（文章 CR+0x60）：只用于泛型实例的 RVA
    il2cpp::s_MethodPointerArray = exe.data() + pe->va_to_offset(*(uint64_t*)(il2cpp::s_Table0 + 0x60));
    // [V] 非泛型方法地址表（文章 +0x80[index]）：`*(T0+0x88)` 按 methodIndex 直接索引
    il2cpp::s_MethodPointerByIndex = exe.data() + pe->va_to_offset(*(uint64_t*)(il2cpp::s_Table0 + 0x88));
    // [V] invoker 数组 = *(T0+0x48)，按 slot 索引。验证：条数 12827 == 数组长度，slot 恰为 0..12826。
    il2cpp::s_InvokerArray = exe.data() + pe->va_to_offset(*(uint64_t*)(il2cpp::s_Table0 + 0x48));

    // 0x141F88938 实测是代码（`00 00 00 33 C0 E9 78 FF` 落在指令中间），
    // CodeRegistration 的新位置未定位，保留旧值仅为不丢失参考。
    (void)il2cpp::s_Il2CppCodeRegistration;
}




int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "usage: " << argv[0] << " <game_root_dir>\n"
                     "  expects <game_root_dir>/gi/Managed/Metadata/global-metadata.dat\n"
                     "          <game_root_dir>/gi/Managed/Metadata/startup-metadata.dat\n"
                     "          <game_root_dir>/gi.exe\n";
        return 1;
    }

    std::string metaDir = (std::string)argv[1] + kPathSep + "gi" + kPathSep + "Managed" + kPathSep + "Metadata" + kPathSep;
    std::string dllDir = (std::string)argv[1] + kPathSep;

    auto global = readFile(metaDir + "global-metadata.dat");
    auto startup = readFile(metaDir + "startup-metadata.dat");
    exe = readFile(dllDir + "gi.exe");
    pe = LIEF::PE::Parser::parse(dllDir + "gi.exe");

    il2cpp::s_GlobalMetadataHeader = global.data() + 0x210;
    il2cpp::metadataSize = global.size();
    il2cpp::s_StartupMetadataHeader = startup.data();
    il2cpp::s_MHYTable = exe.data() + pe->va_to_offset(0x1427D4BD0);   // 本样本 MHY 表（见 ANALYSIS.md §3.1）
    il2cpp::s_Table1  = exe.data() + pe->va_to_offset(0x142870A88);  // 运行时数组总表 = 本版本的 MetadataRegistration
    il2cpp::s_Table0  = exe.data() + pe->va_to_offset(0x1422DE370);
    il2cpp::s_Il2CppCodeRegistration = exe.data() + pe->va_to_offset(0x141F88938);  // 旧地址，未使用

    decryptHeader();

    string_Literal();
    customAttr();

    imageDef();
    typeDef();

    return 0;
}
