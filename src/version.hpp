// ============================================================================
//  自动生成 —— 不要手改！
//  来源: version.json   （用 tools/gen_version.py 生成，make 会自动调用）
//  版本: 7.1 (sample)
// ============================================================================
#pragma once
#include <cstdint>
#include <cstddef>

namespace ver {

struct OpKey { char op; uint64_t key; };
struct Table {
    uint32_t slot; char op; uint64_t key;
    uint32_t stride; bool startup;
    const char* role;  // "offset" | "count_div"
    int32_t countBias; // count_div 时额外加的偏置（如 -2）
};

// ---------------- 全局地址 ----------------
inline constexpr uint64_t kMhyTableVA = 0x1427D4BD0;
inline constexpr uint64_t kTable0VA = 0x1422DE370;
inline constexpr uint64_t kTable1VA = 0x142870A88;
inline constexpr uint64_t kCodeRegistrationVA = 0x141F88938;
inline constexpr uint32_t kGlobalMetadataHeaderOffset = 528;

// ---------------- 字符串解密 ----------------
inline constexpr uint32_t kEntryXor = 0x772FA51Eu;
inline constexpr uint64_t kKeyMulA = 0x5C2B4E660E2D0544ull;
inline constexpr uint64_t kKeyMulB = 0x694418957C890198ull;
inline constexpr uint64_t kKeySeed = 0x55A357D81EF0E48Bull;
inline constexpr uint64_t kKeyStep = 0x6B0B40C349AE61E5ull;
inline constexpr uint32_t kOffsetMask = 0xFFFFFFu;
inline constexpr uint32_t kLengthShift = 24u;

// ---------------- 元数据表 ----------------
inline constexpr Table kImagesCount = { 0x02C, '-', 0x2465B023, 40, false, "bytes", 0 };
inline constexpr Table kImagesOffset = { 0x20C, '-', 0x0ECB27F5, 40, true, "offset", 0 };
inline constexpr Table kStringLiteralDataOffset = { 0x184, '+', 0xBF9D4735, 0, false, "offset", 0 };
inline constexpr Table kTypeDefinitionsOffset = { 0x0B4, '-', 0x13B75461, 70, false, "offset", 0 };
inline constexpr Table kTypeDefinitionsCount = { 0x0E0, '-', 0x1D064F83, 70, false, "count_div", -2 };
inline constexpr Table kMethodsOffset = { 0x16C, '-', 0x1CCA7654, 26, false, "offset", 0 };
inline constexpr Table kMethodsCount = { 0x188, '^', 0x1B58E334, 26, false, "count_div", 0 };
inline constexpr Table kMethodPointerIndexOffset = { 0x94, '^', 0x4A4C0A71, 4, false, "offset", 0 };
inline constexpr Table kMethodSlotTableOffset = { 0x140, '-', 1832561230, 6, false, "offset", 0 };
inline constexpr Table kMethodSlotCount = { 0x1FC, '-', 127184164, 6, false, "count_div", 0 };
inline constexpr Table kParametersOffset = { 0x114, '^', 0x3E5D33E6, 8, false, "offset", 0 };
inline constexpr Table kPropertiesOffset = { 0x150, '-', 0x1C3D5389, 10, false, "offset", 0 };
inline constexpr Table kFieldsOffset = { 0x18C, '-', 336578260, 8, false, "offset", 0 };
inline constexpr Table kEventsOffset = { 0x1E8, '^', 0x100547B1, 14, false, "offset", 0 };
inline constexpr Table kFieldOffset = { 0x204, '-', 450622139, 4, false, "offset", 0 };
inline constexpr Table kInterfacesTable = { 0x1C4, '-', 1518027399, 6, false, "offset", 0 };
inline constexpr Table kNestedTypesTable = { 0x05C, '-', 381850355, 4, false, "offset", 0 };
inline constexpr Table kGenericContainers = { 0x028, '^', 0x774A3BA6, 16, false, "offset", 0 };
inline constexpr Table kGenericParameters = { 0x170, '^', 0x7B3B96A2, 14, false, "offset", 0 };
inline constexpr Table kFieldDefaultValuesOffset = { 0x13C, '^', 0x593DE464, 12, false, "offset", 0 };
inline constexpr Table kFieldAndParameterDefaultValueDataOffset = { 0x0A0, '^', 0x3F525210, 0, false, "offset", 0 };
inline constexpr Table kParameterDefaultValuesOffset = { 0x104, '^', 0x094C42AB, 12, false, "offset", 0 };
inline constexpr Table kParameterDefaultValuesCount = { 0x09C, '-', 259975212, 12, false, "bytes", 0 };
inline constexpr Table kAttributesInfoOffset = { 0x024, '-', 1545100391, 8, false, "offset", 0 };
inline constexpr Table kAttributesInfoCount = { 0x198, '-', 1137860102, 8, false, "count_div", 0 };
inline constexpr Table kAttributeTypesOffset = { 0x0D8, '-', 1927885444, 4, false, "offset", 0 };
inline constexpr Table kMethodSpecs = { 0x1D8, '^', 0x1F85ABE5, 12, false, "offset", 0 };
inline constexpr Table kGenericClassRangeOffset = { 0x134, '^', 0x558E11EC, 8, true, "offset", 0 };
inline constexpr Table kGenericTypeArgOffset = { 0x180, '-', 898198093, 4, true, "offset", 0 };
inline constexpr Table kGenericMethodTable = { 0x0C0, '-', 1630172749, 14, false, "offset", 0 };
inline constexpr Table kGenericMethodTableCount = { 0x130, '-', 565220529, 14, false, "count_div", 0 };
inline constexpr Table kInterfacesOffsetDeprecated = { 0x1F8, '-', 0x7A409361, 0, false, "offset", 0 };
inline constexpr Table kFieldTableOffsetDeprecated = { 0x30, '^', 0x72BDC288, 0, false, "offset", 0 };
inline constexpr Table kFieldIndexTableOffsetDeprecated = { 0xA4, '-', 0x0F6CD032, 0, false, "offset", 0 };

// ---------------- 实测计数（表里没有）----------------
inline constexpr Table kGenericClassRangeCountFormula = { 0x80, '^', 0x4E013BBD, 0, false, "count_raw", 0 };  // T0
inline constexpr Table kGenericInstsCountFormula = { 0x50, '+', 0x9B1B5919, 0, false, "count_raw", 0 };  // T1
inline constexpr Table kTypesCountFormula = { 0x54, '^', 0x6622B34E, 0, false, "count_raw", 0 };  // T1

// ---------------- T0/T1 字段偏移 ----------------
inline constexpr uint32_t kT0MethodPointerIndexArray = 0x88;
inline constexpr uint32_t kT0InvokerArray = 0x48;
inline constexpr uint32_t kT0GenericMethodPointers = 0x60;
inline constexpr uint32_t kT1GenericInsts = 0x08;
inline constexpr uint32_t kT1Il2CppTypes = 0x48;

// ---------------- 逐索引 key 公式参数 ----------------
inline constexpr uint64_t kMethodKeyA = 860405619;
inline constexpr uint64_t kMethodKeyXor = 0x73758947;
inline constexpr uint64_t kMethodKeyAdd = 1547935323;
inline constexpr uint64_t kFieldKeyB = 34782;
inline constexpr uint64_t kFieldKeyXor = 0x59B1DB19;
inline constexpr uint64_t kFieldKeyA = 1824013172;
inline constexpr uint64_t kFieldKeyShift = 16;
inline constexpr uint64_t kFieldKeyAdd = 1410079245;
inline constexpr uint64_t kPropertyKeyB = 0x17A5419F8A28ull;
inline constexpr uint64_t kPropertyKeyShift1 = 9;
inline constexpr uint64_t kPropertyKeyA = 976451930;
inline constexpr uint64_t kPropertyKeyShift2 = 12;
inline constexpr uint64_t kPropertyKeyXor = 0x70BE4B04;
inline constexpr int64_t kEventKeyA = -1599256506;
inline constexpr uint64_t kEventKeyAdd = 1725894951;
inline constexpr uint64_t kEventKeyXor = 0x1B23E40F;
inline constexpr uint64_t kParamKeyB = 41617;
inline constexpr uint64_t kParamKeyAdd1 = 1219887025;
inline constexpr uint64_t kParamKeyXor1 = 0x19E1D47A;
inline constexpr uint64_t kParamKeyA = 1457992407;
inline constexpr uint64_t kParamKeyShift = 21;
inline constexpr uint64_t kParamKeyAdd2 = 2068375556;
inline constexpr uint64_t kImageKeyB = 667674736;
inline constexpr uint64_t kImageKeyInnerMul = 13029;
inline constexpr uint64_t kImageKeyInnerXor = 0x43E2DEB7;
inline constexpr uint64_t kImageKeyInnerAdd = 0xCB287082F0ull;
inline constexpr uint64_t kImageKeyShift1 = 8;
inline constexpr uint64_t kImageKeyA = 1368137530;
inline constexpr uint64_t kImageKeyAdd = 1505552983;
inline constexpr uint64_t kContainerKeyB = 1015151837;
inline constexpr uint64_t kContainerKeyInnerMul = 10661;
inline constexpr uint64_t kContainerKeyInnerAdd = 1371718001;
inline constexpr uint64_t kContainerKeyInnerXor = 0x146D2C3D;
inline constexpr uint64_t kContainerKeyXor = 0x5D7F95E0;
inline constexpr uint64_t kContainerKeyA = 1714760523;
inline constexpr uint64_t kContainerKeyShift = 19;
inline constexpr uint64_t kGenericParamKeyB = 1845531077;
inline constexpr uint64_t kGenericParamKeyInnerMul = 12124;
inline constexpr uint64_t kGenericParamKeyInnerAdd = 1969070457;
inline constexpr uint64_t kGenericParamKeyInnerXor = 0x423B2C8D;
inline constexpr uint64_t kGenericParamKeyShift = 10;
inline constexpr uint64_t kGenericParamKeyAdd = 1212570291;
inline constexpr uint64_t kGenericParamKeyXor = 0x62A3A8F4;

// ---------------- 字段解码（每个字段一组 op/key）----------------
inline constexpr OpKey kTypeDefNamespaceIndex = { '-', 1145778368 };  // sub:1145778368
inline constexpr OpKey kTypeDefPropertyStart = { '-', 1995389561 };  // sub:1995389561
inline constexpr OpKey kTypeDefMethodStart = { '^', 0x4D8127F2 };  // xor:0x4D8127F2
inline constexpr OpKey kTypeDefParentIndex = { '-', 0x3D74901F };  // sub:0x3D74901F
inline constexpr OpKey kTypeDefFieldStart = { '^', 0x29010897 };  // xor:0x29010897
inline constexpr OpKey kTypeDefUnknown20 = { '^', 0x2E8C0EB8 };  // xor:0x2E8C0EB8
inline constexpr OpKey kTypeDefNameIndex = { '-', 72511848 };  // sub:72511848
inline constexpr OpKey kTypeDefFlags = { '-', 0x4159BB8E };  // sub:0x4159BB8E
inline constexpr OpKey kTypeDefMethodCount = { '-', 0xED3A };  // sub:0xED3A
inline constexpr OpKey kTypeDefEventStart = { '+', 3330 };  // add:3330
inline constexpr OpKey kTypeDefNestedTypesStart = { '+', 6631 };  // add:6631
inline constexpr OpKey kTypeDefFieldCount = { '^', 0x51A8 };  // xor:0x51A8
inline constexpr OpKey kTypeDefInterfacesStart = { '^', 0x43DA };  // xor:0x43DA
inline constexpr OpKey kTypeDefGenericContainerIndex = { '-', 26230 };  // sub:26230
inline constexpr OpKey kTypeDefInterfacesCount = { '+', 56 };  // add:56
inline constexpr OpKey kTypeDefPropertyCount = { '^', 0x16 };  // xor:0x16
inline constexpr OpKey kTypeDefEventCount = { '+', 113 };  // add:113
inline constexpr OpKey kTypeDefNestedTypesCount = { '^', 0xBA };  // xor:0xBA
inline constexpr OpKey kMethodNameIndex = { '-', 1524016681 };  // sub:1524016681
inline constexpr OpKey kMethodParameterStart = { '-', 257927898 };  // sub:257927898
inline constexpr OpKey kMethodReturnType = { '^', 0x3F7BDF39 };  // xor:0x3F7BDF39
inline constexpr OpKey kMethodDeclaringType = { '^', 0x59244785 };  // xor:0x59244785
inline constexpr OpKey kMethodIflags = { '-', 25344 };  // sub:25344
inline constexpr OpKey kMethodFlags = { '^', 0x8F60 };  // xor:0x8F60
inline constexpr OpKey kMethodParameterCount = { '-', 31 };  // sub:31
inline constexpr OpKey kFieldTypeIndex = { '^', 0x2D27D873 };  // xor:0x2D27D873
inline constexpr OpKey kFieldNameIndexBase = { '-', 1475293452 };  // sub:1475293452
inline constexpr OpKey kFieldNameIndexXor = { '^', 0x2D027B84 };  // xor:0x2D027B84
inline constexpr OpKey kPropertyNameIndex = { '-', 1953953095 };  // sub:1953953095
inline constexpr OpKey kPropertyGet = { '^', 0xE5A2 };  // xor:0xE5A2
inline constexpr OpKey kPropertySet = { '-', 23324 };  // sub:23324
inline constexpr OpKey kEventTypeIndex = { '-', 452544412 };  // sub:452544412
inline constexpr OpKey kEventNameIndex = { '-', 1037298109 };  // sub:1037298109
inline constexpr OpKey kEventAdd = { '^', 0xBEA7 };  // xor:0xBEA7
inline constexpr OpKey kEventRemove = { '^', 0xEE66 };  // xor:0xEE66
inline constexpr OpKey kEventRaise = { '-', 30703 };  // sub:30703
inline constexpr OpKey kParameterTypeIndex = { '^', 0x31BF59F3 };  // xor:0x31BF59F3
inline constexpr OpKey kParameterNameIndexBase = { '-', 1764493660 };  // sub:1764493660
inline constexpr OpKey kParameterNameIndexXor = { '^', 0x4CDBD093 };  // xor:0x4CDBD093
inline constexpr OpKey kGenericContainerParameterStart = { '^', 0x138FD4C7 };  // xor:0x138FD4C7
inline constexpr OpKey kGenericContainerArgc = { '-', 1053517166 };  // sub:1053517166
inline constexpr OpKey kGenericParameterNameIndex = { '^', 0x664CCEB9 };  // xor:0x664CCEB9

// ---------------- 结构体尺寸 ----------------
inline constexpr size_t kSize_Il2CppImageDefinition = 0x28;
inline constexpr size_t kSize_Il2CppTypeDefinition = 0x46;
inline constexpr size_t kSize_Il2CppType = 0x10;
inline constexpr size_t kSize_Il2CppFieldDefinition = 0x08;
inline constexpr size_t kSize_Il2CppFieldDefaultValue = 0xC;
inline constexpr size_t kSize_Il2CppMethodDefinition = 0x1A;
inline constexpr size_t kSize_Il2CppParameterDefinition = 0x08;
inline constexpr size_t kSize_Il2CppParameterDefaultValue = 0xC;
inline constexpr size_t kSize_Il2CppPropertyDefinition = 0xA;
inline constexpr size_t kSize_Il2CppEventDefinition = 0xE;
inline constexpr size_t kSize_Il2CppStringLiteral = 0x08;
inline constexpr size_t kSize_Il2CppCustomAttributeTypeRange = 0x08;
inline constexpr size_t kSize_Il2CppGenericContainer = 0x10;
inline constexpr size_t kSize_Il2CppGenericParameter = 0xE;
inline constexpr size_t kSize_Il2CppGenericInst = 0x10;
inline constexpr size_t kSize_Il2CppMethodSpec = 0xC;
inline constexpr size_t kSize_Il2CppGenericMethodIndices = 0x08;
inline constexpr size_t kSize_Il2CppGenericMethodFunctionsDefinitions = 0x0E;

// ---------------- 锚点自检值（verify.py 会独立验证）----------------
inline constexpr uint32_t kAnchor_FieldDefaultValues = 0x3D00478;
inline constexpr uint32_t kAnchor_Blob               = 0x00F1754C;
inline constexpr uint32_t kAnchor_ParameterDefaultValues = 0x37274C0;

} // namespace ver
