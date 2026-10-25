// ============================================================================
//  Dumper —— 输出格式化
//
//  职责：把 Il2CppImage 里的元数据渲染成 dump.cs / stringliteral.json。
//  不负责：读文件 / 解析元数据（MetadataFiles / Il2CppImage 的事）。
//
//  ⚠️ 代码体由 tools/split_main.py 从原 main.cpp 机械搬运，逐字一致；
//     换版本时改 version.json，不要改这里。
// ============================================================================
#pragma once

#include "il2cpp_image.hpp"
#include "attributes.hpp"

// parseGenerator 需要 capstone
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <unordered_set>
#include <cstring>
#include <format>
#include <limits>
#include <memory>
#include <sstream>
#include <iomanip>

#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

class Dumper {
public:
    Dumper(Il2CppImage& img, MetadataFiles& files, const std::string& outDir,
           bool trace = false)
        : img_(img), files_(files), trace_(trace),
          dumpOut_(outDir + "/dump.cs"),
          stringLiteralOut_(outDir + "/stringliteral.json") {}

    // 各输出段，顺序与原 main() 一致
    void run() {
        using Clock = std::chrono::steady_clock;
        const auto tAll = Clock::now();

        auto stage = [&](const char* name, auto&& fn) {
            const auto t0 = Clock::now();
            fn();
            const double sec = std::chrono::duration<double>(Clock::now() - t0).count();
            std::cerr << std::format("[dump] stage {:<18} {:8.3f}s\n", name, sec);
        };

        stage("stringLiteral", [&] { string_Literal(); });
        stage("customAttr",    [&] { customAttr(); });
        stage("imageDef",      [&] { imageDef(); });
        stage("typeDef",       [&] { typeDef(); });

        const double total = std::chrono::duration<double>(Clock::now() - tAll).count();
        std::cerr << std::format(
            "[dump] stats images={} types={} methods={} fields={} properties={} events={}\n",
            nImages_, nTypes_, methods.size(), nFields_, nProperties_, nEvents_);
        std::cerr << std::format("[dump] stage {:<18} {:8.3f}s\n", "total", total);
    }

private:
    Il2CppImage&   img_;
    MetadataFiles& files_;
    std::ofstream  dumpOut_;
    std::ofstream  stringLiteralOut_;
    bool           trace_ = false;
    uint64_t nImages_ = 0;
    uint64_t nTypes_ = 0;
    uint64_t nFields_ = 0;
    uint64_t nProperties_ = 0;
    uint64_t nEvents_ = 0;
    using Il2CppTypeEnum = Il2CppImage::Il2CppTypeEnum;
    using Il2CppArrayType = Il2CppImage::Il2CppArrayType;
    using Il2CppCustomAttributeTypeRange = Il2CppImage::Il2CppCustomAttributeTypeRange;
    using Il2CppEventDefinition = Il2CppImage::Il2CppEventDefinition;
    using Il2CppFieldDefaultValue = Il2CppImage::Il2CppFieldDefaultValue;
    using Il2CppFieldDefinition = Il2CppImage::Il2CppFieldDefinition;
    using Il2CppGenericContainer = Il2CppImage::Il2CppGenericContainer;
    using Il2CppGenericInst = Il2CppImage::Il2CppGenericInst;
    using Il2CppGenericMethodFunctionsDefinitions = Il2CppImage::Il2CppGenericMethodFunctionsDefinitions;
    using Il2CppGenericMethodIndices = Il2CppImage::Il2CppGenericMethodIndices;
    using Il2CppGenericParameter = Il2CppImage::Il2CppGenericParameter;
    using Il2CppImageDefinition = Il2CppImage::Il2CppImageDefinition;
    using Il2CppMethodDefinition = Il2CppImage::Il2CppMethodDefinition;
    using Il2CppMethodSpec = Il2CppImage::Il2CppMethodSpec;
    using Il2CppParameterDefaultValue = Il2CppImage::Il2CppParameterDefaultValue;
    using Il2CppParameterDefinition = Il2CppImage::Il2CppParameterDefinition;
    using Il2CppPropertyDefinition = Il2CppImage::Il2CppPropertyDefinition;
    using Il2CppStringLiteral = Il2CppImage::Il2CppStringLiteral;
    using Il2CppType = Il2CppImage::Il2CppType;
    using Il2CppTypeDefinition = Il2CppImage::Il2CppTypeDefinition;

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

public:


    


void imageDef()
{
    uint32_t s_ImagesCount = img_.header.imagesCount / sizeof(Il2CppImageDefinition);
    const Il2CppImageDefinition* imagesDefinitions = (const Il2CppImageDefinition*)(img_.s_StartupMetadataHeader + img_.header.imagesOffset);
    for (uint32_t imageIndex = 0; imageIndex < s_ImagesCount; imageIndex++)
    {
        const Il2CppImageDefinition* imageDefinition = imagesDefinitions + imageIndex;
        // 本版本的逐索引 key（解密用；已验证 75/75）
        uint32_t key = img_.ImageIndexKey(imageIndex);

        // typeStart 的字段偏移和解码公式都由各自的 version.json 提供。
        uint32_t rawTypeStart = *(const uint32_t*)((const uint8_t*)imageDefinition + ver::kIl2CppImageDefinitionTypeStartOffset);
        uint32_t typeStart = ver::decImageTypeStart(rawTypeStart, key);

        // nameIndex 属于解密部分：offset(24)+length(8)；字段偏移/解码形状由 version.json 决定
        uint32_t rawNameIndex = *(const uint32_t*)((const uint8_t*)imageDefinition + ver::kIl2CppImageDefinitionNameIndexOffset);
        uint32_t nameIndex = img_.DecodeImageName(rawNameIndex, imageIndex);

        std::string name{img_.GetStringFromIndex(nameIndex)};

        dumpOut_ << "// Image " << imageIndex << ": " << name << " - " << typeStart << std::endl;
        ++nImages_;
    }
    dumpOut_ << std::endl;
}

struct FieldInfo
{
    int32_t index;
    std::string name;
    const Il2CppType* type;
    std::string typeName;
    uint32_t offset;
};

std::vector<FieldInfo> collectFields(const Il2CppTypeDefinition* typeDefinition)
{
    std::vector<FieldInfo> out;

    // [V] fieldStart +0x1C ^ 0x29010897 ; field_count +0x38 ^ 0x51A8
    //     fields 数组 MHY[0x18C] - 336578260，步长 8，nameIndex @ +4
    //     字段偏移 MHY[0x204] - 450622139，步长 4
    int32_t трушный_старт = img_.typeFieldStart((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionFieldStartOffset));
    int32_t count = img_.typeFieldCount((uint16_t)img_.tdU16(typeDefinition, ver::kIl2CppTypeDefinitionFieldCountOffset));
    if (count <= 0 || count > 4096) return out;
    int32_t end = трушный_старт + count;

    for (int32_t j = 0; j < count; ++j)
    {
        uint32_t fieldIndex = (uint32_t)(трушный_старт + j);
        const Il2CppFieldDefinition* fieldDefinition = img_.GetFieldDefinitionFromIndex((int32_t)fieldIndex);

        // 字段偏移表：
        //   7.1：低 29 位偏移，高 3 位静态标志，直接用 local field index。
        //   7.0：base 表（MHY[0x14C]）给出该 type 的偏移基址，再查 fieldOffsetTable（MHY[0x13C]）。
        uint32_t local = (uint32_t)j;
        if (ver::kFieldOffsetBaseTable && ver::kFieldIndexTable)
        {
            const uint64_t tdIndex = ((const uint8_t*)typeDefinition
                - (img_.s_GlobalMetadataHeader + img_.header.typeDefinitionsOffset)) / 70;
            const uint32_t hash = (uint32_t)(-1963413621u * (uint32_t)((70 * tdIndex) >> 1));
            const int32_t idx = *(const int32_t*)(img_.s_GlobalMetadataHeader
                + (uint32_t)ver::kFieldIndexTable + 4ull * hash);
            if (idx >= 0 && idx < 1000000)
            {
                const uint8_t* ft = img_.s_GlobalMetadataHeader
                    + (uint32_t)ver::kFieldOffsetBaseTable + 12ull * idx;
                local += *(const uint32_t*)(ft + 8);
            }
        }
        uint32_t v35 = *(uint32_t*)(img_.s_GlobalMetadataHeader + img_.header.fieldOffset + 4ull * local);

        std::string name{ img_.GetStringFromIndex(
            img_.fieldNameIndex((uint32_t)fieldDefinition->nameIndex, fieldIndex)) };

        // typeIndex 在字段条目 +0，与 nameIndex 同一个 key (sub_140512870)
        int32_t typeIndexDec = img_.fieldTypeIndex((uint32_t)fieldDefinition->typeIndex, fieldIndex);
        if (typeIndexDec == -1) continue;
        const Il2CppType* type = img_.GetIl2CppTypeFromIndex(typeIndexDec);
        if (!type) continue;

        std::string typeName{ img_.NameFromIl2CppType(type) };

        uint32_t offset = v35 & (uint32_t)ver::kFieldOffsetMask;
        // 7.1 的静态字段标记在 0x01000000/0x02000000/0x04000000，
        // 7.0 是 0x01000000；统一按“高位有标记”处理。
        bool isStatic = ((v35 & (uint32_t)ver::kFieldStaticMask) == (uint32_t)ver::kFieldStaticValue) ||
                        ((v35 & (uint32_t)ver::kFieldStaticHighMask) != 0);
        if (isStatic && ver::kFieldStaticZero) offset = 0;   // 7.0：静态字段没有实例偏移

        // Il2Cpp 的实例字段偏移表包含对象头；只有 7.1 的参考 dump
        // 需要把值类型实例字段减去 0x10。7.0/6.7 的偏移表本身已经是最终值。
        const bool isValueType = img_.typeIsValueType(
            img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionBitfieldOffset)) != 0;
        if (isValueType && !isStatic && ver::kFieldOffsetValueTypeAdjust > 0 &&
            offset >= ver::kFieldOffsetValueTypeAdjust) {
            offset -= ver::kFieldOffsetValueTypeAdjust;
        }

        out.push_back({ fieldIndex, std::move(name), type, std::move(typeName), offset });
    }

    return out;

#if 0
    // ===== 上一版（本样本之前）的实现，原样保留，等 fieldTableOffset / fieldIndexTableOffset
    // 在本版本验证后放开。它走的是 typeIndex -> fieldTableOffset/fieldIndexTableOffset 的
    // 两级间接，而上面那条路径是直接用 typeDefinition 的 fieldStart + 字段偏移表。 =====
    int32_t start = typeFieldStart((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionFieldStartOffset));
    int32_t tr_start = start - 0x2318D1B4;
    int32_t count_old = typeFieldCount((uint16_t)img_.tdU16(typeDefinition, ver::kIl2CppTypeDefinitionFieldCountOffset));
    if (count_old == 0) return out;

    int32_t end_old = tr_start + count_old;

    const uint8_t* typeDefinitions = img_.s_GlobalMetadataHeader + img_.header.typeDefinitionsOffset;
    uint32_t typeIndex = (uint32_t)(-1963413621 * (((uint64_t)((const uint8_t*)typeDefinition - typeDefinitions)) >> 1));
    uint64_t v42 = (uint64_t)(img_.s_GlobalMetadataHeader + img_.header.fieldTableOffset + 12LL * *(uint32_t*)(img_.s_GlobalMetadataHeader + img_.header.fieldIndexTableOffset + 4LL * typeIndex));

    for (int32_t fieldIndex = tr_start; fieldIndex < end_old; ++fieldIndex)
    {
        const Il2CppFieldDefinition* fieldDefinition = img_.GetFieldDefinitionFromIndex(fieldIndex);
        uint32_t v35 = *(uint32_t*)(img_.s_GlobalMetadataHeader + (*(uint32_t*)(img_.s_MHYTable + 372) ^ 0x369C42D5u) + 4 * ((fieldIndex - tr_start) + (*(uint32_t*)(v42 + 8))));
        uint32_t key = (uint32_t)((((uint64_t)0xA3D685EE8C0ULL * fieldIndex >> 13) + 0x6C43549A) ^ 0x7B227EB7);

        std::string name{ img_.GetStringFromIndex((fieldDefinition->nameIndex ^ 0x2C9F4153u) - key) };

        if (((uint32_t)fieldDefinition->typeIndex - key) == 0x5422128A) continue;
        const Il2CppType* type = img_.GetIl2CppTypeFromIndex(fieldDefinition->typeIndex - key - 0x5422128B);
        if (!type) continue;

        std::string typeName{ img_.NameFromIl2CppType(type) };

        uint32_t offset = (v35 & 0x01000000) ? (v35 & 0xFFFFFF) : v35;

        // Il2CppObject
        bool isValueType = img_.typeIsValueType(img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionBitfieldOffset)) != 0;
        if (isValueType && offset > 0x0 && !(type->attrs & (FIELD_ATTRIBUTE_STATIC | FIELD_ATTRIBUTE_LITERAL))) offset -= 0x10;

        out.push_back({ fieldIndex, std::move(name), type, std::move(typeName), offset });
    }
#endif
}

std::string fieldDef(const Il2CppTypeDefinition* typeDefinition)
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
        const Il2CppFieldDefaultValue* entry = img_.GetDefaultValueForField(field.index);
        if (entry != NULL && img_.fdvDataIndex(entry) != -1)
        {
            auto* consttype = img_.GetIl2CppTypeFromIndex(img_.fdvTypeIndex(entry));
            uint8_t* defaultValuesData = (uint8_t*)((const char*)img_.s_GlobalMetadataHeader + img_.fdvDataIndex(entry) + img_.header.fieldAndParameterDefaultValueDataOffset);
            Il2CppTypeEnum code = consttype ? consttype->type : Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_END;
            constValue = img_.GetConstantValueFromBlob(code, defaultValuesData);
        }

        full += getcustomattr(0x04000000 | field.index, true) + "\t" + flags + field.typeName + " " + field.name + (constValue.empty() ? "" : " = " + constValue) + "; // 0x" + std::format("{:X}", field.offset) + "\n";
        ++nFields_;
    }

    return "\t// Fields\n" + full + "\n";
}


std::string methodDef(const Il2CppTypeDefinition* typeDefinition)
{
    static bool genericIndexBuilt = false;
    static std::unordered_map<int32_t, std::vector<uint32_t>> genericEntriesByMethod;

    std::string full{};
    // 已验证：methodStart ^ 0x4D8127F2，method_count - 0xED3A
    int32_t start = img_.typeMethodStart((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionMethodStartOffset));
    int32_t count = (int32_t)img_.typeMethodCount((uint16_t)img_.tdU16(typeDefinition, ver::kIl2CppTypeDefinitionMethodCountOffset));
    if (start < 0) start = 0;
    if (count <= 0 || count > (int32_t)img_.header.methodsCount) return "";

    int32_t end = start + count;

    for (int32_t index = start; index < end; ++index)
    {
        const Il2CppMethodDefinition* methodDefinition = img_.GetMethodDefinitionFromIndex(index);

        // 已验证：methodDefinition.nameIndex 在 +0x00，逐索引 key 后解包 entry
        std::string name{img_.GetStringFromIndex(
            img_.methodNameIndex(img_.mdU32(methodDefinition, ver::kIl2CppMethodDefinitionNameIndexOffset), (uint32_t)index))};

        // [V] flags / iflags（先算，方法指针要用到 VIRTUAL 位）
        uint16_t flags  = img_.methodFlags(img_.mdU16(methodDefinition, ver::kIl2CppMethodDefinitionFlagsOffset), (uint32_t)index);
        uint16_t iflags = img_.methodIFlags(img_.mdU16(methodDefinition, ver::kIl2CppMethodDefinitionIflagsOffset), (uint32_t)index);

        // [V] 方法地址双路径（文章：虚/重写取 +0x90[slot]，其余取 +0x80[index]）：
        //   非虚     = *(T0+0x60)[ MHY[0x94][methodIndex] ]
        //   虚/重写  = *(T0+0x48)[ MHY[0x140] 里查到的 slot ]
        uint64_t mptr = img_.methodPointer((uint32_t)index);
        // 7.1 的 slot 表覆盖了非虚/值类型方法：参考 dump 取的是
        // invoker 入口，而不是直接 methodPointer。7.0/6.7 仍保持原来的
        // “只有 virtual 才走 invoker”路径（由版本配置控制）。
        if (!(flags & METHOD_ATTRIBUTE_ABSTRACT) &&
            (ver::kUseInvokerForSlotMethods || (flags & METHOD_ATTRIBUTE_VIRTUAL)))
        {
            uint64_t inv = img_.methodInvoker((uint32_t)index);
            if (inv) mptr = inv;
        }
        std::string vaInfo;
        if (mptr)
        {
            uint64_t off = files_.pe()->va_to_offset(mptr);
            vaInfo = std::format("// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}\n",
                                 mptr - files_.pe()->optional_header().imagebase(), off, mptr);
        }
        // [V] returnType
        std::string retType;
        {
            int32_t rti = img_.methodReturnTypeIndex((uint32_t)index);
            if (rti >= 0 && img_.header.typesCount && (uint32_t)rti < img_.header.typesCount)
            {
                const Il2CppType* rt = img_.GetIl2CppTypeFromIndex(rti);
                if (rt) { retType = img_.NameFromIl2CppType(rt); if (!retType.empty()) retType += " "; }
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
        else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
            // 7.1 reference distinguishes override from a new virtual slot;
            // older versions keep their original virtual wording.
            if (ver::kUseOverrideKeyword && !(flags & METHOD_ATTRIBUTE_NEW_SLOT))
                attrs += "override ";
            else
                attrs += "virtual ";
        }
        if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) attrs += "extern ";

        // 泛型方法实例（已接，见下）；旧版整段保留在 #if 0。
        // [V] 参数列表
        std::string params;
        std::string lastParamType;   // 最后一个参数的类型（属性 setter / 事件用）
        {
            uint32_t c = img_.methodParamCount(img_.mdU8(methodDefinition, ver::kIl2CppMethodDefinitionParameterCountOffset), (uint32_t)index);
            if (c > 32) c = 32;
            uint32_t ps = img_.methodParamStart(img_.mdU32(methodDefinition, ver::kIl2CppMethodDefinitionParameterStartOffset), (uint32_t)index);
            const uint8_t* pbase = img_.s_GlobalMetadataHeader + img_.header.parametersOffset;
            for (uint32_t k = 0; k < c; k++)
            {
                uint32_t pi = ps + k;
                int32_t pni = img_.paramNameIndex(*(const uint32_t*)(pbase + 8 * pi + 4), pi);
                std::string pn{ img_.GetStringFromIndex(pni) };
                int32_t pti = img_.paramTypeIndex(*(const uint32_t*)(pbase + 8 * pi), pi);
                std::string pt;
                if (pti != -1) { const Il2CppType* t = img_.GetIl2CppTypeFromIndex(pti); if (t) pt = img_.NameFromIl2CppType(t); }
                if (k) params += ", ";
                params += pt + " " + pn;
                lastParamType = pt;
                // 参数默认值：表已定位并验证（25374 项）。原文这行在旧版的 #if 0 里，漏接了。
                if (auto* dv = img_.GetParamDefault(pi))
                {
                    std::string cv = img_.GetDefaultValueData(img_.pdvTypeIndex(dv), img_.pdvDataIndex(dv));
                    if (!cv.empty()) params += " = " + cv;
                }
            }
        }
        // [V] 泛型方法实例（数据链已独立验证：classIndexIndex/methodIndexIndex 索引 genericInsts 20319/0）
        {
            static bool gBuilt = false;
            static std::unordered_map<int32_t, std::vector<uint32_t>> gByMethod;
            const auto* specs = (const Il2CppMethodSpec*)(img_.s_GlobalMetadataHeader + img_.header.methodSpecs);
            const auto* gInsts = (const Il2CppGenericInst*)img_.s_GenericInsts;
            const auto* gmTab = (const Il2CppGenericMethodFunctionsDefinitions*)(img_.s_GlobalMetadataHeader + img_.header.genericMethodTable);
            const uint64_t* gmPtrs = (const uint64_t*)img_.s_MethodPointerArray;
            if (!gBuilt)
            {
                for (uint32_t t = 0; t < img_.header.genericMethodTableCount; ++t)
                {
                    const auto& e = gmTab[t];
                    if (e.genericMethodIndex < 0 || (uint32_t)e.genericMethodIndex >= img_.header.methodSpecsCount) continue;
                    if (e.indices.methodIndex < 0) continue;
                    gByMethod[specs[e.genericMethodIndex].methodDefinitionIndex].push_back(t);
                }
                gBuilt = true;
            }
            auto instName = [&](const Il2CppGenericInst* inst) -> std::string
            {
                if (!inst || inst->type_argc == 0 || inst->type_argc > 64) return "";
                const uint64_t* argv = (const uint64_t*)(files_.exe().data() + files_.pe()->va_to_offset((uint64_t)inst->type_argv));
                std::string r = "<";
                for (uint32_t k = 0; k < inst->type_argc; ++k)
                {
                    if (k) r += ", ";
                    uint64_t o = files_.pe()->va_to_offset(argv[k]);
                    if (o < files_.exe().size()) r += img_.NameFromIl2CppType((const Il2CppType*)(files_.exe().data() + o));
                }
                return r + ">";
            };
            auto it = gByMethod.find(index);
            if (it != gByMethod.end())
            {
                std::string ownerName{ img_.GetStringFromIndex(img_.typeNameIndex((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionNameIndexOffset))) };
                if (size_t q = ownerName.find('`'); q != std::string::npos) ownerName.resize(q);
                std::string instances;
                for (uint32_t t : it->second)
                {
                    const auto& e = gmTab[t];
                    const auto& sp = specs[e.genericMethodIndex];
                    const auto* ci = sp.classIndexIndex == -1 ? nullptr : gInsts + sp.classIndexIndex;
                    const auto* mi = sp.methodIndexIndex == -1 ? nullptr : gInsts + sp.methodIndexIndex;
                    uint64_t va = gmPtrs[e.indices.methodIndex];
                    if (va) instances += std::format("\n\t|-RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}", va - files_.pe()->optional_header().imagebase(), files_.pe()->va_to_offset(va), va);
                    instances += "\n\t|-" + ownerName + instName(ci) + "." + name + instName(mi) + "\n\t|";
                }
                if (!instances.empty()) full += "\t/* GenericInstMethod :" + instances + "\n\t*/\n";
            }
        }
        // [V] declaringType 一致性诊断：methodDefinition+0x0C 解出的声明类型应等于当前类型索引。
        //   不一致说明该方法在元数据里被挂到了别的类型下（正常不应发生）-> 输出标注。
        std::string declNote;
        const int32_t selfTypeIdx = (int32_t)(((const uint8_t*)typeDefinition
                                  - (img_.s_GlobalMetadataHeader + img_.header.typeDefinitionsOffset)) / 70);
        // [V] 7.1 实测 methodDeclaringType == 当前 typeDef：697727/697727；
        //     7.0 的 SetupMethodsLocked 也是 v17[1] = a1（当前 typeDef）。
        //     7.0 的 method 记录没有 declaringType 字段 -> 统一用当前 typeDef。
        //     7.1 输出不变（declNote 永远为空，与修改前一致）。
        const int32_t declType = selfTypeIdx;
        (void)declType;

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
        const Il2CppType* returnType = img_.GetIl2CppTypeFromIndex((methodDefinition->returnType - 978518114) ^ key);
        if (!returnType) continue;
        std::string typeName {img_.NameFromIl2CppType(returnType)};

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

        if (((img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionBitfieldOffset) << 6) & 0x40) != 0)
        {
            uint8_t* v27 = img_.s_GlobalMetadataHeader + (*(uint32_t*)(img_.s_MHYTable + 126 * 4) - 2095267037u);
            uint8_t* v28 = v27;
            if ((*(uint32_t*)(img_.s_MHYTable + 66 * 4) ^ 0x3D054A4Cu) >= 6)
            {
                uint64_t v36 = (*(uint32_t*)(img_.s_MHYTable + 66 * 4) ^ 0x3D054A4CuLL) / 6;
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
            uint8_t* v29 = v27 + 6 * ((*(uint32_t*)(img_.s_MHYTable + 66 * 4) ^ 0x3D054A4CuLL) / 6);
            if (v28 != v29 && v23 >= *(int32_t*)v28)
            {
                v30 = *(uint64_t*)(*(uint64_t*)(img_.s_Il2CppCodeRegistration + 144) + 8ULL * *(uint16_t*)(v28 + 4));
                if (v30)
                    goto LABEL_25;
            }
        }
        v30 = *(uint64_t*)(*(uint64_t*)(img_.s_Il2CppCodeRegistration + 0x80) + 8ULL * (uint32_t)v23);
LABEL_25:
        methodPointer = v30;

        if (!methodPointer) full += "\n\t// RVA: -1 Offset: -1 VA: -1\n";
        else {
            uint64_t rva = methodPointer - files_.pe()->optional_header().imagebase();
            uint64_t off = files_.pe()->va_to_offset(methodPointer);
            full += std::format("\n\t// RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}\n", rva, off, methodPointer);
        }

        uint8_t v9 = (uint8_t)(((0xC4 * index - 6) ^ 0xED) - 0x23);
        uint8_t parameter_count = v9 ^ methodDefinition->parameterCount ^ 0xE1;
        int32_t paramStartDec = (key ^ methodDefinition->parameterStart ^ 0x5A970208);

        std::string params;
        std::string lastParamType;
        for (uint16_t paramIndex = 0; paramIndex < parameter_count; ++paramIndex)
        {
            const Il2CppParameterDefinition* parameterDefinition = img_.GetParameterDefinitionFromIndex(paramStartDec + paramIndex);
            uint32_t parameter_key = (uint32_t)((-2072089200LL * (paramStartDec + paramIndex) - 1328203725) ^ 0xACC85C96);

            std::string parameter_name{ img_.GetStringFromIndex(parameterDefinition->nameIndex + parameter_key - 0x5D4A021B) };

            const Il2CppType* parameter_type = nullptr;
            if (parameter_key + (uint32_t)(parameterDefinition->typeIndex ^ 0x326A9F52) != 1109209749)
                parameter_type = img_.GetIl2CppTypeFromIndex((parameter_key + (parameterDefinition->typeIndex ^ 0x326A9F52) - 1109209750));
            uint16_t paramAttrs = parameter_type ? parameter_type->attrs : 0;

            if (!params.empty()) params += ", ";
            
            if (parameter_type && parameter_type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_BYREF) {
                if (paramAttrs & PARAM_ATTRIBUTE_IN) params += "in ";
                else if (paramAttrs & PARAM_ATTRIBUTE_OUT) params += "out ";
                else params += "ref ";
            } else {
                if (paramAttrs & PARAM_ATTRIBUTE_IN) params += "in ";
                if (paramAttrs & PARAM_ATTRIBUTE_OUT) params += "out ";
            }
            
            params += [](auto s) { return s.back() == '\n' ? s.back() = ' ', s : s; }(getcustomattr(0x08000000 | (paramStartDec + paramIndex))) + img_.NameFromIl2CppType(parameter_type) + " " + parameter_name;
            lastParamType = img_.NameFromIl2CppType(parameter_type);

            std::string constValue;
            if (auto* data = img_.GetParamDefault(paramStartDec + paramIndex)) 
            constValue = (img_.pdvDataIndex(data) == -1) ? "null" : img_.GetDefaultValueData(img_.pdvTypeIndex(data), img_.pdvDataIndex(data));
            
            params += (constValue.empty() ? "" : " = " + constValue);
        }

        if (methods.size() <= (size_t)index) methods.resize(index + 1);
        methods[index] = { name, typeName, attrs, lastParamType, methodPointer, flags, iflags };
        

        full += getcustomattr(0x06000000 | index, true) + "\t" + attrs + typeName + " " + name + "(" + params + ")" + " { }\n";
        {
            // [V] methodSpecs：12 字节 {methodDefinitionIndex, classIndexIndex, methodIndexIndex}
            const auto* specs = (const Il2CppMethodSpec*)(img_.s_GlobalMetadataHeader + img_.header.methodSpecs);
            uint32_t specCount = img_.header.methodSpecsCount;          // 已是条目数（实测 610109）
            // [V] genericInsts = *(T1+0x08)，16 字节 {argc@+0, pad, Il2CppType** argv@+8}
            const auto* genericInsts = (const Il2CppGenericInst*)img_.s_GenericInsts;

            // [V] genericMethodTable：14 字节 {genericMethodIndex, methodIndex, invokerIndex, w}
            const auto* genericMethodTable = (const Il2CppGenericMethodFunctionsDefinitions*)(img_.s_GlobalMetadataHeader + img_.header.genericMethodTable);
            uint32_t genericMethodTableCount = img_.header.genericMethodTableCount;   // 560659（条目数）
            // [V] 方法指针数组 = *(T0+0x60)，按 methodIndex 索引
            const auto* genericMethodPointers = (const uint64_t*)img_.s_MethodPointerArray;

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

            auto instName = [&](const Il2CppGenericInst* inst) -> std::string
                {
                    if (!inst) return "";
                    const uint64_t* argv = (const uint64_t*)(files_.exe().data() + files_.pe()->va_to_offset((uint64_t)inst->type_argv));
                    std::string result = "<";
                    for (uint32_t k = 0; k < inst->type_argc; ++k)
                    {
                        if (k) result += ", ";
                        result += img_.NameFromIl2CppType((const Il2CppType*)(files_.exe().data() + files_.pe()->va_to_offset(argv[k])));
                    }
                    return result + ">";
                };

            std::string ownerName{ img_.GetStringFromIndex(img_.typeNameIndex((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionNameIndexOffset))) };
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

                instances += std::format("\n\t|-RVA: 0x{:X} Offset: 0x{:X} VA: 0x{:X}", va - files_.pe()->optional_header().imagebase(), files_.pe()->va_to_offset(va), va);
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

std::string propDef(const Il2CppTypeDefinition* typeDefinition)
{
    std::string full{};
    // [V] propertyStart +0x08 - 1995389561 ; property_count +0x43 ^ 0x16
    //     properties 数组 MHY[0x150] - 0x1C3D5389，步长 10
    //     name@+0 / token@+4 / get@+6 / set@+8（0xFFFF = 无该访问器）
    uint32_t start = img_.typePropertyStart((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionPropertyStartOffset));
    uint32_t count = img_.typePropertyCount(img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionPropertyCountOffset));

    if (count == 0) return "";

    uint32_t end = start + count;

    for (uint32_t propertyIndex = start; propertyIndex < end; ++propertyIndex)
    {
        const Il2CppPropertyDefinition* propertyDefinition = img_.GetPropertyDefinitionFromIndex((int32_t)propertyIndex);

        std::string name {img_.GetStringFromIndex(
            img_.propertyNameIndex((uint32_t)propertyDefinition->nameIndex, propertyIndex))};

        // get/set 的字段偏移与解码形状由 version.json 决定（7.0: get@+4；7.1: get@+6）
        uint16_t rawGet = *(const uint16_t*)((const uint8_t*)propertyDefinition + ver::kIl2CppPropertyDefinitionGetOffset);
        uint16_t rawSet = *(const uint16_t*)((const uint8_t*)propertyDefinition + ver::kIl2CppPropertyDefinitionSetOffset);
        uint16_t get = img_.propertyGet(rawGet, propertyIndex);
        uint16_t set = img_.propertySet(rawSet, propertyIndex);
        bool hasGet = get != 0xFFFF;
        bool hasSet = set != 0xFFFF;

        int32_t methodStartDec = img_.typeMethodStart((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionMethodStartOffset));
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
        ++nProperties_;
    }

    return "\t// Properties\n" + full + "\n";
    return "";
}

std::string eventDef(const Il2CppTypeDefinition* typeDefinition) 
{
    std::string full{};
    // [V] eventStart +0x34 + 3330 ; event_count +0x44 + 113（0x8F 编码 0）
    //     events 数组 MHY[0x1E8] ^ 0x100547B1，步长 14，name@+4
    //     typeIndex@+0 / add@+8 / remove@+10 / raise@+12（0xFFFF = 无）
    int32_t start = img_.typeEventStart(img_.tdI16(typeDefinition, ver::kIl2CppTypeDefinitionEventStartOffset));
    uint32_t count = img_.typeEventCount(img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionEventCountOffset));

    if (count == 0) return "";

    int32_t end = start + count;

    for (int32_t eventIndex = start; eventIndex < end; ++eventIndex)
    {
        const Il2CppEventDefinition* eventDefinition = img_.GetEventDefinitionFromIndex(eventIndex);

        const uint8_t* eventBytes = (const uint8_t*)eventDefinition;
        uint32_t rawName = *(const uint32_t*)(eventBytes + ver::kIl2CppEventDefinitionNameIndexOffset);
        uint32_t rawType = *(const uint32_t*)(eventBytes + ver::kIl2CppEventDefinitionTypeIndexOffset);
        std::string name {img_.GetStringFromIndex(
            img_.eventNameIndex(rawName, (uint32_t)eventIndex))};
        // typeIndex 解码由 version.json 的 decEventTypeIndex 决定。
        int32_t typeIndex = img_.eventTypeIndex(rawType, (uint32_t)eventIndex);
        if (typeIndex == -1) continue;
        const Il2CppType* type = img_.GetIl2CppTypeFromIndex(typeIndex);
        if (!type) continue;
        std::string type_name {img_.NameFromIl2CppType(type)};

        // [V] add/remove/raise 是**相对 methodStart 的局部索引**，解出后还要 +
        // typeMethodStart(typeDefinition) 才是全局方法索引（文章：methods[methodStartDec + add]）。
        // 原始字段偏移与解码由 version.json 的 structOffsets / decEvent* 决定。
        uint16_t rawAdd    = *(const uint16_t*)((const uint8_t*)eventDefinition + ver::kIl2CppEventDefinitionAddOffset);
        uint16_t rawRemove = *(const uint16_t*)((const uint8_t*)eventDefinition + ver::kIl2CppEventDefinitionRemoveOffset);
        uint16_t rawRaise  = *(const uint16_t*)((const uint8_t*)eventDefinition + ver::kIl2CppEventDefinitionRaiseOffset);
        uint16_t evAdd    = img_.eventAdd(rawAdd, (uint32_t)eventIndex);
        uint16_t evRemove = img_.eventRemove(rawRemove, (uint32_t)eventIndex);
        uint16_t evRaise  = img_.eventRaise(rawRaise, (uint32_t)eventIndex);
        uint16_t add = evAdd, remove = evRemove, raise = evRaise;
        bool hasRemove = remove != 0xFFFF;
        bool hasAdd = add != 0xFFFF;
        bool hasRaise = raise != 0xFFFF;

        int32_t methodStartDec = img_.typeMethodStart((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionMethodStartOffset));
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
        ++nEvents_;
    }

    return "\t// Events\n" + full + "\n";
    return "";
}


// 嵌套类：用 nestedTypes 表反推「子 -> 父」映射（declaringTypeIndex 未定位的替代方案）。
//   表 = MHY[0x05C] - 381850355，步长 4；typeDef +0x36 +6631 = start，+0x45 ^0xBA = count。
//   已验收：9310 个父类型 / 25981 条目；起点互不重叠、恰好铺满整表、条目全为合法 TypeDefIndex。
std::unordered_map<int32_t, int32_t> buildNestingMap()
{
    std::unordered_map<int32_t, int32_t> m;
    if (!img_.header.nestedTypesTable || !img_.header.typeDefinitionsCount) return m;
    const uint32_t* tbl = (const uint32_t*)(img_.s_GlobalMetadataHeader + img_.header.nestedTypesTable);
    const Il2CppTypeDefinition* tds =
        (const Il2CppTypeDefinition*)((const char*)img_.s_GlobalMetadataHeader + img_.header.typeDefinitionsOffset);
    const uint32_t nTypes = img_.header.typeDefinitionsCount;
    for (uint32_t t = 0; t < nTypes; t++)
    {
        int32_t st = img_.typeNestedStart(img_.tdI16(&tds[t], ver::kIl2CppTypeDefinitionNestedTypesStartOffset));
        uint32_t cnt = img_.typeNestedCount(img_.tdU8(&tds[t], ver::kIl2CppTypeDefinitionNestedTypesCountOffset));
        if (st < 0 || cnt == 0) continue;
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
    int32_t typeDefinitionsCount = (int32_t)img_.header.typeDefinitionsCount;
    const Il2CppTypeDefinition* typeDefinitions = (const Il2CppTypeDefinition*)((const char*)img_.s_GlobalMetadataHeader + img_.header.typeDefinitionsOffset);
    
    const auto childToParent = buildNestingMap();   // 一次预扫，供声明前缀使用
    for (int32_t typeIndex = 0; typeIndex < typeDefinitionsCount; typeIndex++)
    {
        ++nTypes_;
        if (trace_)
            std::cerr << "[dump] type " << typeIndex << "/" << typeDefinitionsCount << std::endl;
        const Il2CppTypeDefinition* typeDefinition = typeDefinitions + typeIndex;
        std::string name{ img_.GetStringFromIndex(
            img_.typeNameIndex((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionNameIndexOffset))) };
        if (size_t p = name.find('`'); p != std::string::npos) name.resize(p);
        if (trace_)
            std::cerr << "[dump]   name=" << name << std::endl;

        // [V] flags = +0x28 - 0x4159BB8E（TYPE_ATTRIBUTE）。
        //   type kind 由 version.json 的 bitfield offset/decode 决定。
        uint32_t flags = img_.typeFlags((uint32_t)img_.tdU32(typeDefinition, ver::kIl2CppTypeDefinitionFlagsOffset));
        uint8_t valuetype = img_.typeIsValueType(img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionBitfieldOffset));
        uint8_t enumtype  = img_.typeIsEnum(img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionBitfieldOffset));

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
        uint16_t interfacesStart = img_.typeInterfacesStart((uint16_t)img_.tdU16(typeDefinition, ver::kIl2CppTypeDefinitionInterfacesStartOffset));
        uint32_t interfaces_count = img_.typeInterfacesCount(img_.tdU8(typeDefinition, ver::kIl2CppTypeDefinitionInterfacesCountOffset));
        if (interfaces_count > 256) interfaces_count = 256;   // 防越界
        for (uint32_t i = 0; i < interfaces_count; i++)
        {
            const Il2CppType* type = img_.GetInterfaceFromIndex(interfacesStart + i);
            if (!type) continue;
            if (!interfaces.empty()) interfaces += ", ";
            interfaces += img_.NameFromIl2CppType(type);
        }

        std::string parent{};
        // [V] 基类：parentIndex -> Il2CppType -> 父类型。逻辑照抄 6.7 版（只换常量）。
        {
            int32_t pIdx = img_.typeParentIndex((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionParentIndexOffset));
            if (pIdx != -1)
            {
                const Il2CppType* ptype = img_.GetIl2CppTypeFromIndex(pIdx);
                if (ptype && !valuetype && !enumtype)
                {
                    auto typeCode = ptype->type;
                    if (typeCode == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
                    {
                        parent = img_.NameFromIl2CppType(ptype);
                    }
                    else if (typeCode == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_CLASS
                             && ptype->data.klassIndex != 405 && ptype->data.klassIndex != 204)
                    {
                        parent = img_.GetStringFromIndex(
                            img_.typeNameIndex((uint32_t)img_.tdI32(&typeDefinitions[ptype->data.klassIndex],
                                ver::kIl2CppTypeDefinitionNameIndexOffset)));
                    }
                }
            }
        }
        std::string namespaze{ img_.GetStringFromIndex(
            img_.typeNamespaceIndex((uint32_t)img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionNamespaceIndexOffset))) };

        std::string fullName{};
        std::string declaringType{};
#if 0
        if (img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionParentIndexOffset) != 0xC52CB9C) 
        {
            const Il2CppType* type = img_.GetIl2CppTypeFromIndex(img_.tdI32(typeDefinition, ver::kIl2CppTypeDefinitionParentIndexOffset) - 0xC52CB9D);
            auto typeCode = type->type;

            if (!valuetype && !enumtype)
            {
                if (typeCode == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
                {
                    parent = img_.NameFromIl2CppType(type);
                }
                else if ((typeCode == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_CLASS /*|| typeCode == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT*/) && type->data.klassIndex != 405 && type->data.klassIndex != 204)
                {
                    parent = img_.GetStringFromIndex(
                        img_.typeNameIndex((uint32_t)typeDefinitions[type->data.klassIndex].nameIndex));
                }
            }

        }

        if (typeDefinition->declaringTypeIndex != 0x5C0F5BCB) 
        {
            const Il2CppType* type = img_.GetIl2CppTypeFromIndex(typeDefinition->declaringTypeIndex - 0x5C0F5BCC);
            fullName = img_.NameFromIl2CppType(type);
            if (!fullName.empty()) fullName += ".";

            declaringType = img_.GetStringFromIndex(
                img_.typeNameIndex((uint32_t)typeDefinitions[type->data.klassIndex].nameIndex));
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
                std::string pn{ img_.GetStringFromIndex(
                    img_.typeNameIndex((uint32_t)img_.tdI32(&typeDefinitions[cur],
                        ver::kIl2CppTypeDefinitionNameIndexOffset))) };
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
                namespaze = img_.GetStringFromIndex(
                    img_.typeNamespaceIndex((uint32_t)img_.tdI32(&typeDefinitions[outermost],
                        ver::kIl2CppTypeDefinitionNamespaceIndexOffset)));
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
            uint16_t genericContainerIndex = (img_.tdI16(typeDefinition, ver::kIl2CppTypeDefinitionGenericContainerIndexOffset) ^ 0x1BD3u);
            const auto* container = img_.GetGenericContainerFromIndex(genericContainerIndex);
            if (container)
            {
                uint32_t key = (269045474 * ((1724555473 * ((59131LL * genericContainerIndex) ^ 0x13149C18)) ^ 0x26CF5EFDuLL) + 0x1272614D2E8ALL) >> 16;
                uint32_t count = key ^ 0x1CACE492 ^ container->type_argc;
                if (count != 0 && count <= 32)
                {
                    uint32_t genericParameterStart = key ^ (container->genericParameterStart - 283689125);
                    for (uint32_t i = 0; i < count; ++i)
                    {
                        const auto* parameter = img_.GetGenericParameter(genericParameterStart, i);
                        uint32_t nameKey = (uint32_t)(((0x65DE21D74280ull * (genericParameterStart + i)) ^ 0x154AA920) + 1912316114);
                        if (i) typeGenerics += ", ";

                        uint16_t pflags = parameter->flags;
                        if (pflags & 1) typeGenerics += "out ";
                        else if (pflags & 2) typeGenerics += "in ";
                        typeGenerics += img_.GetStringFromIndex((parameter->nameIndex ^ 0x2DD1C9C6u) - nameKey);
                    }
                }
            }
        }
#endif
        // [V] 类泛型参数：typeDef+0x3E -> 容器 -> (argc, parameterStart) -> genericParameters[]
        //   逻辑照抄 6.7 版，常量全部换成本版本的（sub_140511DB0 / sub_14050E030 / sub_1404B7B20）。
        {
            int32_t cIdx = img_.typeGenericContainerIndex((uint16_t)img_.tdI16(typeDefinition, ver::kIl2CppTypeDefinitionGenericContainerIndexOffset));
            if (cIdx >= 0)
            {
                uint32_t count = img_.genericContainerArgc((uint32_t)cIdx);
                uint32_t pStart = img_.genericParameterStart((uint32_t)cIdx);
                if (count != 0 && count <= 32)
                {
                    for (uint32_t i = 0; i < count; ++i)
                    {
                        if (i) typeGenerics += ", ";
                        typeGenerics += SanitizeGenericName(
                            img_.GetStringFromIndex(img_.genericParameterNameIndex(pStart + i)), i);
                    }
                }
            }
        }
        dumpOut_ << "// Namespace: " << namespaze << "\n// FullName: " << fullName << "\n" << getcustomattr(token) << serializableAttr << visibility << typeAttr << (declaringType.empty() ? "" : declaringType + ".") << name << (typeGenerics.empty() ? "" : "<" + typeGenerics + ">") /*блатной*/
            << (parent.empty() ? "" : ": " + parent)
            << (interfaces.empty() ? "" : (parent.empty() ? ": " : ", ") + interfaces) << " // TypeDefIndex: " << typeIndex << std::endl;
        
        std::string v = methodDef(typeDefinition);
        dumpOut_ << "{\n" 
            << fieldDef(typeDefinition) << propDef(typeDefinition) << eventDef(typeDefinition) << v;
        dumpOut_ << "}\n\n";
    }
}

void string_Literal() {
    // ⚠️ 本版本**没有独立的字面量条目表**（offset/length 打包进 nameIndex，见 decryptHeader），
    //    header.stringLiteralOffset == 0。若仍按「条目表」遍历，stringLiteral 指针会落在
    //    元数据头上，dataIndex/length 解出垃圾 → DecryptStringAt 越界读 → SIGSEGV。
    //    所以本版本直接输出空数组并返回（字符串仍可经 GetStringFromIndex 正常取到）。
    if (img_.header.stringLiteralOffset == 0)
    {
        stringLiteralOut_ << "[]\n";
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

    stringLiteralOut_ << "[\n";
    for (uint32_t index = 0; index < (uint32_t)stringLiteralCount; ++index)
    {
        const auto* stringLiteral = (const Il2CppStringLiteral*)((const char*)img_.s_GlobalMetadataHeader + img_.header.stringLiteralOffset + 4ull * index);

        uint32_t datakey = ((-242635478LL * (int64_t)index + 2077684850) ^ 0xBD35B71B);
        uint32_t lengthKey = (uint32_t)((-242635478LL * (int64_t)index + 1835049372) ^ 0xBD35B71B);

        int32_t dataIndex = (stringLiteral->dataIndex ^ 0x47DBC836) + datakey;
        uint32_t length = (stringLiteral->length ^ 0x47DBC836) + lengthKey - dataIndex;

        uint8_t* stringLiteralData = img_.s_GlobalMetadataHeader + img_.header.stringLiteralDataOffset;

        // 解密部分已更新为本版本算法（已验证）；dataIndex/length 的读取逻辑未验证，保持原样
        std::string s = img_.decryptString((uint32_t)dataIndex, length);
        uint64_t addr = (uint64_t)(stringLiteralData + dataIndex) - (uint64_t)img_.s_GlobalMetadataHeader + 0x210;
        stringLiteralOut_ << "  {\"value\": \"" << format(s) << "\", \"address\": \"" << std::format("0x{:X}", addr) << "\"}" << (index + 1 < (uint32_t)stringLiteralCount ? "," : "") << "\n";

    }
    stringLiteralOut_ << "]\n";
    stringLiteralOut_.flush();
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

                    if (fileOffset <= files_.exe().size() && length <= files_.exe().size() - fileOffset)
                    {
                        result = std::string((const char*)files_.exe().data() + fileOffset, (size_t)length);
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
                uint64_t typePtr = (uint64_t)(img_.s_Il2CppTypes) + itV->second;   // 同样必须转 host 指针
                std::string tname = img_.NameFromIl2CppType((const Il2CppType*)typePtr);
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
            uint64_t off = files_.pe()->va_to_offset(va);
            if (off < files_.exe().size() && 16 <= files_.exe().size() - off)
            {
                uint64_t lo = 0, hi = 0;
                memcpy(&lo, files_.exe().data() + off, 8);
                memcpy(&hi, files_.exe().data() + off + 8, 8);
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

std::string format(const std::string& s)
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

std::string formatEnum(const Il2CppType* enumType, uint64_t raw)
{
    if (!enumType) return std::to_string(raw);
    if (enumType->type != Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE) return std::to_string(raw);
    const Il2CppTypeDefinition* enumDef = img_.GetTypeDefinitionFromIndex(enumType->data.klassIndex);
    // bitfield = +0x3A（已定位）：enumtype = ~(raw>>1)&1
    if (!enumDef) return std::to_string(raw);
    return std::to_string(raw);

    auto fields = collectFields(enumDef);
    std::vector<std::pair<uint64_t, std::string>> vals;
    for (auto& f : fields)
    {
        if (!(f.type->attrs & FIELD_ATTRIBUTE_LITERAL)) continue;
        const Il2CppFieldDefaultValue* d = img_.GetDefaultValueForField(f.index);
        if (!d || img_.fdvDataIndex(d) == -1) continue;
        const Il2CppType* ct = img_.GetIl2CppTypeFromIndex(img_.fdvTypeIndex(d));
        uint8_t* blob = img_.s_GlobalMetadataHeader + img_.fdvDataIndex(d) + img_.header.fieldAndParameterDefaultValueDataOffset;
        uint64_t v = 0;
        auto code = ct ? ct->type : Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_END;
        switch (code)
        {
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN:
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I1: v = (uint64_t)(int64_t)(int8_t)*blob; break;
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U1: v = *blob; break;
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I2: v = (uint64_t)(int64_t)*(int16_t*)blob; break;
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U2: v = *(uint16_t*)blob; break;
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I4: v = (uint64_t)(int64_t)*(int32_t*)blob; break;
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U4: v = *(uint32_t*)blob; break;
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I8: v = *(uint64_t*)blob; break;
        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U8: v = *(uint64_t*)blob; break;
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
    // 7.0 的 codeRegistration 是运行时构造，文件里不存在（version.json 里为 0）-> 直接跳过。
    if (!img_.s_Il2CppCodeRegistration) return;
    const Il2CppCustomAttributeTypeRange* attributeTypeRange = (const Il2CppCustomAttributeTypeRange*)(img_.s_GlobalMetadataHeader + img_.header.attributesInfoOffset);

    int32_t customAttributeCount = *(int32_t*)(img_.s_Il2CppCodeRegistration + 0x70) - 0x2F2BD0D;
    for (int32_t i = 0; i < customAttributeCount; i++)
    {
        uint32_t count = attributeTypeRange[i].start_сount >> 24;
        if (count == 0) continue;

        uint32_t start = attributeTypeRange[i].start_сount & 0xFFFFFF;
        uint32_t token = attributeTypeRange[i].token;

        uint64_t genVA = *(uint64_t*)(files_.exe().data() + files_.pe()->va_to_offset(/*s_Il2CppCodeRegistration + 0x58*/0x141F04D90 + 8ULL * i));
        auto writes = parseGenerator(files_.exe().data() + files_.pe()->va_to_offset(genVA), std::min<size_t>(0x1000, files_.exe().size() - files_.pe()->va_to_offset(genVA)), genVA);

        for (int32_t index = 0; index < count; index++)
        {
            uint32_t typeIndex = *(uint32_t*)(img_.s_GlobalMetadataHeader + img_.header.attributeTypesOffset + 4 * (start + index));
            const Il2CppType* type = img_.GetIl2CppTypeFromIndex(typeIndex);

            std::string attrName{ img_.NameFromIl2CppType(type) };
            std::vector<std::string> args;

            if (type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_CLASS || type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE)
            {
                const Il2CppTypeDefinition* attrTypeDef = img_.GetTypeDefinitionFromIndex(type->data.klassIndex);
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
                        if (it->type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT ||
                            it->type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_CLASS ||
                            it->type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY ||
                            it->type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST)
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
                        if (it->type->type == Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_STRING)
                        {
                            value = "\"" + format(w.str) + "\"";
                        }
                        else continue;
                    }
                    else
                    {
                        value = img_.GetConstantValueFromBlob(it->type->type, (uint8_t*)&w.value);

                        switch (it->type->type)
                        {
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_BOOLEAN: value = w.value ? "true" : "false"; break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I1:  value = std::to_string((int)(int8_t)w.value); break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U1:  value = std::to_string((unsigned)(uint8_t)w.value); break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_CHAR:
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I2:  value = std::to_string((int)(int16_t)w.value); break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U2:  value = std::to_string((unsigned)(uint16_t)w.value); break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I4:  value = std::to_string((int32_t)w.value); break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U4:  value = std::to_string((uint32_t)w.value) + "u"; break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_I8:  value = std::to_string((int64_t)w.value) + "L"; break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_U8:  value = std::to_string(w.value) + "UL"; break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_STRING: value = w.value ? "\"...\"" : "null"; break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_OBJECT:
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_CLASS:
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_SZARRAY:
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_GENERICINST: value = w.value ? "\"...\"" : "null"; break;
                        case Il2CppImage::Il2CppTypeEnum::IL2CPP_TYPE_VALUETYPE:
                        {
                            const Il2CppTypeDefinition* fieldTypeDef = img_.GetTypeDefinitionFromIndex(it->type->data.klassIndex);
                            bool isEnum = img_.typeIsEnum(fieldTypeDef->bitfield) != 0;
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
};
