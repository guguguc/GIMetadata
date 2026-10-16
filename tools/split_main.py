import re, os

SRC = 'main.cpp'
s = open(SRC, encoding='utf-8', newline='').read()

def find_block(text, start_pat):
    i = text.index(start_pat)
    b = text.index('{', i)
    depth = 0
    j = b
    while j < len(text):
        if text[j] == '{': depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0: break
        j += 1
    return i, b + 1, j, j + 1

def cut(text, start_pat):
    i, b, e, end = find_block(text, start_pat)
    return text[:i], text[i:end], text[end:]

# ---------- 1. namespace il2cpp -> class Il2CppImage ----------
ns_i, ns_b, ns_e, ns_end = find_block(s, 'namespace il2cpp')
NS = s[ns_b:ns_e]
ut_i, ut_b, ut_e, ut_end = find_block(NS, 'namespace utils')
GLOBALS_TYPES = NS[:ut_i]
UTILS = NS[ut_b:ut_e]

# decryptHeader（目前是自由函数）→ 变成 Il2CppImage 的成员
_, DECRYPT_FN, rest_after_decrypt = cut(s, 'void decryptHeader()')

def strip_prefix(t):
    t = t.replace('using namespace il2cpp;\r\n', '')
    t = t.replace('il2cpp::utils::', '')
    t = t.replace('il2cpp::header', 'header')
    t = t.replace('il2cpp::s_', 's_')
    t = t.replace('il2cpp::Il2CppTypeEnum::', 'Il2CppTypeEnum::')
    t = t.replace('exe.data()', 'files_.exe().data()')
    t = t.replace('exe.size()', 'files_.exe().size()')
    t = re.sub(r'(?<![A-Za-z0-9_])pe->', 'files_.pe()->', t)
    t = t.replace('il2cpp::', '')          # 类内不再有 il2cpp 命名空间
    t = re.sub(r'(?<![A-Za-z0-9_:])utils::', '', t)
    t = t.replace('        constexpr ', '        static constexpr ')
    t = t.replace('    constexpr ', '    static constexpr ')
    return t

GLOBALS_TYPES = strip_prefix(GLOBALS_TYPES)
UTILS = strip_prefix(UTILS)
DECRYPT_FN = strip_prefix(DECRYPT_FN)
# 成员函数不能带 static/无 about 的自由函数签名注释；去掉函数名前缀里的 "void ")
DECRYPT_MEMBER = DECRYPT_FN.replace('void decryptHeader()', 'void decryptHeader()', 1)

hpp = []
hpp.append('''// ============================================================================
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
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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
''')
hpp.append(DECRYPT_MEMBER.rstrip())
hpp.append('\n\n')
hpp.append(GLOBALS_TYPES.rstrip())
hpp.append('\n\n    // ========== 解密 / 表访问 / 逐索引 key / 名字解析（原 namespace utils）==========\n')
hpp.append(UTILS.rstrip())
hpp.append('''

private:
    MetadataFiles& files_;
};
''')
open('src/il2cpp_image.hpp', 'w', encoding='utf-8', newline='').write('\n'.join(hpp))

# ---------- 2. dump 逻辑 -> class Dumper ----------
an_start = s.index('namespace {\r\n    struct MethodEntry')
an_open  = s.index('{', an_start)
depth, j = 0, an_open
while j < len(s):
    if s[j] == '{': depth += 1
    elif s[j] == '}':
        depth -= 1
        if depth == 0: break
    j += 1
an_close = j
an_stop  = s.index('void decryptHeader()')
DUMPREGION = s[an_open+1:an_close] + s[an_close+1:an_stop]

# 去掉 readFile（已搬到 MetadataFiles）
i, rb, re_, rend = find_block(DUMPREGION, 'std::vector<uint8_t> readFile')
DUMPREGION = DUMPREGION[:i] + DUMPREGION[rend:]

def to_dumper(t):
    t = t.replace('il2cpp::utils::', 'img_.')
    t = t.replace('il2cpp::header', 'img_.header')
    t = t.replace('il2cpp::s_', 'img_.s_')
    t = t.replace('il2cpp::Il2CppTypeEnum::', 'Il2CppImage::Il2CppTypeEnum::')
    t = t.replace('exe.data()', 'files_.exe().data()')
    t = t.replace('exe.size()', 'files_.exe().size()')
    t = re.sub(r'(?<![A-Za-z0-9_])pe->', 'files_.pe()->', t)
    t = t.replace('out <<', 'dumpOut_ <<')
    t = t.replace('стрингиойой', 'stringLiteralOut_')
    t = t.replace('il2cpp::', '')
    # 类内不能用 static 成员函数（会失去 this），去掉这三个自由函数的 static
    t = t.replace('static std::unordered_map<int32_t, int32_t> buildNestingMap()', 'std::unordered_map<int32_t, int32_t> buildNestingMap()')
    t = t.replace('static std::string format(const std::string& s)', 'std::string format(const std::string& s)')
    t = t.replace('static std::string formatEnum(', 'std::string formatEnum(')
    return t

DUMPREGION = to_dumper(DUMPREGION)

# 把「匿名 namespace 私有状态」与「dump 函数」分开
#   私有状态部分到 getcustomattr 结束
gi, gb, ge, gend = find_block(DUMPREGION, 'std::string getcustomattr')
PRIVATE_PART = DUMPREGION[:gend]
FUNCS_PART = DUMPREGION[gend:]

ALIASES = '\n'.join(
    '    using %s = Il2CppImage::%s;' % (t, t) for t in (
        ['Il2CppTypeEnum'] + [
        'Il2CppArrayType',
        'Il2CppCustomAttributeTypeRange',
        'Il2CppEventDefinition',
        'Il2CppFieldDefaultValue',
        'Il2CppFieldDefinition',
        'Il2CppGenericContainer',
        'Il2CppGenericInst',
        'Il2CppGenericMethodFunctionsDefinitions',
        'Il2CppGenericMethodIndices',
        'Il2CppGenericParameter',
        'Il2CppImageDefinition',
        'Il2CppMethodDefinition',
        'Il2CppMethodSpec',
        'Il2CppParameterDefaultValue',
        'Il2CppParameterDefinition',
        'Il2CppPropertyDefinition',
        'Il2CppStringLiteral',
        'Il2CppType',
        'Il2CppTypeDefinition',
    ]))

dhpp = ['''// ============================================================================
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
    Dumper(Il2CppImage& img, MetadataFiles& files, const std::string& outDir)
        : img_(img), files_(files),
          dumpOut_(outDir + "/dump.cs"),
          stringLiteralOut_(outDir + "/stringliteral.json") {}

    // 各输出段，顺序与原 main() 一致
    void run() {
        string_Literal();
        customAttr();
        imageDef();
        typeDef();
    }

private:
    Il2CppImage&   img_;
    MetadataFiles& files_;
    std::ofstream  dumpOut_;
    std::ofstream  stringLiteralOut_;
''' + ALIASES + '\n' + PRIVATE_PART.rstrip() + '\n\npublic:\n' + FUNCS_PART.rstrip() + '\n};\n']
open('src/dumper.hpp', 'w', encoding='utf-8', newline='').write('\n'.join(dhpp))

# ---------- 3. 新的 main.cpp ----------
main_cpp = '''// ============================================================================
//  GIMetadata —— 入口
//
//  结构（面向对象）：
//     MetadataFiles  : 装载 gi.exe / *.dat，解析 PE（RAII）
//     Il2CppImage    : 版本常量 + 文件字节 -> 可查询的 il2cpp 元数据视图
//     Dumper         : 渲染 dump.cs / stringliteral.json
//
//  所有版本相关常量都在 version.json（-> src/version.hpp，make 时自动生成）。
//  换版本：改 version.json -> make -> ./gi-dump <game_root> -> python3 verify.py
// ============================================================================
#include "dumper.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <game_root_dir>\\n"
                     "  expects <game_root_dir>/gi/Managed/Metadata/global-metadata.dat\\n"
                     "          <game_root_dir>/gi/Managed/Metadata/startup-metadata.dat\\n"
                     "          <game_root_dir>/gi.exe\\n";
        return 1;
    }

    MetadataFiles files{argv[1]};   // 读文件 + 解析 PE
    Il2CppImage   image{files};     // 视图
    image.decryptHeader();          // 装载版本常量（version.json -> src/version.hpp）

    std::filesystem::create_directories("out");\n    Dumper dumper{image, files, "out"};
    dumper.run();

    return 0;
}
'''
open('src/main.cpp', 'w', encoding='utf-8', newline='').write(main_cpp)
print("生成完成：src/il2cpp_image.hpp / src/dumper.hpp / main.cpp")
