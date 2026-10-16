// ============================================================================
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

#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <game_root_dir>\n"
                     "  expects <game_root_dir>/gi/Managed/Metadata/global-metadata.dat\n"
                     "          <game_root_dir>/gi/Managed/Metadata/startup-metadata.dat\n"
                     "          <game_root_dir>/gi.exe\n";
        return 1;
    }

    MetadataFiles files{argv[1]};   // 读文件 + 解析 PE
    Il2CppImage   image{files};     // 视图
    image.decryptHeader();          // 装载版本常量（version.json -> src/version.hpp）

    std::filesystem::create_directories("out");   // 输出统一放 out/
    Dumper dumper{image, files, "out"};
    dumper.run();

    return 0;
}
