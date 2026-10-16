// ============================================================================
//  MetadataFiles —— RAII 持有「游戏文件 + PE 解析结果」
//
//  职责：把 gi.exe / global-metadata.dat / startup-metadata.dat 读进内存，
//        并解析 PE（提供 VA -> 文件偏移 / 镜像基址）。
//  不负责：任何元数据语义（那是 Il2CppImage 的事）。
// ============================================================================
#pragma once

#include <LIEF/LIEF.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

class MetadataFiles {
public:
    // root 下应为 <root>/gi.exe 与 <root>/gi/Managed/Metadata/*.dat
    explicit MetadataFiles(const std::string& root) {
#if defined(_WIN32)
        static constexpr char kSep = '\\';
#else
        static constexpr char kSep = '/';
#endif
        const std::string meta = root + kSep + "gi" + kSep + "Managed" + kSep + "Metadata" + kSep;
        global_  = readFile(meta + "global-metadata.dat");
        startup_ = readFile(meta + "startup-metadata.dat");
        exe_     = readFile(root + kSep + "gi.exe");
        pe_      = LIEF::PE::Parser::parse(root + kSep + "gi.exe");
        if (!pe_) {
            std::cerr << "error: cannot parse PE: " << root << kSep << "gi.exe" << std::endl;
            std::exit(1);
        }
    }

    // ---- 数据 ----
    std::vector<uint8_t>&       exe()       { return exe_; }
    const std::vector<uint8_t>& exe() const { return exe_; }
    const uint8_t* global() const { return global_.data(); }
    size_t         globalSize() const { return global_.size(); }
    const uint8_t* startup() const { return startup_.data(); }

    // ---- PE 便捷接口 ----
    LIEF::PE::Binary* pe() const { return pe_.get(); }
    uint64_t vaToFile(uint64_t va) const { return pe_->va_to_offset(va); }
    uint64_t imageBase() const { return pe_->optional_header().imagebase(); }
    // VA -> 宿主指针（越界时返回 nullptr）
    const uint8_t* at(uint64_t va) const {
        const uint64_t off = vaToFile(va);
        return off < exe_.size() ? exe_.data() + off : nullptr;
    }

private:
    static std::vector<uint8_t> readFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            std::cerr << "error: cannot open file: " << path << std::endl;
            std::exit(1);
        }
        f.seekg(0, std::ios::end);
        const std::streamoff end = f.tellg();
        if (end < 0) {
            std::cerr << "error: cannot determine size of: " << path << std::endl;
            std::exit(1);
        }
        f.seekg(0);
        std::vector<uint8_t> buf((size_t)end);
        f.read((char*)buf.data(), (std::streamsize)buf.size());
        return buf;
    }

    std::vector<uint8_t> exe_, global_, startup_;
    std::unique_ptr<LIEF::PE::Binary> pe_;
};
