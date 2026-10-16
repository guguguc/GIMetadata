#!/usr/bin/env python3
"""
gi.exe (本样本) 元数据字符串解密 —— 已验证 75/75 正确

用法:
    python3 gi_string_decrypt.py <exe路径> <global-metadata.dat> [startup-metadata.dat]
    python3 gi_string_decrypt.py <exe> <global.dat> <startup.dat> --all     # 解密所有程序集名

自检: 直接运行会打印本样本 75 个程序集名的解密结果。
"""
import struct, sys

M64 = (1 << 64) - 1

# ---- 从 IDA Hex-Rays 提取的常量（本游戏版本专属）----
MHY_TABLE_VA      = 0x1427D4BD0   # .rdata, 开头 "MHY\0"
RD_VA, RD_RAW     = 0x21AA000, 0x21A9000     # .rdata 的 RVA / 文件偏移
IMAGEBASE         = 0x140000000
GLOBAL_HDR_OFFSET = 0x210         # s_GlobalMetadataHeader = global.data() + 0x210

# MHYTAB 槽位 -> (运算, 密钥)
IMAGES_COUNT_SLOT, IMAGES_COUNT_OP, IMAGES_COUNT_KEY =  44, '-',  610644003   # 字节数，/0x28 = 条目数
IMAGES_DEF_SLOT,  IMAGES_DEF_OP,  IMAGES_DEF_KEY  = 524, '-',  248195061   # startup-metadata 内基址
STRDATA_SLOT,     STRDATA_OP,     STRDATA_KEY     = 388, '-', 1080211659   # global-metadata 内偏移

# 逐索引 key 公式（对应原版 main.cpp 的 imageDef() 里的 key）
def index_key(i: int) -> int:
    return (1368137530 * (((667674736 * (((13029 * i) ^ 0x43E2DEB7)) + 0xCB287082F0) >> 8))
            + 1505552983) & 0xFFFFFFFF

# 字符串条目解码: entry = index_key ^ rawNameIndex ^ 0x772FA51E
#   entry & 0xFFFFFF -> 数据块内 24 位偏移
#   entry >> 24     -> 8 位长度
STRING_ENTRY_XOR = 0x772FA51E

# 解密密钥派生
K_MUL_A   = 0x5C2B4E660E2D0544
K_MUL_B   = 0x694418957C890198
K_SEED    = 0x55A357D81EF0E48B
K_STEP    = 0x6B0B40C349AE61E5      # 每 8 字节递增

class Meta:
    def __init__(self, exe_path: str, global_path: str, startup_path: str = None):
        self.exe = open(exe_path, 'rb').read()
        self.gm = open(global_path, 'rb').read()
        self.sm = open(startup_path, 'rb').read() if startup_path else None
        self.table = self.exe[RD_RAW + (MHY_TABLE_VA - IMAGEBASE - RD_VA):][:0x400]

    def slot(self, off: int) -> int:
        return struct.unpack_from('<I', self.table, off)[0]

    def field(self, off: int, op: str, key: int) -> int:
        raw = self.slot(off)
        v = (raw ^ key) if op == '^' else ((raw - key) & 0xFFFFFFFF) if op == '-' else ((raw + key) & 0xFFFFFFFF)
        return v

    # ---- 字面量 ----
    @property
    def string_data_offset(self) -> int:
        return self.field(STRDATA_SLOT, STRDATA_OP, STRDATA_KEY)

    def decrypt(self, offset: int, length: int) -> bytes:
        key = (K_MUL_A * ((K_MUL_B * offset) ^ K_SEED)) & M64
        base = GLOBAL_HDR_OFFSET + self.string_data_offset + offset
        out = bytearray()
        for k in range((length + 7) // 8):
            c = struct.unpack_from('<Q', self.gm, base + 8 * k)[0]
            out += struct.pack('<Q', c ^ ((key + k * K_STEP) & M64))
        return bytes(out[:length])

    def decode_entry(self, entry: int):
        return entry & 0xFFFFFF, (entry >> 24) & 0xFF

    def string_at(self, raw_index: int, index_key_value: int) -> str:
        entry = (index_key_value ^ raw_index ^ STRING_ENTRY_XOR) & 0xFFFFFFFF
        off, ln = self.decode_entry(entry)
        return self.decrypt(off, ln).decode('utf-8', 'replace')

    # ---- 程序集名（镜像原版 imageDef()）----
    @property
    def images_count(self) -> int:
        return self.field(IMAGES_COUNT_SLOT, IMAGES_COUNT_OP, IMAGES_COUNT_KEY) // 0x28

    @property
    def images_def_offset(self) -> int:
        """startup-metadata.dat 内偏移（该文件基址无 +0x210）"""
        return self.field(IMAGES_DEF_SLOT, IMAGES_DEF_OP, IMAGES_DEF_KEY)

    def image_names(self):
        base = self.images_def_offset
        for i in range(self.images_count):
            raw = struct.unpack_from('<I', self.sm, base + 40 * i + 32)[0]
            yield i, self.string_at(raw, index_key(i))


if __name__ == '__main__':
    import os
    repo = os.path.dirname(os.path.abspath(__file__))
    exe  = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, 'gi.exe')
    md   = sys.argv[2] if len(sys.argv) > 2 else os.path.join(repo, 'Managed/Metadata/global-metadata.dat')
    sm   = sys.argv[3] if len(sys.argv) > 3 else os.path.join(repo, 'Managed/Metadata/startup-metadata.dat')

    m = Meta(exe, md, sm)
    print("imagesCount          = %d" % m.images_count)
    print("stringLiteralDataOff = 0x%X" % m.string_data_offset)
    print()
    ok = 0
    names = []
    for i, nm in m.image_names():
        good = nm.endswith('.dll') and all(32 <= ord(c) < 127 for c in nm)
        ok += good
        names.append((i, good, nm))
    for i, good, nm in names:
        print("  [%2d] %-45s %s" % (i, nm, '' if good else '<-- BAD'))
    print()
    print("解密正确率: %d/%d (%.1f%%)" % (ok, len(names), 100.0 * ok / max(len(names), 1)))