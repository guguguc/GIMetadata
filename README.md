# GIMetadata
> [!WARNING]  
> This is just an example created for educational purposes and has no relation to аnti-сhеаt bураss. Responsibility for any use lies solely with the user.

Third-party libraries:
1) [LIEF](https://github.com/lief-project/LIEF)
2) [capstone](https://github.com/capstone-engine/capstone)

## Layout

```
version.json            ← 版本常量唯一来源（换版本只改这个）
tools/gen_version.py       → 生成 src/version.hpp（make 自动调用）
tools/slot_scan.py         全 .text 扫 MHY 槽位+密钥
tools/sig.py               结构签名工具（gen/scan）：跳过序言取中部指令、寄存器全通配、
                           精确掩码 imm/disp → 字节优先扫描（0.6s / 36 条）
tools/relocate.py          换版本自动重定位（魔数+指令证据+结构自证，numpy 秒级）
tools/gi_string_decrypt.py 字符串解密自检（75/75）

src/version.hpp         (生成物，勿手改)
src/metadata_files.hpp  MetadataFiles : 装载 gi.exe/*.dat + PE（RAII）
src/il2cpp_image.hpp    Il2CppImage   : 版本常量 + 字节 → 可查询 il2cpp 视图
src/dumper.hpp          Dumper        : 渲染 dump.cs / stringliteral.json
src/attributes.hpp      属性位掩码
src/main.cpp            入口

verify.py               换版本后的 28 项自动验收
docs/                   手册与进度
version/7.1/            样本（gi.exe + Managed；可直接 ./gi-dump version/7.1）
version/7.1/            另一个样本（仅 gi.exe）
ida/                    IDA 数据库（~10GB，本地保留）
out/                    dump.cs / stringliteral.json
```

## Build & Run

```bash
make                        # 自动生成 src/version.hpp 并构建
./gi-dump version/7.1       # 产出 out/dump.cs
python3 verify.py           # 28 项验收，必须全 PASS
```

## Documents

- [`USAGE.md`](USAGE.md) — **使用说明**（环境/上手/输出格式/工具逐个/常见任务/排错）

- [`docs/UPDATE.md`](docs/UPDATE.md) — **版本更新维护手册**（换版本怎么做 + 锚点法 + 陷阱集）
- [`docs/status.md`](docs/status.md) — 当前进度、已验证字段、失败记录
- [`docs/gi_fields.md`](docs/gi_fields.md) — 结构体字段与逐索引 key 速查
- [`docs/METHOD.md`](docs/METHOD.md) — 文章方法整理
- [`docs/ANALYSIS.md`](docs/ANALYSIS.md) — 总报告（部分章节已过期，以 status.md 为准）
- [`docs/mhytab_pairs.md`](docs/mhytab_pairs.md) — MHY 槽位配对表
