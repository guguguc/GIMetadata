#!/usr/bin/env python3
# ida_export_gui.py —— 在 IDA GUI 里一键导出（File -> Script file...）
#
# 为什么需要它：
#   · 无头 idat 打不开 GUI 正在用的 .i64（internal error 1228）
#   · 这个脚本直接在当前打开的数据库上跑，不需要另开
#
# 用法：
#   1. IDA 里打开目标版本的数据库（现在是 version/7.0/gi.exe）
#   2. File -> Script file...  选本文件
#   3. 看 Output window；结果写到 /tmp/opencode/ida<版本>.json
#
# 环境变量（可选）：
#   GI_VER=7.0   版本号（决定 hits 和输出文件名）
import os
import sys

ROOT = '/home/gugugu/Repo/GIMetadata'
VER = os.environ.get('GI_VER', '7.0')
OUT = os.environ.get('GI_OUT', '/tmp/opencode/ida%s.json' % VER.replace('.', ''))
HITS = os.environ.get('GI_HITS', os.path.join(ROOT, 'version', VER, 'sig_hits.json'))

_extra = [x for x in os.environ.get('GI_EXTRA', '').replace(',', ' ').split() if x]
sys.argv = ['ida_export.py', OUT, HITS, '--fast'] + _extra
print('[ida_export_gui] ver=%s out=%s hits=%s' % (VER, OUT, HITS))

src = os.path.join(ROOT, 'tools', 'ida_export.py')
with open(src, encoding='utf-8') as f:
    code = compile(f.read(), src, 'exec')

ns = {'__name__': '__main__', '__file__': src}
exec(code, ns)
