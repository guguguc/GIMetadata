#!/usr/bin/env python3
"""
从 IDA 导出 JSON + exe 生成"全局变量清单"和 MHY 槽位表。

用法:
    python3 tools/globals.py <export.json> <exe> <version.json> <out.json>

输出:
    globals: 每个 IDA 全局符号的 name / VA / 段 / 存储(raw|bss) / 引用次数 / 使用函数
    roles  : 已确认语义的全局（MHY / GM / types / allocator ...）
    mhy_slots: MHY 表 0x00..0x300 的原始值与对应表名（来自 version.json）

换版本时只要重新导出 IDA JSON，然后跑一遍即可。
"""
import json, re, sys, os, struct, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sig
import gen_version

GLOBAL_RE = re.compile(r'\b(qword|dword|byte|word|off|xmmword|unk)_([0-9A-Fa-f]{6,})\b')

# 已确认语义的全局（值来自本轮反编译验证；换版本时人工补这里即可）
KNOWN_ROLES = {
    '7.0': {
        'qword_145897158': 'MHY slot table pointer (mhy_global)',
        'qword_145897160': 'GlobalMetadata base (GM)',
        'qword_145897168': 'StartupMetadata base (s_StartupMetadataHeader)',
        'qword_145897140': 'Il2CppType base (array at +0x10)',
        'qword_145896D30': 'allocator / domain (first arg of sub_1404CFDC0)',
        'qword_145896B50': 'MetaStr buffer length',
        'qword_145897A40': 'type registry (FindTypeByName / Helper_5158B0)',
        'qword_145897028': 'DecryptString state',
        'qword_145896C98': 'generic-param bit array (GetGenericParameterInfo)',
    },
    '7.1': {
        'qword_145AD52B8': 'MHY slot table pointer (mhy_global)',
        'qword_145AD52C0': 'GlobalMetadata base (GM)',
        'qword_145AD52A0': 'Il2CppType base (array at +0x48)',
        'qword_145AD4E90': 'allocator / domain (SetupFieldsLocked)',
        'qword_145AD52A8': 'default-value table base (GetDefaultValue / RegisterTables)',
        'qword_145AD5298': 'type handle table (GetTypeHandle / GetTypeInfoFromIndex2)',
    },
}

# 建议的 IDA 名称（只对语义确定的项生成重命名脚本）
RENAMES = {
    '7.0': {
        'qword_145897158': 'g_MHY_Table',
        'qword_145897160': 'g_Metadata_Base',
        'qword_145897168': 'g_Startup_Metadata_Base',
        'qword_145897140': 'g_Il2CppType_Base',
        'qword_145896D30': 'g_Allocator',
        'qword_145896B50': 'g_Str_Buffer_Len',
        'qword_145897A40': 'g_Type_Registry',
        'qword_145897028': 'g_Decrypt_State',
        'qword_145896C98': 'g_GenericFlags',
    },
    '7.1': {
        'qword_145AD52B8': 'g_MHY_Table',
        'qword_145AD52C0': 'g_Metadata_Base',
        'qword_145AD52A0': 'g_Il2CppType_Base',
        'qword_145AD4E90': 'g_Allocator',
        'qword_145AD52A8': 'g_DefaultValue_Base',
        'qword_145AD5298': 'g_TypeHandle_Table',
    },
}


def section_of(pe, va):
    """返回 (section, storage)；storage = raw | bss | ?"""
    for nm, sva, vsz, roff, sz in pe.sec:
        if sva <= va < sva + vsz:
            return nm, ('raw' if va < sva + sz else 'bss')
    return '?', '?'


def read_static(pe, name, va):
    sec, storage = section_of(pe, va)
    if storage != 'raw':
        return None
    try:
        off = pe.va2off(va)
        if off is None:
            return None
        if name.startswith('qword'):
            return struct.unpack_from('<Q', pe.D, off)[0]
        if name.startswith('dword'):
            return struct.unpack_from('<I', pe.D, off)[0]
        if name.startswith('word'):
            return struct.unpack_from('<H', pe.D, off)[0]
        if name.startswith('byte'):
            return pe.D[off]
    except Exception:
        return None
    return None


def read_u32(pe, va):
    off = pe.va2off(va)
    if off is None:
        return None
    return struct.unpack_from('<I', pe.D, off)[0]


def decode_table(raw, op, key):
    if raw is None:
        return None
    if op == '+':
        return (raw + key) & 0xFFFFFFFF
    if op == '-':
        return (raw - key) & 0xFFFFFFFF
    return (raw ^ key) & 0xFFFFFFFF


def collect(exp_path, exe_path, ver_path, tag):
    J = json.load(open(exp_path))
    pe = sig.PE(exe_path)

    refs = collections.Counter()
    funcs = collections.defaultdict(set)
    for f in J.get('formulas', []):
        for m in GLOBAL_RE.finditer(f['text']):
            n = m.group(1) + '_' + m.group(2).upper()
            refs[n] += 1
            funcs[n].add(f['func'])

    globals_out = []
    for n, c in refs.most_common():
        va = int(n.split('_')[1], 16)
        sec, storage = section_of(pe, va)
        val = read_static(pe, n, va)
        globals_out.append({
            'name': n,
            'va': '0x%X' % va,
            'section': sec,
            'storage': storage,
            'static_value': ('0x%X' % val) if val is not None else None,
            'refs': c,
            'functions': sorted(funcs[n]),
            'role': KNOWN_ROLES.get(tag, {}).get(n),
        })

    mhy_raw = J.get('mhy')
    mhy = int(str(mhy_raw), 0) if mhy_raw is not None else None
    mhy_global = J.get('mhy_global')
    # GM: 出现最多的 "GM + *(_DWORD *)(MHY + ...)"
    gm = None
    if mhy_global:
        cnt = collections.Counter()
        pat = re.compile(re.escape(mhy_global) + r'\s*\+\s*(\d+)')
        for f in J.get('formulas', []):
            pass
        pat2 = re.compile(r'(qword_[0-9A-F]+)\s*\+\s*\*\(_DWORD \*\)\(' + re.escape(mhy_global) + r'\s*\+')
        for f in J.get('formulas', []):
            for m in pat2.finditer(f['text']):
                cnt[m.group(1)] += 1
        if cnt:
            gm = cnt.most_common(1)[0][0]

    slots = {}
    V = None
    if ver_path and os.path.exists(ver_path):
        V = gen_version.load_json_with_comments(ver_path)
    if mhy is not None:
        for i in range(0, 0x301, 4):
            raw = read_u32(pe, mhy + i)
            e = {'raw': ('0x%08X' % raw) if raw is not None else None}
            if V:
                for tname, t in V.get('tables', {}).items():
                    try:
                        slot = int(str(t.get('slot')), 16)
                    except Exception:
                        continue
                    if slot != i:
                        continue
                    try:
                        key = int(str(t.get('key')), 0)
                    except Exception:
                        continue
                    dec = decode_table(raw, t.get('op'), key)
                    e.update({
                        'table': tname,
                        'op': t.get('op'),
                        'key': t.get('key'),
                        'decoded': ('0x%08X' % dec) if dec is not None else None,
                        'confirmed': t.get('confirmed'),
                    })
                    break
            slots['0x%03X' % i] = e

    out = {
        'version': tag,
        'export': exp_path,
        'exe': exe_path,
        'mhy': ('0x%X' % mhy) if mhy is not None else None,
        'mhy_global': mhy_global,
        'gm_global': gm,
        'roles': KNOWN_ROLES.get(tag, {}),
        'globals': globals_out,
        'mhy_slots': slots,
    }
    return out


def emit_rename(out, path, tag):
    lines = [
        '# 自动生成：在 IDA 里 File -> Script file... 运行，给关键全局变量命名',
        '# 目标: %s' % out.get('exe'),
        'import ida_name',
        '',
        'RENAMES = {',
    ]
    for name, new in RENAMES.get(tag, {}).items():
        va = int(name.split('_')[1], 16)
        lines.append("    0x%X: %r,  # %s" % (va, new, name))
    lines += [
        '}',
        '',
        'for va, new in RENAMES.items():',
        '    old = ida_name.get_name(va)',
        '    if old:',
        '        ida_name.set_name(va, new, ida_name.SN_NOCHECK)',
        '        print("0x%X  %s -> %s" % (va, old, new))',
        '',
    ]
    open(path, 'w', encoding='utf-8').write('\n'.join(lines))


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        return 1
    exp, exe, ver, out_path = sys.argv[1:5]
    tag = os.path.basename(os.path.dirname(exe)) or '?'
    out = collect(exp, exe, ver, tag)
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as fp:
        json.dump(out, fp, ensure_ascii=False, indent=1)
    rename_path = os.path.join(os.path.dirname(out_path), 'rename_globals.py')
    emit_rename(out, rename_path, tag)
    print('%s: %d globals, %d slots -> %s' % (tag, len(out['globals']), len(out['mhy_slots']), out_path))
    print('  rename script -> %s' % rename_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
