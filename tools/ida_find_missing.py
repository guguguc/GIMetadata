#!/usr/bin/env python3
"""
ida_find_missing.py —— 在 IDA **7.0 数据库**里定位 sig.py 没认出来的 4 个函数。

原理：不靠字节签名（这 4 个寄存器/立即数/结构偏移都变了），靠 **callee 指纹**：
  7.1 里这些函数调用了哪些**已经定位**的函数（sig_hits.json 里有 7.0 地址），
  然后在 7.0 里找"调用同一批函数"的候选 —— 交集越大越可信。

用法（二选一）：
  1. IDA 菜单 File -> Script file... 选本文件
  2. 把内容粘进 IDA 底部的 Python 控制台

输出：每个目标函数给出候选地址、函数大小、命中了几个指纹 callee、具体是哪些。
判据：命中数最多 **且** 大小接近 7.1（size_hint）的那一个。

注意：脚本只读数据库，不修改任何东西。
"""
import json
from collections import Counter, defaultdict

try:
    import idautils, ida_funcs
except ImportError:
    raise SystemExit('必须在 IDA 的 Python 环境里运行')

ROOT = '/home/gugugu/Repo/GIMetadata'
SIGS = ROOT + '/tools/sigs.json'
HITS = ROOT + '/version/7.0/sig_hits.json'

TARGETS = [
    'GIMeta_SetupTypeInfoLocked',
    'GIMeta_GetMethodInfoFromIndex',
    'GIMeta_GetDefaultValue',
    'GIMeta_GetDefaultParameterValueObject',
]

# 7.1 里估的函数大小（ret+填充 边界），只当排序提示，±30% 都正常
SIZE_HINT = {
    'GIMeta_SetupTypeInfoLocked': 0x171F,
    'GIMeta_GetMethodInfoFromIndex': 0x138,
    'GIMeta_GetDefaultValue': 0x4A3,
    'GIMeta_GetDefaultParameterValueObject': 0x30D,
}


def main():
    sigs = {x['name']: x for x in json.load(open(SIGS))}
    hits = json.load(open(HITS))['hits']
    already = set(hits.values())

    for nm in TARGETS:
        sg = sigs.get(nm)
        if not sg:
            print('!! 找不到签名', nm)
            continue
        # 只保留 7.0 里已经定位的 callee 当指纹桩点
        fp = [(c, hits[c]) for c in (sg.get('callees') or []) if c in hits]
        cnt = Counter()
        who = defaultdict(list)
        for cname, tva in fp:
            for x in idautils.XrefsTo(tva, 0):
                f = ida_funcs.get_func(x.frm)
                if not f:
                    continue
                if f.start_ea in already:      # 已经定位的 50 个不可能是这 4 个
                    continue
                if f.start_ea == tva:
                    continue
                cnt[f.start_ea] += 1
                who[f.start_ea].append(cname)

        hint = SIZE_HINT.get(nm, 0)
        print('\n' + '=' * 78)
        print('%s   7.1=%s   size_hint=0x%X   指纹桩点=%d' % (nm, sg['va'], hint, len(fp)))
        print('  callee 指纹:', ', '.join(c for c, _ in fp))
        if not cnt:
            print('  !! 没有任何候选调用这些函数（检查 callee 桩点是否已定位）')
            continue
        rows = sorted(cnt.items(), key=lambda kv: (-kv[1], abs((ida_funcs.get_func(kv[0]).end_ea
                                                               - kv[0]) - hint) if hint else 0))
        print('  候选（按命中数排序；size 接近 hint 的更可信）:')
        for ea, n in rows[:10]:
            f = ida_funcs.get_func(ea)
            size = f.end_ea - f.start_ea
            ratio = (size / float(hint)) if hint else 0
            names = ','.join(sorted(set(who[ea])))
            print('    0x%-12X size=0x%-6X (%.2fx)  命中 %d/%d  %s'
                  % (ea, size, ratio, n, len(fp), names))

    print('\n' + '-' * 78)
    print('确认后写回（在仓库根目录执行，把 0x??? 换成真实地址）:')
    print("""  python3 - <<'PY'
import json
p = 'version/7.0/sig_hits.json'
d = json.load(open(p))
d['hits'].update({
    'GIMeta_SetupTypeInfoLocked': 0x???,
    'GIMeta_GetMethodInfoFromIndex': 0x???,
    'GIMeta_GetDefaultValue': 0x???,
    'GIMeta_GetDefaultParameterValueObject': 0x???,
})
d['stats']['hit'] = len(d['hits'])
d['stats']['miss'] = len(d['ref']) - len(d['hits'])
json.dump(d, open(p, 'w'), indent=1)
print('now', d['stats'])
PY""")


if __name__ == '__main__':
    main()
