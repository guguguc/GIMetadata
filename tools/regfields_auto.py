#!/usr/bin/env python3
"""regfields_auto.py —— 从目标 decomp/数据结构恢复 registrationFields。

只使用上一版 JSON、目标 IDA/decomp、目标 PE/metadata。
"""
import argparse, json, os, re, sys
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.dirname(HERE)
sys.path.insert(0,HERE)
from gen_version import load_json_with_comments
from sig import PE

def main():
    ap=argparse.ArgumentParser();ap.add_argument('root');ap.add_argument('--draft',default=None);ap.add_argument('--base',default=os.path.join(ROOT,'version.json'));ap.add_argument('--out',default=None)
    a=ap.parse_args();root=a.root if os.path.isabs(a.root) else os.path.join(ROOT,'version',a.root)
    if not os.path.isdir(root):root=a.root
    D=load_json_with_comments(a.draft or os.path.join(root,'version.draft.json'))
    B=load_json_with_comments(a.base)
    exe=os.path.join(root,'gi.exe');pe=PE(exe)
    dat=open(os.path.join(root,'gi','Managed','Metadata','global-metadata.dat'),'rb').read();H=0x210
    startup_p=os.path.join(root,'gi','Managed','Metadata','startup-metadata.dat')
    startup=open(startup_p,'rb').read() if os.path.exists(startup_p) else b''
    decdir=os.path.join(root,'ida','decomp')
    texts={}
    for fn in os.listdir(decdir) if os.path.isdir(decdir) else []:
        if fn.endswith('.c'):texts[fn[:-2]]=open(os.path.join(decdir,fn),encoding='utf-8',errors='ignore').read()
    alltxt='\n'.join(texts.values())
    ida_json=open(os.path.join(root,'ida.json'),encoding='utf-8').read() if os.path.exists(os.path.join(root,'ida.json')) else ''
    R=D.setdefault('registrationFields',{}); Rb=B.get('registrationFields',{})
    def hx(v): return '0x%02X' % int(v)

    # T0/T1 全局名和 VA 来自 RegisterTables
    rt='\n'.join(v for k,v in texts.items() if k.startswith('GIMeta_RegisterTables'))
    qs=re.findall(r'(\w+)\s*=\s*[^;]*?&(?:unk|off)_([0-9A-Fa-f]+)',rt)
    if len(qs)<2:
        raise SystemExit('RegisterTables parse failed')
    t0,t0va=int(qs[0][1],16),int(qs[0][1],16)
    t0name=qs[0][0];t1name=qs[1][0];t1va=int(qs[1][1],16)

    def rdq(va):
        o=pe.va2off(va)
        return int.from_bytes(pe.D[o:o+8],'little') if o is not None else 0
    def rdbytes(va,n):
        o=pe.va2off(va)
        return pe.D[o:o+n] if o is not None else b''

    def offsets(ptr,text):
        return set(int(x) for x in re.findall(r'\*\(\s*_QWORD\s*\*\)\s*\(\s*'+re.escape(ptr)+r'\s*\+\s*(\d+)',text))

    # T1: types / genericInsts 用 16 字节数组形态区分
    t1off=offsets(t1name,alltxt)
    best_types=best_gi=None
    for off in t1off:
        ptr=rdq(t1va+off); b=rdbytes(ptr,16*20)
        if not b:continue
        ty=sum(1 for i in range(0,len(b),16) if 1<=b[i+10]<=0x1f)
        gi=0
        for i in range(0,len(b),16):
            argc=int.from_bytes(b[i:i+4],'little'); pv=int.from_bytes(b[i+8:i+16],'little')
            if argc<1000 and pe.va2off(pv) is not None:gi+=1
        if ty>=15 and gi<5:
            if best_types is None or ty>best_types[0]:best_types=(ty,off)
        if gi>=15 and ty<5:
            if best_gi is None or gi>best_gi[0]:best_gi=(gi,off)
    if best_types:R['t1_il2CppTypes']=hx(best_types[1])
    if best_gi:R['t1_genericInsts']=hx(best_gi[1])

    # T0: 按 RuntimeInit / SetupTypeInfo 两个消费者的读取集合定位三个角色
    setup='\n'.join(v for k,v in texts.items() if k.startswith('GIMeta_SetupTypeInfoLocked'))
    run='\n'.join(v for k,v in texts.items() if k.startswith('GIMeta_RuntimeInit'))
    so=offsets(t0name,setup);ro=offsets(t0name,run)
    # offset 0: *(T0) 形式也算
    if re.search(r'\*\(\s*_QWORD\s*\*\)\s*'+re.escape(t0name)+r'\b',run):ro.add(0)
    inter=so&ro;only_s=so-ro;only_r=ro-so
    if inter:R['t0_methodPointerIndexArray']=hx(min(inter))
    if only_s:R['t0_invokerArray']=hx(min(only_s))
    if only_r:R['t0_genericMethodPointers']=hx(min(only_r))

    # 掩码：静态字段判断的 (& mask)==value；字段偏移 mask 取最高频的大掩码
    pairs={}
    for m in re.finditer(r'&\s*(0x[0-9A-Fa-f]+)\)\s*==\s*(0x[0-9A-Fa-f]+)',alltxt):
        mask=int(m.group(1),0); val=int(m.group(2),0)
        if mask<=0xFFFFFFFF and mask>0xFFFF:
            pairs[(mask,val)]=pairs.get((mask,val),0)+1
    if pairs:
        # 高静态位版本（7.1+）的 mask 在最高位；旧版可能用低 24 位方案。
        high=[(m,v) for (m,v) in pairs if m>=0x80000000]
        if high:
            mask,val=max(high,key=lambda x:(x[0],pairs[x]))
        else:
            mask,val=max(pairs.items(),key=lambda kv:kv[1])[0]
        R['fieldStaticMask']='0x%X'%mask;R['fieldStaticValue']='0x%X'%val
        if str(Rb.get('fieldStaticValue','')).lower()!=str(val).lower():R['fieldStaticZero']=0
        if mask>=0x80000000:
            R['fieldOffsetMask']='0x%X'%((~mask)&0xFFFFFFFF)
        else:
            masks={}
            for m in re.finditer(r'&\s*(0x[0-9A-Fa-f]+)',alltxt):
                v=int(m.group(1),0)
                if 0xFFFF<v<=0xFFFFFFFF and v!=mask:masks[v]=masks.get(v,0)+1
            if masks:
                fm,_=max(masks.items(),key=lambda kv:kv[1]);R['fieldOffsetMask']='0x%X'%fm

    # 旧字段常数若在目标 decomp/ida 中不存在，表示该版本未使用
    def present(v):
        if v is None:return False
        try:n=int(str(v),0)
        except:return False
        forms={str(n),'0x%X'%n,'0x%x'%n}
        return any(f in alltxt or f in ida_json for f in forms)
    for name in ('fieldOffsetBaseTable','fieldIndexTable','propertyNoGetter'):
        if name in Rb and not present(Rb[name]):R[name]='0'

    # genericClassesOffset：RuntimeInit 读到的 startup 小表（callee 最多）
    cand=[]
    try:E=json.load(open(os.path.join(root,'ida.json'),encoding='utf-8'))
    except:E={}
    for t in E.get('tables',[]):
        try:v=int(str(t.get('value','0')),0)
        except:continue
        if 'GIMeta_RuntimeInit' in (t.get('funcs') or []) and 0<v<0x200000 and len(t.get('callees') or [])>=2:
            cand.append((len(t.get('callees') or []),v))
    if cand:
        _,off=max(cand)
        R['genericClassesOffset']=hx(off)
        old=Rb.get('genericClassesOffset')
        if old is not None and int(str(old),0)==off:
            R['genericClassesCount']=Rb.get('genericClassesCount')
        elif startup:
            R['genericClassesCount']=(len(startup)-off)//8

    out={k:R[k] for k in sorted(R)}
    outp=a.out or os.path.join(root,'ida','regfields.auto.json')
    os.makedirs(os.path.dirname(outp),exist_ok=True)
    json.dump(out,open(outp,'w',encoding='utf-8'),ensure_ascii=False,indent=1)
    print('已写',outp)
    for k in sorted(out):print(' ',k,out[k])

if __name__=='__main__':main()
