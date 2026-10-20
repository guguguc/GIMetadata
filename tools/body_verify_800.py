import sys,json,re,statistics
sys.path.insert(0,'tools')
import sig
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from name_resolve import parse_dump_ext
S=parse_dump_ext('dump/dump_deobfuscated.cs',old=True)
T=parse_dump_ext('out/dump71.cs',old=False)
J=json.load(open('/tmp/opencode/name_map71_v7.json'))['classes']
oldpe=sig.PE('dump/UserAssembly.dll'); newpe=sig.PE('version/7.1/gi.exe')
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
def obf(s):return bool(s) and '.' not in s and bool(re.fullmatch(r'[A-Z]{8,}',s))
def ends(c):
 rs=sorted(m['rva'] for m in c['methods']);return {r:(rs[i+1] if i+1<len(rs) else r+0x1000) for i,r in enumerate(rs)}
SE={k:ends(c) for k,c in S.items()};TE={k:ends(c) for k,c in T.items()}
def body(sf,tf,methods):
 vals=[]
 for x in methods:
  if not x.get('target'):continue
  oc=S.get(sf);tc=T.get(tf)
  if not oc or not tc:continue
  sm=next((m for m in oc['methods'] if m['name']==x['source']),None)
  tm=next((m for m in tc['methods'] if m['name']==x['target']),None)
  if not sm or not tm:continue
  so=oldpe.va2off(oldpe.img+sm['rva']);to=newpe.va2off(newpe.img+tm['rva'])
  if so is None or to is None:continue
  sfv=sig._func_features(oldpe,md,oldpe.img+sm['rva'],oldpe.img+SE[sf][sm['rva']])
  tfv=sig._func_features(newpe,md,newpe.img+tm['rva'],newpe.img+TE[tf][tm['rva']])
  if sfv and tfv:
   vals.append(sig._cosine(sfv.get('hist') or {},tfv.get('hist') or {}))
 return vals
rows=[]
for sf,v in J.items():
 if not (v.get('target') and v.get('reason')=='shape' and obf(v['target'])):continue
 vals=body(sf,v['target'],v.get('methods',[]))
 rows.append({'source':sf,'target':v['target'],'class_score':v.get('score'),
              'body_count':len(vals),'body_avg':round(sum(vals)/len(vals),4) if vals else None,
              'body_min':round(min(vals),4) if vals else None,
              'body_max':round(max(vals),4) if vals else None})
json.dump(rows,open('/tmp/opencode/body_verify_800.json','w'),ensure_ascii=False,indent=1)
vals=[r['body_avg'] for r in rows if r['body_avg'] is not None]
print('classes',len(rows),'with body',len(vals),'no body',len(rows)-len(vals))
for th in [.9,.85,.8,.75,.7,.65,.6,.5]:
 print('>=%.2f'%th,sum(1 for x in vals if x>=th))
print('median',statistics.median(vals) if vals else None)
print('\nLOW examples')
for r in sorted([r for r in rows if r['body_avg'] is not None],key=lambda x:x['body_avg'])[:20]:print(r)
print('\nHIGH examples')
for r in sorted([r for r in rows if r['body_avg'] is not None],key=lambda x:-x['body_avg'])[:10]:print(r)
