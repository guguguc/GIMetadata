#!/usr/bin/env python3
"""decodeexpr_auto.py —— 从 fieldDecode/keyFormulas 生成 decodeExpr。

不读目标 version.json。输入是已经合并好的 version.draft.json。
"""
import argparse, json, os, sys
HERE=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.dirname(HERE)
sys.path.insert(0,HERE)
from gen_version import load_json_with_comments

def camel(s):
    return ''.join(w[:1].upper()+w[1:] for w in s.replace('-','_').split('_') if w)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('root'); ap.add_argument('--draft',default=None); ap.add_argument('--out',default=None)
    a=ap.parse_args(); root=a.root if os.path.isabs(a.root) else os.path.join(ROOT,'version',a.root)
    if not os.path.isdir(root): root=a.root
    p=a.draft or os.path.join(root,'version.draft.json'); D=load_json_with_comments(p)
    kf=D.get('keyFormulas',{})
    km='keyMethodParam' if 'methodParamKey' in kf else 'keyMethod'
    ka='keyEventAccessor' if 'eventAccessorKey' in kf else 'keyEvent'
    E={}
    DECNAME={
        ('typeDef','nestedTypesStart'):'decTypeNestedStart',
        ('typeDef','nestedTypesCount'):'decTypeNestedCount',
        ('method','iflags'):'decMethodIFlags',
        ('method','parameterStart'):'decMethodParamStart',
        ('method','parameterCount'):'decMethodParamCount',
    }
    def dn(st,fn):
        if (st,fn) in DECNAME:
            return DECNAME[(st,fn)]
        if st=='typeDef':
            return 'decType'+camel(fn)
        return 'dec%s%s'%(camel(st),camel(fn))

    def spec(st,fn):
        v=D.get('fieldDecode',{}).get(st,{}).get(fn)
        if not v: return None
        op,_,k=str(v).partition(':'); return {'sub':'-','add':'+','xor':'^'}.get(op,op),int(k,0)
    def key(st,fn): return 'k%s%s'%(camel(st),camel(fn))
    def binop(raw,op,keyexpr,cast=''):
        x='(uint32_t)(%s)'%raw
        if op=='^': return '%s ^ (uint32_t)%s.key'%(x,keyexpr)
        if op=='-': return '%s - (uint32_t)%s.key'%(x,keyexpr)
        return '%s + (uint32_t)%s.key'%(x,keyexpr)
    def emit(name,sig,cpp): E[name]={'sig':sig,'cpp':cpp}

    # typeDef
    tpl={
      'nameIndex':('int32_t decTypeNameIndex(uint32_t raw)','int32_t','raw'),
      'namespaceIndex':('int32_t decTypeNamespaceIndex(uint32_t raw)','int32_t','raw'),
      'methodStart':('int32_t decTypeMethodStart(uint32_t raw)','int32_t','raw'),
      'fieldStart':('int32_t decTypeFieldStart(uint32_t raw)','int32_t','raw'),
      'propertyStart':('int32_t decTypePropertyStart(uint32_t raw)','int32_t','raw'),
      'parentIndex':('int32_t decTypeParentIndex(uint32_t raw)','int32_t','raw'),
      'method_count':('uint16_t decTypeMethodCount(uint16_t raw)','uint16_t','raw'),
      'field_count':('uint16_t decTypeFieldCount(uint16_t raw)','uint16_t','raw'),
      'property_count':('uint8_t decTypePropertyCount(uint8_t raw)','uint8_t','raw'),
      'eventStart':('int16_t decTypeEventStart(int16_t raw)','int16_t','raw'),
      'flags':('uint32_t decTypeFlags(uint32_t raw)','uint32_t','raw'),
      'interfacesStart':('uint16_t decTypeInterfacesStart(uint16_t raw)','uint16_t','raw'),
      'interfaces_count':('uint8_t decTypeInterfacesCount(uint8_t raw)','uint8_t','raw'),
      'nestedTypesStart':('int16_t decTypeNestedStart(int16_t raw)','int16_t','raw'),
      'nestedTypesCount':('uint32_t decTypeNestedCount(uint8_t raw)','uint32_t','uint8_t(raw)'),
      'event_count':('uint8_t decTypeEventCount(uint8_t raw)','uint8_t','raw'),
      'unknown20':('int32_t decTypeUnknown20(uint32_t raw)','int32_t','raw'),
    }
    for fn,(sig,cast,raw) in tpl.items():
        s=spec('typeDef',fn)
        if not s: continue
        op,k=s; n=dn('typeDef',fn)
        if fn=='unknown20':
            # 语义未确认，保留 op 的直接解码，避免误用。
            emit(n,sig,'return %s;'%binop(raw,op,key('typeDef',fn),cast))
        else:
            emit(n,sig,'return %s;'%binop(raw,op,key('typeDef',fn),cast))
    s=spec('typeDef','genericContainerIndex')
    if s:
        op,k=s; n='decTypeGenericContainerIndex'
        if op=='-':
            emit(n,'int32_t decTypeGenericContainerIndex(uint16_t raw)',
                 'if (raw == (uint16_t)(%s.key - 1u)) return -1; return (int16_t)(uint16_t)(raw - (uint32_t)%s.key);'%(key('typeDef','genericContainerIndex'),key('typeDef','genericContainerIndex')))
        else:
            emit(n,'int32_t decTypeGenericContainerIndex(uint16_t raw)',
                 'return (int16_t)(uint16_t)(raw ^ (uint32_t)%s.key);'%key('typeDef','genericContainerIndex'))
    if 'bitfield' in D.get('structOffsets',{}).get('Il2CppTypeDefinition',{}):
        emit('decTypeBitfield','uint8_t decTypeBitfield(uint8_t raw)','return raw;')

    # method
    mfields={
      'flags':('uint16_t decMethodFlags(uint16_t raw, uint32_t i)','uint16_t'),
      'iflags':('uint16_t decMethodIFlags(uint16_t raw, uint32_t i)','uint16_t'),
      'parameterCount':('uint8_t decMethodParamCount(uint8_t raw, uint32_t i)','uint8_t'),
      'parameterStart':('uint32_t decMethodParamStart(uint32_t raw, uint32_t i)','uint32_t'),
      'genericContainerIndex':('int16_t decMethodGenericContainerIndex(uint16_t raw, uint32_t i)','int16_t'),
    }
    for fn,(sig,cast) in mfields.items():
        s=spec('method',fn)
        if not s: continue
        op,k=s
        if fn in ('flags','iflags'):
            body='(%s(i) ^ %s)'%(km,binop('raw',op,key('method',fn),cast))
        elif fn=='genericContainerIndex':
            body='(int16_t)(uint16_t)(%s(i) ^ %s)'%(km,binop('raw',op,key('method',fn),cast))
        else:
            body='(%s(i) ^ %s)'%(km,binop('raw',op,key('method',fn),cast))
        emit(dn('method',fn),sig,'return (%s)(%s);'%(cast,body))

    # field
    s=spec('field','typeIndex')
    if s:
        op,k=s
        emit('decFieldTypeIndex','int32_t decFieldTypeIndex(uint32_t raw, uint32_t i)',
             'return (int32_t)(keyField(i) ^ %s);'%binop('raw',op,key('field','typeIndex'),'uint32_t'))
    if spec('field','nameIndexBase'):
        b=spec('field','nameIndexBase'); x=spec('field','nameIndexXor')
        if x:
            emit('decFieldNameIndex','int32_t decFieldNameIndex(uint32_t raw, uint32_t i)',
                 'return (int32_t)((raw - (uint32_t)%s.key) ^ keyField(i) ^ (uint32_t)%s.key);'%(key('field','nameIndexBase'),key('field','nameIndexXor')))

    # property
    if spec('property','nameIndex'):
        op,k=spec('property','nameIndex')
        if op=='^':
            body='(raw ^ (uint32_t)%s.key) - keyProperty(i)'%key('property','nameIndex')
        else:
            body='(raw - (uint32_t)%s.key) ^ keyProperty(i)'%key('property','nameIndex')
        emit('decPropertyNameIndex','int32_t decPropertyNameIndex(uint32_t raw, uint32_t i)','return (int32_t)(%s);'%body)
    s=spec('property','get')
    if s:
        op,k=s
        if op=='+':
            if 'kPropertyNoGetter' in open(p,encoding='utf-8').read():
                body='uint16_t v = (uint16_t)((uint16_t)raw - (uint16_t)keyProperty(i)); return v == (uint16_t)kPropertyNoGetter ? 0xFFFF : (uint16_t)(v + (uint16_t)%s.key);'%key('property','get')
            else:
                body='return (uint16_t)((uint16_t)((uint16_t)raw - (uint16_t)keyProperty(i)) + (uint16_t)%s.key);'%key('property','get')
            emit('decPropertyGet','uint16_t decPropertyGet(uint32_t raw, uint32_t i)',body)
        else:
            emit('decPropertyGet','uint16_t decPropertyGet(uint32_t raw, uint32_t i)',
                 'return (uint16_t)(keyProperty(i) ^ %s);'%binop('raw',op,key('property','get'),'uint16_t'))
    s=spec('property','set')
    if s:
        op,k=s
        if op=='^':
            body='((uint16_t)(raw ^ (uint16_t)%s.key)) - (uint16_t)keyProperty(i)'%key('property','set')
        else:
            body='((uint16_t)(raw - (uint16_t)%s.key)) ^ (uint16_t)keyProperty(i)'%key('property','set')
        emit('decPropertySet','uint16_t decPropertySet(uint32_t raw, uint32_t i)','return (uint16_t)(%s);'%body)

    # event
    s=spec('event','typeIndex')
    if s:
        op,k=s
        emit('decEventTypeIndex','int32_t decEventTypeIndex(uint32_t raw, uint32_t i)',
             'return (int32_t)(%s ^ keyEvent(i));'%binop('raw',op,key('event','typeIndex'),'uint32_t'))
    s=spec('event','nameIndex')
    if s:
        op,k=s
        emit('decEventNameIndex','int32_t decEventNameIndex(uint32_t raw, uint32_t i)',
             'return (int32_t)(keyEvent(i) ^ %s);'%binop('raw',op,key('event','nameIndex'),'uint32_t'))
    for fn in ('add','remove','raise'):
        s=spec('event',fn)
        if not s: continue
        op,k=s
        if op=='^':
            body='%s(i) ^ (uint16_t)raw ^ (uint16_t)%s.key'%(ka,key('event',fn))
        else:
            body='%s(i) ^ %s'%(ka,binop('raw',op,key('event',fn),'uint16_t'))
        emit('decEvent'+camel(fn),'uint16_t decEvent%s(uint32_t raw, uint32_t i)'%camel(fn),
             'return (uint16_t)(%s);'%body)

    # parameter
    s=spec('parameter','typeIndex')
    if s:
        op,k=s
        emit('decParamTypeIndex','int32_t decParamTypeIndex(uint32_t raw, uint32_t i)',
             'return (int32_t)(keyParam(i) ^ %s);'%binop('raw',op,key('parameter','typeIndex'),'uint32_t'))
    b=spec('parameter','nameIndexBase'); x=spec('parameter','nameIndexXor')
    if b and x:
        emit('decParamNameIndex','int32_t decParamNameIndex(uint32_t raw, uint32_t i)',
             'return (int32_t)(keyParam(i) ^ (raw - (uint32_t)%s.key) ^ (uint32_t)%s.key);'%(key('parameter','nameIndexBase'),key('parameter','nameIndexXor')))

    # genericContainer
    s=spec('genericContainer','argc')
    if s:
        op,k=s
        body='(%s) - (uint32_t)keyContainer(c)'%binop('raw',op,key('genericContainer','argc'),'uint32_t')
        emit('decGenericContainerArgc','uint32_t decGenericContainerArgc(uint32_t raw, uint32_t c)','return %s;'%body)
    s=spec('genericContainer','parameterStart')
    if s:
        op,k=s
        body='(%s) - (uint32_t)keyContainer(c)'%binop('raw',op,key('genericContainer','parameterStart'),'uint32_t')
        emit('decGenericContainerParameterStart','uint32_t decGenericContainerParameterStart(uint32_t raw, uint32_t c)','return %s;'%body)

    # genericParameter
    s=spec('genericParameter','nameIndex')
    if s:
        op,k=s
        comb='^' if 'methodParamKey' in kf else '-'
        body='(raw ^ (uint32_t)%s.key) %s (uint32_t)keyGenericParam(i)'%(key('genericParameter','nameIndex'),comb)
        emit('decGenericParameterNameIndex','int32_t decGenericParameterNameIndex(uint32_t raw, uint32_t i)','return (int32_t)(%s);'%body)

    # image
    sd=D.get('stringDecrypt',{}); entry=int(str(sd.get('entryXor','0')),0)
    im=spec('image','nameIndexXor')
    if entry:
        emit('decImageNameIndex','uint32_t decImageNameIndex(uint32_t raw, uint32_t i)',
             'return (uint32_t)(raw ^ keyImage(i) ^ kEntryXor);')
    elif im:
        emit('decImageNameIndex','uint32_t decImageNameIndex(uint32_t raw, uint32_t i)',
             'return (uint32_t)((raw ^ (uint32_t)%s.key) - keyImage(i));'%key('image','nameIndexXor'))

    # string key：按目标字符串解密模式
    if entry:
        emit('decStringKey','uint64_t decStringKey(uint32_t offset)',
             'return kKeyMulA * ((kKeyMulB * (uint64_t)offset) ^ kKeySeed);')
    else:
        emit('decStringKey','uint64_t decStringKey(uint32_t offset)',
             'return (kKeyMulB * (uint64_t)offset + kKeySeed) ^ kKeyMulA;')

    outp=a.out or os.path.join(root,'ida','decodeexpr.auto.json')
    os.makedirs(os.path.dirname(outp),exist_ok=True)
    json.dump(E,open(outp,'w',encoding='utf-8'),ensure_ascii=False,indent=1)
    print('已写',outp,'entries',len(E))

if __name__=='__main__': main()
