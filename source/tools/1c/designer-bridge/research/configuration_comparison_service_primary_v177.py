"""Inert TLS/default-Process service lookup evidence; no comparison delta API.

The concrete slot14 returns a runtime registry entry. It does not prove that
the current TLS receiver is this default class or identify the comparison
service's slot7/result slot11. Import performs no file read or native call.
"""
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

import stock_main_db_comparison_result_route_v173 as inherited

ROOT = Path(__file__).resolve().parents[4]
BASE = 0x10020000
PARENT_SHA = '625075196177edf9dc0f157065377db3dc6659b244a318835bb5830e2c77e73f'
FOUNDATION = 'tools/1c/designer-bridge/research/managed_input_record_contract_v145.py'
FOUNDATION_SHA = 'b5d0eca4d06b4d6a9e6ddec9c35e222b7d7a38093850b5bfd2ed2db439249735'
FOUNDATION_NATIVE = 'tools/1c/designer-bridge/tests/NativeManagedInputRecordV145.as'
FOUNDATION_NATIVE_SHA = '120df31299aaeb774ee84cb19b0e316001f9856f15339f6fd806e5a8de6e5ce1'
PROCESS_EXPORT = '?current_process@core@@YAPAVSCOM_Process@1@XZ'
INIT_EXPORT = '?init@Process@core@@QAEXPAVSCOM_ProcessData@2@@Z'
METADATA_SHA = '27ec4dfc88b10845ac182a71cbd6e96ad1327cd6d0f40a81e32809d204e76145'
SPANS = {
    'currentProcess': (0x1df6c0, 13, '350ffc6e1613ad41ba15f029b1fea8ff364933d736c06002d0e0636d814aaa6d'),
    'processInit': (0x1dfae0, 783, '3f765974459b30d7508f158ccaea94c27c78703b118452a4f1d802b9ff83a0c4'),
    'processDataCtor': (0x1df800, 325, 'ae22634c76d0a14be9d5f6ad51c6934a91f48fef59ce90020a1ab8b7e04450be'),
    'processTable50': (0x2d5120, 200, 'e8de6638fc3586375296034a2715d13f49895f91c03d369a399b5bdffe67de80'),
    'getService': (0x159d70, 144, 'fb4618816fceab95d22d0674e3eb861d3f2b3884af6381ef8d0c451f676d06de'),
    'registerService': (0x1596a0, 1109, 'dc44c3350d60e2647fe2a80cffb8456b928cc993447352e4e00645b3a6ebd64d'),
    'registrationTempDtor': (0x159b00, 107, '8cda0ac5de4fd470dc0746ebc4f6ce376ef5b34a24aa538999f1efa8ce062a9d'),
}
FALSE_CLAIMS = ('currentRuntimeTLSReceiverClassVerified', 'runtimeContextOwnerVerified',
    'processCanonicalQIAndLifetimeVerified', 'rawLookupReturnCountedVerified',
    'comparisonServiceRegistrationVerified', 'comparisonServiceClassAndTableVerified',
    'comparisonServiceSlot7ImplementationVerified', 'comparisonResultClassVerified',
    'comparisonResultSlot11ImplementationVerified', 'fullDeltaIteratorVerified',
    'registrationCallbackCreatesObjectVerified',
    'completionEpochVerified', 'onlyOwnPendingVerified', 'wholeComparisonReadOnlyVerified',
    'routeNeverSavesVerified', 'runtimeRefcountsMeasured', 'exceptionUnwindVerified',
    'nativePermit', 'writerAuthorized', 'saveAuthorized', 'databaseUpdateAuthorized')


def need(ok, code):
    if not ok:
        raise ValueError('V177_'+code)


def word(raw, at):
    return struct.unpack_from('<I', raw, at)[0]


def relative(raw, at, rva):
    return rva+at+4+struct.unpack_from('<i', raw, at)[0]


def directory(pe, index):
    nt = word(pe.data, 0x3c)
    return struct.unpack_from('<II', pe.data, nt+24+96+index*8)


def at(pe, rva, size):
    need(type(rva) is int and type(size) is int and 0<size<=2097152, 'METADATA_BOUND')
    start = pe.offset(pe.base+rva)
    for _, _, section, raw_size, _ in pe.sections:
        if section<=rva and rva+size<=section+raw_size:
            result = pe.data[start:start+size]
            need(len(result)==size, 'METADATA_SHORT')
            return result
    raise ValueError('V177_METADATA_SECTION_BOUND')


def string(pe, rva):
    start = pe.offset(pe.base+rva)
    end = pe.data.find(b'\0', start, start+512)
    need(end>=start, 'METADATA_STRING_BOUND')
    raw = at(pe, rva, end-start+1)
    try:
        return raw[:-1].decode('ascii')
    except UnicodeError:
        raise ValueError('V177_METADATA_STRING_ENCODING') from None


def imported(pe, *, iat=None, symbol=None):
    """Resolve only thunks within each actual null-terminated import table."""
    need((iat is None)!=(symbol is None), 'IMPORT_SELECTOR')
    rva, size = directory(pe, 1)
    need(0<size<=65536 and size%20==0, 'IMPORT_DIRECTORY')
    rows = at(pe, rva, size); found=[]; terminated=False
    for offset in range(0, size, 20):
        original, stamp, chain, name, first = struct.unpack_from('<5I', rows, offset)
        if not any((original, stamp, chain, name, first)):
            terminated=True;break
        count=0;matches=[]
        while count<4096:
            value=word(at(pe, (original or first)+count*4, 4),0)
            if value==0:break
            if not value&0x80000000:
                actual=string(pe,value+2)
                if (iat is not None and first+count*4==iat) or actual==symbol:
                    matches.append(dict(module=string(pe,name),symbol=actual,
                        descriptorRva=rva+offset,iatRva=first+count*4,
                        originalThunkRva=original,index=count,hintNameRva=value))
            count+=1
        need(count<4096, 'IMPORT_THUNK_TERMINATOR')
        for row in matches:row['thunkCount']=count
        found.extend(matches)
    need(terminated and len(found)==1, 'IMPORT_MISSING_OR_AMBIGUOUS')
    return found[0]


def exported(pe, symbol):
    rva, size=directory(pe,0);fields=struct.unpack('<IIHH7I',at(pe,rva,40))
    function_count,name_count,functions,names,ordinals=fields[6:]
    need(0<name_count<=65536 and 0<function_count<=65536,'EXPORT_DIRECTORY')
    found=[]
    expected=symbol.encode('ascii')+b'\0'
    need(0<len(expected)<=512,'EXPORT_SELECTOR_BOUND')
    for index in range(name_count):
        name_rva=word(at(pe,names+index*4,4),0)
        # Compare the exact selected export; unrelated decorated names can be
        # much longer and are not a reason to widen this bounded selector.
        if at(pe,name_rva,len(expected))!=expected:continue
        ordinal=struct.unpack('<H',at(pe,ordinals+index*2,2))[0]
        need(ordinal<function_count,'EXPORT_ORDINAL')
        target=word(at(pe,functions+ordinal*4,4),0)
        need(not rva<=target<rva+size,'EXPORT_FORWARDER')
        found.append(dict(symbol=symbol,targetRva=target,nameRva=name_rva,ordinal=ordinal))
    need(len(found)==1,'EXPORT_MISSING_OR_AMBIGUOUS')
    return found[0]


def relocation_refs(pe, target_rva):
    """Structured relocation metadata for one exact address; no DLL/text sweep."""
    rva,size=directory(pe,5);raw=at(pe,rva,size);cursor=0;refs=[]
    while cursor<len(raw):
        need(cursor+8<=len(raw),'RELOC_HEADER')
        page,block=struct.unpack_from('<II',raw,cursor)
        need(block>=8 and block%2==0 and cursor+block<=len(raw),'RELOC_BLOCK')
        for pos in range(cursor+8,cursor+block,2):
            entry=struct.unpack_from('<H',raw,pos)[0]
            if entry>>12!=3:continue
            site=page+(entry&4095)
            if word(at(pe,site,4),0)==pe.base+target_rva:refs.append(site)
        cursor+=block
    need(len(refs)==len(set(refs)),'RELOC_DUPLICATE')
    return refs


def extract_metadata(config, core):
    need(config.base==inherited.BASE and core.base==BASE,'PE_BASE')
    process=imported(config,iat=0x2ad780)
    need(process['module']=='core83.dll' and process['symbol']==PROCESS_EXPORT,'PROCESS_IMPORT_IDENTITY')
    getter=exported(core,PROCESS_EXPORT);init=exported(core,INIT_EXPORT)
    need(getter['targetRva']==0x1df6c0 and init['targetRva']==0x1dfae0,'PROCESS_EXPORT_TARGET')
    get=imported(core,iat=0x2a720c);put=imported(core,symbol='TlsSetValue')
    need(get['module']=='KERNEL32.dll' and get['symbol']=='TlsGetValue'
         and put['module']=='KERNEL32.dll' and put['iatRva']==0x2a70b4,'TLS_IMPORT_IDENTITY')
    sections=[row for row in core.sections if row[2]<=0x3792ec<row[2]+row[1]]
    need(len(sections)==1 and sections[0][0]=='.data'
         and 0x3792ec>=sections[0][2]+sections[0][3],'TLS_INDEX_RUNTIME_STORAGE')
    service_refs=relocation_refs(config,0x2b83b0)
    need(service_refs==[0x2276a7] and len(service_refs)<=4,'KNOWN_KEY_REFS')
    index_refs=relocation_refs(core,0x3792ec);setter_refs=relocation_refs(core,0x2a70b4)
    selected_index=(0x1df6c2,0x1dfbfc,0x1dfc1f);selected_setter=(0x1dfc07,)
    need(set(selected_index)<=set(index_refs) and set(selected_setter)<=set(setter_refs),'INITIALIZER_REFS')
    need(len(set(selected_index+selected_setter))<=6,'SITE_BUDGET')
    return dict(processImport=process,currentProcessExport=getter,processInitExport=init,
        tlsGetImport=get,tlsSetImport=put,tlsIndexRva=0x3792ec,tlsIndexRawFileBacked=False,
        knownConfigKeyRelocationRefs=service_refs,
        knownConfigKeyAddressHasOtherReference=False,
        tlsIndexRelocationCount=len(index_refs),tlsSetterRelocationCount=len(setter_refs),
        examinedTlsIndexSites=list(selected_index),examinedTlsSetterSites=list(selected_setter),
        otherTargetedRelocationsWereNotDisassembled=True)


def verify_linkage(bodies, metadata, process_sdk, foundation_as):
    need(type(bodies) is dict and set(bodies)==set(SPANS),'SPAN_SET')
    need(all(type(bodies[n]) is bytes and len(bodies[n])==size
             for n,(_,size,_) in SPANS.items()),'SPAN_SIZE')
    need(type(process_sdk) is bytes and hashlib.sha256(process_sdk).hexdigest()==inherited.PROCESS_SHA,'PUBLISHED_PROCESS_PIN')
    need(b'bool registerService(const Guid&in, const Guid&in)' in process_sdk
         and b'IUnknown@+ getService(const Guid&in idService)' in process_sdk,'PUBLISHED_SERVICE_METHODS')
    need(type(foundation_as) is bytes and hashlib.sha256(foundation_as).hexdigest()==FOUNDATION_NATIVE_SHA,'FOUNDATION_NATIVE_PIN')
    need(b'0x2d5120,slots' in foundation_as and b'mem::int_ptr[context+0x18]!=p' in foundation_as
         and b'mem::int_ptr[p+0x84]' in foundation_as,'OBSERVED_FOUNDATION_CONTEXT')
    need(type(metadata) is dict and hashlib.sha256(json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()).hexdigest()==METADATA_SHA,'METADATA_PIN')
    need(metadata['processImport']['index']==246
         and metadata['processImport']['thunkCount']==409
         and metadata['tlsIndexRawFileBacked'] is False,'METADATA_SEMANTICS')
    getter=bodies['currentProcess']
    need(getter==b'\xff\x35'+struct.pack('<I',BASE+0x3792ec)
         +b'\xff\x15'+struct.pack('<I',BASE+0x2a720c)+b'\xc3','TLS_GETTER_NORMAL')
    init,ctor=bodies['processInit'],bodies['processDataCtor']
    need(relative(init,0x7e,0x1dfae0)==0x1df800,'INITIALIZER_CTOR_EDGE')
    need(init[0xd6:0xd8]==bytes.fromhex('8b01')
         and init[0xde:0xe3]==bytes.fromhex('8b008945f0'),'INITIALIZER_VALUE_DATAFLOW')
    need(init[0x13a:0x145]==bytes.fromhex('ff75f0ff35')+struct.pack('<I',BASE+0x3792ec)+bytes.fromhex('ffd6')
         and init[0x125:0x12b]==bytes.fromhex('8b35')+struct.pack('<I',BASE+0x2a70b4),'TLS_SET_SAME_VALUE')
    need(init[0x2de:0x2e1]==bytes.fromhex('c20400')
         and init[0x305:]==bytes.fromhex('57ffd1eb8556ffd1ebb0'),'INITIALIZER_RET_AND_COLD_TAILS')
    need(b'\xc7\x07'+struct.pack('<I',BASE+0x2d5120) in ctor
         and bytes.fromhex('8b45f0893889872c010000') in ctor
         and ctor[-1:]==b'\xc3','DEFAULT_CLASS_INSTALL_AND_RETURN')
    cells=struct.unpack('<50I',bodies['processTable50'])
    need(tuple(x-BASE for x in cells[:6])==(0x1e11c0,0x2ccf0,0x2ccf0,0x1585a0,0x158670,0x158600)
         and cells[12]==BASE+0x1596a0 and cells[14]==BASE+0x159d70,'TABLE_PUBLISHED_SLOTS')
    lookup=bodies['getService']
    need(lookup[0xf:0x17]==bytes.fromhex('8b465023018b4e44')
         and lookup[0x1e:0x21]==bytes.fromhex('8b5e3c')
         and bytes.fromhex('8b78108b701433790833710c8b500833118b480c0bfa334b04') in lookup,
         'FULL_GUID_MAP_LOOKUP')
    need(lookup[0x7f:0x88]==bytes.fromhex('8b402c8be55dc20800')
         and lookup[0x88:]==bytes.fromhex('33c08be55dc20800'),'CACHED_POINTER_OR_NULL_RET8')
    # The no-direct-AddRef observation covers the whole exact normal method,
    # including instructions outside the role/ABI anchors above.
    need(hashlib.sha256(lookup).hexdigest()==SPANS['getService'][2],'WHOLE_LOOKUP_EFFECTS')
    register=bodies['registerService']
    need(bytes.fromhex('8b47288b48148b018d55bcc645fc015268')+struct.pack('<I',BASE+0x2aa428)
         +bytes.fromhex('ff75c851ff500c') in register,'REGISTER_FACTORY_RUNTIME_DESCRIPTOR')
    need(bytes.fromhex('51ff75d056ffd0') in register
         and bytes.fromhex('8b4e2c8b45c03bc8') in register
         and bytes.fromhex('89462c') in register,'REGISTER_QI_AND_LOOKUP_CACHE_JOIN')
    need(relative(register,0x384,0x1596a0)==0x159b00
         and register[0x43c:0x43f]==bytes.fromhex('c20c00')
         and register[-5:][0]==0xe8,'REGISTER_RET12_AND_THROW_TAIL')
    temporary=bodies['registrationTempDtor']
    need(bytes.fromhex('8b4e14') in temporary and bytes.fromhex('8b4e10') in temporary
         and temporary.count(bytes.fromhex('ff5008'))==2 and temporary[-1:]==b'\xc3','REGISTER_TEMP_NORMAL_RELEASE')
    result=dict(inheritedV154V173Reused=True,concreteDefaultProcessSlot14Verified=True,
        defaultProcessTableRva=0x2d5120,defaultProcessGetServiceRva=0x159d70,
        defaultProcessRegisterServiceRva=0x1596a0,defaultInitializerDataflowVerified=True,
        defaultBranchCreatesProcess=True,callerSuppliedProcessDataBranchAlsoPresent=True,
        currentProcessReturnsRuntimeTlsPointer=True,processLookupArgumentBytes=8,
        processLookupServiceId=inherited.SERVICE_ID,serviceMapSentinelOffset=0x3c,
        serviceMapBucketsOffset=0x44,serviceMapMaskOffset=0x50,
        nodeServicePointerOffset=0x2c,registrationFactoryDescriptorRuntimeDerived=True,
        registrationHasOpaqueDescriptorCallback=True,
        registrationTemporarySlots4And8CallsVerified=True,rawGetServiceContainsNoDirectAddRefCall=True,
        publishedHandleAnnotationIsNotRuntimeRefcountEvidence=True,
        normalUnits=7,maximumNormalUnitBytes=1109,examinedDistinctTlsSites=4,
        defaultClassIsNotProofOfCurrentTlsClass=True,supportedDeltaShape=None,
        safeCallableComparisonBoundaryVerified=False,
        missingEdges=['Current TLS pointer class/owner must be observed and bound; default initializer does not prove current runtime receiver.',
            'Comparison service GUID registry node+0x2c needs concrete registered class/table and normal slot7 implementation.',
            'Comparison result slot11 class/children/UUID/change-kind/property/module/resource iterator and completion epoch remain opaque.'])
    result.update({name:False for name in FALSE_CLAIMS})
    return result


def require_only_own_pending(*rows, **claims):
    raise ValueError('V177_RUNTIME_SERVICE_CLASS_RESULT_AND_DELTA_UNPROVEN')


def verify_static():
    """Hash-pinned source/PE metadata and seven fixed code/data units only."""
    from repository_pe_probe import PE,HASHES
    need(hashlib.sha256(Path(inherited.__file__).read_bytes()).hexdigest()==PARENT_SHA,'PARENT_SOURCE_PIN')
    need(hashlib.sha256((ROOT/FOUNDATION).read_bytes()).hexdigest()==FOUNDATION_SHA,'FOUNDATION_SOURCE_PIN')
    prior=inherited.verify_static()
    need(prior['fullV154StructureReused'] is True and prior['onlyOwnPendingVerified'] is False,'INHERITED_BOUNDARY')
    config,core=PE('config.dll'),PE('core83.dll');metadata=extract_metadata(config,core);bodies={}
    for name,(rva,size,pin) in SPANS.items():
        raw=at(core,rva,size);need(hashlib.sha256(raw).hexdigest()==pin,'PRIMARY_PIN');bodies[name]=raw
    archive=inherited.parent.ARCHIVE.read_bytes()
    need(hashlib.sha256(archive).hexdigest()==inherited.parent.ARCHIVE_SHA,'SDK_PIN')
    with zipfile.ZipFile(io.BytesIO(archive)) as source:process=source.read(inherited.PROCESS_MEMBER)
    result=verify_linkage(bodies,metadata,process,(ROOT/FOUNDATION_NATIVE).read_bytes())
    result.update(metadata=metadata,primarySpanSha256={n:s[2] for n,s in SPANS.items()},
        inheritedFreezeSpanCount=31,platformSha256={n:HASHES[n].lower() for n in ('config.dll','core83.dll')},
        sourceFoundationSha256=FOUNDATION_SHA,nativeFoundationSha256=FOUNDATION_NATIVE_SHA,
        processSdkSha256=inherited.PROCESS_SHA)
    return result
