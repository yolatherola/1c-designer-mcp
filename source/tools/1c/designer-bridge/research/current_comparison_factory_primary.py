"""Finite primary evidence for the actually observed comparison service.

No native execution/admission. A complete local wrapper CFG and unwind map do
not identify its runtime class provider, returned constructor or delta model.
"""
from pathlib import Path
import hashlib
import struct
import sys
import uuid
from repository_pe_probe import PE,HASHES
from configuration_comparison_service_primary_v177 import imported

ROOT=Path(__file__).resolve().parents[4]
BASE=0x26dc0000
CLSID='815fc7a5-5e8d-4fc3-bc54-3c2ef73db174'
IID='d7b5a01d-f882-4677-8944-d926ea06d67d'
OBSERVATION='fe6e5d72e0c3494eb2ad169de8893c1d'
OBSERVATION_SHA='fc1bf54b84ad7e8db554247e9076fe6dc587914a1e1f265ec8a06a2635689fb5'
SDK=ROOT/'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/modules/snegopat/v8api/process.v'
SDK_SHA='92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef'
SPANS={
 'serviceTable':('frntend.dll',0xc0daa4,48,'3de466f2714a7d31840ef7e60f36f5af62d15f6130df21ab9296329d625d7cca'),
 'factory':('frntend.dll',0x1322e0,2036,'22587954de1c81f20a32ecb27d5b1f1bccf0f65aac5aca5b806045b9e7c9889d'),
 'factoryEH':('frntend.dll',0xb39cdd,40,'cbc4f780f5307b7535cd718ed77788114d3ab8e4638b8ae3918afef2bf73de53'),
 'factoryFuncInfo':('frntend.dll',0xcb2ec8,36,'a703bb0bfa96ac2dd5f5eb2c818442ab4c2725df3217c6f1f320648f34badc94'),
 'factoryUnwind':('frntend.dll',0xcb2ef0,256,'5fcb31cdb8c88acc06013938c22a3c8107dd66a4790619590d26d338284f9d82'),
 'factoryFunclets':('frntend.dll',0xb39c30,173,'fe48c587509ddade55b1e524c193aac60136fb1bf4cdd8126857afba5b8d7e08'),
 'processShim':('frntend.dll',0x95fea0,38,'11e2773730a911603d14df88c2cf15091e9b06cb51fdf75502747e5bfa45d87b'),
 'createOutput':('frntend.dll',0x9607e0,125,'b4ec061e75c3654796b2ccfdce78d4184544b04be2b89e2de9012c20459aa7c3'),
 'outputEH':('frntend.dll',0xb144a0,27,'f3a8ea4e3298d58ec1d4ae46fe5e6b0d9126777a6199e7f41c76c80ad409bbff'),
 'outputFuncInfo':('frntend.dll',0xc7f438,36,'04756a3e525c6f872513fb060d6fa290063e97ff6d451dc00142aabeb6fb2c4b'),
 'outputUnwind':('frntend.dll',0xc7f45c,8,'7365ded0e5b7880a49ecbc42caf63a8f7b20ba803904059cac3523ce3d69a27f'),
 'frameHandlerThunk':('frntend.dll',0xb13644,6,'bf73f2ee1dca1a734d4940fc48b2fbcef18038a357449a9b279d7605754d9a74'),
 'stdTerminateThunk':('frntend.dll',0xb1364a,6,'bcf1e36e48e1596bdb5167d34693e8901e2cc21aa871756e3213379e13a80321'),
 'variantEnvelopeDtor':('frntend.dll',0x132ae0,50,'1e4563c617312cb7788c48fcd62ae657bb949ba973630e611e694207a67b3cce'),
 'variantDtor':('frntend.dll',0x8f0430,15,'f34391b913e7c2c7a6e80f7a6745f13ee44eff131625a54ff56b087ca69e3d7c'),
 'holderRelease':('frntend.dll',0x8ec080,74,'ce34f689df5619cdd2fabf40a12c0775a6a55da1d949526abea631b6a5aeca73'),
 'outputGuids':('frntend.dll',0xc0dae0,64,'6960eef1e62ad7e3f9da27b357a614c1f40d1abc481240e51d269bc486232ed7'),
 'processCreate':('core83.dll',0x158600,99,'103972e414d37962d47a8c8d17db3eb002299fb8028ee8746025c7b56b2eebb4'),
 'processTable':('core83.dll',0x2d5120,200,'e8de6638fc3586375296034a2715d13f49895f91c03d369a399b5bdffe67de80')}


def need(ok,code):
    if not ok:raise ValueError('COMPARISON_FACTORY_PRIMARY_'+code)


def _decoder():
    from prepare_runtime_v40 import CACHE
    sys.path.insert(0,str(CACHE/'analysis-deps'))
    from capstone import Cs,CS_ARCH_X86,CS_MODE_32
    engine=Cs(CS_ARCH_X86,CS_MODE_32);engine.detail=True;return engine


def local_cfg(raw,start,*,allow_indirect_tail=False):
    """Close every local normal edge; leave callees/transitive effects unknown."""
    engine=_decoder()
    from capstone.x86_const import X86_OP_IMM
    instructions=list(engine.disasm(raw,start));rows={i.address:i for i in instructions}
    need(sum(i.size for i in instructions)==len(raw),'CFG_DECODE')
    edges=[];tails=[];returns=[];pending=[start];seen=set()
    while pending:
        at=pending.pop()
        if at in seen:continue
        need(at in rows,'CFG_TARGET');seen.add(at);ins=rows[at];successors=[]
        if ins.mnemonic.startswith('ret'):returns.append(ins.op_str or '0')
        elif ins.mnemonic.startswith('j'):
            if ins.operands[0].type==X86_OP_IMM:successors.append(ins.operands[0].imm)
            else:
                need(allow_indirect_tail and ins.mnemonic=='jmp','CFG_INDIRECT');tails.append(ins.address)
            if ins.mnemonic!='jmp':successors.append(at+ins.size)
        else:successors.append(at+ins.size)
        for target in successors:
            need(target in rows,'CFG_EDGE_OUTSIDE');edges.append((at,target));pending.append(target)
    need(seen==set(rows),'CFG_UNREACHED_BYTES')
    return dict(instructions=len(rows),localEdges=len(edges),returns=sorted(returns),indirectTailRvas=tails)


def verify_units(bodies,*,check_hashes=True):
    need(type(bodies) is dict and set(bodies)==set(SPANS),'UNIT_SET')
    for name,(_,_,size,pin) in SPANS.items():
        need(type(bodies[name]) is bytes and len(bodies[name])==size,'UNIT_BOUND')
        if check_hashes:need(hashlib.sha256(bodies[name]).hexdigest()==pin,'UNIT_PIN')
    table=struct.unpack('<12I',bodies['serviceTable'])
    need(table[7]==BASE+0x1322e0 and table[8]==BASE+0x132b20,'ACTUAL_SLOT7')
    factory=bodies['factory'];cfg=local_cfg(factory,0x1322e0)
    need(cfg['returns']==['0x44'] and factory[-3:]==bytes.fromhex('c24400'),'FACTORY_RET68')
    need(factory[0x7d1:0x7d7]==bytes.fromhex('8b8524ffffff'),'OUTPUT_HOLDER_RETURN')
    need(factory[0x70e:0x714]==bytes.fromhex('ff9534ffffff'),'RESULT_SLOT3_CALL')
    create=bodies['createOutput'];create_cfg=local_cfg(create,0x9607e0)
    need(create_cfg['returns']==['0','0'] and bytes.fromhex('ff501484c07417') in create,'CREATE_BOOL_BRANCH')
    need(struct.pack('<I',BASE+0xc0db10) in create and struct.pack('<I',BASE+0xc0dae0) in create,'RESULT_CLASS_GUID_ARGS')
    need(uuid.UUID(bytes_le=bodies['outputGuids'][:16])==uuid.UUID(IID)
        and uuid.UUID(bytes_le=bodies['outputGuids'][48:64])==uuid.UUID(CLSID),'RESULT_GUID_BYTES')
    process=bodies['processCreate'];process_cfg=local_cfg(process,0x158600,allow_indirect_tail=True)
    need(struct.unpack('<50I',bodies['processTable'])[5]==0x10020000+0x158600,'PROCESS_SLOT5')
    need(process_cfg['returns']==['0x10','0x10'] and process_cfg['indirectTailRvas']==[0x15865a],'PROCESS_RET_AND_FALLBACK')
    need(bytes.fromhex('8b8084000000ff750c8b48148b410483c10451ff5014') in process,'PRIMARY_PROVIDER_CHAIN')
    need(bytes.fromhex('81c160010000') in process,'TLS_FALLBACK_OFFSET')
    info=struct.unpack('<9I',bodies['factoryFuncInfo'])
    need(info[:5]==(0x19930522,32,BASE+0xcb2ef0,0,0),'EH32_NO_CATCHES')
    unwind=struct.unpack('<64I',bodies['factoryUnwind']);actions=set()
    for i in range(32):
        parent=struct.unpack('<i',struct.pack('<I',unwind[2*i]))[0];action=unwind[2*i+1]
        need(-1<=parent<i and action!=0,'EH_STATE_CHAIN');actions.add(action-BASE)
    need(actions==set((0xb1364a,0xb39c30,0xb39c38,0xb39c40,0xb39c48,0xb39c53,0xb39c5e,0xb39c69,
        0xb39c8b,0xb39c96,0xb39c9e,0xb39ca6,0xb39cb1,0xb39cbc,0xb39cc7,0xb39cd2)),'EH_ACTION_SET')
    need(bodies['factoryFunclets'][0x5a:0x5b]==b'\xc3','CONDITIONAL_OUTPUT_CLEANUP_RET')
    need(struct.unpack('<9I',bodies['outputFuncInfo'])[:5]==(0x19930522,1,BASE+0xc7f45c,0,0)
        and struct.unpack('<2I',bodies['outputUnwind'])==(0xffffffff,BASE+0xb1364a),'OUTPUT_EH_TERMINATE')
    return dict(factorySlotRva=0x1322e0,factoryNormalBytes=2036,factoryRetPopBytes=68,
        factoryLocalNormalCFG=cfg,outputCreateLocalNormalCFG=create_cfg,processCreateLocalNormalCFG=process_cfg,
        exceptionStates=32,exceptionActions=16,localCatchBlocks=0,outputClsid=CLSID,outputIid=IID,
        providerReadOffsets=[0x84,0x14,4],providerVirtualSlot=5,providerMinimumPages=[0x88,0x18,8,24],
        providerLastOffsetIsInlineSecondaryInterface=True,
        outputInitializationSlot=3,resultExecutionSlot=11,
        remainingEdges=['Actual Process+0x84 -> object+0x14 -> secondary interface+4 vtable.slot5 attribution is unobserved.',
          'If that provider refuses, Process TLS fallback at +0x160 and its runtime virtual slot5 are unobserved.',
          'CLSID provider constructor/result QI/refcounts, result.slot3 initialization and slot11 execution/cancel/error remain unclosed.',
          'UUID/change-kind/property/module/resource iterator and completion epoch are not identified.'],
        constructorTypeVerified=False,countedResultOwnershipVerified=False,transitiveReadOnlyVerified=False,
        fullDeltaIteratorVerified=False,onlyOwnPendingVerified=False,factoryCallable=False,nativePermit=False,
        sourceWrites=0,configurationSaves=0,databaseUpdates=0,repositoryMutations=0)


def verify_static():
    """Read only fixed PE spans, actual prior JSON and published SDK text."""
    images={name:PE(name) for name in ('frntend.dll','core83.dll')};bodies={}
    for name,(module,rva,size,_) in SPANS.items():
        image=images[module];offset=image.offset(image.base+rva);bodies[name]=image.data[offset:offset+size]
    result=verify_units(bodies)
    raw=SDK.read_bytes();need(hashlib.sha256(raw).hexdigest()==SDK_SHA,'SDK_PIN')
    need(b'bool createByClsid(const Guid&in clsid, const Guid&in iid, IUnknown@&out ppObject)' in raw,'PUBLISHED_CREATE_SIGNATURE')
    process_import=imported(images['frntend.dll'],iat=0xbf9f60)
    need(process_import['module']=='core83.dll' and process_import['symbol']=='?current_process@core@@YAPAVSCOM_Process@1@XZ','PROCESS_GETTER_IMPORT')
    need(imported(images['frntend.dll'],iat=0xbf9224)['symbol']=='__std_terminate'
        and imported(images['frntend.dll'],iat=0xbf9228)['symbol']=='__CxxFrameHandler3','EXCEPTION_IMPORTS')
    observation=ROOT/'build'/('designer-hot-v233-'+OBSERVATION)/'runner-editors-proof.json'
    raw=observation.read_bytes();need(hashlib.sha256(raw).hexdigest()==OBSERVATION_SHA,'ACTUAL_OBSERVATION_PIN')
    import json
    observed=json.loads(raw)
    need(observed.get('operationId')==OBSERVATION and observed.get('status')=='SERVICE_CACHE_OBSERVED'
        and observed.get('coherent') is True and observed.get('passes')==2
        and observed.get('serviceType')=={'module':'frntend.dll','rva':0xc0daa4}
        and observed.get('factorySlot7Type')=={'module':'frntend.dll','rva':0x1322e0},'ACTUAL_SERVICE_TABLE')
    need(observed.get('serviceSlotTypes')==[{'module':'frntend.dll','rva':cell-BASE}
        for cell in struct.unpack('<12I',bodies['serviceTable'])],'ACTUAL_TWELVE_SLOTS')
    result.update(kind='CURRENT_COMPARISON_FACTORY_PRIMARY',units=len(bodies),
        primaryHashes={name:value[3] for name,value in SPANS.items()},
        platformHashes={name:HASHES[name].lower() for name in images},actualObservationSha256=OBSERVATION_SHA)
    return result
