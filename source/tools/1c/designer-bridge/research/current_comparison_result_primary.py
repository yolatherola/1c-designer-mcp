"""Exact returned comparison-result class and stock command route, offline only.

Local CFG/EH closure is not full UUID/property semantics or native authority.
"""
import hashlib
import json
from pathlib import Path
import struct
import uuid
from current_comparison_factory_primary import PE,HASHES,_decoder,local_cfg
from configuration_comparison_service_primary_v177 import imported
import database_configuration_read_route_v154 as stock
ROOT=Path(__file__).resolve().parents[4]
BASE=0x26dc0000
OBSERVATION='905a06f7ba354573a021e33145bddc7b'
OBSERVATION_SHA='7d7ed35e334747baddb1c9dbe02e34c8ec55fbba4003acaef3334a8a3cef5bca'
SPANS={'resultTable': (12640152, 48, 'ab9d08c6b60387eea1e48b04bb2e8776ee8f0c79d99119cde0f53ff5bd0c1388'),
 'initialize': (1272944, 2281, '9faf42389c521214ee3d8fa83ea0c66b3f50057cd41bb147bf45cccd21a3fe42'),
 'execute': (1277344, 494, '70e264e32d55583202163358c1a7f0f1f493aaa6c99c2b317c0dad778a655f58'),
 'prepare': (1321120, 856, '8f5c6ac828b664ac5efd5a72cb650993805df4e355f26b1d31dbe9e886566bd4'),
 'build': (1322144, 1292, '2a4edac4378d77c5821f87925497b54d260227df144decc68bee17dbe90ba0d1'),
 'compute': (1323440, 370, '993cb03fadc43b248b0f302d709012bc36e40c47ce250842d7a0a6fa8258caab'),
 'treeBuild': (844320, 503, 'a0575ad8f7fbc66cf48a1f00160120a391d71836514fd83adcf9a317ead306c5'),
 'treeRecurse': (845888, 2993, '2680c0caff92ba25a87f4545c48b71699ba61839ba35205b9ff5c7bd9bea926e'),
 'calculation': (695856, 607, 'ef5abe54e81d222615759085239b14a3678887fb2d7cfa6c786dc34fef34a296'),
 'showView': (1290976, 588, '010fe9e7dc9e9a2f3febe21ca2fef9072124ebd0d0f0c706dca651dfd5dccc27'),
 'findIdentifier': (851248, 129, '3f3a4934d834a095e9c2508d213023694da099d204bcc78d599283df26de6a46'),
 'viewBindPrefix': (5879920, 165, 'f6d7bffb2a681345728b5e222db11458b3da34a6a7d841c5bacdc31f3b631141'),
 'viewBindTable': (12640636, 16, '53c6aea138e8ffb881a5a8ca72813738d18edd41fff0ca57dbd78063c4c54663'),
 'framedViewIid': (12567312, 16, 'f5b2cf8767b618c0e0ad852001e0dd21d65aa60a05e31b7304392a4b73a9efc4'),
 'urlGetters': (1275408, 121, 'ad2a47538b328e2ee708744a8a50b6820ffda21c33e907c4ff3d3f462261f5d8'),
 'initEH': (11773352, 27, '4a309fa1fb613b99158bbd6d785f30f32371eed170b46ee0b704bfbbd6788344'),
 'initInfo': (13318856, 36, '65fecef78667f20f26a4778252929a52d000f332fcc305e4a648c1edf8a2f176'),
 'initUnwind': (13318896, 416, '5bb2e2172588768d8d10ccc1aec071d161ef41a0565e8c41810aca4c7ebe828a'),
 'initFunclets': (11773264, 88, 'd507b3e05f1677324620e7d4462e4d0a8e0571c2c2128aa2f38d1b08423cca51'),
 'executeEH': (11773633, 27, 'fc747974768fe1a5922ddd169c7dfe8f6a18128fdc017a8c6a2d06e663f086d4'),
 'executeInfo': (13319584, 36, 'a61e94b36bb17ff8cfa7584da66a1d8dc07dfc161c5dd9ed956434e4ad2a46fb'),
 'executeUnwind': (13319620, 16, 'ba02276276446bb42ee80196cd7fc8488c36f356a79cc5042c1bf96572758dc7'),
 'executeFunclets': (11773600, 33, 'a386abffbe99a082b4432c3b7930d15a6984c063975674b93e684e4fb0bf6efa'),
 'prepareEH': (11777752, 27, 'eb0c441410d91e6a3fb22b5efffa837b44919f56d1f804f3e7de0fb579bcf512'),
 'prepareInfo': (13325360, 36, '8f6723d623b168a682ec3302d294b3baee992ef1cac543d9c5f21fd57cd326d0'),
 'prepareUnwind': (13325400, 80, '2a8e21ed93ecd869ee1024cdd997320a16254a75031bec81c75b8794e4a6ca3d'),
 'prepareFunclets': (11777744, 8, '2ae2758b0a57826166507860e136f1a645770af8f0f490b4d8f92667612b466b'),
 'buildEH': (11777913, 40, 'b782907ec99b9b777acb3fade02bc9f5254e064fc2d35e7f88415b0457f4a2ac'),
 'buildInfo': (13325552, 36, '2fa6bfa0c4c4fb03b3265ad8cfcce35d1a295cbd5b2ff7b455cb2d81446cd551'),
 'buildUnwind': (13325592, 144, 'bd2b32e7135274b0ccf85d1e903c62d01cc6fecf93d71a46058dfcc09b0cba04'),
 'buildFunclets': (11777840, 73, 'b5b72036f4907bf32d94b163a0511ab5eaa7166e98d60331b669f12613d8f335'),
 'computeEH': (11778016, 27, 'd577a52334f899bc6936b7be67e0ba402974dad0641a1df685c175a816598233'),
 'computeInfo': (13325736, 36, 'ece23b086a5356fa475cdbb6b952e217050bd1607c9573ac2cdf10cc532a9d9b'),
 'computeUnwind': (13325776, 112, '34652e47affe23961cf9df910de8b2c3a2834dba8fe8aba8a34edc96a2a1be1b'),
 'computeFunclets': (11777968, 48, 'c1d7a05d84226bf75173c80835750bf3eb23c01647c5fec3fae1fa10cbeaf03a'),
 'treeBuildEH': (11719872, 27, '93abcc7014bcd1317c1a6aa78618186187f88bcf7d3f997c0c136ab44c28dd0b'),
 'treeBuildInfo': (13248744, 36, '4c2b5b1b515567bd1a882e04832293d7abc030ca9cb3eb35a30c86e86389af6a'),
 'treeBuildUnwind': (13248784, 72, 'c94af74b2a5964f890a445e749b822be78410d37ead55f2cb4892303b3cb2b1c'),
 'treeBuildFunclets': (11719856, 16, 'b2f3c856594da387b1985f30c7ae9cbcf39c3a7c8245c160ee1986004f91ccea'),
 'treeRecurseEH': (11720122, 40, 'd983974e4c90124324a984f87e9975aa2da16543c37562e55bcc306ce4469c05'),
 'treeRecurseInfo': (13248928, 36, '832e743de0f1667de855d89116e47a4493239f2abce45e9ec0e0cf253cd45159'),
 'treeRecurseUnwind': (13248968, 112, 'aa5bbd0ef17e1764545fa54e48a17eec7eab2880ab4197689039ee33c6ad6dc7'),
 'treeRecurseFunclets': (11720016, 106, '8536466874c5cb994f4adc5b030c58d21ee8ce277c644239cb54ee3de5e228b7'),
 'calculationEH': (11702309, 37, 'f26cb2eded3d22ffa93cfbbcf38c98fe507724cd49e580e7d2ef58ed1f6e47bb'),
 'calculationInfo': (13226992, 36, '76eb1cb33d13d28803ef963b8226d77efbbdffaa0fa3614e3cfa8513a93fef66'),
 'calculationUnwind': (13227032, 72, '14cd4ff900e7cfa1e7c78330ce14b91138f44b1b958123281a3470dfc4c0a8dc'),
 'calculationFunclets': (11702288, 21, '16431db5e7ec29803b5c845ca31212ef160c85cad0b719a2cea6d679695514a9'),
 'showViewEH': (11774967, 40, '4d8d2e7a3667b38df04903a62e6bd82b0a2191f3ca02ec0870112d4efb231ce1'),
 'showViewInfo': (13321112, 36, '816ba3ff9c857a075052695c8665ac280a8c5ad5fc3c5fbba0c384477e7b426c'),
 'showViewUnwind': (13321152, 80, '250b2335c9d7f79f0cce95021e244c6ad2b8e5e03035a977a0022d136f92a8ed'),
 'showViewFunclets': (11774912, 55, 'ec902828b3c7420d7f14c476a35868a50c966e079fb96d3596b3e2777936a697'),
 'terminateThunk': (11613770, 6, 'bcf1e36e48e1596bdb5167d34693e8901e2cc21aa871756e3213379e13a80321'),
 'frameThunk': (11613764, 6, 'bf73f2ee1dca1a734d4940fc48b2fbcef18038a357449a9b279d7605754d9a74')}

NORMAL=('initialize','execute','prepare','build','compute','treeBuild','treeRecurse','calculation','showView','findIdentifier')
EH_COUNTS=dict(init=52,execute=2,prepare=10,build=18,compute=14,treeBuild=9,treeRecurse=14,calculation=9,showView=10)


def need(ok,code):
    if not ok:raise ValueError('COMPARISON_RESULT_PRIMARY_'+code)


def _calls(raw,rva):
    from capstone.x86_const import X86_OP_IMM
    return [(i.address,i.operands[0].imm) for i in _decoder().disasm(raw,rva)
        if i.mnemonic=='call' and i.operands[0].type==X86_OP_IMM]


def _exception_chain(bodies,name,count):
    from capstone.x86_const import X86_OP_IMM
    info=struct.unpack('<9I',bodies[name+'Info'])
    need(info[:5]==(0x19930522,count,BASE+SPANS[name+'Unwind'][0],0,0),'EH_COUNT_NO_CATCH')
    handler=list(_decoder().disasm(bodies[name+'EH'],SPANS[name+'EH'][0]))
    need(any(i.mnemonic=='mov' and i.op_str=='eax, '+hex(BASE+SPANS[name+'Info'][0]) for i in handler)
        and handler[-1].mnemonic=='jmp' and handler[-1].operands[0].imm==0xb13644,'EH_HANDLER_JOIN')
    states=struct.unpack('<'+str(count*2)+'I',bodies[name+'Unwind']);actions=set()
    for i in range(count):
        parent=struct.unpack('<i',struct.pack('<I',states[2*i]))[0]
        need(-1<=parent<i,'EH_STATE_CHAIN');actions.add(states[2*i+1]-BASE)
    exits=[];start=SPANS[name+'Funclets'][0];raw=bodies[name+'Funclets']
    for action in sorted(actions):
        if action==0xb1364a:exits.append(dict(actionRva=action,externalTerminate=True));continue
        need(start<=action<start+len(raw),'EH_ACTION_BOUND')
        instructions=list(_decoder().disasm(raw[action-start:],action));terminal=None
        for i in instructions:
            if i.mnemonic=='jmp' or i.mnemonic.startswith('ret'):
                terminal=i;break
        need(terminal is not None,'EH_ACTION_EXIT')
        if terminal.mnemonic=='jmp':
            need(terminal.operands[0].type==X86_OP_IMM,'EH_ACTION_DIRECT_EXIT')
            exits.append(dict(actionRva=action,directCleanupTailRva=terminal.operands[0].imm))
        else:exits.append(dict(actionRva=action,localRet=True))
    return dict(states=count,actions=exits,localCatchBlocks=0,transitiveCleanupEffectsVerified=False)


def verify_units(bodies,*,check_hashes=True):
    need(type(bodies) is dict and set(bodies)==set(SPANS),'UNIT_SET')
    for name,(_,size,pin) in SPANS.items():
        need(type(bodies[name]) is bytes and len(bodies[name])==size,'UNIT_BOUND')
        if check_hashes:need(hashlib.sha256(bodies[name]).hexdigest()==pin,'UNIT_PIN')
    cells=struct.unpack('<12I',bodies['resultTable'])
    need(cells[3]==BASE+0x136c70 and cells[11]==BASE+0x137da0,'ACTUAL_RESULT_SLOTS')
    cfg={name:local_cfg(bodies[name],SPANS[name][0]) for name in NORMAL}
    need(cfg['initialize']['returns']==['0x50'] and cfg['execute']['returns']==['0x10'],'INIT_EXEC_RET_POP')
    calls={name:_calls(bodies[name],SPANS[name][0]) for name in NORMAL}
    for name,target in (('execute',0x1428a0),('execute',0x142ca0),('execute',0x1431b0),('execute',0x13b2e0),
            ('build',0xce220),('treeBuild',0xce840),('compute',0xa9e30),('treeRecurse',0xce840)):
        need(target in [value for _,value in calls[name]],'DIRECT_TREE_ROUTE')
    need(bytes.fromhex('8d8fa0010000') in bodies['build']
        and bytes.fromhex('8b8f10020000') in bodies['build'],'RESULT_TREE_FIELDS')
    find=bodies['findIdentifier']
    for anchor in ('8b4014','8d5018','83c008','8b4004','8b7808','8b7704','8b7608'):
        need(bytes.fromhex(anchor) in find,'IDENTIFIER_TREE_LAYOUT')
    need(find.count(bytes.fromhex('8b7808'))==2,'IDENTIFIER_TREE_LAYOUT')
    tree=bodies['treeRecurse']
    need(bytes.fromhex('0f104008') in tree and bytes.fromhex('0f114008') in tree
        and bytes.fromhex('0f114018') in tree and bytes.fromhex('8b4f18') in tree,'PAIRED_IDENTIFIER_COPIES')
    need(bytes.fromhex('c60601c6465000') in bodies['calculation'],'CALCULATION_STATE_EXIT')
    view=bodies['showView'];bind=bodies['viewBindPrefix']
    need(struct.unpack('<4I',bodies['viewBindTable'])[3]==BASE+0x59b870
        and bytes.fromhex('8b4610894e10') in bind,'VIEW_RESULT_BINDING')
    need(uuid.UUID(bytes_le=bodies['framedViewIid'])==uuid.UUID('7c27c850-a0f4-11d4-84af-008048da06df')
        and struct.pack('<I',BASE+SPANS['framedViewIid'][0]) in view,'PUBLISHED_FRAME_IID')
    need(view[0x18d:0x193]==bytes.fromhex('ff9500ffffff'),'STOCK_OPEN_VIEW_CALL')
    url=bodies['urlGetters']
    need(url.count(bytes.fromhex('ff15f49f9b27'))==4,'URL_GETTERS_NOT_DELTA')
    eh={name:_exception_chain(bodies,name,count) for name,count in EH_COUNTS.items()}
    return dict(kind='CURRENT_COMPARISON_RESULT_PRIMARY',normalCFG=cfg,exceptionChains=eh,
        initStackBytesIncludingSelf=80,executeStackBytesIncludingSelf=16,directCallEdges=calls,
        treeOffset=0x1a0,treeEnginePointerOffset=0x210,nodeFirstChildOffset=4,nodeNextSiblingOffset=8,nodePayloadOffset=0x14,
        nodePackedKindOffset=0x18,nodeChangeCodeByteOffset=0x1a,payloadIdentifierOffsets=[8,0x18],
        genericIdentifierTreeTraversalStatic=True,identifierSemanticRolesVerified=False,changeCodeMappingVerified=False,
        calculationStateAtResultOffset=0x274,calculationStateFlagIsSuccessEpochVerified=False,
        nextRoute=dict(stockCommandGroup=stock.GROUP,stockCommandId=30,stockExecutionArguments=['self',0,'GuidNull',1],
            publishedFramedViewIid='7c27c850-a0f4-11d4-84af-008048da06df',viewBindingMethodRva=0x59b870,
            viewBindingInterfaceOffset=0x40,bindingStoresResultAtInterfaceOffset=0x10,
            requiresNewExplicitCompareScope=True,oldCreatedPointerReusable=False,needCaptureLiveOwningView=True,
            unknownRawResultCallsRequired=False,privateInitSignatureNeededForStockCommand=False),
        remainingEdges=['Observe fresh Compare30 command/context and its live owning IFramedView, not the released905a pointer.',
            'Capture an owned live view then derive/verify its result binding before borrowed bounded tree reads.',
            'Tree node/payload identifiers and packed change codes need metadata/property semantic projection including resource/module nodes.',
            'Completion/cancel/error epoch must be tied to actual stock return and fresh stable tree; state byte alone is insufficient.'],
        resultInitializationRuntimeVerified=False,resultExecutionRuntimeVerified=False,completionEpochVerified=False,
        fullUuidPropertyDeltaVerified=False,onlyOwnPendingVerified=False,nativePermit=False,
        transitiveReadOnlyVerified=False,sourceWrites=0,configurationSaves=0,databaseUpdates=0,repositoryMutations=0)


def verify_static():
    """Read only the fixed result bodies/EH, prior technical proof and stock pins."""
    image=PE('frntend.dll');bodies={}
    for name,(rva,size,_) in SPANS.items():
        at=image.offset(image.base+rva);bodies[name]=image.data[at:at+size]
    result=verify_units(bodies)
    need(hashlib.sha256(Path(stock.__file__).read_bytes()).hexdigest()=='e258d952d9b25b3954c8c2e1ef42982cb6ab2a2e94ec033496ef4e8417a70aa8','STOCK_PARENT_PIN')
    stock.verify_static()
    config=PE('config.dll');rva,size,pin=stock.RANGES['compareExecute'][1:];at=config.offset(config.base+rva);execute=config.data[at:at+size]
    need(hashlib.sha256(execute).hexdigest()==pin and bytes.fromhex('6a01ff3578d70e268b086a0050ff512c') in execute,'STOCK_FIXED_EXECUTION')
    need(imported(image,iat=0xbf9ff4)['symbol']=='??4URL@core@@QAEAAV01@ABV01@@Z','URL_ASSIGN_IMPORT')
    path=ROOT/'build'/('designer-hot-v233-'+OBSERVATION)/'comparison-result-create-proof.json';raw=path.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==OBSERVATION_SHA,'ACTUAL_CREATION_PIN');observed=json.loads(raw)
    need(observed.get('operationId')==OBSERVATION and observed.get('status')=='CREATED_RESULT_OBSERVED_CLEAN'
        and observed.get('coherent') is True and observed.get('passes')==2
        and observed.get('resultInterfaceType')=={'module':'frntend.dll','rva':0xc0df98}
        and observed.get('resultSlotTypes')==[{'module':'frntend.dll','rva':x-BASE} for x in struct.unpack('<12I',bodies['resultTable'])],'ACTUAL_RESULT_TABLE')
    result.update(units=len(bodies),platformSha256=HASHES['frntend.dll'].lower(),actualObservationSha256=OBSERVATION_SHA,
        primaryHashes={name:value[2] for name,value in SPANS.items()})
    return result
