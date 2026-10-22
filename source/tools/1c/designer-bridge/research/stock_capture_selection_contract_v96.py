"""Fixed stock selection generator research and fake-only ECX adapters.

Reads pinned PE bytes only. Observation validation checks a future trusted
reader's bounded measurements; it is never an authority to invoke the handler.
The own model creates a UI resource. Transitive profile/UI effects remain
unproved even though the caller's modal branch is after the builders.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct

from repository_pe_probe import HASHES, PE

HERE = Path(__file__).resolve().parent
ROOT_ID = '218b5d00-7e10-486f-874c-73c2368ed5da'
OBJECT_ID = '88d7aab7-8f3a-4e1d-9ed7-ca52043fa48d'
CLASS_ID = '061d872a-5787-460e-95ac-ed74ea3a3e84'
DEPENDENCIES = {
    '../tests/NativeRepositorySource.as': '64c20dd68c7e79f3ad4ad77a313081fc4c842e0f9431df86a3703c939131ad25',
    '../tests/NativeFactoryCopyV49.as': '1dc54ce7cbf4e96a4efbfefc05eb864feacc66a5de06d403f291a8e0ef6915fb',
    'NativeSdkCall.s': 'ab5c81990fe2838b366a3cde486e5b06c0650a1bc9bc9b85f43774eb47699374',
    'capture_handler_contract_v92.py': 'b80527701e09f7cd586363a5d5e00f1d8b1794490f12f28167e81fa687667167',
}
RANGES = (
    ('stockCaller', 0xbcea0, 1888, '02cc06cc9e7b7839d9ceb2f7914f2fa706a3e1da219b9761ed6c832339602e3a'),
    ('publicWrapper', 0xbd600, 23, '8025451762cd40637aba312e8814a7d169ec2ab7f14b7c5234154a50362969c4'),
    ('planner', 0xb1d60, 1728, '6401763d52c288df3a60e860ce890435107f4b7a8ca5ccc5c57998945356d677'),
    ('modelFactory', 0x148da0, 362, 'f282a621afdf7163ce06e797ef1d41e2e1f97cd450ed93063eb05ac861ec717b'),
    ('modelInitialize', 0xcb260, 880, '4fcb81cdd55ec8cfeb4981c00f7ce10fc6f14ac0cc5ef437c39fec7ac25fffaf'),
    ('baseUiInitialize', 0xd0680, 1546, 'd9d34cef4f39632e9419d432ce2dbbe94032941828111c2e9a5d3f108214cc52'),
    ('modelContext', 0xcb5d0, 624, '06901cd59bc68eab7217d2c1763af7a06775a1f3b46c60b16bb5cfeaa9853151'),
    ('modelRows', 0xcb840, 1696, '386d1c2d42df2aedca2727a45235c27f46c6e8c5b48438392354c66581d297ec'),
    ('rowBuilder', 0xccfc0, 7248, 'a1ec30a454e8639d87dfd25e3fe79d125feadbada61c29db39e18899aa74e5bb'),
    ('eligibility', 0xcccf0, 720, '527dfb0dd77cdcbc2e63e82f24bbd1b43d46e31143b74929b5e9bf7f76c007c4'),
    ('selectionGetter', 0xcbee0, 1493, '35cec43f8cbe0ffc49913958e1d21d10a53b654fad3a6885f6e9f288e9753db7'),
    ('collectionFactory', 0xb1b50, 528, 'afe291ab2e7e84e5b932da179342601642f8c28f4ede80427d3620ddfa895f78'),
    ('recordCopy', 0x2b9b0, 179, '9d3bf0a7bd939593060fe3001d1b369a65e27449966b315e8ca16b73a8549e57'),
    ('modelRetain', 0x14b5f0, 119, 'c66f6bb2372a3541a86ce09cef2a5ae3627633640eed47f2c8b0cca58eebd96f'),
    ('modelRelease', 0x147cd0, 119, 'b9e16d634f4eb72faa4f882526cfbd40f0cc14a4339c809fea60608811ee9dd6'),
    ('modelDeletingDestructor', 0x14ca00, 246, '0622d7090277e579a9955aac850dcb5cc0445ab81db766ecd6403ba90e84b18d'),
    ('modelFieldsDestructor', 0xd2a80, 438, '5e65f806bbf40fc1e47b9cdd3d4c306e2c8d46bd9a433ead8b5730c95f801543'),
    ('modelTable', 0x18e080, 68, '1ceb7981a53770128312a274ea04e5147bb2fdb4d028de480dc0e9366ed35dd7'),
    ('viewTable', 0x18e028, 12, 'b88fb28981255a986c0164270ff32149b3345502ceed3c66e43b86202e6be71a'),
    ('collectionTable', 0x18ddcc, 24, '79bccd24aba01420e24ef8ef764302d7c0e8fdc4e0a5293f20cd659df33c30e9'),
)
# Fixed instruction-boundary facts, decoded from complete functions. Planner
# and eligibility contain inline jump-table data; those bytes are pinned too.
ANCHORS = (
    (0xbcf47, 'e8144effff'), (0xbd01d, 'e83e4dffff'),
    (0xbd114, 'e8b7e40000'), (0xbd2de, 'e85de50000'),
    (0xbd310, 'ffd1'), (0xbd32f, 'e8aceb0000'), (0xbd367, 'e874eb0000'),
    (0x148e34, '66894654'), (0x148e38, '884656'),
    (0x148e59, 'e882a0f6ff'), (0x148ec1, 'e89a23f8ff'),
    (0x148ef2, 'e8f9260000'),
    (0xb2402, 'c21800'), (0xcb818, 'c21800'), (0xcbec4, 'c21000'),
    (0xcd9e5, '6a01'), (0xcda05, 'c785d0feffff00000000'),
    (0xcdb42, 'c685e0feffff01'), (0xcdb4d, 'c685e0feffff00'),
    (0xcdb84, 'c785f0feffff02000000'),
    (0xcdcbd, '6a00'), (0xcdcdd, 'c78504ffffff05000000'),
    (0xcc20a, 'e8e10a0000'), (0xcc299, '807e5400'),
    (0xcc451, 'c70700000000'), (0xcc468, 'e8e356feff'),
    (0xcc493, '8bc7'), (0xcc4b2, 'c20800'),
    (0x147d19, '8b068bce6a01'), (0x147d1f, 'ff5040'),
    (0xd2bd0, '8d4e2c'), (0xd2bd3, 'e828530700'),
)
ABIS = {
    'planner': (0xb1d60, 6, 24, 'output reference'),
    'modelFactory': (0x148da0, 0, 0, 'own strong-holder reference'),
    'modelContext': (0xcb5d0, 6, 24, 'ignored by stock caller'),
    'modelRows': (0xcb840, 4, 16, 'ignored by stock caller'),
    'selectionGetter': (0xcbee0, 2, 8, 'output reference'),
    'modelRelease': (0x147cd0, 0, 0, 'not a HRESULT'),
}
ZERO_COUNTERS = ('handlerCalls', 'modalCalls', 'hiddenModeSetters', 'flagWrites',
    'goldSourceWrites', 'configurationSaves', 'databaseUpdates',
    'configurationExports', 'configurationImports', 'repositoryMutations', 'businessCalls')
COLLECTION_KEYS = frozenset(('pointer','tableRva','refcount','map','head','node','count','keyId',
    'recordId','classId','helper','recordBytes','recordStorageBytes','recordEqualToFreshServer',
    'variantLifetimeVerified','rawVariantCopyUsed','closingHeadVerified','countedHeldBefore',
    'countedHeldAfter','getterFlag','returnedOutputReferenceVerified'))
TOP_KEYS = frozenset(('stage','platform','rootId','objectId','classId','version','binding','source',
    'ownership','request','planning','model','selected','application','counters',
    'independentCountedLifetimesVerified','generatorComplete','nativeException','returnUnknown'))


def need(ok, code):
    if not ok:
        raise ValueError('V96_' + code)


def _keys(value, names):
    need(type(value) is dict and set(value) == set(names), 'SHAPE_REJECTED')


def _int(value, minimum=0, maximum=2**32-1):
    need(type(value) is int and minimum <= value <= maximum, 'INTEGER_REJECTED')


def _true(value):
    need(value is True, 'TRUE_REQUIRED')


def verify_slices(read_rva):
    """Pin entire known functions, cleanup cold branches and constant tables."""
    spans = {}
    for name, rva, count, expected in RANGES:
        data = read_rva(rva, count)
        need(type(data) is bytes and len(data) == count, 'STATIC_RANGE_SIZE')
        need(hashlib.sha256(data).hexdigest() == expected, 'STATIC_RANGE_CHANGED_' + name)
        spans[name] = data
    for rva, text in ANCHORS:
        expected = bytes.fromhex(text)
        match = next((spans[name][rva-start:rva-start+len(expected)]
                      for name,start,count,_ in RANGES if start <= rva < start+count), None)
        need(match == expected, 'STATIC_ANCHOR_CHANGED')
    return [{'name': n, 'module': 'devtool.dll', 'rva': r, 'bytes': c, 'sha256': h}
            for n,r,c,h in RANGES]


def verify_static():
    """Read installed fixed bytes only; never initialize the own UI model."""
    for name, expected in DEPENDENCIES.items():
        need(hashlib.sha256((HERE/name).read_bytes()).hexdigest() == expected, 'DEPENDENCY_CHANGED')
    pe = PE('devtool.dll')
    ranges = verify_slices(lambda r,c: pe.data[pe.offset(pe.base+r):pe.offset(pe.base+r)+c])
    from capture_handler_contract_v92 import verify_static as handler_static
    handler = handler_static()
    return dict(stage='V96StockCaptureSelectionStaticContract', staticCompatible=True,
        platform='8.3.18.1208', platformSha256=HASHES['devtool.dll'].lower(), ranges=ranges,
        nativeAbi='thiscall(ECX=self); explicit-self checked adapter required',
        abis={k: dict(rva=v[0], argumentDwords=v[1], nativePopBytes=v[2],
                     explicitSelfPopBytes=4*(v[1]+1), nativeReturn=v[3]) for k,v in ABIS.items()},
        modelBytes=432, modelTableRva=0x18e080, modelViewOffset=4, modelViewTableRva=0x18e028,
        modelRowTableOffset=0x88, modelHelperOffset=0x2c, modelControllerOffset=0x28,
        modelFlagsOffsets=[0x54,0x55,0x56], initialFlags=[0,0,0],
        baseUiResource='GetDevObjectsDlg.f', selectedGetterFlag=0, applicationGetterFlag=1,
        generatedSelectedDefault=True, generatedApplicationRequiresMapMembership=True,
        generatedDisabledDefault=False, nativeEligibilityRequired=True,
        callerModalBranchAfterBuilders=True, inlineJumpTablesRetained=True,
        countedStrongHolderRequired=True, titleValueAssignmentRequired=True,
        wholeHandlerSha256=handler['ranges'][0]['sha256'],
        typedSdkModelFactoryPublished=False, modelFactoryLiveAbiVerified=False,
        transitiveProfileEffectsVerified=False, transitiveUiEffectsVerified=False,
        transitiveMetadataEffectsVerified=False, modalFreeRuntimeVerified=False,
        currentBindingsVerified=False, currentSingleUuidVerified=False,
        stockSelectionEquivalentToRawPlanner=False, nativePermit=False, captureVerified=False,
        nativeMethodsExecuted=0, **{k:0 for k in ZERO_COUNTERS})


def encode_fake_adapter(target, fault, argument_dwords):
    """Emit only a disposable fixture adapter; numeric validity is not ownership."""
    _int(target,1); _int(fault,1); _int(argument_dwords)
    need(argument_dwords in (0,2,4,6) and fault%4 == 0 and fault != target, 'FAKE_ADDRESS_REJECTED')
    code = bytearray.fromhex('55 8b ec 8b 4d 08')
    for index in range(argument_dwords,0,-1):
        code += bytes((0xff,0x75,8+4*index))
    code += b'\xb8'+struct.pack('<I',target)+bytes.fromhex('ff d0 39 ec 74 0a c7 05')
    code += struct.pack('<I',fault)+bytes.fromhex('01 00 00 00 8b e5 5d c2')
    code += struct.pack('<H',4*(argument_dwords+1))
    return bytes(code)


def validate_fake_adapter(code, target, fault, argument_dwords):
    need(type(code) is bytes and code == encode_fake_adapter(target,fault,argument_dwords), 'FAKE_ADAPTER_CHANGED')


def verify_selection_observation(info, expected_version, expected_source_sha256, expected_source_bytes):
    """Check exact measurements, not an execution permit or unforgeable token.

    A future trusted native reader must bind this observation to the active
    session/lease/sealed code. No result from this function activates V95.
    No payload, names, Variant contents or arbitrary caller command is accepted.
    """
    _int(expected_version,1); _int(expected_source_bytes,1,4*1024*1024)
    need(type(expected_source_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_source_sha256), 'SOURCE_SHA_REJECTED')
    _keys(info,TOP_KEYS)
    need(info['stage']=='V96StockSelectionObservation' and info['platform']=='8.3.18.1208' and
         (info['rootId'],info['objectId'],info['classId'])==(ROOT_ID,OBJECT_ID,CLASS_ID), 'SCOPE_REJECTED')
    _keys(info['version'],('before','after'))
    for value in info['version'].values():
        _int(value,1); need(value == expected_version, 'VERSION_DRIFT')
    binding=info['binding']; _keys(binding,('controllerBefore','controllerAfter','providerBefore','providerAfter','verifiedBefore','verifiedAfter'))
    for key in ('controllerBefore','controllerAfter','providerBefore','providerAfter'): _int(binding[key],1)
    need(binding['controllerBefore']==binding['controllerAfter'] and binding['providerBefore']==binding['providerAfter'], 'BINDING_DRIFT')
    _true(binding['verifiedBefore']); _true(binding['verifiedAfter'])
    source=info['source']; _keys(source,('sha256Before','sha256After','bytesBefore','bytesAfter','cleanBefore','cleanAfter','fullForeignDescriptorPreserved','fullModulesPreserved'))
    need(source['sha256Before']==source['sha256After']==expected_source_sha256,'SOURCE_DRIFT')
    for key in ('bytesBefore','bytesAfter'):
        _int(source[key],1); need(source[key]==expected_source_bytes,'SOURCE_SIZE_DRIFT')
    for key in ('cleanBefore','cleanAfter','fullForeignDescriptorPreserved','fullModulesPreserved'): _true(source[key])
    _keys(info['ownership'],('before','after')); need(info['ownership']==dict(before='FREE',after='FREE'),'OWNER_REJECTED')
    request=info['request']; _keys(request,('count','elementBytes','ids','callerOwned','heldUntilGeneratorComplete'))
    _int(request['count']); _int(request['elementBytes'])
    need(request['count']==1 and request['elementBytes']==16 and type(request['ids']) is list and request['ids']==[OBJECT_ID],'REQUEST_REJECTED')
    _true(request['callerOwned']); _true(request['heldUntilGeneratorComplete'])
    plan=info['planning']; _keys(plan,('calls','operation','selectorRva','selectedMapCount','applicationMapCount','filteredCount','extraResultMapCounts','helper','helperCounted'))
    for key in ('calls','operation','selectorRva','selectedMapCount','applicationMapCount','filteredCount','helper'): _int(plan[key])
    need((plan['calls'],plan['operation'],plan['selectorRva'],plan['selectedMapCount'],plan['applicationMapCount'],plan['filteredCount'])==(2,1,0x18eaac,1,1,0),'PLANNING_REJECTED')
    need(type(plan['extraResultMapCounts']) is list and len(plan['extraResultMapCounts'])==7,'RESULT_MAP_SHAPE')
    for count in plan['extraResultMapCounts']: _int(count); need(count==0,'EXTRA_RESULT_MAP_REJECTED')
    _int(plan['helper'],1); _true(plan['helperCounted'])
    model=info['model']; _keys(model,('pointer','tableRva','rowTable','helper','factoryCalls','contextCalls','rowBuilderCalls','rowCount','initialMode','flagsBefore','flagsAfter','rowSelected','rowApplication','rowDisabled','ownedStrongHolder','canariesVerified','ownTitleValue','currentUiSelectionUsed'))
    for key in ('pointer','tableRva','rowTable','helper','factoryCalls','contextCalls','rowBuilderCalls','rowCount','initialMode'): _int(model[key],1)
    need((model['tableRva'],model['factoryCalls'],model['contextCalls'],model['rowBuilderCalls'],model['rowCount'],model['initialMode'])==(0x18e080,1,1,1,1,1),'MODEL_REJECTED')
    need(model['helper']==plan['helper'],'MODEL_HELPER_DRIFT')
    for key in ('flagsBefore','flagsAfter'):
        _keys(model[key],('dependency','suppressApplication','extra'))
        for value in model[key].values(): _int(value,0,1); need(value==0,'MODEL_FLAGS_REJECTED')
    for key in ('rowSelected','rowApplication','ownedStrongHolder','canariesVerified','ownTitleValue'): _true(model[key])
    need(model['rowDisabled'] is False and model['currentUiSelectionUsed'] is False,'MODEL_INPUT_REJECTED')
    addresses=[model['pointer'],model['rowTable'],plan['helper'],binding['controllerBefore'],binding['providerBefore']]
    for name,flag in (('selected',0),('application',1)):
        item=info[name]; _keys(item,COLLECTION_KEYS)
        for key in ('pointer','tableRva','refcount','map','head','node','count','helper','recordBytes','recordStorageBytes','getterFlag'): _int(item[key])
        for key in ('pointer','map','head','node','helper'): _int(item[key],1)
        need((item['tableRva'],item['refcount'],item['count'],item['recordBytes'],item['recordStorageBytes'],item['getterFlag'])==(0x18ddcc,1,1,141,144,flag),'COLLECTION_REJECTED')
        need((item['keyId'],item['recordId'],item['classId'])==(OBJECT_ID,OBJECT_ID,CLASS_ID),'COLLECTION_UUID_REJECTED')
        need(item['map']==item['pointer']+20 and item['helper']==plan['helper'],'COLLECTION_LAYOUT_REJECTED')
        for key in ('recordEqualToFreshServer','variantLifetimeVerified','closingHeadVerified','countedHeldBefore','countedHeldAfter','returnedOutputReferenceVerified'): _true(item[key])
        need(item['rawVariantCopyUsed'] is False,'RAW_VARIANT_REJECTED')
        addresses += [item['pointer'],item['map'],item['head'],item['node']]
    need(len(set(addresses))==len(addresses),'LIVE_ALIAS_REJECTED')
    _keys(info['counters'],ZERO_COUNTERS)
    for value in info['counters'].values(): _int(value); need(value==0,'WRITE_OR_MODAL_REJECTED')
    _true(info['independentCountedLifetimesVerified']); _true(info['generatorComplete'])
    need(info['nativeException'] is False and info['returnUnknown'] is False,'UNKNOWN_REJECTED')
    return dict(stage='V96BoundedStockSelectionShape', observationShapeVerified=True,
        trustedLiveReaderRequired=True, actualStockGeneratorVerified=False,
        nativePermit=False, captureVerified=False, handlerCalls=0,
        transitiveProfileEffectsVerified=False, transitiveUiEffectsVerified=False,
        transitiveMetadataEffectsVerified=False, modalFreeRuntimeVerified=False)
