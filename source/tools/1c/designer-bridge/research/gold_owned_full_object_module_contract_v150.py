"""Pinned data/normal Processing ABI contract. Import inert; no native/SDK execution."""
import hashlib
from pathlib import Path
import re
import struct
import uuid
import zipfile

import gold_own_object_module_contract_v82 as p82
import owned_module_payload_contract_v142 as payload
import gold_owned_full_object_module_guard_v150 as guard
from repository_pe_probe import PE
from gold_owned_empty_objects_contract_v130 import _mask

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SOURCE=HERE.parent/'tests/NativeGoldOwnedFullObjectModuleV150.as'
SOURCE_SHA='710abe1f3b12e3bf85d83fa2b1996b17d02b34f498119f5ec03fe7c8d2a73ee5'
SOURCE_REFERENCES={'tests/NativeGoldOwnObjectModuleV82.as': 'ddf4db4e400886500f4e0abf5d2c366c440043a69975bc6e759d9eb507856cb9', 'research/gold_own_object_module_contract_v82.py': '9fca12b69e2785ab52ff5e6ad55d910e912cfb07d40eca1a98ed705c47528dd4', 'research/gold_own_object_module_guard_v82.py': '38c3ecc1f92b4bf86ecd2968e9cad36eb17d45a92bd1cf8bde847c4f5baa92ef', 'tests/NativeOwnedModulePayloadV142.as': 'd7e3dd7e7f938f32d25d4fbba34ffe1439b56ca5d96dd86716628bc2bc1b1f66', 'research/owned_module_payload_contract_v142.py': '0418452c3db4e587cb882786588ea3bcef187bbb18f4cdcbd4c6de3e48dbc657', 'tests/NativeGoldOwnedDocumentStructureV139.as': '79f1f00badcd5f1f167bdaba1930120dcd1975f0d714410b5130790ed0b38a28', 'tests/NativeGoldOwnedConstantV99.as': '6249c98886947d95a5f229923a75d5d5ec7bde0a07ca228bc7a5ed0e194d0799'}
SOURCE_REFERENCES['research/gold_owned_empty_objects_contract_v130.py']='0a2a6eec8be2831dd5ff01808e4676982b19f2092774e0027ae3c7876a6eec48'
SOURCE_REFERENCES['tests/NativeMetadataDocumentPermission.as']='e0031b86bec623fea19c79423be63a0e790585f38a8f06ddd100f86d254685c3'
MANIFEST_SHA='a15cb445875c4b1533214f5cecc621de5483dfbacc78b17584a2d98405018682'
SHA_BODY_SHA='7f947bc01f1e143afab0d3608c7591997145a21e67fa2447cd5e48e9212b425a'
INPUT_RANGE_BODY_SHA='0584efd26fd544e102c064c6d7704162e3678d0e8bb18154af47eac7e92b6689'
PROCESSING_RVAS=(8019348, 8019677, 8016908, 5152784, 157904, 5152816, 5152848, 5152880, 5152992, 5153024, 5153216, 5153248, 5153280, 5153680, 5154080, 5154464, 5154768, 5155168, 5155216, 5155248, 5155280, 5155328, 5155376, 5155424, 5155760, 5155792, 5155840, 5155888, 5156224, 5156272, 5156320, 5156352, 5156384, 5156528, 5156656, 5156688, 5156832)
RANGES={
    'processingTable': ('basic.dll', 9219864, 148, 'aeb1c987d78692543216c76a12db425f111191abe42351bc7afaf20c7e1cef84'),
    'processingClass': ('basic.dll', 9229424, 36, '808ec379a8ccec4982ee37b7f501bffcb21baa9af7b192227476865f322e7e18'),
    'processingFactory': ('basic.dll', 5162576, 184, '27ced2bd9dacb4b686a8fe35ccd7eacf34bfe8bdcac0c30212880e90a35fc673'),
    'processingCtor': ('basic.dll', 8008656, 100, '2c522368de1a08637987188966191d97d81f21e5c2a4ff91273c0f000affdbbc'),
    'processingQiThunk': ('basic.dll', 8019348, 10, 'a387655dab50549295a636af5a43026b2ae9afcc03030661b4026208dddb2d6c'),
    'processingAddThunk': ('basic.dll', 8019677, 10, '2071ed778640e4082e2f1971a80ec3165d7860eea62831c3dbe0d1baa1d1ee4a'),
    'processingReleaseThunk': ('basic.dll', 8016908, 10, '62a7f8e38d7370eaffe670eaaa27919cbaffeec863240b7eb490d2f569a61d07'),
    'processingQi': ('basic.dll', 8008624, 26, '9291e72bbfa3814afdcfa51fbd7dabb4982835a9c362e1097b38d5ee7027bc54'),
    'processingMap': ('basic.dll', 9234128, 16, '8715c1f6e38625d2c3a285b9bd2672c69fae6df80bbde642801d4dee5e75c2f0'),
    'processingAdd': ('basic.dll', 7624032, 19, '812896d218306e6daec469fc3f61f57a5bb32e95318be6886ecd432a5c39e156'),
    'processingRelease': ('basic.dll', 8008288, 45, 'e625d05458cf266803f1ba250b1824e67d125e9fd182118fce0ee54772500f9f'),
    'mdObjectIID': ('basic.dll', 9014020, 16, '5d20555723bbd96d5a0a5e71339e17ec0b28e74ea9ec945cb9e9b37f7f0fd671'),
    'basicCommonQi': ('basic.dll', 7006512, 234, '97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
    'basicUnknownDetector': ('basic.dll', 7006464, 48, '595d8cfdd27660f94dba10cc8c33aa2404e2e86fab71223893013a9ead9de028'),
}


def need(ok,code):
    if not ok:raise ValueError('GFM150_STATIC_'+code)


def prepare_payload(raw):
    """Admit the exact immutable module; decoder grants no writer permission."""
    need(type(raw) is bytes and len(raw)==guard.INPUT_BYTES,'INPUT_LENGTH')
    need(hashlib.sha256(raw).hexdigest()==guard.INPUT_SHA,'INPUT_SHA')
    result=payload.prepare(raw)
    need(result['utf16Units']==guard.UTF16_UNITS and (result['endLine'],result['endColumn'])==guard.END
         and result['normalizedUtf8Sha256']==guard.NORMALIZED_SHA,'NORMALIZED_PAYLOAD')
    return result | dict(nativePermit=False,wholeModuleRuntimeVerified=False,endCoordinates1CVerified=False)


def verify_source_pins(pins):
    need(type(pins) is dict and pins==SOURCE_REFERENCES and all(type(v) is str for v in pins.values()),'SOURCE_REFERENCE_PIN')
    return dict(sourceReferencesVerified=True,nativePermit=False)


def function_only(source):
    masked=_mask(source)
    depth=start=entries=0
    for at,ch in enumerate(masked):
        if ch=='{':
            if depth==0:
                head=masked[start:at].strip()
                need(re.fullmatch(r'class\s+AhGFM(?:StateV150|ProfileV160|ForeignLedgerV162)|(?:bool|Guid|string|uint|void)\s+ah\w+\s*\([^{};]*\)',head) is not None,'EXECUTABLE_GLOBAL')
                entries+=int(head.startswith('string ahGoldOwnedFullObjectModuleV150('))
            depth+=1
        elif ch=='}':
            depth-=1;need(depth>=0,'BALANCE')
            if depth==0:start=at+1
        elif ch==';' and depth==0:
            need(re.fullmatch(r'funcdef\s+(?:int_ptr|int|void)\s+AhGFM(?:Factory|QI|Attach|Delete)V150\s*\([^{};]*\)',masked[start:at].strip()) is not None,'EXECUTABLE_GLOBAL')
            start=at+1
    need(depth==0 and not masked[start:].strip() and entries==1,'FUNCTION_ONLY')


def verify_input_readable_range(source):
    """Require the V156-proven bounded walker; retain the shared 4096 cap.

    This is a static gate. Its pure data/own-heap prerequisite does not grant a
    metadata writer, platform v8string, editor or whole-module capability.
    """
    block=p82._block(source,'bool ahGFMInputReadableV150(')
    need(hashlib.sha256(block.encode()).hexdigest()==INPUT_RANGE_BODY_SHA,'INPUT_RANGE_BODY')
    for token in ('a<65536 || size==0 || size>262144 || uint64(a)+size>0x100000000',
                  'uint current=a+offset,count=4096-(current&4095)',
                  'if(count>size-offset)count=size-offset',
                  'count==0 || count>4096 || ++chunks>65 || !ahPermissionReadable(int_ptr(current),count)',
                  'offset+=count', 'return offset==size'):
        need(token in block,'INPUT_RANGE_BOUNDARY')
    input_block=p82._block(source,'bool ahGFMInputV150(')
    need('if(input._length!=74501 || input.bytes==0 || !ahGFMInputReadableV150(input.bytes,input._length))return false;' in input_block
         and input_block.index('!ahGFMInputReadableV150(')<input_block.index('ahGFMShaV150(')<input_block.index('ahOwnedModulePayloadDecodeV142(')
         and block.count('ahPermissionReadable(')==1,'INPUT_RANGE_BEFORE_READ')
    return dict(inputRangeGuardStaticVerified=True,inputRangeMaximumBytes=262144,inputRangeMaximumChunk=4096,inputRangeMaximumChunks=65)



# V162 changes graph representation only; restore the full immutable V160 source.
FOREIGN_LEDGER_PRE_SHA='51d9bcccdea8ed5b06177993b28ef1ebf003ca9f28b28e76827544b702cad68f'
FOREIGN_LEDGER_ADDITIONS={'CLASS': 'cc0821486c138ea5543d7c9f6bdd5eea7ece05ab44484209b13158d8e5def356', 'FIELD': 'd9072614938f6a66d22ad5c3d1c937c16dd591da8feecc099baca2323828e748', 'INIT': 'bfddac57bed5987c5113af3b545447616e48713f91f8f90c00ac5a1e65f6470a', 'FRESH': '9f996a6ea79a4821c77936ce189815ed11c959d77ce4ccf20556fa464fa81e1e'}
FOREIGN_LEDGER_GRAPH_SHA='374f4f809e93f2f4ecb5f658052e9140d85893158b988aac8a905b5cfa0877a8'
FOREIGN_LEDGER_GRAPH_OLD='string ahGFMGraphV150(IMDObject&& object,uint depth,uint&inout count,AhGFMStateV150&in s){\n    if(object is null || depth>24 || count>=100000)return "ERROR:BOUND";count++;\n    if(depth>0 && object.isModified())return "ERROR:DIRTY";\n    IMDClass&& cls=object.mdClass;if(cls is null || cls.childClassesCount()>64)return "ERROR:CLASS";\n    string value=ahGFMGuidV150(object.id)+":"+ahGFMGuidV150(cls.id)+"[";\n    for(uint i=0;i<cls.childClassesCount();i++){\n        Guid kind=cls.childClassIDAt(i);uint children=object.childCount(kind);if(children>100000)return "ERROR:CHILD";\n        value+=ahGFMGuidV150(kind)+"{";\n        for(uint j=0;j<children;j++){\n            IMDObject&& child=object.childAt(kind,j);if(child is null)return "ERROR:NULL";\n            IMDParentLink&& link=child.mdParentLink;IMDClass&& childClass=child.mdClass;\n            if(link is null || childClass is null || childClass.id!=kind)return "ERROR:LINK";\n            IMDObject&& parent=link.getMDObject();if(parent is null || parent.self!=object.self)return "ERROR:PARENT";\n            if(child.id==ahGFMIdV150()){\n                if(depth!=0 || !s.registry || !s.attached || !ahGFMReceiverV150(s) || child.self!=s.own.self || kind!=ahGFMKindV150())return "ERROR:COLLISION";\n                continue;\n            }\n            string part=ahGFMGraphV150(child,depth+1,count,s);if(part.find("ERROR:")==0)return part;value+=part;\n        }\n        value+="}";\n    }\n    return value+"]";\n}'


def restore_foreign_ledger_source(raw):
    """Reverse only the fixed typed ledger delta; preserve all other source bytes."""
    need(type(raw) is bytes and 0<len(raw)<=65536,'LEDGER_SOURCE_BOUND')
    source=raw.decode('utf-8')
    need(set(re.findall(r'/\*V162_ADD:(\w+)\*/',source))==set(FOREIGN_LEDGER_ADDITIONS),'LEDGER_ADD_SET')
    graph=r'/\*V162_REPLACE:GRAPH\*/(.*?)/\*V162_END_REPLACE:GRAPH\*/'
    rows=re.findall(graph,source,re.S)
    need(len(rows)==1 and hashlib.sha256(rows[0].encode()).hexdigest()==FOREIGN_LEDGER_GRAPH_SHA,'LEDGER_GRAPH')
    source=re.sub(graph,lambda match:FOREIGN_LEDGER_GRAPH_OLD,source,flags=re.S)
    for key,pin in FOREIGN_LEDGER_ADDITIONS.items():
        pattern=r'/\*V162_ADD:'+key+r'\*/(.*?)/\*V162_END:'+key+r'\*/'
        rows=re.findall(pattern,source,re.S)
        need(len(rows)==1 and hashlib.sha256(rows[0].encode()).hexdigest()==pin,'LEDGER_ADDITION')
        source=re.sub(pattern+(r'\n' if key=='CLASS' else ''),'',source,flags=re.S)
    need('V162_' not in source and hashlib.sha256(source.encode()).hexdigest()==FOREIGN_LEDGER_PRE_SHA,'LEDGER_WHOLE_REVERSE')
    return source.encode()


def verify_foreign_ledger_source(raw):
    """Static parity: same fresh published read sequence, no pointer certificate."""
    original=restore_foreign_ledger_source(raw).decode()
    source=raw.decode();walk=p82._block(source,'string ahGFMGraphWalkV162(')
    old=p82._block(original,'string ahGFMGraphV150(')
    pattern=r'\b(?:object|cls|child|childClass|link|parent)\.(?:isModified|mdClass|childClassesCount|id|childClassIDAt|childCount|childAt|mdParentLink|getMDObject|self)\b'
    need(re.findall(pattern,walk)==re.findall(pattern,old),'LEDGER_FRESH_READ_ORDER')
    need('ahGFMGuidV150(' not in walk and walk.count('s.foreignLedger.take(')==4,'LEDGER_VALUE_ONLY')
    ledger=p82._block(source,'class AhGFMForeignLedgerV162')
    need('array<Guid> first,second' in ledger and not re.search(r'\b(?:int_ptr|IMD\w+|IUnknown)\b',ledger),'LEDGER_NO_CACHED_HANDLES')
    need('if(depth!=0 || s.foreignLedger is null || !s.foreignLedger.begin())' in source
         and 's.foreignLedger.finish(value.find("ERROR:")!=0)' in source
         and '&&s.foreignLedger=AhGFMForeignLedgerV162();' in source
         and '&& s.foreignLedger is null' in source,'LEDGER_SCOPE')
    return dict(typedForeignLedgerStaticVerified=True,freshForeignWalkPreserved=True,
                graphReentryRefuses=True,foreignPropertyContentHashed=False,
                typedForeignLedgerRuntimeVerified=False,foreignGraphSpeedupVerified=False)


# V160 additions are fixed passive diagnostics. The exact core remains archived V150.
PRE_PROFILE_SOURCE_SHA='5034840a49eecb1f91a85e08a255350edb10dddeaa32fb4afea10421b1ecda49'
PROFILE_ADDITIONS = {'CLASS': '82e4d89171ead6cdefa452685e7d8e01788a4c7aae48e6b50395dc26ac2f75af', 'FIELD': '3ae7eb0b11dc59f9864807c49d900b6d7b2b885410d2ce4b23c2df87116e5218', 'FUNCTIONS': '7ec5493db9f1c6921c52a6d42589a9b696992c5da9864e9e77b559a02d07b1ea', 'W0B': '4cc8d7cb477c49e04dd0390bb33774fa1bfbb8c8dea425bd8275505cc91ff6ff', 'W0E': '9ebf649e2bb9432d532b1491696168587f75cebdc2046e1820b72c071ba89fc4', 'W1B': 'f18c5b5fd6291c30652943af32312c7d698f55737d7d80d889156d0d22f98773', 'W1E': '41d89d4e2823729aeeb01472bb41e55f72142393fabfc49e786758d85cdf6270', 'W2B': '771b3f0d9c8741c6036c374a9f483fa656bbcb474dacefd2ef96f47a64d68d8c', 'W2E': 'c300fe515f9a7bbefe336bdcc73556df9be12ef3a9c4790a3fd3771ec5def4f8', 'W3B': 'd4b4c7aadf6f90c6081fc9b61800cf088b5d4467aae8904a7010c974c94dbba3', 'W3E': 'be0f33626d143c4ca690eca3899e61ca36d506c0061a1f094e45926968e137f5', 'W4B': '1e39fe15a116cee09da9b941cd24e84729935a44456e6663e6b04a7592784a61', 'W4E': '01cb27b9ee59256a08624730f2f918d65a3287e6c4bfc145a70099feefe40e3f', 'W5B': '028d66b02a0a7aff3c9f81ebcfbd1cda1c02d9593e42c49b3d1abcd9e178843b', 'W5E': 'eef98d011a18d8eef11e4f11084ec18884cbda75ed654b704c3978d73dfcb05a', 'InsertionEchoB': '0c38a88307425b9d8ef4bcf80f58dcf2b03df2d5cc6515edee674520d063e998', 'InsertionEchoE': '8cde90a7b47c9269be57eb521ed9fbd5fa1083ddef426efac198c590099398b6', 'W6B': '9bb4188fad436afd38fea535e210062c77d8c34e694122efa9117f9ce90e3615', 'W6E': '89caef05625fef730b171bf9fbd1462dcd2c76a75409df3f3bce09753d111af3', 'FullEchoB': 'f3028c7c31589ae1f97b9eb06cedd5285c43a6b6991e1fb2de9be151750d86bd', 'FullEchoE': '0e4596fabdad7cf0061c39691f03eac89ae49d59bf09072c7fb471ac37f01ffc', 'W7B': '42ff382d1ddaa39d2f0f70b8e1a6b69c74611b477e1c8fe8cad9abdb3e7718d5', 'W7E': 'ba7d0cf6b7230e6e6d98a8cb8d0b3599631b577300e6ca8649ecdb7297a24936', 'EmptyEchoB': 'd8efcc514f53a8636cee13d94d970397eea52dc26910b1580d58c9775ab7b421', 'EmptyEchoE': 'f6e3049509455a7af36406d941ea78a35bb15f2c48ef16033236db0ab47dc905', 'W8B': '29f9d65d5639adb40f667c5f19d5eea37d79ca3c82f12c5c20ca9e1f38fec3f6', 'W8E': '3a2f35af14bf8139f3ded3b0bf8b546c0110e125dd7506945149251f12da0e69', 'INIT': '0bd917f955795c759397f494fa3a6f8b202a0fdf0d5ce4524067bc8da21b4084', 'SINK': '6cd4a9e1004d08cca209eafa5fb2bb69ebae4d39cc3b796360b828be0705f136'}
PROFILE_REPLACEMENTS = {'Held': ('ahGFMInputHeldV150(input,s)', 1, 'ahGFMProfileHeldV160(input,s)'), 'Root': ('ahGFMRootV150(s)', 4, 'ahGFMProfileRootV160(s)'), 'Source': ('ahGCSourceV99(s.scope)', 2, 'ahGFMProfileSourceV160(s)'), 'Observe': ('ahCollectRepositoryObserve();', 2, 'ahGFMProfileObserveV160(s);'), 'GraphCount': ('ahGFMGraphV150(s.scope.root,0,count,s)', 1, 'ahGFMProfileGraphV160(s.scope.root,count,s)'), 'GraphNodes': ('ahGFMGraphV150(s.scope.root,0,s.nodes,s)', 1, 'ahGFMProfileGraphV160(s.scope.root,s.nodes,s)'), 'CanonicalFalse': ('ahGFMCanonicalV150(s,false)', 1, 'ahGFMProfileCanonicalV160(s,false)'), 'CanonicalTrue': ('ahGFMCanonicalV150(s,true)', 1, 'ahGFMProfileCanonicalV160(s,true)'), 'ModuleFalse': ('ahGFMModuleBoundV150(s,false)', 1, 'ahGFMProfileModuleV160(s,false)'), 'ModuleTrue': ('ahGFMModuleBoundV150(s,true)', 1, 'ahGFMProfileModuleV160(s,true)'), 'Editor': ('ahGFMEditorV150(s)', 1, 'ahGFMProfileEditorV160(s)'), 'WitnessEditor': ('ahGFMWitnessV150("editor",editorAfter.str)', 1, 'ahGFMProfileWitnessV160(s,"editor",editorAfter.str)'), 'WitnessHelper': ('ahGFMWitnessV150("helper",helperAfter.str)', 1, 'ahGFMProfileWitnessV160(s,"helper",helperAfter.str)'), 'WitnessEmptyEditor': ('ahGFMWitnessV150("empty-editor",emptyEditor.str)', 1, 'ahGFMProfileWitnessV160(s,"empty-editor",emptyEditor.str)'), 'WitnessEmptyHelper': ('ahGFMWitnessV150("empty-helper",emptyHelper.str)', 1, 'ahGFMProfileWitnessV160(s,"empty-helper",emptyHelper.str)'), 'DurableMark': ('ahCycleDurable("gold-owned-full-object-module-v150-"', 1, 'ahGFMProfileDurableV160(s,"gold-owned-full-object-module-v150-"'), 'DurableRegistry': ('ahCycleDurable("gold-owned-full-object-module-v150-registry.json"', 1, 'ahGFMProfileDurableV160(s,"gold-owned-full-object-module-v150-registry.json"'), 'DurableDispatch': ('ahCycleDurable("gold-owned-full-object-module-v150-dispatched"', 1, 'ahGFMProfileDurableV160(s,"gold-owned-full-object-module-v150-dispatched"'), 'DurableResult': ('ahCycleDurable("gold-owned-full-object-module-v150.json"', 1, 'ahGFMProfileDurableV160(s,"gold-owned-full-object-module-v150.json"'), 'BaselineRoot': ('ahGCRootV99(s.scope)', 1, 'ahGFMProfileBaselineRootV160(s)')}


def restore_profile_source(raw):
    """Reverse only the exact named instrumentation; never relax core gates."""
    need(type(raw) is bytes and 0<len(raw)<=65536,'PROFILE_SOURCE_BOUND')
    source=restore_foreign_ledger_source(raw).decode('utf-8')
    need(set(re.findall(r'/\*V160_ADD:(\w+)\*/',source))==set(PROFILE_ADDITIONS),'PROFILE_ADD_SET')
    need(set(re.findall(r'/\*V160_REPLACE:(\w+)\*/',source))==set(PROFILE_REPLACEMENTS),'PROFILE_REPLACE_SET')
    for key,(old,count,current) in PROFILE_REPLACEMENTS.items():
        pattern=r'/\*V160_REPLACE:'+key+r'\*/(.*?)/\*V160_END_REPLACE:'+key+r'\*/'
        rows=re.findall(pattern,source,re.S)
        need(len(rows)==count and all(row==current for row in rows),'PROFILE_REPLACEMENT')
        source=re.sub(pattern,lambda match:old,source,flags=re.S)
    for key,pin in PROFILE_ADDITIONS.items():
        pattern=r'/\*V160_ADD:'+key+r'\*/(.*?)/\*V160_END:'+key+r'\*/'
        rows=re.findall(pattern,source,re.S)
        need(len(rows)==1 and hashlib.sha256(rows[0].encode()).hexdigest()==pin,'PROFILE_ADDITION')
        source=re.sub(pattern+(r'\n' if key in ('CLASS','FUNCTIONS') else ''),'',source,flags=re.S)
    need('V160_' not in source,'PROFILE_MARKER_REMAINDER')
    return source.encode('utf-8')


PROFILE_HOST_OLD = b'                $probeSource+="`r`n"+[IO.File]::ReadAllText((Join-Path $PSScriptRoot \'NativeGoldOwnedFullObjectModuleV150.as\'))'
PROFILE_HOST_PATCH_SHA = '14590e176b590dc38c8c5c6aeb919303fe67e6892976869fbfc8799d8aa35661'


def restore_profile_host(raw):
    """Require the sole raw-source SHA substitution; preserve every other host byte."""
    start=b'                # V160 binds the optional profile'
    end=b'                $probeSource+="`r`n"+$fullObjectModuleSourceV160'
    need(type(raw) is bytes and raw.count(start)==1 and raw.count(end)==1,'PROFILE_HOST_MARKERS')
    at=raw.index(start);stop=raw.index(end)+len(end);patch=raw[at:stop]
    need(hashlib.sha256(patch).hexdigest()==PROFILE_HOST_PATCH_SHA,'PROFILE_HOST_PATCH')
    projected=raw[:at]+PROFILE_HOST_OLD+raw[stop:]
    need(hashlib.sha256(projected).hexdigest()=='ac812168459106d32b69fdc542a566c5425598b08fecf295fbc447571080303e','PROFILE_HOST_REVERSE')
    return projected


def verify_source(raw,*,check_pin=True):
    need(type(raw) is bytes and 0<len(raw)<=65536,'SOURCE_BOUND')
    diagnostic=raw.decode('utf-8');function_only(diagnostic)
    range_proof=verify_input_readable_range(diagnostic)
    ledger_proof=verify_foreign_ledger_source(raw)
    projected=restore_profile_source(raw);source=projected.decode('utf-8');function_only(source)
    need(not re.search(r'\b(?:eval|Execute|OpenForm|OnOpen|createByClsid|connectConfig|LoadLibrary|GetProcAddress|setModified|SaveCfg|UpdateDBCfg|setModuleText|loadFromFile)\s*\(',source),'FORBIDDEN_EFFECT')
    need('MemoryBuffer&in ' not in source and 'MemoryBuffer&inout input' in source and 'MemoryBuffer&inout output' in source,'NO_INPUT_COPY')
    need(hashlib.sha256(p82._block(source,'string ahGFMShaV150(').encode()).hexdigest()==SHA_BODY_SHA,'PURE_SHA_BODY')
    need('input._length!=74501' in source and 'input._length!=count' in source and guard.INPUT_SHA in source
         and source.index('ahGFMInputV150(input,s)')<source.index('s.consumed=true')<source.index('&&s.scope.root=ahStatusUi.getMDCont()'),'PRENATIVE_INPUT_PIN')
    need('ahGFMShaV150(input,input._length)==s.inputHash' in source and 's.payload.str==s.normalized' in source,'RETAINED_INPUT')
    need('s.normalized.length!=44744' in source and 's.endLine!=885' in source and 's.endColumn!=1' in source
         and 's.payload=s.normalized' in source and 'ahOwnedModulePayloadDecodeV142(' in source,'PAYLOAD_ENDPOINT')
    need('!__GOLD_OWNED_FULL_OBJECT_MODULE_V150__' in source and '__GOLD_OWNED_FULL_OBJECT_MODULE_TOKEN_V150__|' in source
         and '!ahGFMFreshStateV150(s) || !ahGFMPermitV150(operation)' in source
         and '!s.consumed && s.operation.length==0 && !s.unknown && !s.catcher.hasException && s.attempts==0 && s.sequence==0' in source
         and 's.calls.length==0 && s.phases.length==0' in source
         and '!s.registry && !s.attached && !s.deleted && !s.terminal' in source,'ONE_SHOT_ROLE')
    for value in (guard.OWN_ID,guard.CLASS_ID,guard.PROPERTY_ID,guard.OWN_NAME):need(value in source,'EXACT_OWN_SCOPE')
    table=re.search(r'array<uint> slots=\{([^}]+)\};',source)
    need(table is not None and tuple(int(v,16) for v in table[1].split(','))==PROCESSING_RVAS
         and 'ahGFMTableV150(self,"basic.dll",0x8caf18,37)' in source and 'i<37' in source,'FULL37')
    need('MemoryBuffer output(36)' in source and 's.rawFactory!=0 && !ahGFMAbiV150(s.rawFactory)' in source
         and source.index('s.rawFactory!=0 && !ahGFMAbiV150(s.rawFactory)')<source.index('toIUnknown(s.rawFactory)')
         and 'hr!=0 || s.rawQI!=self || !ahGFMAbiV150(s.rawQI)' in source
         and source.index('s.rawQI!=self')<source.index('toIUnknown(s.rawQI)'),'RAW_ADOPTION')
    need(source.count('if(s.qi is null)initFuncDefFromAddress(')==1 and '&&s.canonicalAfter=known' in source
         and 's.freshOwn=root.objById(ahGFMIdV150())' in source and 'mem::addressOf(s.canonicalAfter)==mem::addressOf(s.canonicalOwn)' in source,'CANONICAL_LIFETIME')
    need('depth>24' in source and 'count>=100000' in source and 'cls.childClassesCount()>64' in source
         and 'parent.self!=object.self' in source and 'depth!=0 || !s.registry || !s.attached' in source
         and 'child.self!=s.own.self || kind!=ahGFMKindV150()' in source
         and 'graph!=s.foreign || count!=s.nodes' in source and 'ahGCSourceV99(s.scope)' in source,'FULL_FOREIGN_BASELINE')
    for writer in range(9):need(source.count(f'ahGFMAttemptV150(input,s,{writer})')==1,'FIXED_WRITERS')
    need('!__GOLD_OWNED_FULL_OBJECT_MODULE_V150__ || !s.consumed || !ahCommandHex(s.operation) || writer>8' in source
         and 's.calls[writer]!=0 || s.attempts>=9' in source and '!ahGFMInputHeldV150(input,s) || !ahGFMControlV150(s)' in source
         and 'writer>=4 && writer<=7 && !ahGFMEditorHeldV150(s)' in source,'BEFORE_EACH_WRITER')
    need(source.count('.setMdPropVal(')==1 and source.count('s.own.id=ahGFMIdV150();')==1 and source.count('.setSelectText(')==1
         and source.count('.ahOwnedActionUndoV63(')==1 and source.count('s.remove(s.scope.root.self,kind.self,id.self)')==1,'WRITER_SET')
    positions=[source.index(value) for value in ('s.registry=ahCycleDurable(', 's.attach(s.scope.root.self,s.own.self)', '.setMdPropVal(',
         '.setSelectText(s.payload.cstr,true)', '.ahOwnedActionCloseV63(after,after)', 's.fullReadback=', '.ahOwnedActionUndoV63(',
         's.restored=', 's.remove(s.scope.root.self,kind.self,id.self)')]
    need(positions==sorted(positions),'LIFECYCLE_ORDER')
    need('editorAfter.str==s.normalized && helperAfter.str==s.normalized' in source and 'ahGFMModuleBoundV150(s,true)' in source
         and 'emptyEditor.str.length!=0 || emptyHelper.str.length!=0 || s.document.isModified()' in source
         and 'observedStart!=after || observedStop!=after' in source,'FULL_READBACK_AND_EMPTY_RESTORE')
    need('!(s.calls[4]==0 && s.calls[5]==0 || s.restored && s.helperEmpty && s.selectionRestored' in source
         and 'if(!s.unknown && !s.catcher.hasException && s.registry && s.attached)' in source
         and 's.rawFactory==0 && s.rawQI==0 && ahGFMControlV150(s)' in source
         and source.index('ahGFMReleaseKnownV150(s);')>source.index('s.registry && s.attached)ahGFMDeleteOwnV150'),'UNKNOWN_NO_DELETE_OR_RELEASE')
    need('if(s.scope.root !is null && !ahGCRootAbiV99(s.scope.root))s.unknown=true;' in source
         and source.index('!ahGCRootAbiV99(s.scope.root)')<source.index('s.scope.root.getConfigMngr()'),'INITIAL_ROOT_ABI')
    need('s.phases.resize(32)' in source and 's.calls.resize(9)' in source and 's.attempts==9 && s.fullReadback' in source,'PHYSICAL_COUNTS')
    need(source.index('s.terminal=terminal;return result;')>source.index('if(!ahCycleDurable("gold-owned-full-object-module-v150.json",result))'), 'RESULT_BEFORE_TERMINAL')
    for false_claim in guard.FALSE_CLAIMS:need(chr(92)+chr(34)+false_claim+chr(92)+chr(34)+":false" in source,'FALSE_CAPABILITY')
    for phase in guard.PHASES:need('"'+phase+'"' in source,'FIXED_PHASES')
    need(hashlib.sha256(projected).hexdigest()==PRE_PROFILE_SOURCE_SHA,'PROFILE_CORE_REVERSE')
    if check_pin:need(hashlib.sha256(raw).hexdigest()==SOURCE_SHA,'SOURCE_PIN')
    return range_proof | ledger_proof | dict(functionOnly=True,inputPinBeforePlatformCalls=True,oneShotCallerHeld=True,nominalWriters=9,physicalPhases=32,
                passiveProfileCoreReversalVerified=True,profileHasNoAuthority=True,processingFull37Verified=True,fullForeignBaselineRequired=True,wholeModuleRuntimeVerified=False,endCoordinates1CVerified=False,nativePermit=False,writerAuthorized=False,pureShaEngineVerified=False)


def verify_linkage(b):
    """Normal-only proof: MD+4 map first row -> IUnknown detector -> counted out.

    No map-minus-four shortcut or Doc/Catalog offset assumption is accepted.
    Exception unwind/destructor transitive effects and runtime remain unproved.
    """
    need(type(b) is dict and set(b)==set(RANGES),'SPAN_SET')
    for name,(_,_,size,_) in RANGES.items():need(type(b[name]) is bytes and len(b[name])==size,'SPAN_SIZE')
    base=0x228b0000
    need(tuple(v-base for v in struct.unpack('<37I',b['processingTable']))==PROCESSING_RVAS,'TABLE_LINKAGE')
    need(struct.unpack_from('<I',b['processingClass'],32)[0]==base+0x4ec650,'CLASS_FACTORY')
    f=b['processingFactory'];need(f[110:113]==b'\x8d\x4e\x04' and f[120:122]==b'\x89\x0f'
         and f[133:139]==bytes.fromhex('8b0151ff5004') and f[160:163]==bytes.fromhex('ff5108') and f[-3:]==b'\xc2\x08\x00'
         and f[75]==0xe8 and 0x4ec650+80+struct.unpack_from('<i',f,76)[0]==0x7a33d0,'COUNTED_FACTORY_OUT')
    need(bytes.fromhex('c74604')+struct.pack('<I',base+0x8caf18) in b['processingCtor'],'CTOR_FACET4')
    targets=(('processingQiThunk',0,0x7a33b0),('processingAddThunk',1,0x745560),('processingReleaseThunk',2,0x7a3260))
    for name,slot,target in targets:
        thunk=b[name];need(thunk[:6]==bytes.fromhex('836c240404e9') and RANGES[name][1]+10+struct.unpack_from('<i',thunk,6)[0]==target
              and PROCESSING_RVAS[slot]==RANGES[name][1],'COUNTED_ADJUSTOR4')
    qi=b['processingQi'];need(qi[9]==0xba and struct.unpack_from('<I',qi,10)[0]==base+0x8ce6d0
         and qi[17]==0xe8 and 0x7a33b0+22+struct.unpack_from('<i',qi,18)[0]==0x6ae930 and qi[-3:]==b'\xc2\x0c\x00','MAP_COMMON_LINK')
    need(str(uuid.UUID(bytes_le=b['mdObjectIID']))=='12bfddd0-36cc-11d4-940f-008048da11f9'
         and struct.unpack_from('<III',b['processingMap'])==(base+0x898b04,4,1),'FIRST_MD_ROW4')
    common=b['basicCommonQi'];detector=b['basicUnknownDetector']
    need(common[0x34]==0xe8 and 0x6ae930+0x39+struct.unpack_from('<i',common,0x35)[0]==0x6ae900
         and common[0x39:0x56]==bytes.fromhex('85c074198b72040375fc568b06ff500489375e5b33c05f8be55dc20800'),'UNKNOWN_NORMAL_BRANCH')
    need(detector[:38]==bytes.fromhex('833900751e837904007518817908c0000000750f81790c000000467506b801000000c333c0c3'),'UNKNOWN_IID')
    need(b['processingAdd'][6:9]==bytes.fromhex('83c044') and b['processingAdd'][13:15]==b'\xff\x25'
         and b['processingRelease'][-3:]==b'\xc2\x04\x00','REFCOUNT_44')
    return dict(processingCanonicalNormalStaticVerified=True,processingFacetOffset=4,normalCountedFactoryVerified=True,
                exceptionUnwindVerified=False,destructorTransitiveEffectsVerified=False,canonicalIUnknownRuntimeVerified=False,nativePermit=False)


def verify_slices(read):
    need(callable(read),'READER')
    bodies={}
    for name,(module,rva,size,sha) in RANGES.items():
        value=read(module,rva,size);need(type(value) is bytes and len(value)==size and hashlib.sha256(value).hexdigest()==sha,'PRIMARY_PIN');bodies[name]=value
    return verify_linkage(bodies) | dict(primarySpanCount=len(bodies))


def verify_static():
    """Read fixed file/PE bytes only; never load/call SDK/native or prepare a host."""
    pins={name:hashlib.sha256((HERE.parent/name).read_bytes()).hexdigest() for name in SOURCE_REFERENCES};verify_source_pins(pins)
    root=HERE.parents[3];manifest=root/'tools/data-anonymization/managed/manifest.json'
    need(hashlib.sha256(manifest.read_bytes()).hexdigest()==MANIFEST_SHA,'MANAGED_MANIFEST_PIN')
    prepare_payload((root/'tools/data-anonymization/managed/ObjectModule.bsl').read_bytes())
    pe=PE('basic.dll')
    def read(module,rva,size):
        need(module=='basic.dll','MODULE_SCOPE');at=pe.offset(pe.base+rva);return pe.data[at:at+size]
    source=verify_source(SOURCE.read_bytes());proof=verify_slices(read)
    # The only buffer extent field used by this candidate is a pinned stock
    # script declaration, not an assumed native C++ layout or caller counter.
    with zipfile.ZipFile(p82.prior.SDK) as archive:
        buffer=archive.read('modules/snegopat/engine/com_files.as')
    need(hashlib.sha256(buffer).hexdigest()=='aa5e7d7d2cb5ec8f835c10d803a8ac7919229c9bc4bf7c2900f7ee226df5c7bc'
         and b'uint _length;' in buffer and b'_length = l;' in buffer and b'bytes = l != 0 ? malloc(l) : 0;' in buffer,'KNOWN_BUFFER_ALLOCATION')
    prior=p82.verify_static()
    return source | proof | dict(v82PinnedRanges=prior['pinnedRanges'],sourceReferences=pins,sourceSha256=SOURCE_SHA,sdkExecuted=False,nativeCalls=0,goldCalls=0)
