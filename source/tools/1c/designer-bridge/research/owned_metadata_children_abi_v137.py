"""Read-only exact 8.3.18.1208 child metadata normal ABI, never a permit.

Import is inert. verify() accepts bounded readers and immutable primary bytes;
verify_static() only reads existing files/PE32 images, never loads a DLL. This
closes normal factory/QI and parent entry paths; transitive ctor, unwind and
runtime receiver/type capability remain unverified.
"""
import hashlib
import json
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE

ROOT = Path(__file__).resolve().parents[4]
SDK_ARCHIVE = ROOT / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
SDK_ARCHIVE_SHA = '464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
SDK_SHAS = {
    'modules/snegopat/v8api/metadata.v': 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed',
    'modules/snegopat/v8api/value.v': 'c99b23ab9d0f81493f138f7bac66b96019ab9c69fd121202beab352772534288',
}
PRIMARY_PATH = ROOT / 'artifacts/designer-bridge/v135-owned-metadata-primary-20261012.json'
PRIMARY_SHA = 'aaf8010f11e0fcbf5bd5c4a590bda6f0a3a0021dea419847e809c76298676618'
CORRECTION_PATH = ROOT / 'artifacts/designer-bridge/v135-static-output-offset-correction-20261012.json'
CORRECTION_SHA = '954dda8329c43e5dee70fb111f37bd964fd0f2daeef5c47f7680bd253cc69f02'
MD_OBJECT_IID = '12bfddd0-36cc-11d4-940f-008048da11f9'
NAME_PROPERTY = 'cf4abea2-37b2-11d4-940f-008048da11f9'
TYPE_PROPERTY = 'b1053250-abe6-11d4-9434-004095e12fc7'
ROWS = (
    ('attribute', 'DocumentAttribute', '45e46cbc-3e24-4165-8b7b-cc98a6f80211', 'basic.dll',
     0x4c4920, 0x79bbe0, 0x8c8350, 0x8c7598, 0x164, 0x79bb70, 0x79bbc0, 0x79bb90, 0x8c89a0),
    ('tablePart', 'TablePart', '21c53e09-8950-4b5e-a6a0-1054f1bbc274', 'basic.dll',
     0x4c8a30, 0x79bad0, 0x8c818c, 0x8c77e0, 0x188, 0x79ba60, 0x79bab0, 0x79ba80, 0x8c8750),
    ('column', 'TablePartAttribute', '888744e1-b616-11d4-9436-004095e12fc7', 'backend.dll',
     0x5e2680, 0xb50340, 0xf1549c, 0xf1324c, 0x164, 0xb50320, 0xb3fe70, 0xb3fe40, 0xf16968),
)
BASES = {'basic.dll': 0x228b0000, 'backend.dll': 0x1f400000}
# Complete entry bodies through their final normal ret/tailcall; map first row
# and tables/data are fixed-size data spans. No guessed function boundary scan.
RANGES = {
    'attributeFactory': ('basic.dll', 0x4c4920, 187, '67354ebc6ecef0de3821185618cf7cd6f606ef2f502a979b66dd529c6433a205'),
    'tablePartFactory': ('basic.dll', 0x4c8a30, 187, '54a581775aead93f7ac78ac4917a19c60b6bc61e2cbcbcd43756f43643e43b58'),
    'attributeCtor': ('basic.dll', 0x79bbe0, 120, '553ba750df4edae9fa23d8526fd5ea4d41f84194deb907144661b5f5892b5db0'),
    'tablePartCtor': ('basic.dll', 0x79bad0, 150, '35adf24b99c7e72910f929fb9c3d7a3fcb9a9f2dca0686273cc740031743e970'),
    'tablePartBaseCtor': ('basic.dll', 0x55e310, 206, 'ab5a23802fb3b0aeb9d9e02271183ed6f1465ad4055b5a31b07390536b526ba4'),
    'attributeClassTable': ('basic.dll', 0x8c8350, 108, 'ac786ae976b381d9100663b4b3914d72afa04c6879e68ea7e912d4987bab24c3'),
    'tablePartClassTable': ('basic.dll', 0x8c818c, 108, '080caed793f5539311952445f6e99be25d78bd912c61f2337a9369c38a9096f4'),
    'attributeMdTable': ('basic.dll', 0x8c7598, 148, '05063228910df3438ed79b33eb81c8cbd956c9ec738a96de38b9baaecbcacb28'),
    'tablePartMdTable': ('basic.dll', 0x8c77e0, 148, 'd1050066f5a207438396035d725793810cbfea46c33194722bf2ec2213f85489'),
    'documentMdTable': ('basic.dll', 0x8c7130, 148, '537348ea62224d1d603a81949f146b38b4f2ed3bd486fcbd291e4a48fa3f2826'),
    'attributeQIThunk': ('basic.dll', 0x79cc58, 13, '84f1f91be96533ed53158b6fadf7dcad95f523eac454216e66845e2457918b86'),
    'attributeAddRefThunk': ('basic.dll', 0x79cdcb, 13, '2f6e2cfb7e1492b95b9c8f11ad4d557ec2320aaa4fb098989f6aff6412d4d729'),
    'attributeReleaseThunk': ('basic.dll', 0x79ccf9, 13, '0b9783763f270be19efe7023a9baf8667ed2e8e6ddc370106685c91b1698806e'),
    'tablePartQIThunk': ('basic.dll', 0x79cbf9, 13, '0e10b4ace2562c296ac927f2743e11cab3842f48ea6077a02b047a64db81fe94'),
    'tablePartAddRefThunk': ('basic.dll', 0x79cd6f, 13, '44f191a489f56fa4f03a1ac6b143818ec16b819f813a4aec1d7d3d19b03002cd'),
    'tablePartReleaseThunk': ('basic.dll', 0x79d105, 13, '8731da0f564d439052cfdc13779bb8f6caf6f4823217c0f9c75fb9e153291485'),
    'attributeQI': ('basic.dll', 0x79bb70, 26, '983f0f0a3ebca191860b364b5219a6ea902b73471946258c8bae4d2e70b24081'),
    'tablePartQI': ('basic.dll', 0x79ba60, 26, '25bc524c9f299c930f622acb1b60c60951963268270332add6cca0b9c59b844a'),
    'attributeAddRef': ('basic.dll', 0x79bbc0, 21, '0ddeff0f672a6be689a35ebe98fd5d9b78ad074f72f00259bd2b8d7e7d53c92b'),
    'tablePartAddRef': ('basic.dll', 0x79bab0, 21, 'f88e948af7a88e7f0b6d6ce10b596860dc658541a37b8a914f09b42d0c81a854'),
    'attributeRelease': ('basic.dll', 0x79bb90, 48, '6e66be78f8a00c4414c34c4f2598f39a2e835612656ee35534b40b59fb711705'),
    'tablePartRelease': ('basic.dll', 0x79ba80, 48, '886f36279565e9512286efa8e94a9f42040d31b9108d4131b6bc5569e3cd5503'),
    'attributeQiMap': ('basic.dll', 0x8c89a0, 12, '75d117846c6da337d78f46f169b2d4c3019ecfab29068585372cb2ba97d4cfc0'),
    'tablePartQiMap': ('basic.dll', 0x8c8750, 12, 'a032d20d8b7aeb6c2af5220ff03c921ad5cfca816a69a221da959f7ba4634a74'),
    'mdObjectIID': ('basic.dll', 0x898b04, 16, '5d20555723bbd96d5a0a5e71339e17ec0b28e74ea9ec945cb9e9b37f7f0fd671'),
    'basicCommonQI': ('basic.dll', 0x6ae930, 234, '97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
    'basicUnknownIIDDetector': ('basic.dll', 0x6ae900, 48, '595d8cfdd27660f94dba10cc8c33aa2404e2e86fab71223893013a9ead9de028'),
    'documentAttach': ('basic.dll', 0x4c0720, 34, '5bcad5d90bf4f3cc07f7a03b976503762ca12d3ecb2f1f9c2b8ee995404139a2'),
    'documentDelete': ('basic.dll', 0x4c0780, 37, '4e2648273e738e08199b658658f0d357e8b2c9a51ba9e47a606239dde46769f6'),
    'tablePartAttach': ('basic.dll', 0x4c6e20, 34, 'd9571d2a4e58a8e19f74822b304a53cde1a5c5c1b96f627fc87335229e9fc942'),
    'tablePartDelete': ('basic.dll', 0x4c6e80, 37, '6dfdce92158ba116000210203dc7279fdcadbd3304c0741b9d34c8036a2b4d15'),
    'sharedAttach': ('basic.dll', 0x3d4d40, 466, '3b0495b1ce2234f5242ba25c7a0deff7d21fccf7013df5789cb5cd194dd0df6a'),
    'sharedDelete': ('basic.dll', 0x3d5190, 539, 'b3cd441e8732ee802835a6cf0da216078b4efd3d97878d52f159bf4774030686'),
    'attributeGetter': ('basic.dll', 0x4c4250, 388, 'ca62b6e7d3e27503ab52146204039921c750e1c4432fdc5a177f0833b5e57085'),
    'attributeSetter': ('basic.dll', 0x4c43e0, 409, '9e2acc5af70a4bcae32241c5f07a662453df0f16e5a0f7927c547aee130f6aa9'),
    'tablePartGetter': ('basic.dll', 0x4c62b0, 573, 'a7bf22d35b5be5a839b27fa53ec50ad7b7a2886d0196737a11d623fd679b4e3e'),
    'tablePartSetter': ('basic.dll', 0x4c64f0, 409, '381b5f66d0648c803aed1fc6ce44f3927f4603c08acbedb2c23a40a60d3fccc3'),
    'attributeGuidSet': ('basic.dll', 0x4cd2f0, 135, '6638dd622c8994897c2abca71433dd54fc7a2706c049674bd739cddbed76dafe'),
    'tablePartGuidSet': ('basic.dll', 0x4cd7c0, 135, 'b234c9487e7663604aa05461f9153ea7d9c379a00582b0b387432c8645299e5a'),
    'attributeIndexSet': ('basic.dll', 0x55dd50, 571, '723b43ac9e22353354ed2379d8b317ee6a1beadb8d42d12fbf0bc320465709a4'),
    'tablePartIndexSet': ('basic.dll', 0x543760, 566, 'a55b77e293c1a6a94f6c814322829fd0f3bd60dd6eb7be3307fb62c5e0bf4913'),
    'nameGuid': ('basic.dll', 0x894d68, 16, '1cbf8deb56a38faf1bbd48feda3cf3013531ed7c8b9f0c7deed4ef22825a4c28'),
    'typeGuid': ('basic.dll', 0x890b84, 16, '30541a298fa9d38c0dcbe25ffc7fa9de98a7784c7f69e041c15c56742fdd7852'),
    'typeRegistration': ('basic.dll', 0x54178c, 22, '329dec4275644e2fb59c8512e578e4cff9c39c0e30ef1aab7bd733bd152730c5'),
    'columnFactory': ('backend.dll', 0x5e2680, 187, '6f7c3b8c242170830f2618149d2245d46c97992d4c4e1874f96a66d6c6605756'),
    'columnCtor': ('backend.dll', 0xb50340, 120, '220e5279ac0292554e5968177d47e619c656c117a219a5939612a1beff92dcd3'),
    'columnClassTable': ('backend.dll', 0xf1549c, 108, '84adb4662e70bd817f46f699934ecf20ed1688c65134530b1605809e9d17f564'),
    'columnMdTable': ('backend.dll', 0xf1324c, 148, '48d677d2408809a5d164628a7a3efbd20bf5e6acbc10858fb2a5e1029d270606'),
    'columnQIThunk': ('backend.dll', 0xb51ca9, 13, 'd125e654363bf5e08188769c79a97c46dd41978916a9d230b1efe8c4d395cbbf'),
    'columnAddRefThunk': ('backend.dll', 0xb421b1, 13, '3a5bdd3924ced849f926d16b868e11bee4cdb62f2480e9b6d38ecd8e37f762cf'),
    'columnReleaseThunk': ('backend.dll', 0xb42740, 13, '0bcf3fa851144e62de7d6f92af9ab8915628d7757eeedb8b9100697c6ccb8cde'),
    'columnQI': ('backend.dll', 0xb50320, 26, '6aba5f70a7441797c6c899640a8d0c4307e49184a98eef530c680cfc6b988250'),
    'columnAddRef': ('backend.dll', 0xb3fe70, 21, '5978c4825a98773192bbe6171220f37053df0e47c007e46d805afdf1ab6abfbe'),
    'columnRelease': ('backend.dll', 0xb3fe40, 48, '9e9417a7462bbf3eb9f4a9eae92a7301b9c32231d708d39e8493db4a991e7bf6'),
    'columnQiMap': ('backend.dll', 0xf16968, 12, '39ace65a1eac1fef534ecbe53564c0117def931c245a3f83602b73171787427a'),
    'columnMdObjectIID': ('backend.dll', 0xe62d7c, 16, '5d20555723bbd96d5a0a5e71339e17ec0b28e74ea9ec945cb9e9b37f7f0fd671'),
    'backendCommonQI': ('backend.dll', 0x966490, 234, '97a0568cd952f0c443fe52096f4962424e7a235baf1f8f6788ed7728941f4d7f'),
    'columnGetter': ('backend.dll', 0x5e2080, 388, '7efac9ba77db6f8836e3196e4e0b04048b9883fa9c36631b311ef55d0b018477'),
    'columnSetter': ('backend.dll', 0x5e2210, 409, 'f8fc8459df56684a292f4d2fc58bda78d2d20f1b38619588e6bac40b31ed346c'),
    'columnGuidSet': ('backend.dll', 0x5fc630, 135, 'f96e09f22cc64a83430a7e42be13c45d87cdb4d544c26cfd0f1713a355219c81'),
    'columnIndexSet': ('backend.dll', 0x629f80, 547, 'ac6802eb1525e764a606760b08c16744aa621f17502211df727c8699fea360fc'),
}


def _need(ok, code):
    if not ok:
        raise ValueError('V137_' + code)


def _word(raw, offset):
    _need(type(raw) is bytes and type(offset) is int and 0 <= offset <= len(raw)-4, 'WORD_BOUND_REJECTED')
    return struct.unpack_from('<I', raw, offset)[0]


def _relative(raw, offset, rva, opcode=0xe8):
    _need(type(raw) is bytes and type(offset) is int and type(rva) is int
          and 0 <= offset <= len(raw)-5 and raw[offset] == opcode, 'RELATIVE_BOUND_REJECTED')
    return rva + offset + 5 + struct.unpack_from('<i', raw, offset+1)[0]


def _span(read, module, rva, size):
    _need(callable(read) and type(module) is str and type(rva) is int and type(size) is int
          and (module, rva, size) in {(m,r,n) for m,r,n,_ in RANGES.values()}, 'SPAN_SCOPE_REJECTED')
    try:
        raw = read(module, rva, size)
    except Exception:
        raise ValueError('V137_SPAN_UNAVAILABLE') from None
    _need(type(raw) is bytes and len(raw) == size, 'SPAN_SIZE_REJECTED')
    return raw


def _sdk_semantics(members):
    try:
        metadata, value = (members[name].decode('utf-8-sig') for name in SDK_SHAS)
    except (KeyError, AttributeError, UnicodeError):
        raise ValueError('V137_SDK_ENCODING_REJECTED') from None
    _need(':iface IMDObject {12BFDDD0-36CC-11D4-940F-008048DA11F9}' in metadata
          and 'IMDClass@+ get_mdClass()' in metadata
          and 'const Guid& get_id()' in metadata and 'void set_id(const Guid& id)' in metadata
          and 'IMDParentLink@+ get_mdParentLink()' in metadata
          and 'int mdPropVal(const Guid& mdPropId, Value& value)' in metadata
          and 'bool setMdPropVal(const Guid& mdPropId, const Value& value)' in metadata
          and 'uint childCount(const Guid& childMdKind)' in metadata
          and 'IMDObject@+ child(const Guid& childMdKind, const Guid& id)' in metadata,
          'SDK_MD_OBJECT_REJECTED')
    _need('bool isMutable()' in value and 'void create(IValue@&out, Vector&)' in value,
          'SDK_TYPE_API_REJECTED')


def verify_sdk(members):
    _need(type(members) is dict and members.keys() == SDK_SHAS.keys(), 'SDK_SET_REJECTED')
    for name, sha in SDK_SHAS.items():
        raw = members[name]
        _need(type(raw) is bytes and 0 < len(raw) <= 65536
              and hashlib.sha256(raw).hexdigest() == sha, 'SDK_HASH_REJECTED')
    _sdk_semantics(members)


def verify_linkage(bodies):
    """Check concrete linkage; callers first verify all immutable span hashes.

    Kept separate for negative tests that alter an offset/IID/ownership byte.
    It grants no runtime adoption, calls or writer authorization.
    """
    _need(type(bodies) is dict and bodies.keys() == RANGES.keys(), 'SPAN_SET_REJECTED')
    for name, (_,_,n,_) in RANGES.items():
        _need(type(bodies[name]) is bytes and len(bodies[name]) == n, 'SPAN_SIZE_REJECTED')
    for name in ('mdObjectIID', 'columnMdObjectIID'):
        _need(str(uuid.UUID(bytes_le=bodies[name])) == MD_OBJECT_IID, 'MD_IID_REJECTED')
    _need(str(uuid.UUID(bytes_le=bodies['nameGuid'])) == NAME_PROPERTY
          and str(uuid.UUID(bytes_le=bodies['typeGuid'])) == TYPE_PROPERTY,
          'PROPERTY_GUID_REJECTED')
    rows = []
    for prefix, kind, cls, module, factory, ctor, class_table, md_table, facet, qi, add, release, qi_map in ROWS:
        base = BASES[module]; body = bodies[prefix+'Factory']
        # SEH prologue is pinned; normal output pointer is written before its
        # AddRef. Temporary primary reference is released only afterwards.
        _need(body[-3:] == b'\xc2\x08\x00'
              and body[0x6e:0x74] == b'\x8d\x8e'+struct.pack('<I',facet)
              and body[0x7b:0x7d] == b'\x89\x0f'
              and body[0x88:0x8e] == bytes.fromhex('8b0151ff5004')
              and body[0xa3:0xa6] == bytes.fromhex('ff5108')
              and _relative(body,0x4b,factory) == ctor, 'FACTORY_COUNTED_OUTPUT_REJECTED')
        constructor = bodies[prefix+'Ctor']
        _need(constructor[-3:] == b'\xc2\x04\x00'
              and b'\xc7\x86'+struct.pack('<II',facet,base+md_table) in constructor
              and _word(bodies[prefix+'ClassTable'],32) == base+factory,
              'CTOR_FACET_REJECTED')
        map_body = bodies[prefix+'QiMap'];iid_rva = 0xe62d7c if module=='backend.dll' else 0x898b04
        _need(struct.unpack('<III',map_body) == (base+iid_rva,facet,1), 'MD_QI_MAP_REJECTED')
        for slot, suffix, target in ((0,'QI',qi),(1,'AddRef',add),(2,'Release',release)):
            thunk = bodies[prefix+suffix+'Thunk'];thunk_rva = RANGES[prefix+suffix+'Thunk'][1]
            _need(_word(bodies[prefix+'MdTable'],slot*4) == base+thunk_rva
                  and thunk[:4] == b'\x81\x6c\x24\x04'
                  and _word(thunk,4) == facet
                  and _relative(thunk,8,thunk_rva,0xe9) == target, 'QI_ADJUSTOR_REJECTED')
        qibody = bodies[prefix+'QI'];common=0x966490 if module=='backend.dll' else 0x6ae930
        _need(qibody[9] == 0xba and _word(qibody,10) == base+qi_map
              and _relative(qibody,17,qi) == common
              and qibody[-3:] == b'\xc2\x0c\x00', 'QI_FORWARD_REJECTED')
        _need(bodies[prefix+'AddRef'][6:11] == b'\x05'+struct.pack('<I',0x1b8 if prefix=='tablePart' else 0x178)
              and bodies[prefix+'AddRef'][15:17] == b'\xff\x25'
              and bodies[prefix+'Release'][-3:] == b'\xc2\x04\x00', 'REFCOUNT_ABI_REJECTED')
        for slot, suffix in ((12,'Getter'),(13,'Setter')):
            _need(_word(bodies[prefix+'MdTable'],slot*4) == base+RANGES[prefix+suffix][1]
                  and bodies[prefix+suffix][-3:] == b'\xc2\x0c\x00', 'PROPERTY_ABI_REJECTED')
        # The GUID setter maps the actual receiver class property to an index;
        # no assumption that TablePart has the attribute's Type property.
        guid_set=bodies[prefix+'GuidSet'];index_set=RANGES[prefix+'IndexSet'][1]
        _need(guid_set[-3:] == b'\xc2\x08\x00'
              and _relative(guid_set,0x59,RANGES[prefix+'GuidSet'][1]) == index_set,
              'PROPERTY_INDEX_FORWARD_REJECTED')
        rows.append(dict(kind=kind,classId=cls,module=module,factoryRva=factory,
                         outputMdObjectTableRva=md_table,factoryOutputOffset=facet,
                         mdObjectQiOffset=facet,normalCountedOutputStaticVerified=True,
                         mdObjectQiStaticVerified=True,classRegistrationRuntimeVerified=False))
    for name in ('basicCommonQI','backendCommonQI'):
        b=bodies[name]
        _need(b[0x3d:0x4b] == bytes.fromhex('8b72040375fc568b06ff50048937')
              and b[0xc3:0xd4] == bytes.fromhex('8b76fc0375fc568b06ff50048b450c8930'),
              'QI_ADDREF_BEFORE_OUT_REJECTED')
    _need(_relative(bodies['tablePartCtor'],10,0x79bad0) == 0x55e310
          and bodies['tablePartBaseCtor'][-1:] == b'\xc3', 'TABLEPART_BASE_CTOR_REJECTED')
    for prefix, delta in (('document',0x8c),('tablePart',-0x180)):
        for slot,suffix,ret,target,call_offset in (
            (24,'Attach',8,0x3d4d40,25),(26,'Delete',12,0x3d5190,28)):
            raw=bodies[prefix+suffix];table=bodies[prefix+'MdTable']
            _need(_word(table,slot*4) == 0x228b0000+RANGES[prefix+suffix][1]
                  and raw[-3:] == b'\xc2'+struct.pack('<H',ret)
                  and b'\x8d\x88'+struct.pack('<i',delta) in raw
                  and _relative(raw,call_offset,RANGES[prefix+suffix][1]) == target,
                  'PARENT_ATTACH_DELETE_REJECTED')
    _need(bodies['sharedAttach'][-3:] == b'\xc2\x04\x00'
          and bodies['sharedDelete'][-3:] == b'\xc2\x08\x00', 'PARENT_IMPL_RET_REJECTED')
    _need(_relative(bodies['attributeIndexSet'],0x4a,0x55dd50) == 0x542440
          and _relative(bodies['tablePartIndexSet'],0x4d,0x543760) == 0x3cf210,
          'TYPE_VS_PLAIN_PARENT_REJECTED')
    _need(bytes.fromhex('6a016a0568840b1423') in bodies['typeRegistration'],
          'TYPE_REGISTRATION_REJECTED')
    return dict(staticNormalAbiVerified=True,primarySpanCount=len(bodies),rows=rows,
                documentAttachRva=0x4c0720,documentDeleteRva=0x4c0780,
                tablePartAttachRva=0x4c6e20,tablePartDeleteRva=0x4c6e80,
                parentAttachArgumentBytes=8,parentDeleteArgumentBytes=12,
                namePropertyId=NAME_PROPERTY,typePropertyId=TYPE_PROPERTY,
                receiverPropertyCapabilityRuntimeVerified=False,
                exceptionUnwindVerified=False,fullTransitiveCtorVerified=False,
                destructorTransitiveEffectsVerified=False,countedAdoptionRuntimeVerified=False,
                metadataCrudVerified=False,nativePermit=False,writerAuthorized=False)


def verify(read, sdk_members, primary_bytes, correction_bytes):
    """Read only the closed spans, verify immutable context, return no authority."""
    verify_sdk(sdk_members)
    for raw,sha in ((primary_bytes,PRIMARY_SHA),(correction_bytes,CORRECTION_SHA)):
        _need(type(raw) is bytes and 0 < len(raw) <= 32768
              and hashlib.sha256(raw).hexdigest() == sha, 'PRIMARY_CONTEXT_REJECTED')
    primary=json.loads(primary_bytes)
    _need(primary['passed'] is True and primary['nativePermit'] is False
          and primary['rows'][1]['factoryNormalOutputOffset'] == 0x164,
          'IMMUTABLE_HISTORICAL_CONTEXT_REJECTED')
    bodies={}
    for name,(module,rva,size,sha) in RANGES.items():
        raw=_span(read,module,rva,size)
        _need(hashlib.sha256(raw).hexdigest() == sha,'SPAN_HASH_REJECTED')
        bodies[name]=raw
    result=verify_linkage(bodies)
    result.update(platformVersion='8.3.18.1208',tablePartHistoricalOffsetCorrectionVerified=True,
                  historicalFactoryOutputOffset=0x164,correctedFactoryOutputOffset=0x188,
                  primaryContextSha256=PRIMARY_SHA,correctionContextSha256=CORRECTION_SHA)
    return result


def read_sdk_members():
    _need(hashlib.sha256(SDK_ARCHIVE.read_bytes()).hexdigest() == SDK_ARCHIVE_SHA,
          'SDK_ARCHIVE_REJECTED')
    with zipfile.ZipFile(SDK_ARCHIVE) as archive:
        for name in SDK_SHAS:
            _need(sum(item.filename==name for item in archive.infolist()) == 1
                  and 0 < archive.getinfo(name).file_size <= 65536,'SDK_MEMBER_REJECTED')
        return {name:archive.read(name) for name in SDK_SHAS}


def verify_static():
    """Read existing pinned SDK/PE only; no extraction, native call or writer."""
    images={name:PE(name) for name in BASES}
    def read(module,rva,size):
        image=images[module];at=image.offset(image.base+rva)
        return image.data[at:at+size]
    return verify(read,read_sdk_members(),PRIMARY_PATH.read_bytes(),CORRECTION_PATH.read_bytes())
