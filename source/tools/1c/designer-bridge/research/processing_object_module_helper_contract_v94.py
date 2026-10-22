"""Fixed Processing ObjectModule helper ABI prerequisite; local bytes only.

No native calls, cache preparation, protected settings or live source reads.
This does not grant a writer, attest getter/open success or create a resource.
"""
import hashlib
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE

PLATFORM_VERSION = '8.3.18.1208'
BASE = 0x24770000
PE_SHA = 'e19126902ca7b0ee839c3492224f91a28d11000d3f1a74116443a21d2fab2ea8'
SDK = Path(__file__).resolve().parents[4] / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
SDK_SHA = '464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
SDK_MEMBER = 'modules/snegopat/v8api/metadata.v'
SDK_MEMBER_SHA = 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed'
HELPER_IID = '888744f9-b616-11d4-9436-004095e12fc7'
MODULE_IID = '963ce56b-fcf9-4e6d-8ebc-374721b63aba'
HELPER_TABLE_RVA = 0x60ae54
MODULE_TABLE_RVA = 0x60ad5c
METHOD_RVAS = (0xf3b70, 0x35c470, 0x35c6f0)

# Whole functions exclude padding; both openModule returns are included.
RANGES = {
    'factory': (0x55bca0, 326, 'ec5d8b3a392f0e4c11e2b4a52df782790f07861f8115144df2f6e407779f3333'),
    'baseCtor': (0x34ed40, 299, '2f2a02fb966736f2a6a267d7163093faa463ffc107218a5cc79aaaa21b6d81db'),
    'primaryTable': (0x60ae40, 20, '628263d1e04f94af081e4734a140078e1d9a0bbb770b3b4598e363804a7a09b4'),
    'helperTable': (HELPER_TABLE_RVA, 96, 'a37c74c2e3106c7ba1e222366459d53519d5d45ac2508abf72ca7f69ce4ec38a'),
    'moduleTable': (MODULE_TABLE_RVA, 48, '61f309911c80ee9b15cc17276acd55d19ba739ce89800ce5e1d9ebb3985c583a'),
    'qiMap': (0x60a340, 156, 'fa0eb06738d64c5f141767d193bf3fd4ba99e869bb78d2b19b74013cebf1ada8'),
    'helperIID': (0x5fabc4, 16, '879f68b4bef0b848a3ce0d934fc44cf61182ecdbfd2bdbdcc9a97a9acb77f00f'),
    'moduleIID': (0x5fab74, 16, '8c7bac33989e255cc8b582f65a8623139c8b577cd757143d1fd98dadfdd5b05e'),
    'primaryQI': (0x55c0d0, 26, '7f4fc4846a849ac2b60260169f35d987568842529448348c77a61a50e9601717'),
    'helperQI': (0x55d022, 10, '16d35965bca75f3f4d3221163d087853b8bf3d4efd1c4b06677fe1aa1528ab70'),
    'moduleQI': (0x55d0ae, 13, 'eaf7547755ab8c77c16e75f6f3b1095293128b731aac848835766bbbfca004ab'),
    'primaryAddRef': (0x5180d0, 21, '1a01b0b9f672df55df666958b71499729e697ef682b6dc7e73d9cb60febae45e'),
    'primaryRelease': (0x5180a0, 48, 'ff764ccbf87cf6932052b9227337b149caa5c9b72cd86e5e525a9a2154719027'),
    'helperAddRef': (0x51d4f7, 10, 'b9f7a4fb16ef7fa2d61c5c9c16192e8f12c7337fa397fad264277200b93fccae'),
    'helperRelease': (0x51d44a, 10, '735399cbd361b1f54c6c5960665fe02f4927be60b0cb7b423acb5bac9c253e7c'),
    'moduleAddRef': (0x51d5cb, 13, 'e5d5efb207d6721d42c2d598853ced845d44e1cdc02a5a47bcf7d2aa354078ea'),
    'moduleRelease': (0x51d53f, 13, '99d3c9d6d483f8c809df079e54c33fc15e5ea620612809f829525ecacf799e95'),
    'getMDObj': (METHOD_RVAS[0], 25, '974c25d96065a28a81f19869636af46fd3be0e73d596208adec8b6e50075409b'),
    'textOfModule': (METHOD_RVAS[1], 255, '3f23fa7c4fec6db13ed1eb12d1c2ded0765e35816bd1f0b5e4dc7c1cb06af7aa'),
    'openModule': (METHOD_RVAS[2], 131, 'e458b407e8c33b0be34cd13e0a888886b5e6afc71423a1f41515c55074f0133a'),
}

ABI_PROFILE = {
    'platform': PLATFORM_VERSION, 'architecture': 'x86', 'module': 'basicui.dll',
    'helper': {'iid': HELPER_IID, 'tableRva': HELPER_TABLE_RVA, 'primaryOffset': 0x7c,
               'getMDObjSlot': 23, 'getMDObjRva': METHOD_RVAS[0]},
    'moduleHelper': {'iid': MODULE_IID, 'tableRva': MODULE_TABLE_RVA, 'primaryOffset': 0x84,
                     'textSlot': 5, 'textRva': METHOD_RVAS[1], 'openSlot': 11, 'openRva': METHOD_RVAS[2]},
    'owner': {'primaryTableRva': 0x60ae40, 'objectPointerOffset': 0x1c,
              'referenceCountOffset': 0xb0, 'allocationBytes': 0xcc},
    'getMDObj': {'convention': 'stdcall', 'stackBytes': 4, 'arguments': ('helperSelf',),
                 'nativeAddRefInGetter': False, 'publishedResult': 'IMDObject@+'},
    'textOfModule': {'convention': 'stdcall', 'stackBytes': 16,
                    'arguments': ('moduleSelf', 'constPropertyGuid', 'boolS', 'v8stringOut'),
                    'nativeResult': 'AL bool', 'requiredReturned': True, 'requiredInitialLength': 0},
    'openModule': {'convention': 'stdcall', 'stackBytes': 20,
                   'arguments': ('moduleSelf', 'textManagerOut', 'constPropertyGuid', 'uint32FlagsRef', 'textEditorOut'),
                   'publishedResult': 'uint', 'nativeResultIsHRESULT': False},
}


def need(ok, code):
    if not ok:
        raise ValueError('V94_' + code)


def _exact(a, b):
    if type(a) is not type(b):
        return False
    if type(b) is dict:
        return a.keys() == b.keys() and all(_exact(a[k], b[k]) for k in b)
    if type(b) is tuple:
        return len(a) == len(b) and all(_exact(x, y) for x, y in zip(a, b))
    return a == b


def verify_abi_profile(profile):
    need(_exact(profile, ABI_PROFILE), 'ABI_PROFILE_REJECTED')


def verify_binding(table_rvas, method_rvas):
    """Check supplied sanitized RVA inventory, without attesting its origin."""
    need(_exact(table_rvas, (HELPER_TABLE_RVA, MODULE_TABLE_RVA))
         and _exact(method_rvas, METHOD_RVAS), 'PROCESSING_BINDING_REJECTED')


def verify_sdk(member):
    need(type(member) is bytes and len(member) <= 65536
         and hashlib.sha256(member).hexdigest() == SDK_MEMBER_SHA, 'SDK_MEMBER_REJECTED')
    text = member.decode('utf-8-sig')
    need(':iface IMDEditHelper {' + HELPER_IID.upper() + '}' in text
         and ':iface IMDEditModuleHelper {' + MODULE_IID.upper() + '}' in text
         and '22\n\t\tvoid getTreeItemInfo' in text.replace('\r', '')
         and 'IMDObject@+ getMDObj()' in text
         and 'bool textOfModule(const Guid& propId, bool s, v8string&out result)' in text
         and 'uint openModule(ITextManager@&, const Guid& propId, uint32& open, ITextEditor@& editor)' in text,
         'PUBLISHED_SIGNATURE_REJECTED')


def collect_ranges(pe):
    need(pe.name == 'basicui.dll' and pe.base == BASE
         and hashlib.sha256(pe.data).hexdigest() == PE_SHA, 'PE_PROFILE_REJECTED')
    return {name: pe.data[pe.offset(BASE + rva):pe.offset(BASE + rva) + size]
            for name, (rva, size, _) in RANGES.items()}


def verify_ranges(ranges):
    need(type(ranges) is dict and ranges.keys() == RANGES.keys(), 'RANGE_SCOPE_REJECTED')
    for name, (_, size, sha) in RANGES.items():
        data = ranges[name]
        need(type(data) is bytes and len(data) == size
             and hashlib.sha256(data).hexdigest() == sha, 'RANGE_PIN_REJECTED')
    words = lambda name: struct.unpack('<' + 'I' * (len(ranges[name]) // 4), ranges[name])
    helper, module = words('helperTable'), words('moduleTable')
    need(helper[:3] == tuple(BASE + x for x in (0x55d022, 0x51d4f7, 0x51d44a))
         and module[:3] == tuple(BASE + x for x in (0x55d0ae, 0x51d5cb, 0x51d53f))
         and (helper[23], module[5], module[11]) == tuple(BASE + x for x in METHOD_RVAS),
         'TABLE_SLOTS_REJECTED')
    rows = tuple(struct.iter_unpack('<III', ranges['qiMap']))
    need(rows[1] == (BASE + 0x5fabc4, 0x7c, 1)
         and rows[4] == (BASE + 0x5fab74, 0x84, 1)
         and rows[-1] == (0, 0, 0)
         and str(uuid.UUID(bytes_le=ranges['helperIID'])) == HELPER_IID
         and str(uuid.UUID(bytes_le=ranges['moduleIID'])) == MODULE_IID, 'QI_LAYOUT_REJECTED')
    verify_argument_flow(ranges)


def verify_argument_flow(ranges):
    # Called after full pins; pointed arguments make the intended ABI explicit.
    need(ranges['getMDObj'] == bytes.fromhex('558bec8b4d08ba1c00000085c98d41a00f44c28b005dc20400'),
         'GETTER_FIELD_ABI_REJECTED')
    for key, offset, target in (
            ('helperQI', 0x7c, 0x55c0d0), ('moduleQI', 0x84, 0x55c0d0),
            ('helperAddRef', 0x7c, 0x5180d0), ('helperRelease', 0x7c, 0x5180a0),
            ('moduleAddRef', 0x84, 0x5180d0), ('moduleRelease', 0x84, 0x5180a0)):
        body = ranges[key]
        prefix = (bytes.fromhex('836c2404') + bytes([offset])) if offset < 0x80 else (bytes.fromhex('816c2404') + struct.pack('<I', offset))
        need(body.startswith(prefix) and body[len(prefix)] == 0xe9
             and RANGES[key][0] + len(body) + struct.unpack_from('<i', body, len(prefix) + 1)[0] == target,
             'QI_REFCOUNT_ADJUSTMENT_REJECTED')
    need(bytes.fromhex('c787b000000000000000') in ranges['baseCtor']
         and bytes.fromhex('c7471c00000000') in ranges['baseCtor']
         and bytes.fromhex('68cc000000') in ranges['factory']
         and bytes.fromhex('c70640aed724') in ranges['factory']
         and bytes.fromhex('c7467c54aed724') in ranges['factory']
         and bytes.fromhex('c786840000005cadd724') in ranges['factory'], 'CONSTRUCTOR_LAYOUT_REJECTED')
    text, opening = ranges['textOfModule'], ranges['openModule']
    need(text.startswith(bytes.fromhex('558bec')) and text.endswith(bytes.fromhex('c21000'))
         and bytes.fromhex('ff75140fb646048bcfff75105053') in text
         and bytes.fromhex('8b75e83b75ec753a85f67432') in text, 'TEXT_ARGUMENT_ABI_REJECTED')
    need(opening.startswith(bytes.fromhex('558bec'))
         and opening.count(bytes.fromhex('c21400')) == 2
         and bytes.fromhex('ff75188bcfff7514568b750c56') in opening
         and bytes.fromhex('8b450cc70000000000') in opening, 'OPEN_ARGUMENT_ABI_REJECTED')


def verify_static():
    need(0 < SDK.stat().st_size <= 8 * 1024 * 1024
         and hashlib.sha256(SDK.read_bytes()).hexdigest() == SDK_SHA, 'SDK_ARCHIVE_REJECTED')
    with zipfile.ZipFile(SDK) as archive:
        need(0 < archive.getinfo(SDK_MEMBER).file_size <= 65536, 'SDK_SIZE_REJECTED')
        verify_sdk(archive.read(SDK_MEMBER))
    verify_abi_profile(ABI_PROFILE)
    verify_ranges(collect_ranges(PE('basicui.dll')))
    return dict(staticContractVerified=True, version='V94', platform=PLATFORM_VERSION,
                architecture='x86', pinnedRanges=len(RANGES), platformSha256=PE_SHA,
                sdkArchiveSha256=SDK_SHA, sdkMemberSha256=SDK_MEMBER_SHA,
                helperTableRva=HELPER_TABLE_RVA, moduleTableRva=MODULE_TABLE_RVA,
                methodRvas=METHOD_RVAS, helperCountedQIOffsets=(0x7c, 0x84),
                storedObjectPointerOffset=0x1c, sharedReferenceCountOffset=0xb0,
                runtimeOwnObjectAndUiBindingRequired=True, runtimeTextReturnedAndEmptyRequired=True,
                factoryRegistrationClassIndependentlyProven=False, absentModuleResourceCreationProven=False,
                runtimeGetterVerified=False, runtimeTextReadVerified=False, runtimeModuleOpenVerified=False,
                runtimeUndoVerified=False, transitiveOpenCalleesFullyProven=False,
                nativePermitGranted=False, goldSavePermitted=False, databaseUpdatePermitted=False)
