"""Exact aggregated Processing ObjectModule ITextEditor prerequisite.

Pure fixed PE/SDK reads only; never calls native code or reads runtime/settings.
Runtime output identity and write/Undo permissions remain separate checks.
"""
import hashlib
from pathlib import Path
import struct
import uuid
import zipfile

from repository_pe_probe import PE

PLATFORM_VERSION = '8.3.18.1208'
BASE = 0x17f20000
PE_SHA = 'a379297bfcff186f456e260f8bd36102d3d723d422379734706f80a3f201962a'
SDK = Path(__file__).resolve().parents[4] / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
SDK_SHA = '464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
SDK_MEMBER = 'modules/snegopat/v8api/text.v'
SDK_MEMBER_SHA = '629f8c74cd5cdefb41eceb43a7b9133da2719c3afafea73de670e47df8f89904'
EDITOR_IID = 'e82efaf1-28b8-11d5-b08a-008048da0765'
EDITOR_TABLE_RVA = 0x10db3c
EDITOR_PREFIX_RVAS = (0xe4680, 0xe45ab, 0xe439d, 0xa2020)

# Whole small bodies; table prefixes contain exactly the slots used below.
RANGES = {
    'factory': (0xe12c0, 594, '785fce202fde60e8fd29ef3d1ab06950c0d439d069f34fffbc279105ddf0fb62'),
    'outerCtor': (0x80290, 116, '039f8afff017c18d1ac21a2bba189ea90ef71427b0aff46ea702f642272bcc26'),
    'outerTable': (0x109624, 12, '91c08d46009f1d5f99ea264d43e8e746f6e91d8b2de0ec3604968664f124dcf1'),
    'outerQI': (0x80220, 26, 'a59bfcd4265372c7cd701e8072a3d594995c65abcaa707f672f692208b902c52'),
    'outerQIMap': (0x10a5f8, 204, '0d2f5f6e710c8dd0d6332d6a233d716e5fe7fb3ddde9122d2c53bf13b5482d7e'),
    'outerDelegate': (0xc600, 38, '40025ab02e7b85d595cc8228384a09d87a5772f68fc87bd80948b865dc7cbdbb'),
    'innerUnknownTable': (0x10dd84, 12, '7ef27432c32f8efeb97cc2c54ffea402a32f862f6791e894fa6e772142eb902e'),
    'innerQI': (0xe3a30, 126, '7eb218d1aaa8dcc7dbf655e51b3cc5a687572c18665b31fd23b5fdac89f1cfb8'),
    'innerQIMap': (0x105838, 240, '5517b5bd907f6b3cd15ccf814f8f286edb6eabe7645e8575ca78cf68070819dd'),
    'editorIID': (0x1059f8, 16, '87f35f3e4933e7f2ecfb128b568a430be4d3ae896c6464fd953d7188d48b7d00'),
    'aggregatePrimaryTable': (0x10dd94, 12, '91ee42023a35fe91db83651c6f8c1b2755e26cb9e3c792ba0dc321bb2d60929e'),
    'primaryWindowPrefix64': (0x10dc14, 256, 'cbf53408aeaf0f8b53ec132e7f6649f92536d34a7301bef0ce08f26dab827a84'),
    'editorTable': (EDITOR_TABLE_RVA, 40, '5b46f9ede517a5c6c956d030090a52ea125d4ffe8ade8116fbf33756c26399c6'),
    'editorQI': (0xe4680, 13, '1dcd2c427ef0adae42f708e6e64fdc664e28371b74c0f40e997234dedc708b86'),
    'editorAddRef': (0xe45ab, 13, '9257094b0d6684c83eca8b6172b840d77c5113528888f4c69843758629218daf'),
    'editorRelease': (0xe439d, 13, '9a64303fce621c38eeda508e0ffd2ae42e6d38927ac31c23017a803b54deaed0'),
    'aggregateQI': (0xe3910, 71, '8e226ee8af9e2ef2a279eb4e37e06ef7093f32597955beea02883e628fccf923'),
    'aggregateAddRef': (0xe39b0, 66, 'f515c012054b1ce03753eed2b61b3ef033d89c14592412008b4cab4b6d507ad1'),
    'aggregateRelease': (0xe3960, 66, '11ce4e30a8a2e53dff0b04f8a0d655f4fc36b215e4cf8c4cee74f167a6e83345'),
    'managerGetter': (0xa2020, 226, '8a971033b364f5e7b37ed896ccc92b9bb0305a4d7f7de22fe71d4d15190e9909'),
    'contextGetter': (0x84d30, 83, '04ca7125f2f45390ea21df0bd676f8bede1808ebe24156995a64a44511387694'),
    'qiMatcher': (0xd3e0, 252, '44f197ce4cff832ba653b0400191dff8e1263fc28bec8381f3e7ecb4478fe430'),
}

ABI_PROFILE = {
    'platform': PLATFORM_VERSION, 'architecture': 'x86', 'module': 'txtedui.dll',
    'editor': {'iid': EDITOR_IID, 'tableRva': EDITOR_TABLE_RVA,
               'subobjectOffset': 0x13c, 'prefixRvas': EDITOR_PREFIX_RVAS},
    'ownership': {'aggregated': True, 'outerPointerOffset': 0x54c,
                  'outerHeldInnerUnknownOffset': 0x94, 'rawUnkIsCanonical': False},
    'getITextManager': {'slot': 3, 'rva': 0xa2020, 'convention': 'stdcall',
                       'stackBytes': 8, 'arguments': ('editorSelf', 'textManagerOut'),
                       'nativeResultIsHRESULT': False, 'outputCounted': True,
                       'selfAdjustment': -0x138, 'contextGetterSlot': 63,
                       'contextGetterRva': 0x84d30, 'contextManagerSlot': 7},
    'contextGetter': {'convention': 'thiscall', 'stackBytes': 4,
                      'arguments': ('windowSelfECX', 'contextOut'),
                      'contextPointerOffset': 0x188, 'addRefReturnedContext': True},
}


def need(ok, code):
    if not ok:
        raise ValueError('V98_' + code)


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


def verify_binding(table_rva, prefix_rvas):
    """Validate supplied sanitized inventory; does not attest live origin."""
    need(_exact(table_rva, EDITOR_TABLE_RVA)
         and _exact(prefix_rvas, EDITOR_PREFIX_RVAS), 'EDITOR_BINDING_REJECTED')


def verify_sdk(member):
    need(type(member) is bytes and 0 < len(member) <= 65536
         and hashlib.sha256(member).hexdigest() == SDK_MEMBER_SHA, 'SDK_MEMBER_REJECTED')
    text = member.decode('utf-8-sig')
    need(':iface itexteditor {' + EDITOR_IID + '}' in text.lower()
         and 'uint getITextManager(ITextManager@&out)' in text
         and 'TextManager& getTextManager()' in text,
         'PUBLISHED_SIGNATURE_REJECTED')


def collect_ranges(pe):
    need(pe.name == 'txtedui.dll' and pe.base == BASE
         and hashlib.sha256(pe.data).hexdigest() == PE_SHA, 'PE_PROFILE_REJECTED')
    return {k: pe.data[pe.offset(BASE + r):pe.offset(BASE + r) + n]
            for k, (r, n, _) in RANGES.items()}


def verify_argument_flow(ranges):
    """Explicit ABI checks follow exact complete-body pins in verify_ranges."""
    factory = ranges['factory']
    need(factory.startswith(bytes.fromhex('558bec')) and factory.endswith(b'\xc3')
         and bytes.fromhex('c7873c0100003cdb0218') in factory
         and bytes.fromhex('c7874c05000000000000') in factory
         and bytes.fromhex('89b74c050000') in factory,
         'CONSTRUCTOR_LAYOUT_REJECTED')
    for key, target in (('editorQI', 0xe3910), ('editorAddRef', 0xe39b0), ('editorRelease', 0xe3960)):
        body = ranges[key]
        need(body[:8] == bytes.fromhex('816c24043c010000') and body[8] == 0xe9
             and RANGES[key][0] + 13 + struct.unpack_from('<i', body, 9)[0] == target,
             'EDITOR_ADJUSTMENT_REJECTED')
    for key, suffix in (('aggregateQI', 'c20c00'), ('aggregateAddRef', 'c20400'), ('aggregateRelease', 'c20400')):
        need(ranges[key].endswith(bytes.fromhex(suffix))
             and bytes.fromhex('4c050000') in ranges[key], 'AGGREGATION_ABI_REJECTED')
    getter, context = ranges['managerGetter'], ranges['contextGetter']
    need(getter.startswith(bytes.fromhex('558bec')) and getter.endswith(bytes.fromhex('c20800'))
         and bytes.fromhex('8b750cc70600000000') in getter
         and bytes.fromhex('8b4d0881c1c8feffff') in getter
         and bytes.fromhex('ff90fc000000') in getter
         and bytes.fromhex('ff501c') in getter
         and bytes.fromhex('8906c70700000000') in getter,
         'MANAGER_OUTPUT_ABI_REJECTED')
    need(context.endswith(bytes.fromhex('c20400'))
         and bytes.fromhex('8b91880100008916') in context
         and bytes.fromhex('8b0a52ff5104') in context,
         'COUNTED_CONTEXT_ABI_REJECTED')


def verify_ranges(ranges):
    need(type(ranges) is dict and ranges.keys() == RANGES.keys(), 'RANGE_SCOPE_REJECTED')
    for k, (_, size, sha) in RANGES.items():
        b = ranges[k]
        need(type(b) is bytes and len(b) == size and hashlib.sha256(b).hexdigest() == sha,
             'RANGE_PIN_REJECTED')
    words = lambda name: struct.unpack('<' + 'I' * (len(ranges[name]) // 4), ranges[name])
    need(words('editorTable')[:4] == tuple(BASE + r for r in EDITOR_PREFIX_RVAS)
         and words('primaryWindowPrefix64')[63] == BASE + 0x84d30,
         'TABLE_SLOTS_REJECTED')
    inner = tuple(struct.iter_unpack('<III', ranges['innerQIMap']))
    outer = tuple(struct.iter_unpack('<III', ranges['outerQIMap']))
    need(inner[2] == (BASE + 0x1059f8, 0x13c, 1) and inner[-1] == (0, 0, 0)
         and outer[-2] == (0, 0x94, BASE + 0xc600) and outer[-1] == (0, 0, 0)
         and str(uuid.UUID(bytes_le=ranges['editorIID'])) == EDITOR_IID,
         'QI_LAYOUT_REJECTED')
    verify_argument_flow(ranges)


def verify_static():
    need(0 < SDK.stat().st_size <= 8 * 1024 * 1024
         and hashlib.sha256(SDK.read_bytes()).hexdigest() == SDK_SHA, 'SDK_ARCHIVE_REJECTED')
    with zipfile.ZipFile(SDK) as archive:
        need(0 < archive.getinfo(SDK_MEMBER).file_size <= 65536, 'SDK_SIZE_REJECTED')
        verify_sdk(archive.read(SDK_MEMBER))
    verify_abi_profile(ABI_PROFILE)
    verify_ranges(collect_ranges(PE('txtedui.dll')))
    return dict(staticContractVerified=True, version='V98', platform=PLATFORM_VERSION,
                architecture='x86', pinnedRanges=len(RANGES), platformSha256=PE_SHA,
                sdkArchiveSha256=SDK_SHA, sdkMemberSha256=SDK_MEMBER_SHA,
                editorTableRva=EDITOR_TABLE_RVA, editorPrefixRvas=EDITOR_PREFIX_RVAS,
                publishedEditorIid=EDITOR_IID, editorAggregated=True,
                editorSubobjectOffset=0x13c, countedTextManagerOutputProven=True,
                rawUnkCanonicalProven=False, runtimeEditorVerified=False,
                runtimeTextManagerIdentityVerified=False, runtimeOwnedObjectBindingVerified=False,
                contextManagerClassAndTransitiveBodyFullyProven=False,
                runtimeUndoVerified=False, nativePermitGranted=False,
                unknownClosePermitted=False, goldSavePermitted=False,
                databaseUpdatePermitted=False)
