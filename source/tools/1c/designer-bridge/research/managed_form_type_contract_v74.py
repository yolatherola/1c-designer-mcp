"""Const enum input for one owned FormType scalar setter; no native calls.

The fixed branch copies an integer into the receiver. It neither stores the
input carrier nor forwards it into property/modified synchronization. A pure
receipt checker validates supplied prerequisites, never attests their origin or
grants a process, native invocation, Gold write, or complete-form claim.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import managed_form_type_contract_v72 as base

V72_SOURCE_SHA = 'a2e3ddceb80fd6448ae52a11e6b2e30a499ecb148f53772028a4dca2aa14d68d'
OWN_PROCESSING = 'f0e50730-e59b-4c8a-a189-0e62365aa372'
OWN_FORM = '4e68b5c9-17f4-4e20-a63b-804392cd97a2'
FORM_CLASS = 'd5b0e5ed-256d-401c-9c36-f630cafd8a62'
PROPERTY = base.FORM_TYPE_PROPERTY.lower()
FORM_TYPE = base.FORM_TYPE.lower()
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
GOLD_CONTROL = '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')

# The V72 pin already covers each complete function. Recheck them independently
# together with pointed argument slices, including both synchronization ends.
WHOLE_FUNCTIONS = {
    'setGuid': (0x4edec0, 400, '5bd7411c90c406e47b7b348c4659a9b8558291ce61d79a8f2e60a977bc0cb31a'),
    'propertyChanged': (0x3d4570, 125, '615c5e74ba8a0f3ebbf2118b8e88f36cc87e51fdb30713e73c1dff2bd62eebec'),
    'propertyIndexChanged': (0x3d3500, 103, 'a1b177c990d3a2ebe63c66daae08cf98844f4e340e93baee034c8184ced9ecfb'),
    'setModified': (0x49e630, 125, '669097f9a8f67cfe0118187d76e7a0a277887204749f32eba97e8e84b7b328eb'),
}
SLICES = {
    'postScalarSync': (0x4ee001, 30, '246553208569362626dd5e2a184211876be8d0a31fde8b9cd6e866e8e3ba5d97'),
    'propertyGuidAndOwnController': (0x3d4595, 52, '9832ce991c3bdf797effb0fff32fd00834ec12b15e68df833467bc95ece49c81'),
    'propertyControllerExit': (0x3d45d0, 10, 'ab3047bfd0681cc913abb76139375d76982fc417f66606eb82e940b2d1f93f73'),
    'modifiedOwnControllerAndByte': (0x49e654, 70, '9e032dd072a75cb1d6ae59d0d58e6738b42fd4b75028bd73ba18bdcd7d50cb48'),
    'enumIdStoredAsOwnScalar': (0x50aef9, 19, 'c562e8900a29c3fc7eb5b599fd6137245770b729543f104624d50a2a772c7918'),
}
RANGES = WHOLE_FUNCTIONS | SLICES
ABI_PROFILE = {
    'setter': {'module': 'basic.dll', 'tableRva': 0x8cb258, 'slot': 13,
               'rva': 0x4edec0, 'convention': 'stdcall', 'retBytes': 12,
               'arguments': ('ownFormSelf', 'propertyGuid', 'constValue')},
    'propertyDispatch': {'propertyId': PROPERTY, 'index': 6, 'branchRva': 0x50aeab,
                         'ownBodyFromFormSelf': 12, 'storedScalarOffset': 0xdc},
    'input': {'typeId': FORM_TYPE, 'iValueTableRva': 0xf1563c, 'iValueQIRva': 0xb4b200,
              'enumIID': base.I_ENUM, 'enumOffset': 4, 'enumTableRva': 0xf15624,
              'idSlot': 4, 'idRva': 0x92140, 'idConvention': 'stdcall', 'idRetBytes': 4,
              'sourceReadonly': True, 'creatorFactoryRequired': False},
    'postScalar': {'propertyChangedArguments': ('ownBodySelf', 'propertyGuid'),
                   'propertyIndexChangedArguments': ('ownBodySelf', 'propertyIndex'),
                   'modifiedArguments': ('ownFormSelf', True),
                   'controllerVirtualArguments': ('ownControllerSelf',),
                   'inputValueForwarded': False, 'inputIValueForwarded': False},
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verify_reused_source(data):
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == V72_SOURCE_SHA,
            'V74_V72_SOURCE_CHANGED')


def verify_abi_profile(profile):
    require(base.exact_equal(profile, ABI_PROFILE), 'V74_ABI_PROFILE_CHANGED')


def collect_ranges(pe):
    return {name: base.read_range(pe, rva, size) for name, (rva, size, _) in RANGES.items()}


def verify_ranges(ranges):
    require(type(ranges) is dict and ranges.keys() == RANGES.keys(), 'V74_RANGE_SET_CHANGED')
    for name, (_, size, sha) in RANGES.items():
        data = ranges[name]
        require(type(data) is bytes and len(data) == size, 'V74_RANGE_BOUNDARY_CHANGED')
        require(hashlib.sha256(data).hexdigest() == sha, 'V74_RANGE_BYTES_CHANGED')


def verify_argument_flow(ranges):
    """Check exact x86 argument provenance on already pinned function bytes."""
    post = ranges['postScalarSync']
    # ESI is own IMDObject; ECX=ESI+0xc. EDI was replaced with property GUID
    # before dispatch; push EDI goes only to propertyChanged(own body, GUID).
    require(post[:14] == bytes.fromhex('85f68d4e0cb8140000000f44c857') and post[14] == 0xe8
            and 0x4ee00f + 5 + struct.unpack_from('<i', post, 15)[0] == 0x3d4570
            and post[19:] == bytes.fromhex('8b066a0156ff9084000000'), 'V74_POST_SCALAR_ARGUMENTS_CHANGED')
    prop = ranges['propertyGuidAndOwnController']
    require(prop[:5] == bytes.fromhex('8bf98b7734')
            and bytes.fromhex('8b0656ff5014') in prop
            and bytes.fromhex('ff7508') in prop
            and prop[-8:-5] == bytes.fromhex('508bcf') and prop[-5] == 0xe8
            and 0x3d45c4 + 5 + struct.unpack_from('<i', prop, len(prop)-4)[0] == 0x3d3500,
            'V74_PROPERTY_GUID_ARGUMENTS_CHANGED')
    require(ranges['propertyControllerExit'] == bytes.fromhex('85f674068b0656ff5018'),
            'V74_PROPERTY_CONTROLLER_ARGUMENTS_CHANGED')
    modified = ranges['modifiedOwnControllerAndByte']
    require(modified.startswith(bytes.fromhex('8b7d08b94800000085ff8d47400f44c18b30'))
            and bytes.fromhex('8d4f3c85ff0f44c88a450c8801') in modified
            and modified.endswith(bytes.fromhex('85f674068b0656ff5018')),
            'V74_MODIFIED_OWN_ARGUMENTS_CHANGED')
    require(ranges['enumIdStoredAsOwnScalar'] == bytes.fromhex(
        '8b0151ff501083bea0000000018986dc000000'), 'V74_SCALAR_STORE_CHANGED')
    # Both independent complete implementations retain their actual return ABI.
    require(ranges['setGuid'].endswith(b'\xc2\x0c\x00')
            and ranges['setModified'].endswith(b'\xc2\x08\x00')
            and ranges['propertyChanged'].endswith(b'\xc2\x04\x00')
            and ranges['propertyIndexChanged'].endswith(b'\xc2\x04\x00'), 'V74_RETURN_ABI_CHANGED')


def _shape(value, keys, code):
    require(type(value) is dict and value.keys() == set(keys), code)


def _pointer(value):
    return type(value) is int and 0x10000 <= value <= 0xfffffffb and value % 4 == 0


def _enum(value):
    _shape(value, ('iValueAddress', 'enumAddress', 'canonicalIUnknown', 'typeId', 'enumId',
                   'iValueTableRva', 'iValueQIRva', 'enumTableRva', 'enumIID'), 'V74_ENUM_SCHEMA_REJECTED')
    require(all(_pointer(value[key]) for key in ('iValueAddress', 'enumAddress', 'canonicalIUnknown'))
            and value['enumAddress'] == value['iValueAddress'] + 4, 'V74_ENUM_POINTER_REJECTED')
    require(value['typeId'] == FORM_TYPE and value['enumIID'] == base.I_ENUM
            and type(value['enumId']) is int and value['enumId'] in (0, 1), 'V74_ENUM_TYPE_REJECTED')
    require(all(type(value[key]) is int and value[key] == expected for key, expected in
                {'iValueTableRva': 0xf1563c, 'iValueQIRva': 0xb4b200, 'enumTableRva': 0xf15624}.items()),
            'V74_ENUM_TABLE_REJECTED')


def validate_const_input_inventory(info):
    """Validate supplied scalar evidence; this is not a native mutation permit.

    Source and own readback may legitimately use the same cached enum carrier.
    Complete backing independence cannot be derived from these addresses. The
    trusted host must establish memory bounds, counted lifetimes and provenance.
    """
    _shape(info, ('receiver', 'source', 'sourceAfter', 'ownBefore', 'ownAfter', 'evidence'),
           'V74_INVENTORY_SCHEMA_REJECTED')
    receiver = info['receiver']
    fixed = {'formId': OWN_FORM, 'processingId': OWN_PROCESSING, 'classId': FORM_CLASS,
             'propertyId': PROPERTY, 'tableModule': 'basic.dll', 'tableRva': 0x8cb258, 'setterRva': 0x4edec0}
    pointers = ('formAddress', 'ownManagerAddress', 'ownRootAddress', 'goldManagerAddress',
                'goldRootAddress', 'goldControlFormAddress')
    flags = ('indexedOwnReceiver', 'parentsVerified', 'managerContextVerified')
    _shape(receiver, tuple(fixed) + pointers + flags + ('ownRootId',), 'V74_RECEIVER_SCHEMA_REJECTED')
    require(all(type(receiver[key]) is type(expected) and receiver[key] == expected
                for key, expected in fixed.items()), 'V74_RECEIVER_SCOPE_REJECTED')
    require(all(_pointer(receiver[key]) for key in pointers)
            and len({receiver[key] for key in pointers}) == len(pointers)
            and all(receiver[key] is True for key in flags), 'V74_RECEIVER_ALIAS_REJECTED')
    root = receiver['ownRootId']
    require(type(root) is str and GUID.fullmatch(root) is not None
            and root not in (GOLD_ROOT, GOLD_CONTROL, OWN_PROCESSING, OWN_FORM), 'V74_ROOT_SCOPE_REJECTED')
    for name in ('source', 'sourceAfter', 'ownBefore', 'ownAfter'):
        _enum(info[name])
    evidence_flags = ('sourceReadonly', 'knownManagedControlReadOnly', 'countedEnumQI',
                      'idGetterAbiVerified', 'equalityAbiVerified', 'memoryBoundsVerified',
                      'typedLifetimesVerified', 'beforeUnequalSource', 'afterEqualSource',
                      'sourceEqualAfter', 'sourcePreserved', 'sourceScopeExited', 'goldCountersZero')
    source_scope = {'goldRootId': GOLD_ROOT, 'goldControlFormId': GOLD_CONTROL,
                    'goldControlFormClassId': 'fb880e93-47d7-4127-9357-a20e69c17545'}
    _shape(info['evidence'], evidence_flags + tuple(source_scope), 'V74_EVIDENCE_SCHEMA_REJECTED')
    require(all(info['evidence'][key] is True for key in evidence_flags), 'V74_EVIDENCE_REJECTED')
    require(all(info['evidence'][key] == expected for key, expected in source_scope.items()),
            'V74_SOURCE_SCOPE_REJECTED')
    source, before, after = (info[key] for key in ('source', 'ownBefore', 'ownAfter'))
    require(source == info['sourceAfter'], 'V74_SOURCE_CHANGED')
    require(before['enumId'] != source['enumId'] and after['enumId'] == source['enumId']
            and before['iValueAddress'] != source['iValueAddress'], 'V74_TRANSITION_REJECTED')
    return {'constInputPrerequisitesAccepted': True, 'managedId': source['enumId'],
            'sourceReadonly': True, 'creatorFactoryRequired': False, 'nativePermitGranted': False,
            'deepEnumCloneProven': False, 'wholeFormBackingIndependent': False}


def verify_static():
    verify_reused_source((HERE / 'managed_form_type_contract_v72.py').read_bytes())
    reused = base.verify_static()
    pe = base.PE('basic.dll')
    base.verify_module('basic.dll', pe.base, pe.data)
    ranges = collect_ranges(pe)
    verify_ranges(ranges)
    verify_argument_flow(ranges)
    verify_abi_profile(ABI_PROFILE)
    return {
        'platform': '8.3.18.1208', 'architecture': 'x86', 'staticContractVerified': True,
        'reusedV72SourceSha256': V72_SOURCE_SHA, 'moduleShas': reused['moduleShas'],
        'sdkMemberShas': reused['sdkMemberShas'], 'extraPinnedRanges': len(RANGES),
        'constInputConditionallySupported': True, 'sourceReadonly': True,
        'sourceReadonlyRuntimeProven': False, 'scalarStoredInOwnFormBranch': True,
        'inputValueForwardedToSynchronization': False, 'inputIValueForwardedToSynchronization': False,
        'enumCarrierPointerStoredInFormKind': False, 'inputKindTypeWrittenByBranch': False,
        'creatorFactoryRequired': False, 'obsoleteV72FactoryOriginProven': False,
        'managedIdAssumed': False, 'runtimeMappingProven': False,
        'virtualSyncDeepCalleesProven': False, 'managedKindRuntimeProven': False,
        'bodyRuntimeProven': False, 'deepEnumCloneProven': False, 'wholeFormBackingIndependent': False,
        'nativePermitGranted': False, 'setterAuthorized': False, 'nativeCalls': 0, 'goldCalls': 0,
    }


if __name__ == '__main__':
    print(json.dumps(verify_static(), ensure_ascii=False, sort_keys=True))
