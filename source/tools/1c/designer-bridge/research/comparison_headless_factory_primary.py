"""Pinned 17-DWORD stock comparison factory ABI; pure PE reads, no invocation.

This closes the caller frame, not pre-initialization detached object identity.
The factory initializes its result internally: a later pointer comparison cannot
prove that an existing UI-owned object was not initialized by a cached creator.
"""
import hashlib
from pathlib import Path
import re
import uuid

import comparison_native_source_roles_primary as roles
import current_comparison_factory_primary as factory
import database_configuration_read_route_v154 as stock

ROOT = Path(__file__).resolve().parents[4]
PINS = {
    Path(roles.__file__): '7396acb1db47e520cdfaa73606174706760b2dad0ce5ccbab7d3fb06acbc69e7',
    Path(factory.__file__): '83f52e681af5b2f03bc7b4adffd2015d13b464874a6dd747468364f337f455e3',
    ROOT / 'tools/1c/designer-bridge/research/NativeSdkCall.s': 'ab5c81990fe2838b366a3cde486e5b06c0650a1bc9bc9b85f43774eb47699374',
    ROOT / 'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/modules/snegopat/v8api/process.v': '92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef',
}
SPANS = dict(roles.SPANS)
SPANS.update({
    'stockCaller': stock.RANGES['compareExecute'],
    'descriptorGetter': ('frntend.dll', 0x132240, 150, '6cd3e279d7dd5fbd2a376194e206b053753061a1681fa00bbdcd8aa8972f4fca'),
    'valueCopy': ('frntend.dll', 0x8ee7a0, 259, '6d56d0fb090dccc7712fdfeb56a5afc1c8403e22cd8334cbb7bfd151787487d5'),
    'builderKeyA': ('config.dll', 0x2c9d0c, 16, '1be22ee1386e8f8c332a691d54400975f1d9ccd84a8adb8d2649dcf76f3d9028'),
    'builderKeyB': ('config.dll', 0x2bdea0, 16, '29fe684d4dc699c8919daf53513afb9895da811db39ed6194cedeafccd613b0d'),
    'getterKeyA': ('frntend.dll', 0xc3487c, 16, '1be22ee1386e8f8c332a691d54400975f1d9ccd84a8adb8d2649dcf76f3d9028'),
    'getterKeyB': ('frntend.dll', 0xc3486c, 16, '29fe684d4dc699c8919daf53513afb9895da811db39ed6194cedeafccd613b0d'),
})
EXPECTED_WORDS = ['SERVICE', 'OUT_HOLDER', 1, 2, 'GUID_NULL',
                  'DESCRIPTOR_A', 'DESCRIPTOR_B', 'DESCRIPTOR_C',
                  'MAIN', 0, 'DB', 0, 0, 0, 1, 0, 0]


def need(ok, code):
    if not ok:
        raise ValueError('HEADLESS_FACTORY_' + code)


def project_words(rows):
    """Interpret the one fixed linear caller tail, including LEA and nested calls.

    Nonnull AddRef paths are deliberately taken. Their four-byte standard COM
    stack cleanup is explicit and cannot swallow an outer factory argument.
    """
    regs = {'edx': 'DB_MANAGER', 'esi': 'MAIN_MANAGER', 'edi': 'OUT_HOLDER'}
    locals_ = {-0x118: 'SERVICE', -0x11c: 'GUID_NULL'}
    stack, seen = [], []
    calls = {0xc159a: (2, 'DB', ['DB_MANAGER', 0]),
             0xc15b4: (1, 'REFCOUNT', ['DB']),
             0xc15c0: (2, 'MAIN', ['MAIN_MANAGER', 0]),
             0xc15d8: (1, 'REFCOUNT', ['MAIN'])}

    def read(value):
        if value == 'esp':
            return ('stack', len(stack) - 1)
        if value in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
            return regs.get(value, 'UNKNOWN:' + value)
        match = re.fullmatch(r'dword ptr \[ebp - (0x[0-9a-f]+)\]', value)
        if match:
            return locals_.get(-int(match[1], 16), 'UNKNOWN_LOCAL')
        try:
            return int(value, 0)
        except ValueError:
            return 'UNKNOWN_MEMORY'

    for at in sorted(x for x in rows if 0xc155b <= x < 0xc1604):
        ins = rows[at]
        if ins.mnemonic == 'push':
            stack.append(read(ins.op_str))
        elif ins.mnemonic == 'lea':
            destination, source = ins.op_str.split(', ', 1)
            need(destination == 'eax' and source in ('[ebp - 0x8c]', '[ebp - 0x3c]', '[ebp - 0x64]'), 'DESCRIPTOR_LEA')
            regs[destination] = {'[ebp - 0x8c]': 'DESCRIPTOR_C', '[ebp - 0x3c]': 'DESCRIPTOR_B', '[ebp - 0x64]': 'DESCRIPTOR_A'}[source]
        elif ins.mnemonic == 'call':
            need(at in calls, 'CALL_NOT_CLASSIFIED')
            count, result, expected = calls[at]
            need(list(reversed(stack[-count:])) == expected, 'CALL_ARGUMENTS')
            del stack[-count:]
            regs['eax'] = result
            seen.append(at)
        elif ins.mnemonic == 'mov':
            destination, source = ins.op_str.split(', ', 1)
            value = read(source)
            if destination in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
                regs[destination] = value
            else:
                local = re.fullmatch(r'dword ptr \[ebp - (0x[0-9a-f]+)\]', destination)
                slot = re.fullmatch(r'dword ptr \[(eax|ecx|edx)\]', destination)
                if local:
                    locals_[-int(local[1], 16)] = value
                elif slot and isinstance(regs.get(slot[1]), tuple):
                    pointer = regs[slot[1]]
                    need(pointer[0] == 'stack', 'STACK_POINTER')
                    stack[pointer[1]] = value
        elif ins.mnemonic in ('pop', 'ret') or ins.op_str.startswith('esp,'):
            need(False, 'UNKNOWN_STACK_CHANGE')
    need(set(seen) == set(calls), 'MISSING_CALL')
    return list(reversed(stack))


def verify_units(bodies, *, check_hashes=True):
    need(type(bodies) is dict and set(bodies) == set(SPANS), 'UNIT_SET')
    for name, (_, _, size, pin) in SPANS.items():
        need(type(bodies[name]) is bytes and len(bodies[name]) == size, 'UNIT_BOUND')
        if check_hashes:
            need(hashlib.sha256(bodies[name]).hexdigest() == pin, 'UNIT_PIN_' + name)
    parent = roles.verify_units({key: bodies[key] for key in roles.SPANS}, check_hashes=check_hashes)
    rows = {ins.address: ins for name, (_, rva, _, _) in SPANS.items()
            if not name.endswith(('KeyA', 'KeyB'))
            for ins in factory._decoder().disasm(bodies[name], rva)}
    need(project_words(rows) == EXPECTED_WORDS, 'ALL17_ARGUMENTS')
    anchors = {
        0xc15db: ('mov', 'ecx, dword ptr [ebp - 0x118]'),
        0xc1604: ('call', 'dword ptr [ebp - 0x120]'),
        0x141c54: ('lea', 'eax, [ebp - 0x10]'),
        0x141c64: ('mov', 'eax, dword ptr [ebp - 0x10]'),
        0x141c8f: ('call', 'dword ptr [eax + 8]'),
        0x13230d: ('mov', 'eax, dword ptr [ebp + 0xc]'),
        0x132310: ('mov', 'ecx, dword ptr [ebp + 8]'),
        0x13231c: ('mov', 'dword ptr [ebp - 0xdc], eax'),
        0x132ab1: ('mov', 'eax, dword ptr [ebp - 0xdc]'),
        0x132287: ('add', 'eax, 0x60'), 0x1322bc: ('add', 'eax, 0x88'),
        0x13280a: ('movups', 'xmm0, xmmword ptr [eax]'),
        0x13280d: ('add', 'eax, 0x10'), 0x132818: ('call', '0x8ee7a0'),
        0x132834: ('call', '0x8ee7a0'), 0x13284d: ('call', '0x8ee7a0'),
        0x8ee808: ('mov', 'eax, dword ptr [esi + 0x10]'),
        0x8ee80e: ('mov', 'eax, dword ptr [esi + 0x14]'),
        0x132a6a: ('mov', 'ecx, dword ptr [ebp + 0x28]'),
        0x132a82: ('mov', 'ecx, dword ptr [ebp + 0x30]'),
    }
    need(all(at in rows and (rows[at].mnemonic, rows[at].op_str) == pair for at, pair in anchors.items()), 'ABI_ANCHOR')
    # ECX is overwritten before any instruction can consume its incoming value.
    prefix = [i for at, i in sorted(rows.items()) if 0x1322e0 <= at < 0x132310]
    need(all('ecx' not in i.op_str for i in prefix), 'INCOMING_ECX_USED')
    getter = factory.local_cfg(bodies['descriptorGetter'], 0x132240)
    value = factory.local_cfg(bodies['valueCopy'], 0x8ee7a0)
    need(getter['returns'] == ['8', '8', '8'] and value['returns'] == ['4', '4', '4'], 'DESCRIPTOR_ABI')
    need(bodies['builderKeyA'] == bodies['getterKeyA'] and bodies['builderKeyB'] == bodies['getterKeyB'], 'KEYS_DO_NOT_MATCH')
    need(bodies['factory'][-3:] == bytes.fromhex('c24400') and bodies['initialize'][-3:] == bytes.fromhex('c25000'), '17_NOT20')
    return dict(kind='HEADLESS_COMPARISON_FACTORY_PRIMARY', factorySlot=7, factoryRva=0x1322e0,
                argumentWords=list(EXPECTED_WORDS), explicitSelfIncluded=True, factoryStackPopBytes=68,
                incomingEcxUnused=True, shimEcxMayBeZero=True, initializerWordCount=20,
                outputArgumentIndex=1, outputArgumentKind='address_of_zero_initialized_owned_interface_holder',
                eaxReturnKind='same_holder_address_not_interface_or_boolean', outputInterface='*outHolder',
                outputNormalCleanup='one standard IUnknown.Release of nonnull *outHolder after all use',
                transferredSourceReferences=[dict(index=8, source='Main', addRefBeforeDispatch=1, consumedByFactory=True),
                                             dict(index=10, source='DB', addRefBeforeDispatch=1, consumedByFactory=True)],
                unknownDispatchTransferState='retain_unknown_no_retry_or_blind_release',
                sourceMapping=[dict(factoryOffset=0x28, initializeOffset=0x34, resultOffset=0x34, source='Main'),
                               dict(factoryOffset=0x30, initializeOffset=0x3c, resultOffset=0x38, source='DB')],
                descriptorBytes=40, descriptorGuidBytes=16, descriptorPrivateValueBytes=24,
                descriptorSemanticType='opaque_native_GUID_plus_privateValue_not_v8string_or_URL',
                descriptorA=dict(formula='heldService+0x60', key=str(uuid.UUID(bytes_le=bodies['builderKeyA']))),
                descriptorB=dict(formula='heldService+0x88', key=str(uuid.UUID(bytes_le=bodies['builderKeyB']))),
                descriptorC='bridge_owned_zero_initialized_40_bytes_alive_through_call',
                descriptorInputsBorrowed=True, descriptorBackingServiceMustRemainOwned=True,
                descriptorGetterCFG=getter, valueCopyCFG=value,
                serviceAcquisition='strong SDK IUnknown handle from currentProcess().getService(Guid(5c54d1a0-d0df-4550-bfc6-7deed8622790)); verify actual frntend c0daa4 before fields',
                sourceRoleProof=parent['nativeDirectionStaticallyVerified'],
                factoryInitializesBeforeReturn=True, outputOwningReferenceIsNotFreshAllocationProof=True,
                detachedBeforeInitializationVerified=False, postFactoryUiResultSetExclusionSufficient=False,
                remainingGate='prove uncached creator/new identity before init OR controlled new constructor then pinned 20-word init',
                all17WordsStaticallyClosed=True, runtimeProvidersBound=False, nativePermit=False,
                databaseUpdateAuthorized=False, sourceWritesAuthorized=False)


def verify_primary():
    for path, pin in PINS.items():
        need(hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'PARENT_PIN')
    images, bodies = {}, {}
    for name, (module, rva, size, _) in SPANS.items():
        if module not in images:
            images[module] = factory.PE(module)
        image = images[module]
        at = image.offset(image.base + rva)
        bodies[name] = image.data[at:at + size]
    return verify_units(bodies), bodies
