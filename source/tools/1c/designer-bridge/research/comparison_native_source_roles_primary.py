"""Native Compare30 source order from exact pushes and stores, never CLI labels."""
import hashlib
from pathlib import Path
import re
from current_comparison_factory_primary import PE, _decoder, SPANS as FACTORY_SPANS
import current_comparison_result_primary as result
import database_configuration_read_route_v154 as stock

ROOT = Path(__file__).resolve().parents[4]
SDK = ROOT / 'build/designer-v43-013dc010bd784e859b1e3ba4def25f3c/runtime/modules/snegopat/v8api/metadata.v'
SDK_SHA = 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed'
PINS = {
    ROOT / 'tools/1c/designer-bridge/research/comparison_completion_change_semantics_primary.py': '6337c21bcb5ea92d6e8a8df36bb616d90c329f8704cd0bde1ff189a5f84cfb9c',
    Path(result.__file__): '27f9978d2145897ce3210ca364bfbcfe1afb2093f73a58c418a5fc73a53e972c',
    Path(stock.__file__): 'e258d952d9b25b3954c8c2e1ef42982cb6ab2a2e94ec033496ef4e8417a70aa8',
}
SPANS = {name: ('frntend.dll', *result.SPANS[name]) for name in
         ('initialize', 'execute', 'prepare', 'build', 'treeBuild', 'treeRecurse')}
SPANS.update({
    'builder': stock.RANGES['compareBuilder'],
    'mainManagerModel': stock.RANGES['mainManager'],
    'databaseManagerModel': stock.RANGES['dbManager'],
    'factory': FACTORY_SPANS['factory'],
    # Deliberately bounded ABI witnesses, not a whole 2.8KB manager implementation.
    'knownManagerEntry': ('backend.dll', 0x2aeb40, 126, 'c68f0f61c1233a62a3c24aee2369d6de42a8d5d453e10d213dc91f782277f01e'),
    'knownManagerExit': ('backend.dll', 0x2af5b7, 30, 'a4ec316398c2c9bac8c49ddd3e2adbcb66f139f0c372c19f715db379b6fe18b9'),
})


def need(ok, code):
    if not ok:
        raise ValueError('NATIVE_SOURCE_ROLES_' + code)


def _push_projection(rows, start, end, calls, *, arguments=None, registers=None):
    """Tiny bounded interpreter for push words and local copies at TWO callsites.

    Calls have independently pinned standard stack-pop ABI. All conditional QI/
    AddRef calls consume exactly their just-pushed arguments, so taking their
    nonnull branch cannot change the final outer argument ordering.
    """
    arguments, registers = arguments or {}, dict(registers or {})
    stack, locals_ = [], {}

    def read(operand):
        if operand == 'esp':
            return ('slot', len(stack) - 1)
        if operand in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
            return registers.get(operand, 'unknown:' + operand)
        match = re.fullmatch(r'dword ptr \[ebp ([+-]) (0x[0-9a-f]+|[0-9]+)\]', operand)
        if match:
            offset = int(match[2], 0) * (1 if match[1] == '+' else -1)
            return arguments.get(offset, 'arg:' + str(offset)) if offset >= 0 else locals_.get(offset, 'local:' + str(offset))
        try:
            return int(operand, 0)
        except ValueError:
            return 'unknown:' + operand

    observed = []
    for at in sorted(x for x in rows if start <= x < end):
        ins = rows[at]
        if ins.mnemonic == 'push':
            stack.append(read(ins.op_str))
        elif ins.mnemonic == 'call':
            need(at in calls, 'UNCLASSIFIED_CALL')
            pop, returned, expected = calls[at]
            need(pop % 4 == 0 and len(stack) >= pop // 4, 'CALL_STACK')
            words = list(reversed(stack[-pop // 4:]))
            if expected is not None:
                need(words == expected, 'GET_MD_CONT_CALL_ARGUMENTS')
            del stack[-pop // 4:]
            registers['eax'] = returned
            observed.append(at)
        elif ins.mnemonic == 'mov':
            destination, source = ins.op_str.split(', ', 1)
            value = read(source)
            if destination in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'):
                registers[destination] = value
            else:
                slot = re.fullmatch(r'dword ptr \[(eax|ecx|edx)\]', destination)
                local = re.fullmatch(r'dword ptr \[ebp - (0x[0-9a-f]+|[0-9]+)\]', destination)
                if slot:
                    pointer = registers.get(slot[1])
                    if type(pointer) is tuple and pointer[0] == 'slot':
                        need(0 <= pointer[1] < len(stack), 'OUTPUT_SLOT')
                        stack[pointer[1]] = value
                elif local:
                    locals_[-int(local[1], 0)] = value
        elif ins.mnemonic in ('pop', 'ret') or ins.op_str.startswith('esp,'):
            need(False, 'UNCLASSIFIED_STACK_CHANGE')
    need(set(observed) == set(calls), 'CALL_SET')
    return list(reversed(stack))


def verify_units(bodies, *, check_hashes=True):
    need(type(bodies) is dict and set(bodies) == set(SPANS), 'UNIT_SET')
    rows = {}
    for name, (_, rva, size, pin) in SPANS.items():
        need(type(bodies[name]) is bytes and len(bodies[name]) == size, 'UNIT_BOUND')
        if check_hashes:
            need(hashlib.sha256(bodies[name]).hexdigest() == pin, 'UNIT_PIN')
        rows.update({i.address: i for i in _decoder().disasm(bodies[name], rva)})
    anchors = {
        0xc1555: ('mov', 'edx, dword ptr [esi + 0x24]'),
        0xc1558: ('mov', 'esi, dword ptr [esi + 0x1c]'),
        0xc156e: ('mov', 'ecx, dword ptr [eax + 0x154]'),
        0xc157d: ('mov', 'eax, dword ptr [eax + 0x154]'),
        0xc1583: ('mov', 'dword ptr [ebp - 0x114], eax'),
        0xc159a: ('call', 'ecx'), 0xc15c0: ('call', 'dword ptr [ebp - 0x114]'),
        0x136ca7: ('mov', 'esi, dword ptr [ebp + 0x34]'),
        0x136ccf: ('mov', 'eax, dword ptr [ebp + 0x3c]'),
        0x136cd2: ('mov', 'dword ptr [ebp - 0x10], eax'),
        0x136cef: ('mov', 'dword ptr [edi + 0x34], esi'),
        0x136d14: ('mov', 'ecx, dword ptr [ebp - 0x10]'),
        0x136d1a: ('mov', 'dword ptr [esi + 0x38], ecx'),
        0x137df8: ('push', 'dword ptr [esi + 0x38]'),
        0x137dfd: ('push', 'dword ptr [esi + 0x34]'),
        0x142b73: ('mov', 'edi, dword ptr [ebp + 0xc]'),
        0x142b8d: ('mov', 'dword ptr [esi + 0x598], edi'),
        0x142ba4: ('mov', 'edi, dword ptr [ebp + 0x10]'),
        0x142bbe: ('mov', 'dword ptr [esi + 0x59c], edi'),
        0x142f8e: ('push', 'dword ptr [edi + 0x59c]'),
        0x142f97: ('push', 'dword ptr [edi + 0x598]'),
        0xce30d: ('mov', 'ecx, dword ptr [ebp + 0x14]'),
        0xce326: ('lea', 'ecx, [ebp - 0x68]'),
        0xce332: ('mov', 'ebx, dword ptr [ebp + 0x18]'),
        0xce354: ('lea', 'ecx, [ebp - 0x44]'),
        0xce388: ('push', '0'), 0xce38a: ('push', '0'),
        0xce38f: ('push', 'eax'), 0xce393: ('push', 'eax'),
        0xce394: ('lea', 'eax, [ebp - 0x44]'),
        0xce398: ('lea', 'eax, [ebp - 0x68]'),
        0xce88b: ('mov', 'eax, dword ptr [ebp + 0x10]'),
        0xce88e: ('mov', 'dword ptr [ebp - 0x70], eax'),
        0xce891: ('mov', 'eax, dword ptr [ebp + 0x14]'),
        0xce894: ('mov', 'dword ptr [ebp - 0x68], eax'),
        0xce97c: ('mov', 'esi, dword ptr [ebp - 0x70]'),
        0xce97f: ('mov', 'edx, dword ptr [ebp - 0x68]'),
        0xce98c: ('movups', 'xmmword ptr [eax + 8], xmm0'),
        0xce99a: ('movups', 'xmmword ptr [eax + 0x18], xmm0'),
    }
    need(all(at in rows and (rows[at].mnemonic, rows[at].op_str) == expected for at, expected in anchors.items()), 'EXACT_ROLE_CHAIN')
    need(bytes.fromhex('8b701c') in bodies['mainManagerModel'] and
         bytes.fromhex('8b4824') in bodies['databaseManagerModel'], 'MODEL_MANAGER_ROLES')
    need(bodies['knownManagerExit'][-3:] == bytes.fromhex('c20800'), 'GET_MD_CONT_RET8')
    native = _push_projection(rows, 0xc155b, 0xc1604, {
        0xc159a: (8, 'DB', ['DB_MANAGER', 0]),
        0xc15b4: (4, 'refcount', None),
        0xc15c0: (8, 'MAIN', ['MAIN_MANAGER', 0]),
        0xc15d8: (4, 'refcount', None),
    }, registers={'edx': 'DB_MANAGER', 'esi': 'MAIN_MANAGER'})
    need(len(native) == 17 and native[(0x28 - 8) // 4] == 'MAIN' and
         native[(0x30 - 8) // 4] == 'DB' and bodies['factory'][-3:] == bytes.fromhex('c24400'), 'NATIVE_FACTORY_ARG_ROLES')
    initialized = _push_projection(rows, 0x1328f6, 0x1329ee, {
        0x13291b: (4, 'refcount', None), 0x13293a: (4, 'refcount', None),
        0x132959: (4, 'refcount', None), 0x13299a: (12, 'qi_return', None),
        0x1329bc: (12, 'qi_return', None), 0x1329d8: (12, 'qi_return', None),
    }, arguments={8 + index * 4: value for index, value in enumerate(native)})
    need(len(initialized) == 20 and initialized[(0x34 - 8) // 4] == 'MAIN' and
         initialized[(0x3c - 8) // 4] == 'DB' and bodies['initialize'][-3:] == bytes.fromhex('c25000'), 'INITIALIZER_SOURCE_ROLES')
    return dict(nativeFactoryWordCount=17, initializeWordCount=20,
                managerMainField=0x1c, managerDatabaseField=0x24, getMdContStackPopBytes=8,
                nativeFactoryMainArgumentOffset=0x28, nativeFactoryDatabaseArgumentOffset=0x30,
                resultMainSourceOffset=0x34, resultDatabaseSourceOffset=0x38,
                resultMainTreeSourceOffset=0x598, resultDatabaseTreeSourceOffset=0x59c,
                nodeMainUuidOffset=8, nodeDatabaseUuidOffset=0x18,
                leftSource='MainConfiguration', rightSource='DBConfiguration',
                leftOnlyChange3Means='present_in_Main_only', rightOnlyChange4Means='present_in_DB_only',
                nativeDirectionStaticallyVerified=True, runtimeSourceRolesBound=False,
                cliProfileUsedAsNativeProof=False, completionEpochVerified=False,
                errorFreeEpochVerified=False, databaseUpdateAuthorized=False)


def verify_primary():
    for path, pin in PINS.items():
        need(hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'FROZEN_PARENT_PIN')
    sdk = SDK.read_bytes()
    need(hashlib.sha256(sdk).hexdigest() == SDK_SHA and b'IMDContainer@+ getMDCont(int i = 0)' in sdk, 'PUBLISHED_GET_MD_CONT_ABI')
    images, bodies = {}, {}
    for name, (dll, rva, size, _) in SPANS.items():
        if dll not in images:
            images[dll] = PE(dll)
        image = images[dll]
        offset = image.offset(image.base + rva)
        bodies[name] = image.data[offset:offset + size]
    return verify_units(bodies), bodies
