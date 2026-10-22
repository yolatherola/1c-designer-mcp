"""Finite headless flag effect in exact stock result.execute; no native API.

Mode zero preserves selectAll=1; show zero skips post-compute UI opening.
Its forwarded hash-helper parameter is unused, including the catch/rethrow.
This does NOT prove fresh ownership/initialization or permit cached result reuse.
"""
import hashlib
from pathlib import Path
import struct
from current_comparison_factory_primary import PE, _decoder, local_cfg
import current_comparison_result_primary as result
import database_configuration_read_route_v154 as stock

BASE = 0x26dc0000
PINS = {Path(result.__file__): '27f9978d2145897ce3210ca364bfbcfe1afb2093f73a58c418a5fc73a53e972c',
        Path(stock.__file__): 'e258d952d9b25b3954c8c2e1ef42982cb6ab2a2e94ec033496ef4e8417a70aa8'}
SPANS = {
    'execute': ('frntend.dll', *result.SPANS['execute']),
    'resultTable': ('frntend.dll', *result.SPANS['resultTable']),
    'stockCaller': stock.RANGES['compareExecute'],
    'hashInsert': ('frntend.dll', 0x8ffec0, 337, '2a1bb8cfc1a99f9eb0b5c6be700f696304da23369f9763b335d845e0c3d06dd2'),
    'hashEh': ('frntend.dll', 0xb16fa0, 27, 'e18620365ee80e407db0ab8b1fcc56488f5349cc8ea075d0de5b195111b4c049'),
    'hashInfo': ('frntend.dll', 0xc835c0, 36, '0a3df8253c23ea78b71a1b69ffcdc2f0a07bba3d2bc12e411d9aa1848a776105'),
    'hashUnwind': ('frntend.dll', 0xc835e4, 32, '140b4dd25fba9a34726bc92b4c31e9d58d2b128837285f66a24c6c5982cf41b7'),
    'hashTry': ('frntend.dll', 0xc83604, 20, '75d6e309a5188a53256439c9127a0e62177161c785fc957cca7634ac8e7d219f'),
    'hashCatch': ('frntend.dll', 0xc83618, 16, 'efd7ed87ee5cefb18f21352d58297b5b00833675c96fffd34504f39d4982445e'),
    'hashCatchBody': ('frntend.dll', 0x900011, 35, '525ff3274509809f28ddc11a1c1c8903787255a2a7948f416698851a2efb8203'),
    'copyGuid': ('frntend.dll', 0x900680, 28, 'a77d6fc241255fc26a905031b510ceb2aca17ae827875a05a0cd70d964d12b7d'),
}


def need(ok, code):
    if not ok:
        raise ValueError('HEADLESS_EXECUTE_' + code)


def _stack_offsets(instructions):
    from capstone.x86_const import X86_OP_MEM
    return sorted(set(op.mem.disp for ins in instructions for op in ins.operands
                      if op.type == X86_OP_MEM and ins.reg_name(op.mem.base) == 'ebp' and op.mem.disp > 0))


def verify_units(bodies, *, check_hashes=True):
    """Validate fixed bodies and local normal/EH edges; never adopt a pointer."""
    need(type(bodies) is dict and set(bodies) == set(SPANS), 'UNIT_SET')
    rows, instructions = {}, {}
    for name, (_, rva, size, pin) in SPANS.items():
        raw = bodies[name]
        need(type(raw) is bytes and len(raw) == size, 'UNIT_BOUND')
        if check_hashes:
            need(hashlib.sha256(raw).hexdigest() == pin, 'UNIT_PIN')
        if name not in ('resultTable', 'hashInfo', 'hashUnwind', 'hashTry', 'hashCatch'):
            units = list(_decoder().disasm(raw, rva))
            need(sum(i.size for i in units) == size, 'UNIT_DECODE')
            instructions[name] = units
            rows.update({i.address: (i.mnemonic, i.op_str) for i in units})
    cfg = {name: local_cfg(bodies[name], SPANS[name][1]) for name in ('execute', 'stockCaller', 'hashInsert', 'copyGuid')}
    need(cfg['execute']['returns'] == ['0x10'] and cfg['hashInsert']['returns'] == ['0xc', '0xc'], 'STACK_POP')
    need(struct.unpack('<12I', bodies['resultTable'])[11] == BASE + 0x137da0, 'RESULT_SLOT11')
    anchors = {
        0x141c58: ('call', '0xc1420'),
        0x141c67: ('push', '1'), 0x141c69: ('push', 'dword ptr [0x260ed778]'),
        0x141c71: ('push', '0'), 0x141c73: ('push', 'eax'),
        0x141c74: ('call', 'dword ptr [ecx + 0x2c]'),
        0x141c8f: ('call', 'dword ptr [eax + 8]'),
        0x137dc7: ('mov', 'esi, dword ptr [ebp + 8]'),
        0x137e53: ('push', 'dword ptr [ebp + 0x14]'),
        0x137e5e: ('call', '0x8ffec0'),
        0x137e83: ('cmp', 'byte ptr [ebp + 0xc], 0'), 0x137e92: ('je', '0x137e9e'),
        0x137e94: ('cmp', 'byte ptr [ebp + 0x14], 0'),
        0x137e9e: ('mov', 'byte ptr [ebp + 0x10], 1'),
        0x137ecd: ('push', 'dword ptr [ebp + 0x10]'), 0x137ed0: ('call', '0x1431b0'),
        0x137f2c: ('cmp', 'byte ptr [ebp + 0xc], 0'), 0x137f30: ('je', '0x137f38'),
        0x137f32: ('cmp', 'byte ptr [ebp + 0x14], 0'),
        0x137f3f: ('cmp', 'byte ptr [ebp + 0x14], 0'), 0x137f43: ('je', '0x137f50'),
        0x137f4b: ('call', '0x13b2e0'), 0x137f50: ('cmp', 'byte ptr [ebp + 0xc], 0'),
        0x137f54: ('je', '0x137f5e'), 0x137f59: ('call', '0x141f40'),
        0x900689: ('call', '0x901390'),
        0x90068e: ('mov', 'ecx, dword ptr [ebp + 0x10]'),
        0x900691: ('movups', 'xmm0, xmmword ptr [ecx]'),
        0x900694: ('movups', 'xmmword ptr [eax + 8], xmm0'),
        0x900011: ('push', 'dword ptr [ebp + 0xc]'),
        0x90002f: ('call', '0xb1366e'),
    }
    need(all(rows.get(at) == expected for at, expected in anchors.items()), 'EXACT_FLAG_FLOW')
    # A local use/address of the forwarded third word would invalidate the
    # equivalence argument. Check every decoded operand, including catch body.
    need(_stack_offsets(instructions['hashInsert']) == [8, 12]
         and _stack_offsets(instructions['hashCatchBody']) == [8, 12], 'FORWARDED_WORD_UNUSED')
    need(struct.unpack('<9I', bodies['hashInfo']) ==
         (0x19930522, 4, BASE + 0xc835e4, 1, BASE + 0xc83604, 0, 0, 0, 1), 'EH_INFO')
    need(struct.unpack('<8I', bodies['hashUnwind']) == (0xffffffff, 0) * 4, 'EH_UNWIND')
    need(struct.unpack('<5I', bodies['hashTry']) == (2, 2, 3, 1, BASE + 0xc83618)
         and struct.unpack('<4I', bodies['hashCatch']) == (0x40, 0, 0, BASE + 0x900011), 'CATCH_ALL_RETHROW')
    need(rows.get(0xb16fb1) == ('mov', 'eax, ' + hex(BASE + 0xc835c0))
         and rows.get(0xb16fb6) == ('jmp', '0xb13644'), 'EH_LINK')
    return dict(kind='COMPARISON_HEADLESS_EXECUTE_PRIMARY', localCfg=cfg,
                executeVirtualByteOffset=0x2c, executeRva=0x137da0, executeStackPopBytes=16,
                explicitStackWords=['self', 'mode', 'scopeGuidPointer', 'showView'],
                candidateCallingConvention='x86_stdcall_COM_explicit_self',
                candidateReturnValue='void_or_ignored_not_success_indicator',
                stockMode=0, stockShowView=1, candidateMode=0, candidateShowView=0,
                forwardedHashThirdWordUnusedNormalAndCatch=True, hashKeyBytes=16,
                modeZeroSelectAll=1, modeZeroComputeInputsUnchangedByShowFlag=True,
                showZeroSkipsPostComputeView=True, modeZeroSkipsOtherPostAction=True,
                uiBoundExistingResultReuseAllowed=False, freshResultOwnershipVerified=False,
                sourceModelsInitializationVerified=False, publicResultSdkSignatureVerified=False,
                runtimeHeadlessVerified=False, errorFreeEpochVerified=False,
                nativePermit=False, databaseUpdateAuthorized=False,
                nextRequired=['Independently acquire and initialize a new owned result, excluding every old UI-bound result.',
                              'Bind runtime table/ABI/source roles and retain ownership through fresh headless epoch/tree reads.',
                              'Keep typed ListStream blocking; a zero completion code is not an error-free epoch.'])


def verify_primary():
    for path, pin in PINS.items():
        need(hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'PARENT_PIN')
    images = {name: PE(name) for name in ('frntend.dll', 'config.dll')}
    bodies = {}
    for name, (module, rva, size, _) in SPANS.items():
        image = images[module]; start = image.offset(image.base + rva)
        bodies[name] = image.data[start:start + size]
    return verify_units(bodies), bodies
