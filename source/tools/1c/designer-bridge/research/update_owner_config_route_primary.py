"""Resolve fixed Config29 dispatch statically, never execute a platform method.

The bounded interpreter follows the actual command through the complete
dispatcher. External calls on this path are only the pinned CmdID comparator;
the update adapter is a stopping point, not a function this module invokes.
Runtime owner binding and permission to update remain separate evidence.
"""
import hashlib
import struct
import uuid
from repository_pe_probe import PE
from current_comparison_factory_primary import _decoder, local_cfg

BASE = 0x25e40000
GROUP = 'f10cbb81-f679-11d4-9dd3-0050bae2bc79'
COMMAND = uuid.UUID(GROUP).bytes_le + struct.pack('<I', 29)
PLATFORM_SHA = '5579c1f48bf8fa512fbb87d04603b871a204e48be67ad7868bc7b51749391219'
SPANS = {
    'execute': (0x142c80, 58, 'f64e306b517a543110bb8b1d063864751e889a614616e58c9ad3c0eda69d853b'),
    'dispatcher': (0xa3170, 3913, '7471cc738d5c610b5ca8d64453425da67913b4d109670761a08a3c4381170c76'),
    'adapter': (0xa11d0, 167, 'f03bc21a676aeeab21a034bcbc907c76fc9a76a5a03e9439b533ececb313a250'),
    'thunk': (0x141bf0, 16, '4c9d343b7f265672cc3cf507f36a0920ab94baaf63412877d91cee1fd13e9251'),
    'equal': (0x19600, 66, 'e9a3b941974142ce136d97127ea97a7dd42a4a660564cc481697310e5d6096bb'),
    'keys': (0x340228, 1000, 'adad8eb836dd929b2e9683a5a72c133dab8a1453cc45834c630e8e9c2b274517'),
    'key137': (0x33fe68, 20, 'c88a5f67e9cdff95202a04a312c38c3a925bb5c9288cfebb23c78515b06c1a88'),
    'key260': (0x341088, 20, '2e90b7b7cad9ebb5ce4c521cc5e516488aef21e2a3a1982b3f33dba23f4bddab'),
    'targetTable': (0x2b945c, 24, '69b20a33a924e88afa60f404915f2b8cfb92222a5bc215782c39ecfe4bf89613'),
    'modeTable': (0x2b9568, 28, '6b7dce7e7fcdf5234840d13b9d13b01d7e257dd93f0f7748244822d9c76cca01')}


def need(ok, code):
    if not ok: raise ValueError('CONFIG29_ROUTE_' + code)


def trace_dispatch(rows, keys, *, extra_keys=None, command=COMMAND, maximum_steps=2048):
    """Interpret only a finite fixed normal path with known register bits.

    Synthetic addresses model arguments and stack. No process memory is read.
    Unknown instructions, reads, flag uses, callees, or frame changes refuse.
    """
    from capstone.x86_const import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    need(type(command) is bytes and len(command) == 20, 'COMMAND')
    extra_keys = {} if extra_keys is None else extra_keys
    need(type(keys) is bytes and len(keys) == 1000 and type(extra_keys) is dict
         and all(type(rva) is int and type(raw) is bytes and len(raw) == 20 for rva, raw in extra_keys.items()), 'KEY_INPUT')
    need(type(maximum_steps) is int and 1 <= maximum_steps <= 2048, 'STEP_BOUND')
    frame, command_at, canonical, stack = 0x71001000, 0x71002000, 0x71003000, 0x71000f00
    registers = {k: (0, 0) for k in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi')}
    registers.update(ebp=(frame, 0xffffffff), esp=(stack, 0xffffffff), ecx=(canonical, 0xffffffff))
    memory = {frame + 8: 0, frame + 12: command_at, frame + 16: command_at}
    zero, trace, comparisons = None, [], []

    def reg(name):
        parent, mask = ('eax', 255) if name == 'al' else (name, 0xffffffff)
        need(parent in registers and registers[parent][1] & mask == mask, 'UNKNOWN_REGISTER')
        return registers[parent][0] & mask

    def set_reg(name, value):
        parent, mask = ('eax', 255) if name == 'al' else (name, 0xffffffff)
        need(parent in registers, 'REGISTER_NAME')
        previous, known = registers[parent]
        registers[parent] = ((previous & ~mask | value & mask) & 0xffffffff, known | mask)

    def read(address, size):
        chunks = [(command_at, command), (BASE + SPANS['keys'][0], keys)]
        chunks.extend((BASE + rva, raw) for rva, raw in extra_keys.items())
        for start, body in chunks:
            if start <= address and address + size <= start + len(body):
                return int.from_bytes(body[address - start:address - start + size], 'little')
        need(size == 4 and address in memory, 'UNKNOWN_MEMORY')
        return memory[address]

    def address(ins, operand):
        item = operand.mem
        need(not item.segment and not item.index, 'MEMORY_ADDRESS')
        return ((reg(ins.reg_name(item.base)) if item.base else 0) + item.disp) & 0xffffffff

    def value(ins, operand):
        if operand.type == X86_OP_REG: return reg(ins.reg_name(operand.reg))
        if operand.type == X86_OP_IMM: return operand.imm & 0xffffffff
        need(operand.type == X86_OP_MEM, 'OPERAND')
        return read(address(ins, operand), operand.size)

    def store(ins, operand, number):
        if operand.type == X86_OP_REG:
            set_reg(ins.reg_name(operand.reg), number); return
        need(operand.type == X86_OP_MEM and operand.size == 4, 'STORE_OPERAND')
        target = address(ins, operand)
        need(frame - 0x100 <= target < frame, 'NONLOCAL_STORE')
        memory[target] = number & 0xffffffff

    at = 0xa319b
    for _ in range(maximum_steps):
        need(at in rows and 0xa319b <= at < 0xa40b9, 'PATH_ADDRESS')
        ins = rows[at]; trace.append(at); operands = ins.operands
        if at == 0xa321b:
            need(ins.mnemonic == 'call' and value(ins, operands[0]) == 0xa11d0, 'ADAPTER_CALL')
            need(reg('ecx') == canonical and reg('edx') == command_at, 'CANONICAL_TRANSFER')
            need(read(reg('esp'), 4) == BASE + 0x141bf0 and read(reg('esp') + 4, 4) == 0, 'THUNK_ARGUMENTS')
            need(comparisons and comparisons[-1] == 0x340458 and 0xa3ad8 in trace, 'EXACT_UPDATE_BRANCH')
            return dict(instructions=len(trace), traceRvas=trace, equalCalls=len(comparisons),
                        comparedRecordRvas=comparisons, canonicalPreserved=True,
                        thunkRva=0x141bf0, thisAdjustment=0, stoppedBeforeAdapter=True)
        following = at + ins.size
        if ins.mnemonic == 'mov': store(ins, operands[0], value(ins, operands[1]))
        elif ins.mnemonic in ('xor', 'or', 'sub', 'add', 'and'):
            left, right = value(ins, operands[0]), value(ins, operands[1])
            answer = {'xor': lambda: left ^ right, 'or': lambda: left | right,
                      'sub': lambda: left - right, 'add': lambda: left + right,
                      'and': lambda: left & right}[ins.mnemonic]() & 0xffffffff
            store(ins, operands[0], answer); zero = answer == 0
        elif ins.mnemonic in ('cmp', 'test'):
            left, right = value(ins, operands[0]), value(ins, operands[1])
            zero = left == right if ins.mnemonic == 'cmp' else left & right == 0
        elif ins.mnemonic == 'push':
            pushed = value(ins, operands[0]); set_reg('esp', reg('esp') - 4); memory[reg('esp')] = pushed
        elif ins.mnemonic == 'call':
            need(operands[0].type == X86_OP_IMM and operands[0].imm == 0x19600, 'UNCLASSIFIED_CALLEE')
            key = read(reg('esp'), 4); need(reg('ecx') == command_at, 'EQUAL_THIS')
            key_offset = key - BASE - SPANS['keys'][0]
            need((0 <= key_offset <= len(keys) - 20 and key_offset % 20 == 0) or key - BASE in extra_keys, 'EQUAL_KEY')
            equal = all(read(key + offset, 4) == read(command_at + offset, 4) for offset in range(0, 20, 4))
            comparisons.append(key - BASE); set_reg('esp', reg('esp') + 4)
            for name in ('eax', 'ecx', 'edx'): registers[name] = (0, 0)
            set_reg('al', int(equal)); zero = None
        elif ins.mnemonic in ('je', 'jne', 'jmp'):
            need(operands[0].type == X86_OP_IMM, 'INDIRECT_BRANCH')
            if ins.mnemonic != 'jmp': need(type(zero) is bool, 'UNKNOWN_FLAGS')
            if ins.mnemonic == 'jmp' or (zero if ins.mnemonic == 'je' else not zero): following = operands[0].imm
        else: need(False, 'UNSUPPORTED_INSTRUCTION')
        at = following
    need(False, 'STEP_EXHAUSTED')


def verify_units(bodies, *, check_hashes=True):
    need(type(bodies) is dict and set(bodies) == set(SPANS), 'UNIT_SET')
    for name, (_, size, pin) in SPANS.items():
        need(type(bodies[name]) is bytes and len(bodies[name]) == size, 'UNIT_BOUND')
        if check_hashes: need(hashlib.sha256(bodies[name]).hexdigest() == pin, 'UNIT_PIN')
    rows = {i.address: i for name, (rva, _, _) in SPANS.items()
            if name not in ('keys', 'key137', 'key260', 'targetTable', 'modeTable') for i in _decoder().disasm(bodies[name], rva)}
    def anchor(at, mnemonic, operand):
        need(at in rows and (rows[at].mnemonic, rows[at].op_str) == (mnemonic, operand), 'ROUTE_ANCHOR')
    for at, mnemonic, operand in (
        (0x142c8b,'mov','ecx, dword ptr [edi + 0x18]'), (0x142c96,'call','dword ptr [eax + 0xc]'),
        (0x142c9b,'je','0x142ca5'), (0x142ca8,'lea','ecx, [edi - 0x10]'),
        (0x142cad,'push','0'), (0x142caf,'mov','eax, dword ptr [eax + 0x18]'), (0x142cb2,'call','eax'),
        (0xa11fd,'mov','dword ptr [ebp - 0x18], ecx'), (0xa1228,'mov','ecx, dword ptr [ebp - 0x18]'),
        (0xa1234,'add','ecx, dword ptr [ebp + 0xc]'), (0xa1237,'call','dword ptr [ebp + 8]'),
        (0x141bf3,'mov','ecx, dword ptr [ecx + 0x24]'), (0x141bf8,'call','0xc1240')):
        anchor(at, mnemonic, operand)
    need(struct.unpack('<6I', bodies['targetTable'])[3] == BASE + 0x142c80, 'TARGET_TABLE')
    need(struct.unpack('<7I', bodies['modeTable'])[6] == BASE + 0xa3170, 'CANONICAL_TABLE')
    need(bodies['keys'][0x340458 - 0x340228:0x340458 - 0x340228 + 20] == COMMAND, 'UPDATE_KEY')
    need(sum(bodies['keys'][i:i+20] == COMMAND for i in range(0, 1000, 20)) == 1, 'DUPLICATE_UPDATE_KEY')
    cfg = {name: local_cfg(bodies[name], SPANS[name][0]) for name in ('execute', 'dispatcher', 'thunk', 'equal')}
    extras = {SPANS[name][0]: bodies[name] for name in ('key137', 'key260')}
    need(all(raw != COMMAND for raw in extras.values()), 'DUPLICATE_EXTRA_UPDATE_KEY')
    trace = trace_dispatch(rows, bodies['keys'], extra_keys=extras)
    return dict(kind='CONFIG29_FIXED_OWNER_ROUTE_PRIMARY', platformVersion='8.3.18.1208',
                platformSha256=PLATFORM_SHA, commandGroup=GROUP, commandId=29,
                targetToCanonicalOffset=-16, canonicalToOwnerOffset=36,
                requiresDelegateFalse=True, explicitTargetOnly=True,
                commandRecordCount=52, normalCfg=cfg, dispatchTrace=trace,
                ownerArgumentStaticallyVerified=True, runtimeOwnerBindingVerified=False,
                updateModeResolved=False, permissionChecksPassed=False,
                nativeCalls=0, databaseUpdateAuthorized=False)


def verify_primary():
    image = PE('config.dll'); need(image.base == BASE, 'IMAGE_BASE')
    bodies = {}
    for name, (rva, size, _) in SPANS.items():
        off = image.offset(BASE + rva); bodies[name] = image.data[off:off + size]
    return verify_units(bodies), bodies
