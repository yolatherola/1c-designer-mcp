"""Read-only, hash-pinned PE32 repository API research for 8.3.18.1208.

Prints static addresses/instructions; never loads a platform DLL or calls it.
Capstone is supplied from the invocation's isolated dependency directory.
"""
import argparse
import hashlib
from pathlib import Path
import re
import struct
import sys
import uuid

PLATFORM = Path(r'C:\Program Files (x86)\1cv8\8.3.18.1208\bin')
HASHES = {
    '1cv8.exe': 'C49E36E4E1CA2F6DB2C1B51228161297FD79B42D3D0C6DD046551E06D0A51E12',
    'rclient.dll': '38FDABEF23D97C6C41320C8F8F39473B30403FA4AF744E568198D2E0A41B5AD0',
    'configshell.dll': '174B4DD3B54F287A0C06E61F97ACF08AD9FF27BFBDB08A3002D8BA97076638D2',
    'backend.dll': '498664A61CEE45D979BD4D8EACFDDF20E7510780DF52DAAEACD5314BCE22E739',
    'config.dll': '5579C1F48BF8FA512FBB87D04603B871A204E48BE67AD7868BC7B51749391219',
    'devtool.dll': 'DF0EE6F205BA6C11B9738BC89DF916DC997C6BB757EC393A463FE402C9F83EE2',
    'crcore.dll': '2AD43A6B27639A41CEAAFE6AB7E1EF23A4AE0785B793FD7A8C6B37F851A30FA0',
    'frntend.dll': '9556DEFC1CCD1CD8B05ED63D4B0287F40FAC2BCCBA42A68FC229927C8B5FC8A5',
    'frame.dll': 'F63271B8A15F9B36234B937153C44305FDF5D33C8A967FA8D24F61907DD6F418',
    'basic.dll': '1D6C1020B517BF19FEF2626ACE1BC0C2402F38D8993C192DA05E2B67404863A2',
    'txtedui.dll': 'A379297BFCFF186F456E260F8BD36102D3D723D422379734706F80A3F201962A',
    'txtedt.dll': '8B86B064895131589D760C49C2E4E88841486104B1B897F6BC3C4E0FF973CCB5',
    'core83.dll': '46E7019A142A01367D27C28B646CE8DEFEA54AD60AFE9FC467738B75C8663F14',
    'basicui.dll': 'E19126902CA7B0EE839C3492224F91A28D11000D3F1A74116443A21D2FAB2EA8',
    'mngbase.dll': 'EC0A815DF2A9A71E75C99A91E3FD076CB67F0A33AE866CAB3277881599E172C8',
    'mngcore.dll': 'DC5CB334612EDAD964A712DBCFBB2C206160125C5B2B7D0F63BD42341194B477',
    'mngdsgn.dll': 'B42DA7FE2F41C881587F51839CDA68D8D8D5A5AF815E8E87D41A2A76A4128FE3',
}


class PE:
    def __init__(self, name: str):
        if name not in HASHES:
            raise ValueError('PLATFORM_FILE_REJECTED')
        self.name = name
        self.data = (PLATFORM / name).read_bytes()
        if hashlib.sha256(self.data).hexdigest().upper() != HASHES[name]:
            raise ValueError('PLATFORM_HASH_REJECTED')
        d = self.data
        if d[:2] != b'MZ':
            raise ValueError('PE_REJECTED')
        nt = struct.unpack_from('<I', d, 0x3C)[0]
        if d[nt:nt+4] != b'PE\0\0' or struct.unpack_from('<H', d, nt+4)[0] != 0x14C:
            raise ValueError('PE32_REQUIRED')
        optional = nt+24
        if struct.unpack_from('<H', d, optional)[0] != 0x10B:
            raise ValueError('PE32_REQUIRED')
        size = struct.unpack_from('<H', d, nt+20)[0]
        self.base = struct.unpack_from('<I', d, optional+28)[0]
        self.sections = []
        for index in range(struct.unpack_from('<H', d, nt+6)[0]):
            at = optional+size+40*index
            section = d[at:at+8].rstrip(b'\0').decode('ascii')
            virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', d, at+8)
            if raw+raw_size > len(d):
                raise ValueError('PE_SECTION_REJECTED')
            self.sections.append((section, virtual_size, rva, raw_size, raw))

    def offset(self, va: int) -> int:
        for _, _, rva, raw_size, raw in self.sections:
            if rva <= va-self.base < rva+raw_size:
                return raw+va-self.base-rva
        raise ValueError('VA_OUTSIDE_FILE')

    def va(self, offset: int) -> int:
        for _, _, rva, raw_size, raw in self.sections:
            if raw <= offset < raw+raw_size:
                return self.base+rva+offset-raw
        raise ValueError('OFFSET_OUTSIDE_SECTIONS')

    def xrefs(self, va: int):
        needle = struct.pack('<I', va)
        for section, _, rva, raw_size, raw in self.sections:
            if section != '.text':
                continue
            for match in re.finditer(re.escape(needle), self.data[raw:raw+raw_size]):
                yield self.base+rva+match.start()

    def callers(self, target: int):
        # These are candidates until instruction-boundary disassembly confirms
        # them. An E8 byte can also occur in another instruction's immediate.
        for section, _, rva, raw_size, raw in self.sections:
            if section != '.text':
                continue
            code = self.data[raw:raw+raw_size]
            for match in re.finditer(b'\xe8', code[:-4]):
                pos = match.start()
                address = self.base+rva+pos
                if address+5+struct.unpack_from('<i', code, pos+1)[0] == target:
                    yield address

    def disassemble(self, va: int, length: int, dependencies: Path):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        offset = self.offset(va)
        engine = Cs(CS_ARCH_X86, CS_MODE_32)
        engine.skipdata = True
        for address, _, instruction, operands in engine.disasm_lite(self.data[offset:offset+length], va):
            print(hex(address), instruction, operands)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', choices=HASHES)
    parser.add_argument('--dependencies', type=Path, required=True)
    parser.add_argument('--string', action='append', default=[])
    parser.add_argument('--guid', action='append', default=[])
    parser.add_argument('--disasm', type=lambda value: int(value, 0), action='append', default=[])
    parser.add_argument('--calls-to', type=lambda value: int(value, 0), action='append', default=[])
    parser.add_argument('--pointers', type=lambda value: int(value, 0))
    parser.add_argument('--length', type=int, default=180)
    parser.add_argument('--limit', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.length <= 8192 or not 1 <= args.limit <= 40:
        raise SystemExit('OUTPUT_BOUND_REJECTED')
    sys.path.insert(0, str(args.dependencies.resolve()))
    pe = PE(args.dll)
    print('PE', pe.name, 'base', hex(pe.base), 'sha256', HASHES[pe.name])
    for key in args.string:
        needle = key.encode('ascii')+b'\0'
        matches = list(re.finditer(re.escape(needle), pe.data))
        for match in matches[:args.limit]:
            address = pe.va(match.start())
            refs = list(pe.xrefs(address))
            print('STRING', key, hex(address), 'candidate-xrefs', [hex(x) for x in refs])
            for at in refs[:args.limit]:
                pe.disassemble(at-1, args.length, args.dependencies)
    for text in args.guid:
        needle = uuid.UUID(text).bytes_le
        for match in list(re.finditer(re.escape(needle), pe.data))[:args.limit]:
            address = pe.va(match.start())
            print('GUID', text, hex(address), 'candidate-xrefs', [hex(x) for x in pe.xrefs(address)])
    for address in args.disasm:
        print('DISASM', hex(address))
        pe.disassemble(address, args.length, args.dependencies)
    for target in args.calls_to:
        callers = list(pe.callers(target))
        print('CALLERS', hex(target), [hex(x) for x in callers])
        for address in callers[:args.limit]:
            pe.disassemble(address-16, args.length, args.dependencies)
    if args.pointers is not None:
        offset = pe.offset(args.pointers)
        print('POINTERS', hex(args.pointers), [hex(x) for x in struct.unpack_from('<'+'I'*args.limit, pe.data, offset)])


if __name__ == '__main__':
    main()
