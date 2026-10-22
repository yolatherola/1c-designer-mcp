"""Static, hash-pinned Core.As/Snegopat SDK inspection. Never loads a DLL."""
from pathlib import Path
import argparse
import hashlib
import struct
import sys

PINNED = {
    'core_as.dll': '7867174add6fb4f52b8b8c9288c1daea2193fc679621d773a6d355d780d30541',
    'snegopat.dll': 'f348e965eacd90b94a1c51a2cde6f510038d313665c66a67a300e60a6aaa3c32',
}

class Image:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        if hashlib.sha256(self.data).hexdigest() != PINNED[Path(path).name]:
            raise ValueError('SDK_HASH_REJECTED')
        d = self.data
        nt = self.u32(0x3c)
        if d[:2] != b'MZ' or d[nt:nt+4] != b'PE\0\0' or self.u16(nt+4) != 0x14c or self.u16(nt+24) != 0x10b:
            raise ValueError('SDK_PE32_REJECTED')
        opt = nt+24
        self.base = self.u32(opt+28)
        self.sections = []
        for i in range(self.u16(nt+6)):
            p = opt+self.u16(nt+20)+40*i
            vs, rva, size, raw = struct.unpack_from('<IIII',d,p+8)
            if raw+size > len(d): raise ValueError('SDK_SECTION_BOUNDS')
            self.sections.append((rva,size,raw))
        self.export_rva = self.u32(opt+96)

    def u16(self, p): return struct.unpack_from('<H',self.data,p)[0]
    def u32(self, p): return struct.unpack_from('<I',self.data,p)[0]
    def offset(self,rva):
        for start,size,raw in self.sections:
            if start <= rva < start+size: return raw+rva-start
        raise ValueError('SDK_RVA_REJECTED')
    def exports(self):
        p=self.offset(self.export_rva)
        count=self.u32(p+24)
        if count>10000: raise ValueError('SDK_EXPORT_BOUND')
        functions=self.offset(self.u32(p+28))
        names=self.offset(self.u32(p+32))
        ordinals=self.offset(self.u32(p+36))
        for i in range(count):
            a=self.offset(self.u32(names+4*i)); end=self.data.index(b'\0',a,a+512)
            yield self.data[a:end].decode('ascii'),self.u32(functions+4*self.u16(ordinals+2*i))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('image');p.add_argument('--deps');p.add_argument('--rva',type=lambda x:int(x,0));p.add_argument('--bytes',type=int,default=160)
    a=p.parse_args();image=Image(a.image)
    if a.rva is None:
        for name,rva in image.exports(): print(hex(rva),name)
        return
    if not 1<=a.bytes<=4096: raise ValueError('SDK_DISASSEMBLY_BOUND')
    if a.deps: sys.path.insert(0,a.deps)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    raw=image.offset(a.rva)
    for ins in Cs(CS_ARCH_X86,CS_MODE_32).disasm(image.data[raw:raw+a.bytes],image.base+a.rva):
        print(hex(ins.address-image.base),ins.mnemonic,ins.op_str)

if __name__=='__main__': main()
