#!/usr/bin/env python3
"""Locate the 'IODFB: driver' panic in the stripped arm64 kernelcache and
dump the surrounding function disassembly so the exact property check can be
read. Minimal hand-written AArch64 decoder, no external dependencies."""
import struct
import sys
from pathlib import Path

def u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]
def u64(buf, off):
    return struct.unpack_from('<Q', buf, off)[0]
def sign_extend(v, bits):
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v

def parse_macho(data):
    magic = u32(data, 0)
    if magic not in (0xFEEDFACF, 0xCFFAEDFE):
        raise ValueError('not 64-bit Mach-O')
    ncmds = u32(data, 16)
    off = 32
    segments = []
    for _ in range(ncmds):
        cmd = u32(data, off); cmdsize = u32(data, off + 4)
        if cmd == 0x19:
            segname = data[off+8:off+24].split(b'\0')[0].decode()
            vmaddr = u64(data, off+24); fileoff = u64(data, off+40)
            filesize = u64(data, off+48); nsects = u32(data, off+64)
            sect_off = off + 72; sections = []
            for _ in range(nsects):
                nm = data[sect_off:sect_off+16].split(b'\0')[0].decode()
                s_addr = u64(data, sect_off+32); s_size = u64(data, sect_off+40)
                s_off = u32(data, sect_off+48)
                sections.append((nm, s_addr, s_size, s_off))
                sect_off += 80
            segments.append((segname, fileoff, filesize, sections))
        off += cmdsize
    return segments

def find_string(data, segments, needle):
    for _, _, _, sections in segments:
        for nm, s_addr, s_size, s_off in sections:
            idx = data[s_off:s_off+s_size].find(needle)
            if idx >= 0:
                return s_addr + idx, nm, s_off + idx
    return None, None, None

def dump_near_strings(data, file_off):
    lo = max(0, file_off - 96); hi = min(len(data), file_off + 160)
    blob = data[lo:hi]
    print(f'--- nearby bytes around string (offset {file_off}) ---')
    print(blob)
    return

def disasm(insn, addr):
    # returns (opcode_text, is_branch)
    b = lambda n: (insn >> n) & 1
    def reg(n):
        return 'x%d' % ((insn >> n) & 0x1f)
    # ADRP
    if (insn & 0x9F000000) == 0x90000000:
        immlo = (insn >> 29) & 0x3; immhi = (insn >> 5) & 0x7FFFF
        imm = sign_extend((immhi << 2) | immlo, 21)
        return 'ADRP %s, 0x%x' % (reg(0), (addr & ~0xFFF) + (imm << 12)), False
    # ADD (immediate) rd, rn, #imm
    if (insn & 0xFF800000) == 0x91000000:
        imm = (insn >> 10) & 0xFFF; shift = (insn >> 22) & 0x3
        return 'ADD %s, %s, #0x%x' % (reg(0), reg(5), imm << (shift*12)), False
    # LDR literal
    if (insn & 0xFF000000) == 0x58000000:
        imm = sign_extend((insn >> 5) & 0x7FFFF, 19)
        return 'LDR %s, [pc+0x%x]' % (reg(0), imm << 2), False
    # LDR register (base+imm)
    if (insn & 0xFFC00000) == 0xF9400000:
        imm = ((insn >> 10) & 0xFFF) * (8 if b(30) else 1)
        return 'LDR %s, [%s, #0x%x]' % (reg(0), reg(5), imm), False
    # STR register
    if (insn & 0xFFC00000) == 0xF9000000:
        imm = ((insn >> 10) & 0xFFF) * 8
        return 'STR %s, [%s, #0x%x]' % (reg(0), reg(5), imm), False
    # MOVZ
    if (insn & 0x7F800000) == 0x52800000:
        imm = (insn >> 5) & 0xFFFF; shift = (insn >> 21) & 0x3
        return 'MOVZ %s, #0x%x' % (reg(0), imm << (shift*16)), False
    # CMP (subs immediate) / SUB
    if (insn & 0xFF800000) == 0xD1000000:
        imm = (insn >> 10) & 0xFFF
        return 'SUB %s, %s, #0x%x' % (reg(0), reg(5), imm), False
    # CMP register (subs xzr)
    if (insn & 0xFFC00000) == 0xEB000000:
        return 'CMP %s, %s' % (reg(5), reg(16)), False
    # B / BL
    if (insn & 0x7C000000) == 0x14000000:
        imm = sign_extend(insn & 0x03FFFFFF, 26)
        op = 'BL' if b(31) else 'B'
        return '%s 0x%x' % (op, addr + (imm << 2)), True
    # CBZ / CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        imm = sign_extend(((insn >> 5) & 0x7FFFF), 19)
        op = 'CBNZ' if b(24) else 'CBZ'
        return '%s %s, 0x%x' % (op, reg(0), addr + (imm << 2)), True
    # TBNZ / TBZ
    if (insn & 0x7E000000) == 0x36000000:
        bit = b(31) << 5 | ((insn >> 19) & 0x1f)
        imm = sign_extend((insn >> 5) & 0x3FFF, 14)
        op = 'TBNZ' if b(24) else 'TBZ'
        return '%s %s, #%d, 0x%x' % (op, reg(0), bit, addr + (imm << 2)), True
    # RET
    if insn == 0xD65F03C0:
        return 'RET', True
    # STP/LDP (x29/x30 style)
    if (insn & 0xFFC00000) == 0xA9800000:
        return 'STP %s, %s, [%s, #0x%x]' % (reg(0), reg(10), reg(5), ((insn>>15)&0x7f)<<3), False
    if (insn & 0xFFC00000) == 0xA9400000:
        return 'LDP %s, %s, [%s, #0x%x]' % (reg(0), reg(10), reg(5), ((insn>>15)&0x7f)<<3), False
    return 'insn 0x%08x' % insn, False

def main():
    kernel = Path(sys.argv[1])
    data = kernel.read_bytes()
    segments = parse_macho(data)
    # try several needles; the panic string is '"DISPLAY DRIVER FAILED TO LOAD" @%s:%d' (leading quote)
    for needle in (b'"DISPLAY DRIVER FAILED TO LOAD', b'DRIVER FAILED TO LOAD', b'IOMFB: driver commit'):
        addr, sect, fileoff = find_string(data, segments, needle)
        if addr is not None:
            print(f'FOUND "{needle.decode()}" @ 0x{addr:x} ({sect}) fileoff {fileoff}')
            dump_near_strings(data, fileoff)
            break
    else:
        print('ERROR: none of IODFB/IOBootFramebuffer found', file=sys.stderr)
        return 1
    # find ADRP xN,page + ADD xN,xN,#lo12 that resolves to the EXACT string address
    string_page = addr & ~0xFFF
    string_lo = addr & 0xFFF
    text = [(s_off, s_addr, s_size) for _,_,_,sections in segments for nm,s_addr,s_size,s_off in sections if nm in ('__text','__TEXT_EXEC','__text_exec')]
    xref = None
    for s_off, s_addr, s_size in text:
        for i in range(0, s_size - 3, 4):
            insn = u32(data, s_off + i)
            if (insn & 0x9F000000) != 0x90000000:  # ADRP
                continue
            rd = insn & 0x1f
            immlo = (insn >> 29) & 0x3; immhi = (insn >> 5) & 0x7FFFF
            imm = sign_extend((immhi << 2) | immlo, 21)
            if ((s_addr + i) & ~0xFFF) + (imm << 12) != string_page:
                continue
            # must be followed by ADD r?, <adrp_rd>, #string_lo (exact string; the dest register may differ)
            for j in range(1, 8):
                insn2 = u32(data, s_off + i + j*4)
                if (insn2 & 0xFF800000) == 0x91000000 and ((insn2 >> 5) & 0x1f) == rd:
                    add_imm = (insn2 >> 10) & 0xFFF
                    if add_imm == string_lo:
                        xref = (s_off, s_addr, s_size, i)
                        break
            if xref: break
        if xref: break
    if xref is None:
        print('ERROR: no xref found', file=sys.stderr)
        return 1
    s_off, s_addr, s_size, i = xref
    print(f'ADRP xref @ 0x{s_addr+i:x}')
    # find the panic wrapper start (scan back for the SUB sp prologue)
    wrap = s_addr + i
    for k in range(i, max(0, i - 16), -4):
        insn = u32(data, s_off + k)
        if (insn & 0xFFC003FF) == 0xD10003FF:  # SUB sp, sp, #imm
            wrap = s_addr + k
            break
    print(f'panic wrapper start @ 0x{wrap:x}')
    # find the caller: any BL to the wrapper
    caller = None
    for t_off, t_addr, t_size in text:
        for j in range(0, t_size - 3, 4):
            insn = u32(data, t_off + j)
            if (insn & 0xFC000000) == 0x94000000:
                imm = sign_extend(insn & 0x03FFFFFF, 26)
                if (t_addr + j) + (imm << 2) == wrap:
                    caller = (t_off, t_addr, t_size, j)
                    break
        if caller: break
    if caller is None:
        print('ERROR: no caller BL found', file=sys.stderr)
        return 1
    t_off, t_addr, t_size, j = caller
    print(f'caller BL @ 0x{t_addr+j:x}')
    start = max(0, j - 60*4); end = min(t_size, j + 20*4)
    for m in range(start, end, 4):
        insn = u32(data, t_off + m)
        txt, _ = disasm(insn, t_addr + m)
        mark = '   <== BL panic' if m == j else ''
        print(f'0x{t_addr+m:016x}: {insn:08x}  {txt}{mark}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
