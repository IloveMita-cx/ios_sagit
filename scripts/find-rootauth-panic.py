#!/usr/bin/env python3
"""Locate the 'rootvp not authenticated after mounting' panic call in a
stripped arm64 kernelcache and emit a kernelcache_patcher patch list that
NOPs the BL to _panic, so a release kernel keeps booting with an unsealed
APFS root instead of panicking.

No external dependencies; decodes AArch64 ADRP/BL by hand.
"""
import struct
import sys
from pathlib import Path

NOP = 0xD503201F  # AArch64 NOP


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
        raise ValueError('not a 64-bit Mach-O')
    ncmds = u32(data, 16)
    off = 32
    segments = []
    for _ in range(ncmds):
        cmd = u32(data, off)
        cmdsize = u32(data, off + 4)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].split(b'\0')[0].decode()
            vmaddr = u64(data, off + 24)
            fileoff = u64(data, off + 40)
            filesize = u64(data, off + 48)
            nsects = u32(data, off + 64)
            sect_off = off + 72
            sections = []
            for _ in range(nsects):
                sectname = data[sect_off:sect_off + 16].split(b'\0')[0].decode()
                s_addr = u64(data, sect_off + 32)
                s_size = u64(data, sect_off + 40)
                s_off = u32(data, sect_off + 48)
                sections.append((sectname, s_addr, s_size, s_off))
                sect_off += 80
            segments.append((segname, fileoff, filesize, sections))
        off += cmdsize
    return segments


def find_string(data, segments, needle):
    for _, _, _, sections in segments:
        for sectname, s_addr, s_size, s_off in sections:
            if sectname in ('__cstring', '__const'):
                idx = data[s_off:s_off + s_size].find(needle)
                if idx >= 0:
                    return s_addr + idx
    return None


def find_bl_after_adrp(data, segments, string_addr):
    string_page = string_addr & ~0xFFF
    for _, _, _, sections in segments:
        for sectname, s_addr, s_size, s_off in sections:
            if sectname not in ('__text', '__TEXT_EXEC', '__text_exec'):
                continue
            for i in range(0, s_size - 3, 4):
                insn = u32(data, s_off + i)
                if (insn & 0x9F000000) != 0x90000000:  # ADRP
                    continue
                immlo = (insn >> 29) & 0x3
                immhi = (insn >> 5) & 0x7FFFF
                imm = sign_extend((immhi << 2) | immlo, 21)
                adrp_addr = s_addr + i
                target = (adrp_addr & ~0xFFF) + (imm << 12)
                if target != string_page:
                    continue
                # ADRP found; the BL _panic is a few instructions ahead.
                for j in range(1, 12):
                    bl_addr = adrp_addr + j * 4
                    if bl_addr >= s_addr + s_size:
                        break
                    bl = u32(data, s_off + i + j * 4)
                    if (bl & 0xFC000000) == 0x94000000:  # BL
                        return bl_addr
    return None


def main():
    kernel = Path(sys.argv[1])
    data = kernel.read_bytes()
    segments = parse_macho(data)
    needle = b'rootvp not authenticated after mounting\0'
    string_addr = find_string(data, segments, needle)
    if string_addr is None:
        print('ERROR: string not found', file=sys.stderr)
        return 1
    print(f'string @ 0x{string_addr:x}')
    bl_addr = find_bl_after_adrp(data, segments, string_addr)
    if bl_addr is None:
        print('ERROR: panic BL not found', file=sys.stderr)
        return 1
    print(f'panic BL @ 0x{bl_addr:x}')
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else kernel.with_suffix('.rootauth.patch')
    out.write_text(f'*0x{bl_addr:x}:\n+{NOP:x}\n')
    print(f'patch list written to {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
