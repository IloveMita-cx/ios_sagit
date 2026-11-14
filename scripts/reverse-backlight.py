#!/usr/bin/env python3
"""Reverse the PreBoard backlight provider assertion in BacklightServicesHost.

Reads the original 22H374 shared cache straight from the SystemOS Cryptex and
disassembles the two frames from the PreBoard crash log:
  -[BLSHBacklightOSInterfaceProvider initWithPlatformProvider:]
  -[BLSHBacklightOSInterfaceProvider initWithPlatformProvider:].cold.1
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

from apfs_sealed import SealedImage, digest
from baseband_dyld import Cache, Files

ROOT = Path(__file__).resolve().parents[1]
BLSH = '/System/Library/PrivateFrameworks/BacklightServicesHost.framework/BacklightServicesHost'
# imageOffset values from the PreBoard .ips (imageIndex 2). INIT_OFF is the
# return address recorded in frame 1, not the symbol start: the crash report's
# symbolLocation (2132 = 0x854) puts -[BLSHBacklightOSInterfaceProvider
# initWithPlatformProvider:] at 0x818C. Sampling starts there so the leading
# conditionals that branch into .cold.1 are included.
FUNC_OFF = 0x818C    # -[BLSHBacklightOSInterfaceProvider initWithPlatformProvider:] symbol start
INIT_OFF = 0x89E0    # 35296  frame 1 recorded return address (FUNC_OFF + 0x854)
COLD_OFF = 0x5C96C   # 379244 brk inside .cold.1 (.cold.1 starts at 0x5C894)


def load_iodfb():
    spec = importlib.util.spec_from_file_location('iodfb', ROOT / 'scripts/find-iodfb-panic.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dump(data, base, out):
    iodfb = load_iodfb()
    lines = []
    for i in range(0, len(data) - 3, 4):
        insn = struct.unpack_from('<I', data, i)[0]
        lines.append(f'{base + i:#x}: {insn:08x}  {iodfb.disasm(insn, base + i)}')
    out.write_text('\n'.join(lines) + '\n')


# String addresses referenced by ADRP+ADD in the disassembly (assertion messages / file:line).
STRING_ADDRS = [
    0x2172A2000,   # ADRP x0 -> _bs_set_crash_log_message format
    0x21732FEFE, 0x21732FECF, 0x21732F9B6, 0x2173300B4, 0x21732FF4E,
    0x217329B31,
]


def cstring(cache, addr, maxlen=1024):
    data = cache.read(addr, maxlen)
    end = data.find(b'\0')
    return data[:end if end >= 0 else maxlen].decode('utf8', 'replace')


def dump_strings(cache, out):
    lines = []
    for addr in STRING_ADDRS:
        try:
            lines.append(f'{addr:#x}: {cstring(cache, addr)!r}')
        except Exception as exc:  # noqa: BLE001
            lines.append(f'{addr:#x}: <read failed: {exc}>')
    (out / 'strings.txt').write_text('\n'.join(lines) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'build/apfs/firmware/094-33089-038.dmg')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/backlight-reverse')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)

    decoder = out / 'libzbitmap.so'
    subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-I', str(ROOT / 'tools/src/apfsprogs/include'),
                    str(ROOT / 'tools/src/apfsprogs/lib/libzbitmap.c'), '-o', str(decoder)], check=True)

    image = SealedImage(args.source)
    try:
        cache = Cache(Files(image, decoder))
        base = cache.images[BLSH]
        report = {'path': BLSH, 'base': hex(base)}
        # Sample from the confirmed symbol start (0x818C), not from the recorded
        # return address, so every branch that can reach .cold.1 is covered.
        # .cold.1 itself starts at 0x5C894; take a little before it too.
        windows = [
            ('initWithPlatformProvider', FUNC_OFF, 0xB00, INIT_OFF),
            ('cold1', COLD_OFF - 0x300, 0x700, COLD_OFF),
        ]
        for name, start, span, frame in windows:
            data = cache.read(base + start, span)
            (out / f'{name}.bin').write_bytes(data)
            dump(data, base + start, out / f'{name}.disasm.txt')
            report[name] = {'va': hex(base + start), 'frame_va': hex(base + frame),
                            'bytes': span, 'sha256': digest(data).hex()}
        (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        dump_strings(cache, out)
        print(json.dumps(report, indent=2))
    finally:
        image.close()


if __name__ == '__main__':
    main()
