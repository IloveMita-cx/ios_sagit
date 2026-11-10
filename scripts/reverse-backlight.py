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
# imageOffset values from D:\\hackios\\crash-preboard\\data.bin (imageIndex 2)
INIT_OFF = 0x89E0    # 35296  -[BLSHBacklightOSInterfaceProvider initWithPlatformProvider:]
COLD_OFF = 0x5C96C   # 379244 -[BLSHBacklightOSInterfaceProvider initWithPlatformProvider:].cold.1


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
        for name, off, size in [('initWithPlatformProvider', INIT_OFF, 0x800),
                                ('cold1', COLD_OFF, 0x400)]:
            data = cache.read(base + off, size)
            (out / f'{name}.bin').write_bytes(data)
            dump(data, base + off, out / f'{name}.disasm.txt')
            report[name] = {'va': hex(base + off), 'bytes': size, 'sha256': digest(data).hex()}
        (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    finally:
        image.close()


if __name__ == '__main__':
    main()
