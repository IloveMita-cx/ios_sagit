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
from uuid import UUID

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


def rebased_target(cache, va, raw):
    # dyld_cache_header.mappingWithSlideOffset / Count.
    path = next(path for base, size, path, _ in cache.maps if base <= va < base + size)
    offset, count = struct.unpack('<II', cache.files.read(path, 312, 8))
    if not offset or not 0 < count <= 32:
        return None, None
    mappings = cache.files.read(path, offset, count * 56)
    for base, size, _, slide, slide_size, _, _, _ in struct.iter_unpack('<6Q2I', mappings):
        if not (base <= va < base + size and slide and slide_size >= 24):
            continue
        header = cache.files.read(path, slide, min(slide_size, 40))
        version, = struct.unpack_from('<I', header)
        if version == 2 and len(header) >= 40:
            mask, add = struct.unpack_from('<QQ', header, 24)
            value = raw & ~mask
            return version, value + add if value else 0
        if version == 3:
            if raw >> 63:
                add, = struct.unpack_from('<Q', header, 16)
                return version, add + (raw & 0xFFFFFFFF)
            return version, raw & ((1 << 43) - 1)
        if version == 5:
            add, = struct.unpack_from('<Q', header, 16)
            return version, add + (raw & ((1 << 34) - 1))
        return version, None
    return None, None


def dump_assertion_inputs(cache, out):
    # Addresses apply only to the cache and image validated by main().
    spans = {
        'message_stub': (0x21735BCA0, 0x30),
        'assertion_object_1': (0x2523D4698, 0x20),
        'assertion_object_2': (0x2523D46B8, 0x20),
        'ivar_offsets': (0x25ACEC41C, 0x08),
    }
    report = {}
    for name, (va, size) in spans.items():
        data = cache.read(va, size)
        (out / f'{name}.bin').write_bytes(data)
        report[name] = {'va': hex(va), 'bytes': size, 'raw': data.hex()}
    stub_va, stub_size = spans['message_stub']
    stub = cache.read(stub_va, stub_size)
    dump(stub, stub_va, out / 'message_stub.disasm.txt')

    # An arm64 ObjC message-send stub typically uses ADRP x1; LDR x1,[x1,...].
    # Record the storage address even if this stub uses a different layout.
    pages = {}
    text_inputs = {}
    for pos in range(0, len(stub), 4):
        word, = struct.unpack_from('<I', stub, pos)
        reg = word & 31
        if word & 0x9F000000 == 0x90000000:
            imm = ((word >> 29) & 3) | (((word >> 5) & 0x7FFFF) << 2)
            if imm & (1 << 20):
                imm -= 1 << 21
            pages[reg] = ((stub_va + pos) & ~0xFFF) + (imm << 12)
        elif word & 0xFFC00000 == 0xF9400000:
            base_reg = (word >> 5) & 31
            if reg == 1 and base_reg in pages:
                text_inputs[f'selector_ref_{pos:x}'] = pages[base_reg] + ((word >> 10) & 0xFFF) * 8
            pages.pop(reg, None)
    offsets = struct.unpack('<ii', cache.read(0x25ACEC41C, 8))
    report['ivar_offsets'].update(checked_field_offset=offsets[0], stored_field_offset=offsets[1])
    for name in ('assertion_object_1', 'assertion_object_2'):
        va, _ = spans[name]
        flags, chars, length = struct.unpack('<QQQ', cache.read(va + 8, 24))
        report[name].update(flags=hex(flags), raw_chars=hex(chars), length=length)
        text_inputs[name] = va + 16

    for name, va in text_inputs.items():
        raw, = struct.unpack('<Q', cache.read(va, 8))
        version, target = rebased_target(cache, va, raw)
        candidates = {'direct': raw}
        if target:
            candidates[f'slide_v{version}'] = target
        # Preserve a testable candidate if this mapping has no supported
        # rebase record. It is not a verified fixup.
        candidates['low_36_bits_candidate'] = raw & ((1 << 36) - 1)
        item = {'storage_va': hex(va), 'raw_pointer': hex(raw),
                'mapping_slide_version': version, 'candidates': []}
        for encoding, target in candidates.items():
            try:
                length = report.get(name, {}).get('length')
                if length is not None and 0 < length <= 1024:
                    chars = cache.read(target, length)
                    value = chars.decode('utf-8', errors='replace')
                    if not value.isprintable() or '\ufffd' in value:
                        value = cache.read(target, 2 * length).decode('utf-16-le')
                else:
                    value = cstring(cache, target, 256)
                if value and value.isprintable() and '\ufffd' not in value:
                    item['candidates'].append({'encoding': encoding, 'va': hex(target), 'text': value})
            except (ValueError, UnicodeError):
                continue
        report.setdefault('text_references', {})[name] = item
    (out / 'assertion-inputs.json').write_text(json.dumps(report, indent=2) + '\n')


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
        uuid = str(UUID(hex=cache.library(BLSH)['uuid']))
        if base != 0x2172A2000 or uuid != '0b42b93f-0246-3cd1-ab1a-68ce37f9b496':
            raise ValueError(f'Unexpected BacklightServicesHost: base={base:#x}, uuid={uuid}')
        report = {'path': BLSH, 'base': hex(base), 'uuid': uuid}
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
        dump_assertion_inputs(cache, out)
        print(json.dumps(report, indent=2))
    finally:
        image.close()


if __name__ == '__main__':
    main()
