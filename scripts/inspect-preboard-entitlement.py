#!/usr/bin/env python3
"""Report the display-state entitlement embedded in the original PreBoard Mach-O."""
import ctypes
import hashlib
import json
import plistlib
from pathlib import Path
import struct
import sys
from uuid import UUID
import zlib

from macho_development_sign import signature_blobs

DISPLAY_STATE = 'com.apple.QuartzCore.display-state'
RUN_N_UUID = 'dfd2aed4-e2d8-3ac0-be34-9637b1042bd3'


def inspect(data):
    magic, cpu, _, _, count, size, _, _ = struct.unpack_from('<8I', data)
    if magic != 0xfeedfacf or cpu != 0x0100000c or 32 + size > len(data):
        raise ValueError('expected a thin arm64 Mach-O')
    pos = 32
    uuid = None
    signature = None
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', data, pos)
        if length < 8 or pos + length > 32 + size:
            raise ValueError('invalid load command')
        if cmd == 0x1b and length == 24:
            uuid = str(UUID(bytes=data[pos + 8:pos + 24]))
        if cmd == 0x1d and length == 16:
            offset, length_in_file = struct.unpack_from('<II', data, pos + 8)
            if length_in_file < 12 or offset + length_in_file > len(data):
                raise ValueError('invalid signature range')
            signature = data[offset:offset + length_in_file]
        pos += length
    if pos != 32 + size or uuid is None or signature is None:
        raise ValueError('missing UUID or code signature')
    blobs, _ = signature_blobs(signature)
    xml = blobs.get(5)
    der = blobs.get(7)
    entitlement = None
    if xml is not None:
        if xml[:4] != bytes.fromhex('fade7171'):
            raise ValueError('invalid XML entitlement slot')
        entitlement = plistlib.loads(xml[8:].rstrip(bytes(1))).get(DISPLAY_STATE)
    return {'macho_uuid': uuid, 'matches_run_n_uuid': uuid == RUN_N_UUID,
            'sha256': hashlib.sha256(data).hexdigest(), 'xml_slot_present': xml is not None,
            'xml_display_state': entitlement, 'der_slot_present': der is not None,
            'der_contains_display_state_key': der is not None and DISPLAY_STATE.encode() in der}


def read_extracted(path, decoder_path):
    if path.stat().st_size:
        return path.read_bytes()
    header = (path.parent / 'xattr_com.apple.decmpfs').read_bytes()
    magic, method, size = struct.unpack('<4sIQ', header)
    if magic != b'fpmc' or not 0 < size <= 8 * 1024 * 1024:
        raise ValueError('invalid exported decmpfs header')
    fork = (path.parent / 'xattr_com.apple.ResourceFork').read_bytes()
    count = (size + 65535) // 65536
    if method == 14:
        offsets = struct.unpack_from(f'<{count + 1}I', fork)
        if offsets[0] != 4 * (count + 1) or offsets[-1] != len(fork):
            raise ValueError('bad LZBITMAP resource table')
        spans = list(zip(offsets, offsets[1:]))
        decoder = ctypes.CDLL(str(decoder_path.resolve())).zbm_decompress
        decoder.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
        decoder.restype = ctypes.c_int
        limit = len(fork)
        previous = offsets[0]
    elif method == 4:
        base, limit, _, _ = struct.unpack_from('>4I', fork)
        if struct.unpack_from('<I', fork, base + 4)[0] != count:
            raise ValueError('bad zlib resource table')
        spans = [(base + 4 + off, base + 4 + off + length)
                 for off, length in struct.iter_unpack('<II', fork[base + 8:base + 8 + count * 8])]
        previous = base + 8 + count * 8
    else:
        raise ValueError(f'unsupported decmpfs method {method}')
    output = bytearray()
    for index, (start, end) in enumerate(spans):
        length = min(65536, size - index * 65536)
        if not previous <= start < end <= min(limit, len(fork)):
            raise ValueError('invalid compressed chunk bounds')
        previous = end
        compressed = fork[start:end]
        if compressed[:1] == b'\xff':
            data = compressed[1:]
        elif method == 4:
            if len(compressed) < 3 or compressed[0] != 0x78:
                raise ValueError('invalid zlib header')
            inflater = zlib.decompressobj(-15)
            data = inflater.decompress(compressed[2:], length + 1)
            if not inflater.eof:
                raise ValueError('incomplete deflate chunk')
        else:
            buffer = ctypes.create_string_buffer(length)
            written = ctypes.c_size_t()
            if decoder(buffer, length, compressed, len(compressed), ctypes.byref(written)) or written.value != length:
                raise ValueError('LZBITMAP decode failed')
            data = buffer.raw
        if len(data) != length:
            raise ValueError('unexpected decoded chunk length')
        output += data
    if len(output) != size:
        raise ValueError('incomplete executable')
    return bytes(output)


def main():
    print(json.dumps(inspect(read_extracted(Path(sys.argv[1]), Path(sys.argv[3]))), indent=2))


if __name__ == '__main__':
    main()
