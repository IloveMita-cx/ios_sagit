#!/usr/bin/env python3
"""Report the display-state entitlement embedded in the original PreBoard Mach-O."""
import hashlib
import json
import plistlib
from pathlib import Path
import struct
import sys
from uuid import UUID

from macho_development_sign import signature_blobs

DISPLAY_STATE = 'com.apple.QuartzCore.display-state'
RUN_N_UUID = 'dfd2aed4-e2d8-3ac0-be34-9637b1042bd3'
APP = '/Applications/PreBoard.app/PreBoard'


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


def main():
    path = Path(sys.argv[1])
    if path.stat().st_size:
        data = path.read_bytes()
    else:
        # Some stock executables have APFS file compression and an empty data fork.
        from apfs_sealed import SealedImage
        from baseband_dyld import Files
        image = SealedImage(Path(sys.argv[2]))
        try:
            files = Files(image, Path(sys.argv[3]))
            data = files.read(APP, 0, files.info(APP)['size'])
        finally:
            image.close()
    print(json.dumps(inspect(data), indent=2))


if __name__ == '__main__':
    main()
