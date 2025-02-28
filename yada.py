#!/usr/bin/env python3

from pathlib import Path
from utils import unpack
import sys

def main():
    try:
        path = Path(sys.argv[1])
    except IndexError:
        print("Usage: {} [path]".format(sys.argv[0]))
        sys.exit(1)

    with path.open('rb') as f:
        header, size = unpack(f, '<4sL')
        if header != b'YARA':
            print('Invalid File (Bad header)')
            exit()

        # lookahead for newer versions
        # v8 -> version: 1byte, 3.9.0 -> version: 4bytes
        version = unpack(f, '<L')[0]
        if version != 0x150020:
            f.seek(-4, 1)
            version = unpack(f, '<B')[0]
        if version in [8, 11, 12]:
            import v11dec as decompiler
        elif version == 0x150020:
            import v39dec as decompiler
        else:
            print('Unsupported Yara version')
            exit()
        dec =  decompiler.decompiler(f, size)

    rules = dec.parse_rules()
    cnt = 0
    unrecoverable = 0
    for rule in rules:
        o = str(rule)
        cnt += 1
        if 'UNRECOVERABLE_REGEXP' in o or 'DecompileError' in o or '[Unsupported]' in o:
            unrecoverable += 1
        print(o)
    
    print('/* Decompile %d/%d rules */' % (cnt - unrecoverable, cnt))


if __name__ == '__main__':
    main()
