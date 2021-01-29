#!/usr/bin/env python3

from pathlib import Path
from pprint import pprint
import sys

from utils import unpack
import decompiler


decoders = {
    8: decompiler.v11,
    11: decompiler.v11,
    12: decompiler.v11,  # TODO: look for changes in v12
}


def load_file(fn=None, fp=None):
    if fn:
        fp = open(fn, 'rb')

    header, size, version = unpack(fp, '<4sLB')
    if header != b'YARA':
        print('Invalid File (Bad header)')
        exit()

    try:
        return decoders[version](fp, size)
    except KeyError:
        print('Unsupported Yara version')
        exit()


def main():
    try:
        path = Path(sys.argv[1])
    except IndexError:
        print("Usage: {} [path]".format(sys.argv[0]))
        sys.exit(1)

    with path.open('rb') as f:
        header, size, version = unpack(f, '<4sLB')
        if header != b'YARA':
            print('Invalid File (Bad header)')
            exit()

        try:
            dec =  decoders[version](f, size)
        except KeyError:
            print('Unsupported Yara version')
            exit()

    rules = dec.parse_rules()
    cnt = 0
    unrecoverable = 0
    for rule in rules:
        o = str(rule)
        cnt += 1
        if 'UNRECOVERABLE_REGEXP' in o:
            unrecoverable += 1
        print(o)

    print('/* Decompile %d/%d rules */' % (cnt - unrecoverable, cnt))
    print('// vim: ft=yara')

    dec.parse_automaton()
    pprint(dec.automaton_root)

    #for addr, opcode, args in dec.disasm():
    #    print('%.8x: %-10s %r' % (addr, opcode, args))

if __name__ == '__main__':
    main()
