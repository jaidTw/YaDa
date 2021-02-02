#!/usr/bin/env python3

from pathlib import Path
import sys

from utils import unpack
import decompiler
from pprint import pprint

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
    for rule in rules:
        print(rule)

    # ptr -> (id, rule_name)
    str_table = {}
    for rule in rules:
        for i, v in rule.data['strings'].items():
            str_table[v['ptr']] = (i, rule.data['identifier'])
    print('Extraced regular expressions:')
    #(re, matches[match0, match1 ...])
    for re, matches in dec.REs:
        print(repr(re).ljust(25), 'Used by:', 
                ', '.join([ str_table[match['string']['ptr']][1]+ ':' + 
                     match['string']['identifier'] for match in matches]
                    )
                )

if __name__ == '__main__':
    main()
