from collections import OrderedDict
from itertools import product
from utils import unpack, unpack2
from pprint import pprint

import io
import string
import struct
import json
from v11_const import Opcode, StrFlag, RuleFlag, MetaType, _MAX_THREADS, UNDEFINED, SINGLE_ARG_OPCODES, TWO_ARG_OPCODES, MAX_TABLE_BASED_STATES_DEPTH, RegexpOpcode, NO_ARG_OPCODES, IGNORED_OPCODES, SINGLE_ARG_HAS_PARENTHESES, SINGLE_ARG_NO_PARENTHESES, SPLIT_OPCODES, CLASS_OPCODES

OPTIONS_OUTPUT_ASM = False
OPTIONS_OUTPUT_TREE = False
OPTIONS_DUMP_RE_ASM = False

GOOD_ASCII = string.ascii_letters + string.digits

class DecompileError(Exception):
    pass

def escape_str(s):
    return '"%s"' % (s
            .replace('\\', '\\\\')
            .replace('\0', '\\0')
            .replace('\n', '\\n')
            .replace('\r', '\\r')
            .replace('\t', '\\t')
            .replace('"', '\\"'))

def stringify(op):
    TABLE = {
        Opcode.OP_SHL: '>>',
        Opcode.OP_SHR: '<<',
        Opcode.OP_STR_EQ: '==',
        Opcode.OP_STR_NEQ: '!=',
        Opcode.OP_STR_LT: '<',
        Opcode.OP_STR_GT: '>',
        Opcode.OP_STR_LE: '<=',
        Opcode.OP_STR_GE: '>=',
        Opcode.OP_INT_EQ: '==',
        Opcode.OP_INT_NEQ: '!=',
        Opcode.OP_INT_LT: '<',
        Opcode.OP_INT_GT: '>',
        Opcode.OP_INT_LE: '<=',
        Opcode.OP_INT_GE: '>=',
        Opcode.OP_INT_ADD: '+',
        Opcode.OP_INT_SUB: '-',
        Opcode.OP_INT_MUL: '*',
        Opcode.OP_INT_DIV: '/',
        Opcode.OP_INT_MINUS: '-',
        Opcode.OP_DBL_EQ: '==',
        Opcode.OP_DBL_NEQ: '!=',
        Opcode.OP_DBL_LT: '<',
        Opcode.OP_DBL_GT: '>',
        Opcode.OP_DBL_LE: '<=',
        Opcode.OP_DBL_GE: '>=',
        Opcode.OP_DBL_ADD: '+',
        Opcode.OP_DBL_SUB: '-',
        Opcode.OP_DBL_MUL: '*',
        Opcode.OP_DBL_DIV: '/',
        Opcode.OP_DBL_MINUS: '-',
        Opcode.OP_NOT: 'not ',
        Opcode.OP_AND: 'and',
        Opcode.OP_OR: 'or',
        Opcode.OP_BITWISE_NOT: '~',
        Opcode.OP_BITWISE_AND: '&',
        Opcode.OP_BITWISE_OR: '|',
        Opcode.OP_BITWISE_XOR: '^',
        Opcode.OP_INT8: 'int8',
        Opcode.OP_INT16: 'int16',
        Opcode.OP_INT32: 'int32',
        Opcode.OP_UINT8: 'uint8',
        Opcode.OP_UINT16: 'uint16',
        Opcode.OP_UINT32: 'uint32',
        Opcode.OP_INT8BE: 'int8be',
        Opcode.OP_INT16BE: 'int16be',
        Opcode.OP_INT32BE: 'int32be',
        Opcode.OP_UINT8BE: 'uint8be',
        Opcode.OP_UINT16BE: 'uint16be',
        Opcode.OP_UINT32BE: 'uint32be',
        Opcode.OP_FOUND_AT: 'at',
        Opcode.OP_FILESIZE: 'filesize',
        Opcode.OP_ENTRYPOINT: 'pe.entrypoint',
    }
    try:
        return TABLE[op] # TABLE.get(op, str(op))
    except KeyError as e:
        raise DecompileError('Opcode %r mapping not found' % op) from e

def _decompile_RE_hex(code, start, end, backward=0):
    pattern = []
    i = start
    while i < end:
        _, opcode, args = code[i]
        if opcode == RegexpOpcode.RE_OPCODE_ANY:
            pattern.append('??')
        elif opcode in [RegexpOpcode.RE_OPCODE_LITERAL, RegexpOpcode.RE_OPCODE_LITERAL_NO_CASE]:
            pattern.append('%02x' % args[0])
        elif opcode == RegexpOpcode.RE_OPCODE_MASKED_LITERAL:
            if args[1] == 0xf0:
                pattern.append('%x?' % (args[0] >> 4))
            else:
                pattern.append('?%x' % (args[0], ))
        elif opcode == RegexpOpcode.RE_OPCODE_PUSH:
            """
            Code for e{n,m} looks like:
            
                       code for e       (repeated n times)
                       push m-n-1
                   L0: split L1, L2
                   L1: code for e
                       jnz L0
                   L2: pop
                       split L3, L4
                   L3: code for e
                   L4:
            This is how the code looks like after the PUSH:
            
                       push m-n-1        (3 bytes long)
                   L0: split L1, L2      (3 bytes long)
                   L1: any               (1 byte long)
                       jnz L0            (3 bytes long)
                   L2: pop               (1 byte long)
                       ...
            """
            m_n_1 = args[0]
            # count # of ANY before the loop
            n = 0
            while True:
                c = code[i-n-1][1]
                if c != RegexpOpcode.RE_OPCODE_ANY:
                    break
                n += 1
                pattern.pop()
            m = m_n_1 + n + 1
            pattern.append("[%d-%d]" % (n, m))
            i += 6
            
        elif opcode == RegexpOpcode.RE_OPCODE_SPLIT_B:
            """
            SPLIT_B occurs without PUSH only when range = [N, N+1]
            The code would be like:
                any       (repeated n times)
                split_b
                any
            """
            # count # of ANY before split_b
            n = 0
            while True:
                c = code[i-n-1][1]
                if c != RegexpOpcode.RE_OPCODE_ANY:
                    break
                n += 1
                pattern.pop()
            pattern.append("[%d-%d]" % (n, n+1))
            # skip the next any
            i += 1
        elif opcode == RegexpOpcode.RE_OPCODE_SPLIT_A:
            """
            SPLIT_A occurs if there is ( A | B ) structure
            code:
                  split_a L1, 0
                  code for A      ----- n
                  jmp L2
            L1:   code for B      ----- m
            L2:   ...
            """
            # Find jump and get the displacement to identify the address of L2
            n, m = 0, 0
            while code[i+n][1] != RegexpOpcode.RE_OPCODE_JUMP:
                n += 1
            disp = code[i+n][2][0]
            while code[i+n][0] + disp != code[i+n+m][0]:
                m += 1
            A_pattern = _decompile_RE_hex(code, i+1, i+n)
            B_pattern = _decompile_RE_hex(code, i+n+1, i+n+m)
            if backward:
                pattern.append(f'( {" ".join(reversed(A_pattern))} | {" ".join(reversed(B_pattern))} )')
            else:
                pattern.append(f'( {" ".join(A_pattern)} | {" ".join(B_pattern)} )')
            i += n + m - 1
        elif opcode == RegexpOpcode.RE_OPCODE_MATCH:
            break

        else:
            raise DecompileError('Impossible opcode met in _decompile_RE_hex:', opcode)
        i += 1

    return pattern

def _decompile_RE_range(code, start, end, backward=0):
    pattern = []
    i = start
    while i < end:
        _, opcode, args = code[i]
        if opcode == RegexpOpcode.RE_OPCODE_ANY:
            pattern.append('.')
        elif opcode == RegexpOpcode.RE_OPCODE_ANY_EXCEPT_NEW_LINE:
            pattern.append('.')
        elif opcode in [RegexpOpcode.RE_OPCODE_LITERAL, RegexpOpcode.RE_OPCODE_LITERAL_NO_CASE]:
            if chr(args[0]) in GOOD_ASCII:
                pattern.append(bytes([args[0]]).decode('ascii'))
            else:
                pattern.append('\\x%.2x' % args[0])
        elif opcode == RegexpOpcode.RE_OPCODE_MASKED_LITERAL:
            # This is a hex pattern, abort the work and call _decompile_RE_hex
            # The second return value is True if this is a hex pattern (meeting MASKED_LITERAL)
            return [], True
        elif opcode in SPLIT_OPCODES:
            pass
        elif opcode == RegexpOpcode.RE_OPCODE_JUMP:
            # backtrace to RE_OPCODE_SPLIT_A or RE_OPCODE_SPLIT_B to identify the repeat part
            j = i - 1
            while not code[j][1] in SPLIT_OPCODES:
                j -= 1
                try:
                    pattern.pop()
                except IndexError as e:
                    raise DecompileError() from e
            # get the repeat part
            subpattern, _ = _decompile_RE_range(code, j, i, backward)
            if len(subpattern) > 1:
                if backward:
                    pattern.append('(%s)*' % ''.join(reversed(subpattern)))
                else:
                    pattern.append('(%s)*' % ''.join(subpattern))
            elif len(subpattern) == 0:
                pattern.append('[Unsupported]')
            else:
                pattern.append('%s*' % subpattern[0])
        elif opcode == RegexpOpcode.RE_OPCODE_PUSH:
            """
            Code for e{n,m} looks like:
            
                       code for e       (repeated n times)
                       push m-n-1
                   L0: split L1, L2
                   L1: code for e
                       jnz L0
                   L2: pop
                       split L3, L4
                   L3: code for e
                   L4:
            """
            m_n_1 = args[0]
            # find jnz and identify the repeat part
            j = i + 1
            while code[j][1] != RegexpOpcode.RE_OPCODE_JNZ:
                j += 1
            sub_len = j - (i + 2)
            subpattern, _ = _decompile_RE_range(code, i + 2, j, backward)

            # count # of repeat part before the loop
            n = 0
            while True:
                if code[i - n - 1][1] != code[j - n - 1][1]:
                    break
                n += 1
            n = n // sub_len
            for _ in range(n):
                pattern.pop()
            m = m_n_1 + n + 1
            pattern.append(f"{''.join(subpattern)}{{%d,%d}}" % (n, m))
            # skip the tail part
            i = j + 2 + sub_len
            
        elif opcode in [RegexpOpcode.RE_OPCODE_CLASS, RegexpOpcode.RE_OPCODE_CLASS_NO_CASE]:
            cls = args[0]
            # Look Fowrward for repetition?
            j = i + 1
            while code[j][1] in {RegexpOpcode.RE_OPCODE_CLASS, RegexpOpcode.RE_OPCODE_CLASS_NO_CASE} and code[j][2][0] == cls:
                j += 1
            if (j - i) > 1:
                cls = f'[{cls}]{{{j - i}}}'
            else:
                cls = f'[{cls}]'
            pattern.append(cls)
            i = j - 1
        elif opcode == RegexpOpcode.RE_OPCODE_MATCH:
            break
        else:
            raise DecompileError('Impossible opcode met in _decompile_RE_range:', opcode)
        i += 1
    return pattern, False

def decompile_RE(fw_code, bw_code, flags):
    if flags & StrFlag.FAST_HEX_REGEXP:
        fw = _decompile_RE_hex(fw_code, 0, len(fw_code))
        bw = _decompile_RE_hex(bw_code, 0, len(bw_code), 1)
        if any(bw):
            re = f'{{ {" ".join(reversed(bw))} {" ".join(fw)} }}'
        else:
            re = f'{{ {" ".join(fw)} }}'
    else:
        fw, is_hex = _decompile_RE_range(fw_code, 0, len(fw_code))
        if not is_hex:
            bw, is_hex = _decompile_RE_range(bw_code, 0, len(bw_code), 1)
            if not is_hex:
                fw = ''.join(fw).replace('/', '\\/').replace('?', '\\?')
                bw = ''.join(reversed(bw)).replace('/', '\\/').replace('?', '\\?')
                re = f'/{bw}{fw}/'
                return re
        fw = _decompile_RE_hex(fw_code, 0, len(fw_code))
        bw = _decompile_RE_hex(bw_code, 0, len(bw_code), 1)
        if any(bw):
            re = f'{{ {" ".join(reversed(bw))} {" ".join(fw)} }}'
        else:
            re = f'{{ {" ".join(fw)} }}'
    return re

def optimize_walk(node):
    if node.type == 'val':
        return

    if node.data == Opcode.OP_PUSH:   # eliminate push nodes
        node.type = 'val'
        node.data = node.childs[0].data
        node.childs = []
    elif node.data == Opcode.OP_PUSH_RULE:   # eliminate push nodes
        node.type = 'val'
        node.data = node.childs[0].data
        node.childs = []

    for child in node.childs:
        optimize_walk(child)
    if node.type == 'val':
        return

class Node:
    def __init__(self, data, type, rule):
        if type != 'op' and type != 'val':
            raise ValueError("Node type should be 'op' or 'val'.")
        self.data = data
        self.type = type
        self.childs = []
        self.rule = rule

    def append(self, n):
        self.childs.append(n)

    def __str__(self):
        if self.type == 'val':
            return f'{{"data": {json.dumps(self.data, default=str)}}}'
        else:
            return f'{{"data": "{str(self.data)}", "childs": {self.childs}}}'

    def __repr__(self):
        return str(self)

    def pretty(self):
        out = ''
        if self.type == 'val':
            arg_id = ''
            try:
                arg_id = self.data[1]['identifier']
            except:
                pass
            if arg_id:
                out += str(arg_id)
            elif isinstance(self.data[0], int):
                v = self.data[0]
                if v > 9:
                    out += '0x%x' % v
                else:
                    out += '%d' % v
            else:
                out += str(self.data[0])
        elif self.type == 'op':
            if self.data == Opcode.OP_COUNT:
                return '#' + self.childs[0].data[1]['identifier'][1:]
            elif self.data == Opcode.OP_MATCH_RULE:
                for child in self.childs:
                    out += child.pretty()
                
            elif self.data == Opcode.OP_OFFSET:
                rhs = self.childs[0].pretty()
                out += f'@{rhs[1:]}'
            elif self.data in TWO_ARG_OPCODES:
                rchild, lchild = self.childs[0:2]
                lhs = lchild.pretty()
                rhs = rchild.pretty()
                # Add parentheses
                if lchild.type != 'val' and lchild.data in {*TWO_ARG_OPCODES, Opcode.OP_OF}:
                    lhs = f'({lhs})'
                if rchild.type != 'val' and rchild.data in {*TWO_ARG_OPCODES, Opcode.OP_OF}:
                    rhs = f'({rhs})'
                if self.data == Opcode.OP_FOUND_AT:
                    lhs, rhs = rhs, lhs
                out += f'{lhs} {stringify(self.data)} {rhs}'

            elif self.data == Opcode.OP_FOUND:
                out += f'{self.childs[0].pretty()}'
            
            elif self.data in SINGLE_ARG_HAS_PARENTHESES:
                out += f'{stringify(self.data)}({self.childs[0].pretty()})'

            elif self.data in SINGLE_ARG_NO_PARENTHESES:
                out += f'{stringify(self.data)}{self.childs[0].pretty()}'

            elif self.data == Opcode.OP_FOUND_IN:
                string, end, begin = self.childs[0:3]
                out += f'{string.pretty()} in ({begin.pretty()}..{end.pretty()})'

            elif self.data == Opcode.OP_OF:
                n = self.childs[-1]
                # substitute specific constant to keyword
                if n.data[0] == 'UNDEFINED':
                    lhs = 'all'
                elif n.data[0] == 1:
                    lhs = 'any'
                else:
                    lhs = n.pretty()

                operands = self.childs[0:-2]
                if len(operands) == len(self.rule.data['strings']):
                    rhs = 'them' # TODO: more check
                else:
                    rhs = ', '.join([child.data[1]['identifier'] for child in reversed(operands)])

                out += f'{lhs} of {rhs}'

            elif self.data in NO_ARG_OPCODES:
                out += f'{stringify(self.data)}'

            elif self.data == Opcode.OP_PUSH:
                # Usually push should be optimized out
                out += f'PUSH({self.childs[0].pretty()})'
            else:
                raise DecompileError(self)
        else: # not op, not val?
            assert 0

        return out


class YaraRule:
    def __init__(self, data: dict):
        self.data = data
        self.data.setdefault('strings', OrderedDict())

        strings_ptr_set = self.data.setdefault('strings_ptr_set', set())
        for s in self.data.get('strings_list'):
            self.data['strings'][s['identifier']] = s
            strings_ptr_set.add(s['ptr'])

    def __str__(self):
        out = ''
        if self.data['flags'] & RuleFlag.PRIVATE:
            out += 'private '
        out += 'rule {ns}{identifier}'.format(**self.data)
        if self.data['tags']:
            out += ' : {}'.format(self.data['tags'])
        out += ' {\n'
        out += '\t// ptr = {:x}\n'.format(self.data['ptr'])
        if self.data.get('metadata'):
            out += '\tmeta:\n'
            for name, val in self.data['metadata'].items():
                if val['type'] == MetaType.STRING:
                    value = '"{}"'.format(val['string'])
                elif val['type'] == MetaType.INTEGER:
                    value = '{}'.format(val['integer'])
                elif val['type'] == MetaType.BOOLEAN:
                    value = '{}'.format(val['boolean'])
                out += '\t\t{} = {}\n'.format(name, value)

        if self.data.get('strings'):
            out += '\tstrings:\n'
            for string in self.data['strings'].values():
                out += '\t/*0x{ptr:x}*/\t{identifier}'.format(**string)

                if string['flags'] & StrFlag.HEXADECIMAL and string['flags'] & StrFlag.LITERAL:
                    out += ' = {str}'.format(**string)
                elif string['flags'] & StrFlag.LITERAL:
                    out += ' = ' + escape_str(string['str'])
                else:
                    if 're' in string:
                        out += ' = ' + string['re']
                    else:
                        out += ' = /UNRECOVERABLE_REGEXP/ /* regex is unrecoverable right now. flags = %s */' % string['flags']

                if string['flags'] & StrFlag.FULL_WORD:
                    out += ' fullword'
                if string['flags'] & StrFlag.WIDE:
                    out += ' wide'
                    # ASCII is the default, show ascii only if wide is set
                    if string['flags'] & StrFlag.ASCII:
                        out += ' ascii'
                if string['flags'] & StrFlag.NO_CASE:
                    out += ' nocase'
#                if string['flags'] & StrFlag.REGEXP:
#                    out += ' regex'
                out += '\n'

        if OPTIONS_OUTPUT_ASM:
            out += self.asm()
        if self.AST:
            try:
                out += self.decompile()
            except DecompileError as e:
                out += '/*\nDecompileError: %r\n*/' % e
                out += self.asm()
            if OPTIONS_OUTPUT_TREE:
                out += '\n/*\n%s\n*/\n' % repr(self.AST)
        out += '}\n'
        out += '\n'

        return out


    def build_AST(self):
        code = self.data['code']
        stack = []
        for inst in code:
            opcode = inst['opcode']
            if opcode in {Opcode.OP_PUSH, Opcode.OP_PUSH_RULE}:
                node = Node(opcode, 'op', self)
                node.append(Node(inst['args'], 'val', self))
                stack.append(node)

            elif opcode in SINGLE_ARG_OPCODES:
                node = Node(opcode, 'op', self)
                node.append(stack.pop())
                stack.append(node)
                    
            elif opcode in {*TWO_ARG_OPCODES, Opcode.OP_OFFSET}:
                node = Node(opcode, 'op', self)
                node.append(stack.pop())
                node.append(stack.pop())
                stack.append(node)

            elif opcode in NO_ARG_OPCODES:
                node = Node(opcode, 'op', self)
                stack.append(node)

            elif opcode == Opcode.OP_FOUND_IN:
                node = Node(opcode, 'op', self)
                node.append(stack.pop())
                node.append(stack.pop())
                node.append(stack.pop())
                stack.append(node)

            elif opcode == Opcode.OP_OF:
                node = Node(opcode, 'op', self)
                while True:
                    n = stack.pop() 
                    node.append(n)
                    if n.childs[0].data[0] == 'UNDEFINED':
                        break

                node.append(stack.pop())
                stack.append(node)
            elif opcode in {*IGNORED_OPCODES, Opcode.OP_OBJ_LOAD, Opcode.OP_OBJ_FIELD, Opcode.OP_CALL, Opcode.OP_OBJ_VALUE}:
                continue

            elif opcode == Opcode.OP_MATCH_RULE:
                node = Node(opcode, 'op', self)
                while any(stack):
                    node.append(stack.pop())
                stack.append(node)

            else:
                print(self.asm())
                raise DecompileError(opcode)

        self.AST = stack.pop()

    def json(self):
        return str(self.AST)

    def asm(self):
        out = '\t__yada_asm__:\n'
        for val in self.data.get('code', []):
            out += '\t{:x}\t{}'.format(val['ptr'], val['opcode'].name)
            if val['args']:
                out += ' ('
                for x in val['args']:
                    pass
                    if isinstance(x, int):
                        out += ' 0x{:X} '.format(x)
                    elif isinstance(x, dict):
                        out += ' {} '.format(x['identifier'])
                    else:
                        out += ' {} '.format(x)
                out += ')'
            out += '\n'
        return out

    def decompile(self):
        out = '\tcondition:\n'
        node = self.AST
        out += '\t\t' + node.pretty() + '\n'
        return out

    def optimize(self):
        if self.AST:
            optimize_walk(self.AST)


class decompiler:
    def __init__(self, stream, size):
        self.size = size
        self.data = io.BytesIO(stream.read(size))
        self.code = OrderedDict()
        self.addr_string_map = {}

        if not self.relocate(stream):
            raise RuntimeError('Invalid file')

        self.version, self.rules, self.externals, self.code_start, self.automaton = unpack(self.data, '<LQQQQ')

    def relocate(self, stream):
        try:
            reloc = unpack(stream, '<L')[0]
            while reloc != 0xffffffff:
                if reloc > self.size - 4:
                    print("Invalid file (bad relocs)")
                    return False

                reloc_target = struct.unpack('<L', self.data.getbuffer()[reloc:reloc + 4])[0]
                if (reloc_target == 0xFFFABADA):
                    self.data.getbuffer()[reloc:reloc + 4] = b'\0\0\0\0'

                reloc = unpack(stream, '<L')[0]
        except struct.error:
            print("Invalid file (bad relocs)")
            return False
        return True

    def regexp_disasm(self, ip):
        if ip == 0:
            return
        buf = self.data.getbuffer()
        if OPTIONS_DUMP_RE_ASM:
            print('--- BEGIN REGEXP DISASM AT 0x%.8x ---' % ip)

        while True:
            opcode = RegexpOpcode(unpack2(buf, ip, '<B')[0])
            ip_inc = 1
            args = []

            if opcode in [RegexpOpcode.RE_OPCODE_LITERAL, RegexpOpcode.RE_OPCODE_LITERAL_NO_CASE]:
                ip_inc = 2
                args.append(unpack2(buf, ip + 1, '<B')[0])
            elif opcode == RegexpOpcode.RE_OPCODE_MASKED_LITERAL:
                ip_inc = 3
                args.append(unpack2(buf, ip + 1, '<B')[0])
                args.append(unpack2(buf, ip + 2, '<B')[0])
            elif opcode in [RegexpOpcode.RE_OPCODE_SPLIT_B, RegexpOpcode.RE_OPCODE_SPLIT_A]:
                ip_inc = 3
                args.append(unpack2(buf, ip + 1, '<B')[0])
                args.append(unpack2(buf, ip + 2, '<B')[0])
            elif opcode == RegexpOpcode.RE_OPCODE_PUSH:
                ip_inc = 3
                args.append(unpack2(buf, ip + 1, '<H')[0])
            elif opcode in [RegexpOpcode.RE_OPCODE_JNZ, RegexpOpcode.RE_OPCODE_JUMP]:
                ip_inc = 3
                args.append(unpack2(buf, ip + 1, '<h')[0])
            elif opcode in CLASS_OPCODES:
                ip_inc = 33
                n = unpack2(buf, ip + 1, '<64s')[0]
                n = int.from_bytes(n, byteorder='little')
                # extract bit positions
                bit_pos = []
                for j in range(256):
                    if n & 1 == 1:
                        bit_pos.append(j)
                    n >>= 1
                # TODO: mask and reduce \w \W \s \S \d \D
                # extract consecutive segment
                cls = ""
                l, r = bit_pos[0], 0
                for j in range(len(bit_pos) - 1):
                    if bit_pos[j + 1] != bit_pos[j] + 1:
                        r = bit_pos[j]
                        if r != l:
                            cls += f'{chr(l)}-{chr(r)}'
                        else:
                            cls += f'{chr(l)}'
                        l = bit_pos[j + 1]
                if bit_pos[-1] != l:
                    cls += f'{chr(l)}-{chr(bit_pos[-1])}'
                else:
                    cls += f'{chr(l)}'
                args.append(cls)
            elif opcode in [
                    RegexpOpcode.RE_OPCODE_ANY,
                    RegexpOpcode.RE_OPCODE_POP,
                    RegexpOpcode.RE_OPCODE_ANY_EXCEPT_NEW_LINE,
                ]:
                pass
            elif opcode == RegexpOpcode.RE_OPCODE_MATCH:
                pass
            else:
                raise DecompileError('Unknown opcode' + repr(opcode))

            if opcode in CLASS_OPCODES:
                args_str = repr(args)
            else:
                args_str = ' '.join('0x%x' % i for i in args)
            if OPTIONS_DUMP_RE_ASM:
                print('0x%.8x (%-9d): %-24s %s' % (ip, ip, opcode, args_str))
            yield ip, opcode, args
            ip += ip_inc

            if opcode == RegexpOpcode.RE_OPCODE_MATCH:
                break

    def get_code(self, buf, ip):
        if self.code.get(ip):
            return []

        opcode = Opcode(unpack2(buf, ip, '<B')[0])
        args = []

        if opcode == Opcode.OP_HALT:
            next = []
        elif opcode in [
            Opcode.OP_CLEAR_M,
            Opcode.OP_ADD_M,
            Opcode.OP_INCR_M,
            Opcode.OP_PUSH_M,
            Opcode.OP_POP_M,
            Opcode.OP_SWAPUNDEF,
            Opcode.OP_INIT_RULE,
            Opcode.OP_PUSH_RULE,
            Opcode.OP_MATCH_RULE,
            Opcode.OP_OBJ_LOAD,
            Opcode.OP_OBJ_FIELD,
            Opcode.OP_CALL,
            Opcode.OP_IMPORT,
            Opcode.OP_INT_TO_DBL,
        ]:
            args.append(unpack2(buf, ip + 1, '<Q')[0])
            next = [ip + 9]
        elif opcode in [
            Opcode.OP_JNUNDEF,
            Opcode.OP_JLE,
            Opcode.OP_JTRUE,
            Opcode.OP_JFALSE,
        ]:
            branch = unpack2(buf, ip + 1, '<Q')[0]
            next = [branch, ip + 9]
            args.append(branch)
        elif opcode == Opcode.OP_PUSH:
            arg = unpack2(buf, ip + 1, '<Q')[0]
            if arg == UNDEFINED:
                args.append('UNDEFINED')
            else:
                args.append(arg)
                # TODO: args.append(string)
            next = [ip + 8 + 1]
        elif opcode in [
            Opcode.OP_ERROR,
        ]:
            next = []
        else:
            #print('Unknown OPcode: %d (%s?)' % (opcode, opcode))
            next = [ip + 1]

        self.code[ip] = dict(ptr=ip, next=next, opcode=opcode, args=args)
        return next

    def get_raw_str(self, addr):
        if not addr:
            return None
        self.data.seek(addr)
        blob = self.data.read(512)
        while b'\0' not in blob:
            n = self.data.read(len(blob)*2)
            if not n: break
            blob += n
        return blob.split(b'\0', 1)[0].decode('latin1')

    def get_meta(self, addr):
        '''
        typedef struct _YR_META
        {
          int32_t type;
          int32_t integer;

          DECLARE_REFERENCE(const char*, identifier);
          DECLARE_REFERENCE(char*, string);

        } YR_META;
        '''
        fmt = '<LLQQ'
        size = struct.calcsize(fmt)
        buf = self.data.getbuffer()
        i = 0
        metadatas = OrderedDict()

        while True:
            meta_data = unpack2(buf, addr + i * size, fmt)
            i += 1
            meta_type = MetaType(meta_data[0])
            if meta_type == MetaType.NULL:
                break
            data = dict(
                type=meta_type,
            )
            if meta_type == MetaType.STRING:
                data['string'] = self.get_raw_str(meta_data[3])
            elif meta_type == MetaType.INTEGER:
                data['integer'] = meta_data[1]
            elif meta_type == MetaType.BOOLEAN:
                data['boolean'] = bool(meta_data[1])
            metadatas[self.get_raw_str(meta_data[2])] = data
        return metadatas

    def get_ns(self, addr):
        fmt = '<' + 'x' * (_MAX_THREADS*4) + 'L'
        buf = self.data.getbuffer()
        ns = self.get_raw_str(unpack2(buf, addr, fmt)[0])
        return '{}:'.format(ns) if ns else ''

    def get_strings(self, addr):
        while True:
            string = self.get_string(addr)
            if not string:
                break
            yield string
            addr += 4 * 4 + 8 * 4 + (20*_MAX_THREADS*2)

    def get_string(self, addr):
        '''
        typedef struct _YR_STRING
        {
          int32_t g_flags;
          int32_t length;

          DECLARE_REFERENCE(char*, identifier);
          DECLARE_REFERENCE(uint8_t*, string);
          DECLARE_REFERENCE(struct _YR_STRING*, chained_to);

          int32_t chain_gap_min;
          int32_t chain_gap_max;

          int64_t fixed_offset;

          YR_MATCHES matches[MAX_THREADS];
          YR_MATCHES unconfirmed_matches[MAX_THREADS];

          #ifdef PROFILING_ENABLED
          uint64_t clock_ticks;
          #endif

        } YR_STRING;
        '''

        buf = self.data.getbuffer()
        g_flags, length, identifier, str_data, chained_to, chain_gap_min, chain_gap_max, fixed_offset = unpack2(buf, addr, '<LLQQQLLQ' + 'x' * (20*_MAX_THREADS*2))

        flags = StrFlag(g_flags)

        if flags == StrFlag.NOFLAG or length > 0xffffff:
            return None

        str_str = unpack2(buf, str_data, '{}s'.format(length))[0]  # type: bytes

        data = dict(
            ptr=addr,
            flags=flags,
            length=length,
            chained_to=chained_to,
            chain_gap_min=chain_gap_min,
            chain_gap_max=chain_gap_max,
            fixed_offset=fixed_offset,
            identifier=self.get_raw_str(identifier),
        )

        if flags & StrFlag.HEXADECIMAL and flags & StrFlag.LITERAL:
            data['str'] = '{ ' + ' '.join(['{:02X}'.format(x) for x in str_str]) + ' }'
        elif flags & StrFlag.LITERAL:
            data['str'] = str_str.decode('latin1')
        else:
            data['str'] = None

        return data

    def get_rule(self, addr):
        '''
        typedef struct _YR_RULE
        {
          int32_t g_flags;               // Global flags
          int32_t t_flags[MAX_THREADS];  // Thread-specific flags

          DECLARE_REFERENCE(const char*, identifier);
          DECLARE_REFERENCE(const char*, tags);
          DECLARE_REFERENCE(YR_META*, metas);
          DECLARE_REFERENCE(YR_STRING*, strings);
          DECLARE_REFERENCE(YR_NAMESPACE*, ns);

          #ifdef PROFILING_ENABLED
          uint64_t clock_ticks;
          #endif

        } YR_RULE;
        '''
        fmt = '<L' + 'x' * (_MAX_THREADS * 4) + 'QQQQQ'
        buf = self.data.getbuffer()
        flags, identifier, tags, meta, strings, ns = unpack2(buf, addr, fmt)

        data = dict(ptr=addr)

        data['flags'] = flags = RuleFlag(flags)
        if flags & RuleFlag.NULL:
            return None

        if identifier:
            data['identifier'] = self.get_raw_str(identifier)

        if tags:
            data['tags'] = self.get_raw_str(tags)
        else:
            data['tags'] = None

        if meta:
            data['metadata'] = self.get_meta(meta)

        if ns:
            data['ns'] = self.get_ns(ns)
        else:
            data['ns'] = ''

        if strings:
            data['strings_list'] = list(self.get_strings(strings))
            data['strings_map'] = { s['ptr']: s for s in data['strings_list'] }
        else:
            data['strings_list'] = []
            data['strings_map'] = {}

        return data

    def parse_bytecode(self):
        buf = self.data.getbuffer()
        ip = self.code_start

        todo = [ip]
        while todo:
            ip = todo.pop()
            todo += self.get_code(buf, ip)

    def get_rules(self):
        i = 0
        while True:
            c = self.get_rule(self.rules + i * 0xac)
            if not c: break
            i += 1
            c['code'] = []
            yield YaraRule(c)

    def parse_rules(self):
        rules = list(self.get_rules())
        addr_rules_map = { r.data['ptr']: r for r in rules }

        self.parse_bytecode()
        cur_rule = None
        for val in self.code.values():
            if val['opcode'] == Opcode.OP_INIT_RULE:
                cur_rule = addr_rules_map[val['args'][0]]

            elif val['opcode'] == Opcode.OP_IMPORT:
                continue

            elif val['opcode'] == Opcode.OP_PUSH:
                arg0 = val['args'][0]
                if arg0 in cur_rule.data['strings_ptr_set']:
                    val['args'].append(cur_rule.data['strings_map'][arg0])

            elif val['opcode'] == Opcode.OP_PUSH_RULE:
                arg = addr_rules_map.get(val['args'][0])
                if arg:
                    val['args'].append(arg.data)

            elif val['opcode'] == Opcode.OP_HALT:
                break
            cur_rule.data['code'].append(val)

        for rule in rules:
            rule.build_AST()
            rule.optimize()
            self.addr_string_map.update(rule.data['strings_map'])

        self.parse_automaton()

        return rules

    def parse_automaton(self):
        buf = self.data.getbuffer()
        self.automaton_addr_map = addr_map = {}
        root_addr = unpack2(buf, self.automaton, 'Q')[0]
        queue = [root_addr]
        self.automaton_root = root = addr_map.setdefault(root_addr, {})

        while queue:
            addr = queue.pop(0)
            node = addr_map.setdefault(addr, {})
            if node: # visited?
                continue
            if not addr:
                continue

            depth, failure, match_ptr, *transitions = unpack2(buf, addr, '<B' + 'Q' * (2 + 256))

            matches = []
            while match_ptr:
                '''
                typedef struct _YR_AC_MATCH
                {
                  uint16_t backtrack;

                  DECLARE_REFERENCE(YR_STRING*, string);
                  DECLARE_REFERENCE(uint8_t*, forward_code);
                  DECLARE_REFERENCE(uint8_t*, backward_code);
                  DECLARE_REFERENCE(struct _YR_AC_MATCH*, next);

                } YR_AC_MATCH;
                '''
                backtrack, string, forward_code, backward_code, next_match_ptr = unpack2(buf, match_ptr, '<HQQQQ')
                string_obj = self.addr_string_map[string]
                if not string_obj['str']:
                    string_obj.setdefault('ac_ref_count', 0)
                    string_obj['ac_ref_count'] += 1
                    match_obj = dict(
                        ptr=match_ptr,
                        backtrack=backtrack,
                        string=string_obj,
                        forward_code=forward_code,
                        backward_code=backward_code,
                    )
                    matches.append(match_obj)
                    # TODO: instead of iterative process, checked the "chained_to" field to chain several REs together
                    try:
                        match_obj['forward_code_asm'] = list(self.regexp_disasm(forward_code))
                        match_obj['backward_code_asm'] = list(self.regexp_disasm(backward_code))
                        string_obj['re'] = decompile_RE(match_obj['forward_code_asm'], match_obj['backward_code_asm'], match_obj['string']['flags'])
                    except DecompileError as e:
                        print('--- DecompileError while process following object ---')
                        pprint(match_obj)
                        print(e)
                        pass
                match_ptr = next_match_ptr

            node['addr'] = addr
            node['depth'] = depth
            node['failure'] = failure
            node['matches'] = matches
            node['transitions'] = T = {}

            if depth <= MAX_TABLE_BASED_STATES_DEPTH: # array-based
                for i, addr in enumerate(transitions):
                    if addr:
                        T[bytes([i])] = addr_map.setdefault(addr, {})
                        queue.append(addr)

            else: # list-based
                '''
                typedef struct _YR_AC_STATE_TRANSITION
                {
                  uint8_t input;

                  DECLARE_REFERENCE(YR_AC_STATE*, state);
                  DECLARE_REFERENCE(struct _YR_AC_STATE_TRANSITION*, next);

                } YR_AC_STATE_TRANSITION;
                '''
                t = transitions[0]
                while t:
                    input_byte, state, next_t = unpack2(buf, t, '<BQQ')
                    if state:
                        T[bytes([input_byte])] = addr_map.setdefault(state, {})
                        queue.append(state)
                    t = next_t

        def eliminate_empty_tail(node):
            for key, child in list(node['transitions'].items()):
                eliminate_empty_tail(child)
                if not child['matches'] and not child['transitions']:
                    node['transitions'].pop(key, None)

        eliminate_empty_tail(root)
