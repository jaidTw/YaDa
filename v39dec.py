from collections import OrderedDict
from itertools import product
from utils import unpack, unpack2

import io
import struct
import json
from v39_const import Opcode, StrFlag, RuleFlag, MetaType, _MAX_THREADS, UNDEFINED, SINGLE_ARG_OPCODES, TWO_ARG_OPCODES, MAX_TABLE_BASED_STATES_DEPTH, RegexpOpcode, NO_ARG_OPCODES, IGNORED_OPCODES, SINGLE_ARG_HAS_PARENTHESES, SINGLE_ARG_NO_PARENTHESES, SPLIT_OPCODES

OPTIONS_OUTPUT_ASM = False
OPTIONS_OUTPUT_TREE = False
OPTIONS_DUMP_RE_ASM = False

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
    return TABLE[op]

def _decompile_RE_fast(code):
    """
    The only possible opcodes in yr_re_fast_exec are RE_OPCODE_ANY,
    RE_OPCODE_REPEAT_ANY_UNGREEDY, RE_OPCODE_LITERAL and RE_OPCODE_MASKED_LITERAL
    """
    pattern = []
    for _, opcode, args in code:
        if opcode == RegexpOpcode.RE_OPCODE_ANY:
            pattern.append('??')
        elif opcode == RegexpOpcode.RE_OPCODE_REPEAT_ANY_UNGREEDY:
            pattern.append('[%d-%d]' % (args[0], args[1]))
        elif opcode == RegexpOpcode.RE_OPCODE_LITERAL:
            pattern.append('%02x' % args[0])
        elif opcode == RegexpOpcode.RE_OPCODE_MASKED_LITERAL:
            if args[1] == 0xf0:
                pattern.append('%x?' % (args[0] >> 4))
            else:
                pattern.append('?%x' % (args[0], ))
        elif opcode == RegexpOpcode.RE_OPCODE_MATCH:
            break
        else:
            raise DecompileError('Impossible opcode met in _decompile_RE_fast')

    return pattern

def _decompile_RE_range(code, start, end):
    pattern = []
    i = start
    while i < end:
        _, opcode, args = code[i]
        if opcode == RegexpOpcode.RE_OPCODE_ANY:
            pattern.append('.')
        elif opcode == RegexpOpcode.RE_OPCODE_REPEAT_ANY_UNGREEDY:
            pattern.append('[%d-%d]' % (args[0], args[1]))
        elif opcode == RegexpOpcode.RE_OPCODE_LITERAL:
            pattern.append(bytes([args[0]]).decode('latin1'))
        elif opcode == RegexpOpcode.RE_OPCODE_MASKED_LITERAL:
            if args[1] == 0xf0:
                pattern.append('%x?' % (args[0] >> 4))
            else:
                pattern.append('?%x' % (args[0], ))
        elif opcode == RegexpOpcode.RE_OPCODE_MATCH:
            break
        elif opcode == RegexpOpcode.RE_OPCODE_REPEAT_START_GREEDY:
            """
            Code for e{n,m} looks like:
            
                       code for e              ---   prolog
                       repeat_start n, m, L1   --+
                   L0: code for e                |   repeat
                       repeat_end n, m, L0     --+
                   L1: split L2, L3            ---   split
                   L2: code for e              ---   epilog
                   L3:
            
            Not all sections (prolog, repeat, split and epilog) are generated in all
            cases, it depends on the values of n and m. The following table shows
            which sections are generated for the first few values of n and m.
            
                   n,m   prolog  repeat      split  epilog
                                 (min,max)
                   ---------------------------------------
                   0,0     -       -           -      -
                   0,1     -       -           X      X
                   0,2     -       0,1         X      X
                   0,3     -       0,2         X      X
                   0,M     -       0,M-1       X      X
            
                   1,1     X       -           -      -
                   1,2     X       -           X      X
                   1,3     X       0,1         X      X
                   1,4     X       1,2         X      X
                   1,M     X       1,M-2       X      X
            
                   2,2     X       -           -      X
                   2,3     X       1,1         X      X
                   2,4     X       1,2         X      X
                   2,M     X       1,M-2       X      X
            
                   3,3     X       1,1         -      X
                   3,4     X       2,2         X      X
                   3,M     X       2,M-2       X      X
            
                   4,4     X       2,2         -      X
                   4,5     X       3,3         X      X
                   4,M     X       3,M-2       X      X
            
            The code can't consists simply in the repeat section, the prolog and
            epilog are required because we can't have atoms pointing to code inside
            the repeat loop. Atoms' forwards_code will point to code in the prolog
            and backwards_code will point to code in the epilog (or in prolog if
            epilog wasn't generated, like in n=1,m=1)
            """
            n = args[0] + 1
            m = args[1] + n + 1
            # identify the repeat part
            j = i - 1
            while code[j][1] != RegexpOpcode.RE_OPCODE_REPEAT_END_GREEDY:
                j += 1
            subpattern = _decompile_RE_range(code, i + 1, j)
            # pop prolog if n > 0
            if n > 0:
                while pattern.pop() != subpattern[0]: pass
            if n != m:
                # skip split & epilog if n != m
                i = j + 1 + (j - i)
            elif n == 1:
                # no split and epilog if n == m == 1
                i = j + 1
            else:
                # skip eplilog
                i = j + (j - i)
            if len(subpattern) > 1:
                pattern.append(f'({"".join(subpattern)}){{{n},{m}}}')
            else:
                pattern.append(''.join(subpattern) + f'{{{n},{m}}}')
        elif opcode == RegexpOpcode.RE_OPCODE_JUMP:
            # backtrace to RE_OPCODE_SPLIT_A or RE_OPCODE_SPLIT_B to identify the repeat part
            j = i - 1
            while not code[j][1] in SPLIT_OPCODES:
                j -= 1
                pattern.pop()
            # get the repeat part
            subpattern = _decompile_RE_range(code, j, i)
            if len(subpattern) > 1:
                pattern.append('(%s)*' % ''.join(subpattern))
            else:
                pattern.append('%s*' % subpattern[0])
        elif opcode in SPLIT_OPCODES:
            pass
        else:
            raise DecompileError('Unsupported opcode met in _decompile_RE_range', opcode)
        i += 1
    return pattern

def decompile_RE(fw_code, bw_code, flags):
    if flags & StrFlag.FAST_HEX_REGEXP:
        fw = _decompile_RE_fast(fw_code)
        bw = _decompile_RE_fast(bw_code)
        if any(bw):
            re = f'{{ {" ".join(reversed(bw))} {" ".join(fw)} }}'
        else:
            re = f'{{ {" ".join(fw)} }}'
    else:
        fw = _decompile_RE_range(fw_code, 0, len(fw_code))
        bw = _decompile_RE_range(bw_code, 0, len(bw_code))
        re = f'/{"".join(reversed(bw))}{"".join(fw)}/'
    return re


def optimize_walk(node):
    if node.type == 'val':
        return

    if node.data == Opcode.OP_PUSH:   # eliminate push nodes
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
            if self.data == Opcode.OP_MATCH_RULE:
                for child in self.childs:
                    out += child.pretty()
                
            elif self.data == Opcode.OP_OFFSET:
                rhs = self.childs[0].pretty()
                out += f'@{rhs[1:]}'
            elif self.data in TWO_ARG_OPCODES:
                rchild, lchild = self.childs[0:2]
                lhs = lchild.pretty()
                rhs = rchild.pretty()
                # TODO: Only add parentheses if parentheses
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

            elif self.data == Opcode.OP_PUSH_RULE:
                try:
                    reference_rule = rules_table[self.childs[0].data[0]]
                    out += f"{reference_rule.data['identifier']}"
                except KeyError:
                    # Unanble to find the definition of the referencing rule
                    out += f"RULE_{self.childs[0].data[0]}"

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
                if string['flags'] & StrFlag.REGEXP:
                    out += ' regex'
                out += '\n'

        if OPTIONS_OUTPUT_ASM:
            out += self.asm()
        if self.AST:
            try:
                out += self.condition()
            except DecompileError as e:
                out += '/*\nDecompileError: %r\n*/' % e
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
                raise DecompileError('unsupported opcode in build_AST:', opcode)

        self.AST = stack.pop()

    def json(self):
        return str(self.AST)

    def asm(self):
        out = '\t__yaradec_asm__:\n'
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

    def condition(self):
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

        self.rules, self.externals, self.code_start, self.ac_match_table, self.ac_transition_table, self.ac_tables_size = unpack(self.data, '<QQQQQQ')

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
        buf = self.data.getbuffer()
        if OPTIONS_DUMP_RE_ASM:
            print('--- BEGIN REGEXP DISASM AT 0x%.8x ---' % ip)

        while True:
            opcode = RegexpOpcode(unpack2(buf, ip, '<B')[0])
            args = []

            if opcode == RegexpOpcode.RE_OPCODE_LITERAL:
                ip_inc = 2
                args.append(unpack2(buf, ip + 1, '<B')[0])
            elif opcode == RegexpOpcode.RE_OPCODE_MASKED_LITERAL:
                ip_inc = 3
                args.append(unpack2(buf, ip + 1, '<B')[0])
                args.append(unpack2(buf, ip + 2, '<B')[0])
            elif opcode in SPLIT_OPCODES:
                ip_inc = 4
                args.append(unpack2(buf, ip + 1, '<B')[0])
                args.append(unpack2(buf, ip + 2, '<h')[0])
            elif opcode in [RegexpOpcode.RE_OPCODE_REPEAT_ANY_UNGREEDY]:
                ip_inc = 5
                min_rep, max_rep = unpack2(buf, ip + 1, '<HH')
                args.append(min_rep)
                args.append(max_rep)
            elif opcode in [
                    RegexpOpcode.RE_OPCODE_REPEAT_START_GREEDY,
                    RegexpOpcode.RE_OPCODE_REPEAT_START_UNGREEDY,
                    RegexpOpcode.RE_OPCODE_REPEAT_END_GREEDY,
                    RegexpOpcode.RE_OPCODE_REPEAT_END_UNGREEDY
                ]:
                ip_inc = 9
                min_rep, max_rep, offset = unpack2(buf, ip+1, '<HHl')
                args.append(min_rep)
                args.append(max_rep)
                args.append(offset)
            elif opcode == RegexpOpcode.RE_OPCODE_JUMP:
                ip_inc = 3
                args.append(unpack2(buf, ip + 1, '<h')[0])
            elif opcode in [RegexpOpcode.RE_OPCODE_ANY]:
                ip_inc =  1
            elif opcode == RegexpOpcode.RE_OPCODE_MATCH:
                ip_inc = 1
            else:
                raise DecompileError('Unknown opcode' + repr(opcode))

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
        elif opcode == Opcode.OP_INIT_RULE:
            """
            typedef struct _YR_INIT_RULE_ARGS
            {
                DECLARE_REFERENCE(YR_RULE*, rule);
                DECLARE_REFERENCE(const uint8_t*, jmp_addr);

            } YR_INIT_RULE_ARGS;
            """
            args.append(unpack2(buf, ip + 1, '<Q')[0])
            args.append(unpack2(buf, ip + 9, '<Q')[0])
            next = [ip + 17]
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
        struct YR_META
        {
            int32_t type;
            YR_ALIGN(8) int64_t integer;

            DECLARE_REFERENCE(const char*, identifier);
            DECLARE_REFERENCE(char*, string);
        };
        '''
        fmt = '<LxxxxQQQ'
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
            # 
            addr += 4 * 4 + 8 * 5 + (24*_MAX_THREADS*2)

    def get_string(self, addr):
        '''
        struct YR_STRING
        {
            int32_t g_flags;
            int32_t length;

            DECLARE_REFERENCE(char*, identifier);
            DECLARE_REFERENCE(uint8_t*, string);
            DECLARE_REFERENCE(YR_STRING*, chained_to);
            DECLARE_REFERENCE(YR_RULE*, rule);

            int32_t chain_gap_min;
            int32_t chain_gap_max;

            int64_t fixed_offset;

            YR_MATCHES matches[YR_MAX_THREADS];
            YR_MATCHES unconfirmed_matches[YR_MAX_THREADS];
        };
        '''

        buf = self.data.getbuffer()
        g_flags, length, identifier, str_data, chained_to, rule, chain_gap_min, chain_gap_max, fixed_offset = unpack2(buf, addr, '<LLQQQQLLQ' + 'x' * (24*_MAX_THREADS*2))

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
        struct YR_RULE
        {
            int32_t g_flags;                  // Global flags
            int32_t t_flags[YR_MAX_THREADS];  // Thread-specific flags

            DECLARE_REFERENCE(const char*, identifier);
            DECLARE_REFERENCE(const char*, tags);
            DECLARE_REFERENCE(YR_META*, metas);
            DECLARE_REFERENCE(YR_STRING*, strings);
            DECLARE_REFERENCE(YR_NAMESPACE*, ns);
            int32_t num_atoms;
            volatile int64_t time_cost;
            int64_t time_cost_per_thread[YR_MAX_THREADS];
        }; padding = 8, size = 0x1c0
        '''
        fmt = '<Q' + 'x' * (_MAX_THREADS * 4) + 'QQQQQ'
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
            c = self.get_rule(self.rules + i * 0x1c0)
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

            elif val['opcode'] == Opcode.OP_IMPORT: # ignore
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

        REs = self.parse_automaton()

        for ptr, re in REs:
            for rule in rules:
                for string in rule.data['strings_list']:
                    if string['ptr'] == ptr:
                        string['re'] = re

        return rules

    def parse_automaton(self):
        buf = self.data.getbuffer()
        self.automaton_addr_map = addr_map = {}
        # Actually we only need the match_table
        match_list = []

        for i in range(self.ac_tables_size):
            addr = unpack2(buf, self.ac_match_table + i * 8, '<Q')[0]
            while addr != 0:
                backtrack, string, forward_code, backward_code, nxt = unpack2(buf, addr, '<QQQQQ')
                fwcode, bwcode = [], []
                if forward_code != 0:
                    fwcode = list(self.regexp_disasm(forward_code))
                if backward_code != 0:
                    bwcode = list(self.regexp_disasm(backward_code))
                match_list.append({
                    'backtrack': backtrack,
                    'string': self.get_string(string),
                    'forward_code': fwcode,
                    'backward_code': bwcode,
                    'next': nxt
                })
                addr = nxt

        REs = []
        for match in match_list:
            ptr = match['string']['ptr']
            re = decompile_RE(match['forward_code'], match['backward_code'], match['string']['flags'])
            REs.append((ptr, re))
        return REs

