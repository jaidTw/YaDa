from typing import List
from collections import OrderedDict
import io
import struct
import json

from utils import unpack, unpack2
from yara_const import Opcode, StrFlag, RuleFlag, MetaType, _MAX_THREADS, UNDEFINED
from yara_const import NO_ARG_OPCODES, SINGLE_ARG_OPCODES, TWO_ARG_OPCODES, IGNORED_OPCODES
from yara_const import SINGLE_ARG_NO_PARENTHESES, SINGLE_ARG_HAS_PARENTHESES, MAX_TABLE_BASED_STATES_DEPTH

rules_table = {}


OPTIONS_OUTPUT_ASM = False
OPTIONS_OUTPUT_TREE = False

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

def optimize_walk(node):
    if node.type == 'val':
        return

    # TODO: should we do constant folding or constant propagation?
    if node.data == Opcode.OP_PUSH:   # eliminate push nodes
        node.type = 'val'
        node.data = node.childs[0].data
        node.childs = []

    for child in node.childs:
        optimize_walk(child)

def AC_to_RE(root, start=1):
    EPSILON = b''
    def _flatten(state, graph):
        state_id = graph['N']
        if len(state['matches']) > 0:
            graph['ac'].append((state_id, state['matches']))
        for sym, to in state['transitions'].items():
            dfs_no = graph['N']
            if not state_id in graph:
                graph[state_id] = {sym: dfs_no  + 1}
            else:
                graph[state_id][sym] = dfs_no + 1
            graph['N'] += 1
            _flatten(to, graph)

    graph = {'N': 1, 'ac': []}
    _flatten(root, graph)

    accept = graph['ac']
    n = graph['N']
    re_table = [[[None for _ in range(n+1)] for _ in range(n+1)] for _ in range(n+1)]

    for k in range(n+1):
        for i in range(1, n+1):
            for j in range(1, n+1):
                if k == 0:
                    r = None
                    if i == j:
                        r = EPSILON
                    elif i in graph:
                        for sym, state in graph[i].items():
                            if state == j:
                                r = sym
                else:
                    # Rij^k = Rij^k-1 + R
                    r = re_table[k-1][i][j]
                    s = None
                   
                    re1, re2, re3 = re_table[k-1][i][k], re_table[k-1][k][k], re_table[k-1][k][j]
                    if re1 != None and re2 != None and re3 != None:
                        if re2 != EPSILON:
                            if len(re2) > 1:
                                re2 = b'(' + re2 + b')'
                            s = re1 + re2 + b'*' + re3
                        else:
                            if re1 == EPSILON and re3 == EPSILON:
                                s = EPSILON
                            else:
                                s = re1 + re3

                    if r == None:
                        r = s
                    elif r != s and s != None:
                        if len(r) > 1:
                            r = b'(' + r + b')'
                        r = r + b'|' + s
                
                re_table[k][i][j]= r

    return [(re_table[n][start][j], *inf) for j, *inf in accept]


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

    def __repr__(self):
        return str(self)

    def __str__(self):
        if self.type == 'val':
            return f'{{"data": {json.dumps(self.data, default=str)}}}'
        else:
            return f'{{"data": "{str(self.data)}", "childs": {self.childs}}}'

    def pretty(self):
        out = ''
        if self.type == 'val':
            arg_id = None
            try:
                arg_id = self.data[1]['identifier']
            except:
                pass
            if arg_id != None and any(arg_id) and arg_id.isascii():
                out += str(arg_id)
            else:
                out += str(self.data[0])
        else:
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

#        out += self.asm()
        out += self.condition()
        out += '\n}\n'

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
            elif opcode in IGNORED_OPCODES:
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
        #print(self.AST)

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
        out = '\tcondition:\n\t\t'
        node = self.AST
        out += node.pretty()
        return out

    def optimize(self):
        if self.AST:
            optimize_walk(self.AST)


class v11:
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

                #print('reloc: 0x%.8x: 0x%.8x' % (reloc, reloc_target))

                reloc = unpack(stream, '<L')[0]
        except struct.error:
            print("Invalid file (bad relocs)")
            return False
        return True

    def _disasm(self, ip):
        self.data.seek(ip)
        opcode = Opcode(self.data.read(1)[0])

        if opcode in (
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

            Opcode.OP_JNUNDEF,
            Opcode.OP_JLE,
            Opcode.OP_JTRUE,
            Opcode.OP_JFALSE,

            Opcode.OP_PUSH,
            ):
            return ip + 9, opcode, (unpack(self.data, '<Q')[0], )
        else:
            return ip + 1, opcode, ()

    def disasm(self):
        ip = self.code_start
        while True:
            ip, opcode, args = self._disasm(ip)
            yield (ip, opcode, args)

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
                try:
                    args.append(self.get_string(arg))
                except struct.error as exc:
                    pass
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
                    matches.append(dict(
                        ptr=match_ptr,
                        backtrack=backtrack,
                        string=string_obj,
                        forward_code=forward_code,
                        backward_code=backward_code,
                        ))
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
            data['str'] = '{' + ' '.join(['{:X}'.format(x) for x in str_str]) + '}'
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

        if strings:
            data['strings_list'] = list(self.get_strings(strings))
            data['strings_map'] = { s['ptr']: s for s in data['strings_list'] }
        else:
            data['strings_list'] = []
            data['strings_map'] = {}

        return data

    def parse(self):
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

    def parse_rules(self) -> List[YaraRule]:
        global rules_table
        rules = list(self.get_rules())
        rules_table = {}
        addr_rules_map = { r.data['ptr']: r for r in rules }
        self.parse()

        cur_rule = None
        for val in self.code.values():
            if val['opcode'] == Opcode.OP_INIT_RULE:
                cur_rule = addr_rules_map[val['args'][0]]

                rules_table[cur_rule.data['ptr']] = cur_rule
            elif val['opcode'] == Opcode.OP_HALT:
                break
            elif val['opcode'] == Opcode.OP_IMPORT:
                continue

            cur_rule.data['code'].append(val)

        for rule in rules_table.values():
            rule.build_AST()
            rule.optimize()
            self.addr_string_map.update(rule.data['strings_map'])

        self.parse_automaton()
        
        self.REs = AC_to_RE(self.automaton_root)

        return list(rules_table.values())
