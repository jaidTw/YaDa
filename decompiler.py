from typing import List
from collections import OrderedDict
import io
import struct

from utils import unpack, unpack2
from yara_const import Opcode, StrFlag, RuleFlag, MetaType, _MAX_THREADS, UNDEFINED, SINGLE_ARG_OPCODES, DOUBLE_ARG_OPCODES, MAX_TABLE_BASED_STATES_DEPTH

OPTIONS_OUTPUT_ASM = True
OPTIONS_OUTPUT_TREE = True

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
        Opcode.OP_INT_EQ: '==',
        Opcode.OP_INT_NEQ: '!=',
        Opcode.OP_INT_ADD: '+',
        Opcode.OP_AND: 'and',
        Opcode.OP_OR: 'or',
        Opcode.OP_UINT8: 'uint8',
        Opcode.OP_UINT16: 'uint16',
        Opcode.OP_FOUND: '',
        Opcode.OP_FOUND_AT: 'at',
        Opcode.OP_UINT32BE: 'uint32be',
        Opcode.OP_UINT32: 'uint32',
        Opcode.OP_NOT: 'not',
    }
    return TABLE[op]
    #return TABLE.get(op) or repr(op)

def optimize_walk(node):
    if node.type == 'val':
        return

    # TODO: should we do constant folding or constant propagation?
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
        """
        Print underlying tree structure
        """
        if self.type == 'val':
            out = str(self.data[0])
        else:
            out = str(self.data)
            out += f' childs={self.childs}'
        return f'<Node {out}>'

    def as_tree(self, depth=0):
        indent = ' ' * (depth * 4)
        out = [indent, '<Node type=%s ' % self.type]

        if self.type == 'val':
            out.append(str(self.data[0]))
        else:
            out.append(str(self.data))
            out.append(f' childs=[\n')
            for i in self.childs:
                if i.as_tree:
                    out.extend([i.as_tree(depth + 1), ',\n'])
                else:
                    out.extend([indent, '    ', repr(out)])
            out.append(f'{indent}]')

        out.append('>')
        return ''.join(out)

    def __repr__(self):
        return self.as_tree()

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
            elif self.data in DOUBLE_ARG_OPCODES:
                lchild = self.childs[1]
                rchild = self.childs[0]
                lhs = lchild.pretty()
                if lchild.type != 'val' and lchild.data in DOUBLE_ARG_OPCODES:
                    lhs = f'({lhs})'
                rhs = self.childs[0].pretty()
                if rchild.type != 'val' and rchild.data in DOUBLE_ARG_OPCODES:
                    rhs = f'({rhs})'
                if self.data == Opcode.OP_FOUND_AT:
                    lhs, rhs = rhs, lhs
                out += f'{lhs} {stringify(self.data)} {rhs}'

            elif self.data in SINGLE_ARG_OPCODES:
                out += f'{stringify(self.data)} ({self.childs[0].pretty()})'

            elif self.data == Opcode.OP_OF:
                n = self.childs[-1]
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

                out += f'({lhs} of {rhs})'
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
                    out += ' = /UNRECOVERABLE_REGEXP/ /* regex is unrecoverable right now. flags = %s */' % string['flags']

                if string['flags'] & StrFlag.FULL_WORD:
                    out += ' fullword'
                # ASCII is the default
                # if string['flags'] & StrFlag.ASCII:
                #    out += ' ascii'
                if string['flags'] & StrFlag.WIDE:
                    out += ' wide'
                if string['flags'] & StrFlag.NO_CASE:
                    out += ' nocase'
                if string['flags'] & StrFlag.REGEXP:
                    out += ' regex'
                out += '\n'

        if OPTIONS_OUTPUT_ASM:
            out += self.print_asm()
        if self.AST:
            try:
                out += self.print_decompile()
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
            if opcode in [Opcode.OP_PUSH, Opcode.OP_PUSH_RULE]:
                node = Node(opcode, 'op', self)
                node.append(Node(inst['args'], 'val', self))
                stack.append(node)

            elif opcode in SINGLE_ARG_OPCODES:
                node = Node(opcode, 'op', self)
                node.append(stack.pop())
                stack.append(node)

            elif opcode in DOUBLE_ARG_OPCODES:
                node = Node(opcode, 'op', self)
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

            elif opcode in (Opcode.OP_INIT_RULE, Opcode.OP_JFALSE, Opcode.OP_JTRUE, Opcode.OP_MATCH_RULE):
                pass

            else:
                self.AST = None
                return

        self.AST = stack.pop()

    def print_asm(self):
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

    def print_decompile(self):
        out = '\tcondition:\n'
        node = self.AST
        out += '\t\t' + node.pretty()
        return out

    def optimize(self):
        if self.AST:
            optimize_walk(self.AST)


class v11:
    def __init__(self, stream, size):
        self.size = size
        self.data = io.BytesIO(stream.read(size))
        self.code = OrderedDict()

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
        else:
            data['ns'] = ''

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
        rules = list(self.get_rules())
        addr_rules_map = { r.data['ptr']: r for r in rules }

        self.parse()
        cur_rule = None
        for val in self.code.values():
            if val['opcode'] == Opcode.OP_INIT_RULE:
                cur_rule = addr_rules_map[val['args'][0]]

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

        return rules

    def parse_automaton(self):
        buf = self.data.getbuffer()
        self.automaton_addr_map = addr_map = {}
        root = unpack2(buf, self.automaton, 'Q')[0]
        queue = [root]
        self.automaton_root = addr_map.setdefault(root, {})

        while queue:
            addr = queue.pop(0)
            node = addr_map.setdefault(addr, {})
            if node: # visited?
                continue
            if not addr:
                continue

            depth, failure, matches, *transitions = unpack2(buf, addr, '<B' + 'Q' * (2 + 256))
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
