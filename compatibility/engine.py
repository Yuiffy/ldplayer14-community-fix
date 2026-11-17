"""Offline, bounded compatibility proofs. This module never opens a process."""

import bisect
import hashlib
import json
import re
import struct
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import capstone as cs
import pefile

ENGINE_VERSION = 1
MAX_NODES = 4096
MAX_CODE_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024


class Incompatible(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Incompatible(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fingerprint(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


class Image:
    def __init__(self, path):
        require(cs.__version__ == '5.0.7' and pefile.__version__ == '2024.8.26',
                'Automatic adaptation requires capstone==5.0.7 and pefile==2024.8.26')
        self.path = Path(path)
        require(0 < self.path.stat().st_size <= MAX_FILE_BYTES, 'PE file size is outside the analysis limit')
        self.raw = self.path.read_bytes()
        self.sha256 = digest(self.raw)
        self.pe = pefile.PE(data=self.raw)
        require(self.pe.FILE_HEADER.Machine == 0x8664 and self.pe.OPTIONAL_HEADER.Magic == 0x20b,
                'Only AMD64 PE32+ images are supported')
        require(self.pe.OPTIONAL_HEADER.SizeOfImage <= MAX_FILE_BYTES, 'Mapped PE is too large')
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = self.pe.get_memory_mapped_image()
        self.sections = list(self.pe.sections)
        self.headers = SimpleNamespace(VirtualAddress=0, Misc_VirtualSize=self.pe.OPTIONAL_HEADER.SizeOfHeaders,
                                       Name=b'HEADERS', Characteristics=0x40000040)
        self.functions = sorted((e.struct.BeginAddress, e.struct.EndAddress, e.struct.UnwindData)
                                for e in getattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION', []))
        self.starts = [a for a, b, u in self.functions]
        self.imports = {}
        for library in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
            for imp in library.imports:
                self.imports[imp.address - self.base] = (
                    library.dll.decode().lower() + '!' +
                    (imp.name.decode() if imp.name else '#' + str(imp.ordinal)))
        self.relocations = set()
        for block in getattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC', []):
            for entry in block.entries:
                require(entry.type in (0, 10), 'Unsupported PE relocation kind')
                if entry.type == 10:
                    self.relocations.add(entry.rva)
        self.dis = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.dis.detail = True

    def section(self, rva, length=1):
        if 0 <= rva and rva + length <= self.headers.Misc_VirtualSize:
            return self.headers
        for section in self.sections:
            if section.VirtualAddress <= rva and rva + length <= section.VirtualAddress + section.Misc_VirtualSize:
                return section
        raise Incompatible('Reference outside mapped section: ' + hex(rva))

    def executable(self, rva):
        return bool(self.section(rva).Characteristics & 0x20000000)

    def read(self, rva, length):
        self.section(rva, length)
        require(rva >= 0 and rva + length <= len(self.data), 'Truncated image range')
        return self.data[rva:rva + length]

    def bounds(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0:
            a, b, u = self.functions[i]
            if a <= rva < b:
                return a, b, u
        return None

    def unwind(self, rva):
        bounds = self.bounds(rva)
        if bounds is None:
            return None
        a, b, u = bounds
        header = self.read(u, 4)
        require(header[0] & 7 in (1, 2), 'Unsupported x64 unwind format at ' + hex(rva) + ': ' + header.hex())
        # Preserve the exact prologue, stack frame and unwind codes. Handler
        # addresses are not unwind opcodes; handler code is outside our stubs.
        codes = self.read(u, 4 + header[2] * 2)
        return [a - rva, b - rva, digest(codes)]

    def node(self, rva, size=None):
        require(self.executable(rva), 'Code reference points to non-executable data')
        bounds = self.bounds(rva)
        if size is None and bounds:
            size = bounds[1] - rva
        if size is None:
            # A metadata-free leaf/thunk ends at its first return or jump.
            length = min(16384, self.section(rva).VirtualAddress + self.section(rva).Misc_VirtualSize - rva)
            decoded = self.dis.disasm(self.read(rva, length), self.base + rva)
            ending = next((i for i in decoded if i.group(cs.CS_GRP_RET) or i.mnemonic == 'jmp'), None)
            require(ending is not None, 'Unbounded metadata-free code at ' + hex(rva))
            size = ending.address - self.base + ending.size - rva
        require(0 < size <= 65536, 'Function size is outside the analysis limit')
        raw = self.read(rva, size)
        instructions = list(self.dis.disasm(raw, self.base + rva))
        # LLVM sometimes includes a relative switch table at the end of the
        # unwind range. Accept only a complete table whose every entry names
        # a decoded instruction inside this same function. Its bytes stay
        # unmasked, so both table shape and all branch offsets must agree.
        code_size = size
        boundaries = {i.address - self.base for i in instructions}
        for ins in instructions:
            if ins.mnemonic != 'lea':
                continue
            for operand in ins.operands:
                if operand.type != cs.x86.X86_OP_MEM or operand.mem.base != cs.x86.X86_REG_RIP:
                    continue
                target = ins.address + ins.size + operand.mem.disp - self.base
                offset = target - rva
                if not (0 < offset < size and (size - offset) % 4 == 0 and size - offset >= 8):
                    continue
                entries = struct.unpack('<' + 'i' * ((size - offset) // 4), raw[offset:])
                if all(rva <= target + v < target and target + v in boundaries for v in entries):
                    code_size = min(code_size, offset)
        instructions = [i for i in instructions if i.address - self.base < rva + code_size]
        require(sum(i.size for i in instructions) == code_size, 'Undecodable code/data range at ' + hex(rva))
        masked = bytearray(raw)
        edges = []
        for ins in instructions:
            offset = ins.address - self.base - rva
            if any(o.type == cs.x86.X86_OP_MEM and o.mem.base == cs.x86.X86_REG_RIP for o in ins.operands):
                operand = next(o for o in ins.operands if o.type == cs.x86.X86_OP_MEM and o.mem.base == cs.x86.X86_REG_RIP)
                target = ins.address + ins.size + operand.mem.disp - self.base
                masked[offset + ins.disp_offset:offset + ins.disp_offset + ins.disp_size] = bytes(ins.disp_size)
                edges.append(self.edge(offset, target, rva, size))
            if ((ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL)) and ins.operands and
                    ins.operands[0].type == cs.x86.X86_OP_IMM):
                target = ins.operands[0].imm - self.base
                masked[offset + ins.imm_offset:offset + ins.imm_offset + ins.imm_size] = bytes(ins.imm_size)
                edges.append(self.edge(offset, target, rva, size))
        for address in sorted(self.relocations):
            if rva <= address < rva + size:
                require(address + 8 <= rva + size, 'Relocation crosses code boundary')
                target = struct.unpack('<Q', self.read(address, 8))[0] - self.base
                masked[address - rva:address - rva + 8] = bytes(8)
                edges.append(self.edge(address - rva, target, rva, size))
        coverage = [[a - rva, b - rva, self.unwind(a)[2]] for a, b, u in self.functions
                    if a < rva + size and b > rva]
        return {'size': size, 'code_size': code_size, 'hash': digest(masked),
                'unwind': self.unwind(rva), 'coverage': coverage, 'edges': edges}

    def edge(self, offset, target, start, size):
        if start <= target < start + size:
            return [offset, 'internal', target - start]
        if target in self.imports:
            return [offset, 'import', self.imports[target]]
        return [offset, 'code' if self.executable(target) else 'data', target]

    def data_node(self, rva):
        section = self.section(rva)
        start = rva & ~7
        size = min(24, section.VirtualAddress + section.Misc_VirtualSize - start)
        for address in sorted(self.relocations):
            if start <= address < start + size:
                size = max(size, address + 8 - start)
        require(size <= 64, 'Unbounded data proof window')
        value = bytearray(self.read(start, size))
        pointers, pointee_sections = [], []
        for address in sorted(self.relocations):
            if start <= address < start + size:
                require(address + 8 <= start + size, 'Data relocation crosses proof window')
                target = struct.unpack('<Q', self.read(address, 8))[0] - self.base
                value[address - start:address - start + 8] = bytes(8)
                if target in self.imports:
                    pointers.append([address - start, 'import', self.imports[target]])
                else:
                    pointers.append([address - start, 'code' if self.executable(target) else 'data', target])
                    target_section = self.section(target)
                    pointee_sections.append([address - start, target_section.Name.rstrip(b'\0').decode(),
                                             target_section.Characteristics])
        return {'section': section.Name.rstrip(b'\0').decode(),
                'flags': section.Characteristics, 'offset': rva - start, 'size': size,
                'hash': digest(value), 'pointers': pointers, 'pointee_sections': pointee_sections}

    def find(self, anchor):
        pattern = re.escape(bytes.fromhex(anchor))
        return [section.VirtualAddress + m.start() for section in self.sections
                if section.Characteristics & 0x20000000
                for m in re.finditer(pattern, section.get_data())]


def build_graph(image, roots):
    nodes, data, opaque = {}, {}, {}
    pending = deque((rva, size) for rva, size in roots.values())
    total = 0
    while pending:
        rva, size = pending.popleft()
        key = str(rva)
        if key in nodes:
            require(size is None or nodes[key]['size'] == size, 'Conflicting code ranges')
            continue
        node = image.node(rva, size)
        nodes[key] = node
        total += node['size']
        require(len(nodes) <= MAX_NODES and total <= MAX_CODE_BYTES, 'Code graph exceeds analysis limits')
        for offset, kind, target in node['edges']:
            if kind == 'code':
                pending.append((target, None))
            elif kind == 'data' and str(target) not in data:
                d = image.data_node(target)
                data[str(target)] = d
                require(len(data) <= MAX_NODES * 4, 'Data graph exceeds analysis limits')
    # Do not guess a call graph through arbitrary vtables. A pointer into the
    # proved graph must retain that identity. Other referenced code pointers
    # are accepted only at their original RVA with their entire unwind range
    # byte-for-byte unchanged (no address masking or automatic relocation).
    for d in data.values():
        for at, kind, target in d['pointers']:
            if kind == 'code' and str(target) not in nodes:
                bounds = image.bounds(target)
                size = bounds[1] - target if bounds is not None else image.node(target)['size']
                require(0 < size <= 1024 * 1024, 'Indirect code range exceeds limit')
                opaque[str(target)] = {'size': size, 'hash': digest(image.read(target, size)),
                                       'unwind': image.unwind(target)}
    def anchor(rva, size):
        length = min(9, size)
        for ins in image.dis.disasm(image.read(rva, size), image.base + rva):
            offset = ins.address - image.base - rva
            if offset >= length:
                break
            if any(o.type == cs.x86.X86_OP_MEM and o.mem.base == cs.x86.X86_REG_RIP for o in ins.operands):
                length = min(length, offset + ins.disp_offset)
            if ((ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL)) and ins.operands and
                    ins.operands[0].type == cs.x86.X86_OP_IMM):
                length = min(length, offset + ins.imm_offset)
        for address in image.relocations:
            if rva <= address < rva + length:
                length = address - rva
        require(length >= 2, 'Root has no stable literal anchor')
        return image.read(rva, length).hex()
    return {'source_sha256': image.sha256, 'nodes': nodes, 'data': data, 'opaque': opaque,
            'roots': {name: {'rva': rva, 'size': nodes[str(rva)]['size'],
                             'anchor': anchor(rva, nodes[str(rva)]['size'])}
                      for name, (rva, size) in roots.items()}}


def match_graph(image, template):
    """Match all direct dependencies and data identities, not isolated signatures."""
    mapping, reverse, data_mapping, data_delta = {}, {}, {}, {}
    pending = deque()
    for name, root in template['roots'].items():
        expected = template['nodes'][str(root['rva'])]
        candidates = []
        for rva in image.find(root['anchor']):
            try:
                node = image.node(rva, root['size'])
                if all(node[k] == expected[k] for k in ('hash', 'unwind', 'code_size', 'coverage')):
                    candidates.append(rva)
            except Incompatible:
                pass
        require(len(candidates) == 1, 'Root ' + name + ' has ' + str(len(candidates)) + ' compatible candidates')
        pending.append((root['rva'], candidates[0]))
    def bind_data(old, new, descriptor=None):
        previous = data_mapping.setdefault(old, new)
        require(previous == new, 'Data alias identity changed')
        baseline = descriptor or template['data'].get(str(old))
        if baseline is not None:
            actual = image.data_node(new)
            require([actual[k] for k in ('section', 'flags', 'offset', 'size', 'hash')] ==
                    [baseline[k] for k in ('section', 'flags', 'offset', 'size', 'hash')],
                    'Referenced data changed at ' + hex(old))
            delta_key = baseline['section']
            require(data_delta.setdefault(delta_key, new - old) == new - old,
                    'Referenced data layout changed in ' + delta_key)
            require(len(actual['pointers']) == len(baseline['pointers']), 'Data pointer layout changed')
            require(actual['pointee_sections'] == baseline['pointee_sections'], 'Data pointee section changed')
            for wanted, found in zip(baseline['pointers'], actual['pointers']):
                require(wanted[:2] == found[:2], 'Data pointer kind changed')
                if wanted[1] == 'code':
                    if str(wanted[2]) in template['nodes']:
                        pending.append((wanted[2], found[2]))
                    else:
                        opaque = template['opaque'][str(wanted[2])]
                        require(found[2] == wanted[2] and image.unwind(found[2]) == opaque['unwind'] and
                                digest(image.read(found[2], opaque['size'])) == opaque['hash'],
                                'Indirect code target moved or changed; review required')
                elif wanted[1] == 'data':
                    require(data_mapping.setdefault(wanted[2], found[2]) == found[2], 'Data pointer alias changed')
                    # Preserve pointee layout within each mapped section too.
                    section = image.section(found[2])
                    label = section.Name.rstrip(b'\0').decode()
                    require(data_delta.setdefault(label, found[2] - wanted[2]) == found[2] - wanted[2],
                            'Data pointee layout changed')
                else:
                    require(wanted[2] == found[2], 'Data import changed')
    total = 0
    while pending:
        old, new = pending.popleft()
        if old in mapping:
            require(mapping[old] == new, 'Code alias identity changed')
            continue
        require(new not in reverse or reverse[new] == old, 'Distinct functions merged')
        require(str(old) in template['nodes'], 'Dependency absent from baseline')
        expected = template['nodes'][str(old)]
        actual = image.node(new, expected['size'])
        require(all(actual[k] == expected[k] for k in ('hash', 'unwind', 'code_size', 'coverage')),
                'Code or unwind changed at dependency ' + hex(old))
        require(len(actual['edges']) == len(expected['edges']), 'Reference count changed')
        mapping[old], reverse[new] = new, old
        total += actual['size']
        require(len(mapping) <= MAX_NODES and total <= MAX_CODE_BYTES, 'Proof exceeds limits')
        for wanted, found in zip(expected['edges'], actual['edges']):
            require(wanted[:2] == found[:2], 'Reference kind or instruction offset changed')
            kind = wanted[1]
            if kind == 'code':
                pending.append((wanted[2], found[2]))
            elif kind == 'data':
                bind_data(wanted[2], found[2])
            else:
                require(wanted[2] == found[2], 'Internal branch or imported API changed')
    require(len(mapping) == len(template['nodes']), 'Not all baseline dependencies were proved')
    return mapping


def pipe_identity(image):
    """Metadata-only updates may pass; changed fastpipe implementation must stop."""
    result = []
    debug = []
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]
    if directory.Size:
        debug.append((directory.VirtualAddress, directory.Size))
    for item in getattr(image.pe, 'DIRECTORY_ENTRY_DEBUG', []):
        if item.struct.AddressOfRawData and item.struct.SizeOfData:
            debug.append((item.struct.AddressOfRawData, item.struct.SizeOfData))
    for section in image.sections:
        name = section.Name.rstrip(b'\0').decode()
        if name in ('.rsrc', '.reloc'):
            require(not section.Characteristics & 0xa0000000,
                    'Resource/relocation section is executable or writable')
            continue
        value = bytearray(image.read(section.VirtualAddress, section.Misc_VirtualSize))
        for start, size in debug:
            if section.VirtualAddress <= start and start + size <= section.VirtualAddress + len(value):
                value[start - section.VirtualAddress:start - section.VirtualAddress + size] = bytes(size)
        # Keep RVAs fixed here: moving code/data requires a new reviewed bridge.
        for address in image.relocations:
            if section.VirtualAddress <= address and address + 8 <= section.VirtualAddress + len(value):
                target = struct.unpack('<Q', image.read(address, 8))[0] - image.base
                struct.pack_into('<Q', value, address - section.VirtualAddress, target)
        result.append([name, section.VirtualAddress, section.Misc_VirtualSize,
                       section.Characteristics, digest(value)])
    # Loader-controlled state is part of implementation identity too. A new
    # TLS/exception/load-config directory or relocation table must not pass
    # merely because the corresponding section bytes happen to be unchanged.
    optional = image.pe.OPTIONAL_HEADER
    directories = [[i, d.VirtualAddress, d.Size] for i, d in enumerate(optional.DATA_DIRECTORY)
                   if i not in (2, 4, 6)]  # resources, Authenticode, debug metadata
    headers = {name: getattr(optional, name) for name in (
        'AddressOfEntryPoint', 'SectionAlignment', 'FileAlignment', 'SizeOfImage',
        'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit',
        'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags')}
    return fingerprint({'sections': result, 'imports': sorted(image.imports.items()),
                        'relocations': sorted(image.relocations), 'directories': directories,
                        'debug_ranges': sorted(debug), 'headers': headers,
                        'characteristics': image.pe.FILE_HEADER.Characteristics})


def runtime_guards(image, mapping, template, excluded=()):
    """Whole proved code, excluding the patch sites themselves, checked live."""
    ranges = sorted((new, new + template['nodes'][str(old)]['size']) for old, new in mapping.items())
    ranges.extend((int(rva), int(rva) + node['size']) for rva, node in template['opaque'].items())
    ranges.sort()
    merged = []
    for a, b in ranges:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(b, merged[-1][1])
        else:
            merged.append([a, b])
    guards = []
    for a, b in merged:
        points = sorted({a, b, *(v for lo, hi in excluded for v in (lo, hi) if a < v < b)})
        for lo, hi in zip(points, points[1:]):
            if any(x <= lo < y for x, y in excluded):
                continue
            require(not any(lo <= r < hi for r in image.relocations),
                    'Absolute code relocations need manual runtime-guard support')
            guards.append([lo, image.read(lo, hi - lo).hex()])
    return guards


def renderer_profile(image, pipe, baseline):
    require(pipe_identity(pipe) == baseline['pipe_identity'], 'fastpipe implementation changed; review required')
    template = baseline['renderer']
    mapping = match_graph(image, template)
    old_destructor = template['roots']['destructor']['rva']
    destructor = mapping[old_destructor]
    rvas = [destructor + offset for offset in (0x52, 0xe1, 0x16f)]
    def jump(a, b):
        return b'\xe9' + struct.pack('<i', b - a - 5)
    originals = ['662e0f1f8400000000000f1f4000', '662e0f1f8400000000000f1f440000', '488b8fc0040000']
    values = [bytes.fromhex('488b8fb8040000ffd6') + jump(rvas[0] + 9, rvas[1]),
              bytes.fromhex('488b8fc0040000') + jump(rvas[1] + 7, rvas[2] + 7) + b'\x90' * 3,
              jump(rvas[2], rvas[0]) + b'\x90' * 2]
    for rva, original in zip(rvas, originals):
        require(image.read(rva, len(bytes.fromhex(original))).hex() == original, 'Patch site is not original padding/code')
    page = min(rvas) & ~0xfff
    require(max(rva + len(value) for rva, value in zip(rvas, values)) <= page + 4096,
            'Patch crosses code pages; review required')
    excluded = [(rva, rva + len(value)) for rva, value in zip(rvas, values)]
    return {'version': 'auto-compatible-with-14.0.36.0', 'fastpipe_sha256': pipe.sha256,
            'patches': [[rva, original, value.hex()] for rva, original, value in zip(rvas, originals, values)],
            'guards': runtime_guards(image, mapping, template, excluded),
            'page_rva': page, 'proof_nodes': len(mapping)}


def driver_profile(image, baseline):
    template = baseline['driver']
    if template.get('mode') == 'image-equivalent':
        require(pipe_identity(image) == template['identity'],
                'NVIDIA implementation changed beyond the automatic proof boundary; manual review required')
        return {'version': 'auto-image-equivalent-to-621.01', 'rvas': dict(baseline['driver_rvas']),
                'guards': baseline['driver_guards'], 'proof_nodes': 0, 'proof_mode': 'image-equivalent'}
    mapping = match_graph(image, template)
    old = baseline['driver_rvas']
    rvas = {name: mapping[rva] for name, rva in old.items() if name in ('entry', 'thread_done', 'current_teb')}
    require(rvas['entry'] == image.pe.OPTIONAL_HEADER.AddressOfEntryPoint, 'Matched entry is not PE entry')
    # Decode the three known references after proving the complete code graph.
    done = rvas['thread_done']
    references = {edge[0]: edge for edge in image.node(done, 0x162)['edges']}
    rvas.update(tls_index=references[9][2], empty_heap=references[0x4b][2], main_heap=references[0xaf][2])
    tls = getattr(image.pe, 'DIRECTORY_ENTRY_TLS', None)
    require(tls is not None and tls.struct.AddressOfIndex - image.base == rvas['tls_index'], 'PE TLS index disagrees')
    require(rvas['empty_heap'] != rvas['main_heap'] and not image.executable(rvas['main_heap']), 'Invalid heap identities')
    callbacks = []
    cursor = tls.struct.AddressOfCallBacks - image.base
    for _ in range(32):
        address = struct.unpack('<Q', image.read(cursor, 8))[0]
        if not address:
            break
        callbacks.append(address - image.base)
        cursor += 8
    else:
        raise Incompatible('Unbounded TLS callback table')
    require(mapping[template['roots']['tls_detach']['rva']] in callbacks, 'Proved TLS detach is not registered')
    return {'version': 'auto-compatible-with-621.01', 'rvas': rvas,
            'guards': runtime_guards(image, mapping, template), 'proof_nodes': len(mapping)}
