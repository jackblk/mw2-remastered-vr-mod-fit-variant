"""Porting and crash-triage tool for the MW2CR 1.1.2.1279292 accessibility variant.

See docs/accessibility-variant-port.md for the porting loop. Paths come from
--game-dir or %OVERLORD_GAME_DIR% (the folder with MW2CR.exe, overlord.exe,
overlord.log, diagnose/ and minidumps/); --exe or %MW2CR_EXE% overrides the
game binary. Optional packages: capstone (disassembly, references), numpy
(reference search) and minidump (crash dumps).

Porting:
  unwrapped              raw data literals in src/client, each checked against the binary
  data-refs [ADDR...]    code references to official data addresses at +0, -0x1000, +0x1000
  hook-bytes             expected byte arrays in src/client: exact, data-tolerant or unmatched

Binary:
  sections               PE sections of MW2CR.exe
  disasm ADDR...         disassemble around addresses, RIP-relative targets resolved
  refs LO [HI]           instructions whose RIP-relative operand targets LO or [LO, HI)
  callers ADDR...        direct call/jmp sites of functions
  disp VALUE...          instructions encoding a 32-bit displacement (image-relative RVAs)
  strings TEXT...        strings containing TEXT and the code that loads them

Run and crash:
  logs                   errors and diagnostics from overlord.log, status report, newest dumps
  crash [DMP]            exception, registers and unwound stack (default: newest minidump)
  mem DMP ADDR:LEN...    memory captured in a minidump
  sym OFFSET...          overlord.exe offsets to function and source line (needs the PDB)
"""
from __future__ import annotations

import argparse
import bisect
import ctypes
import os
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "client"
DATA_BEGIN = 0x140BE8000  # official .data; the variant maps it 0x1000 lower
IMAGE_END = 0x151E6BC00   # official image end
DATA_DELTA = -0x1000
DATA_LITERAL = re.compile(r"0[xX](1[45][0-9A-Fa-f]{7})(?![0-9A-Fa-f])")
# Already relocated, or marked `// variant-keep` (an official address on purpose).
WRAPPED = re.compile(r"relocate\(0x|data_address|symbol<|read_only_global|variant-keep")
CODE = 0x20  # IMAGE_SCN_CNT_CODE; the variant marks every section executable


def need(module: str):
    try:
        return __import__(module)
    except ImportError:
        raise SystemExit(f"This command needs the '{module}' package: python -m pip install {module}")


def is_data(address: int) -> bool:
    return DATA_BEGIN <= address < IMAGE_END


class Pe:
    """A PE file on disk, addressed by virtual address at its preferred or a given base."""

    def __init__(self, path: Path, base: int | None = None):
        self.path = path
        self.data = path.read_bytes()
        nt = struct.unpack_from("<I", self.data, 0x3C)[0]
        count = struct.unpack_from("<H", self.data, nt + 6)[0]
        optional = struct.unpack_from("<H", self.data, nt + 20)[0]
        self.base = base if base is not None else struct.unpack_from("<Q", self.data, nt + 24 + 24)[0]
        self.size = struct.unpack_from("<I", self.data, nt + 24 + 56)[0]
        self.sections = []
        for index in range(count):
            offset = nt + 24 + optional + index * 40
            name, vsize, rva, rsize, raw = struct.unpack_from("<8sIIII", self.data, offset)
            flags = struct.unpack_from("<I", self.data, offset + 36)[0]
            self.sections.append((name.rstrip(b"\0").decode(errors="replace"), rva, vsize, raw, rsize, flags))
        exception_rva, exception_size = struct.unpack_from("<II", self.data, nt + 24 + 112 + 3 * 8)
        table = self.read_rva(exception_rva, exception_size) or b""
        self.functions = sorted(struct.unpack_from("<III", table, i) for i in range(0, len(table) - 11, 12))
        self._starts = [f[0] for f in self.functions]

    def read_rva(self, rva: int, size: int) -> bytes | None:
        for _, start, _, raw, rsize, _ in self.sections:
            if start <= rva < start + rsize:
                return self.data[raw + rva - start:raw + min(rva - start + size, rsize)]
        return None

    def read(self, address: int, size: int) -> bytes | None:
        return self.read_rva(address - self.base, size)

    def contains(self, address: int) -> bool:
        return self.base <= address < self.base + self.size

    def function(self, address: int) -> tuple[int, int, int] | None:
        """RUNTIME_FUNCTION (begin, end, unwind) RVAs containing address."""
        index = bisect.bisect_right(self._starts, address - self.base) - 1
        if index >= 0 and self.functions[index][0] <= address - self.base < self.functions[index][1]:
            return self.functions[index]
        return None

    def code(self):
        """(start address, bytes) of each code section."""
        for _, rva, _, raw, rsize, flags in self.sections:
            if flags & CODE:
                yield self.base + rva, self.data[raw:raw + rsize]

    def address_of_offset(self, offset: int) -> int | None:
        for _, rva, _, raw, rsize, _ in self.sections:
            if raw <= offset < raw + rsize:
                return self.base + rva + offset - raw
        return None


class Disassembler:
    def __init__(self, pe: Pe):
        capstone = need("capstone")
        self.pe = pe
        self.engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.engine.detail = True
        self.x86 = __import__("capstone.x86", fromlist=["X86_OP_MEM", "X86_REG_RIP"])

    def one(self, address: int, code: bytes | None = None):
        code = code if code is not None else self.pe.read(address, 16)
        return next(self.engine.disasm(code or b"", address), None)

    def rip_target(self, instruction) -> int | None:
        for operand in instruction.operands:
            if operand.type == self.x86.X86_OP_MEM and operand.mem.base == self.x86.X86_REG_RIP:
                return instruction.address + instruction.size + operand.mem.disp
        return None

    def text(self, instruction) -> str:
        target = self.rip_target(instruction)
        suffix = f"    ; -> {target:#x}" if target is not None else ""
        return f"{instruction.address:#x}  {instruction.bytes.hex():<24} {instruction.mnemonic} {instruction.op_str}{suffix}"


def rip_references(pe: Pe, disassembler: Disassembler, wanted) -> list[tuple[int, int, object]]:
    """Verified RIP-relative references: (target, instruction address, instruction) for targets
    accepted by wanted(numpy array of targets) -> boolean mask."""
    np = need("numpy")
    found = {}
    for start, code in pe.code():
        if len(code) < 8:
            continue
        array = np.frombuffer(code, dtype=np.uint8)
        n = len(code) - 4
        displacement = (array[:n].astype(np.int64) | (array[1:n + 1].astype(np.int64) << 8) |
                        (array[2:n + 2].astype(np.int64) << 16) | (array[3:n + 3].astype(np.int64) << 24))
        displacement = np.where(displacement >= 2 ** 31, displacement - 2 ** 32, displacement)
        position = np.arange(n, dtype=np.int64)
        for immediate in (0, 1, 2, 4):
            targets = start + position + 4 + immediate + displacement
            for p in np.nonzero(wanted(targets))[0].tolist():
                for back in range(1, 11):
                    if p - back < 0:
                        break
                    address = start + p - back
                    instruction = disassembler.one(address, code[p - back:p - back + 15])
                    if instruction and instruction.size == back + 4 + immediate:
                        target = disassembler.rip_target(instruction)
                        if target == int(targets[p]):
                            found[address] = (target, address, instruction)
                            break
    return sorted(found.values(), key=lambda item: item[1])


def game_dir(args) -> Path:
    directory = args.game_dir or os.environ.get("OVERLORD_GAME_DIR")
    if not directory:
        raise SystemExit("Set --game-dir or %OVERLORD_GAME_DIR% to the game folder.")
    return Path(directory)


def game_binary(args) -> Pe:
    path = Path(args.exe or os.environ.get("MW2CR_EXE") or game_dir(args) / "MW2CR.exe")
    return Pe(path)


def source_literals():
    """(path, line number, line, address) for every data literal in src/client."""
    for path in sorted(SOURCE.rglob("*")):
        if path.suffix not in (".cpp", ".hpp", ".h"):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            for match in DATA_LITERAL.finditer(line):
                address = int(match.group(1), 16)
                if is_data(address):
                    yield path, number, line, address, match.start()


def count_references(pe: Pe, addresses: list[int]) -> dict[int, tuple[int, int, int]]:
    np = need("numpy")
    probe = sorted({a + shift for a in addresses for shift in (0, DATA_DELTA, -DATA_DELTA)})
    probe_array = np.array(probe, dtype=np.int64)
    hits = rip_references(pe, Disassembler(pe), lambda targets: np.isin(targets, probe_array))
    counts: dict[int, int] = {}
    for target, _, _ in hits:
        counts[target] = counts.get(target, 0) + 1
    return {a: (counts.get(a, 0), counts.get(a + DATA_DELTA, 0), counts.get(a - DATA_DELTA, 0)) for a in addresses}


def verdict(same: int, moved: int, other: int) -> str:
    if moved and not same:
        return "shifted (relocate)"
    if same and not moved:
        return "NOT shifted (check by hand)"
    if not same and not moved:
        return "no RIP reference (check by hand)"
    return "ambiguous (check by hand)"


# ---- porting ----------------------------------------------------------------------------------

def command_unwrapped(args) -> int:
    rows = []
    for path, number, line, address, column in source_literals():
        comment = line.find("//")
        if WRAPPED.search(line) or 0 <= comment < column:
            continue
        rows.append((path.relative_to(ROOT).as_posix(), number, line.strip(), address))
    if not rows:
        print("No unwrapped data literals.")
        return 0
    counts = count_references(game_binary(args), sorted({r[3] for r in rows})) if not args.no_binary else {}
    for path, number, line, address in rows:
        detail = ""
        if counts:
            same, moved, other = counts[address]
            detail = f"  [+0={same} -0x1000={moved} +0x1000={other}: {verdict(same, moved, other)}]"
        print(f"{path}:{number}: {address:#x}{detail}\n    {line[:160]}")
    return 1


def command_data_refs(args) -> int:
    addresses = [int(a, 16) for a in args.address] or sorted({row[3] for row in source_literals()})
    for address, (same, moved, other) in count_references(game_binary(args), addresses).items():
        print(f"{address:#x}  +0={same:<4} -0x1000={moved:<4} +0x1000={other:<4} {verdict(same, moved, other)}")
    return 0


def command_hook_bytes(args) -> int:
    pe = game_binary(args)
    array = re.compile(r"\{\s*((?:0x[0-9A-Fa-f]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})){4,})\s*,?\s*\}")
    address = re.compile(r"0x14[0-9A-Fa-f]{7}(?![0-9A-Fa-f])")

    def tolerant(start: int, expected: bytes) -> bool:
        actual = pe.read(start, len(expected) + 4)
        if not actual or len(actual) < len(expected) + 4:
            return False
        index = 0
        while index < len(expected):
            if actual[index] == expected[index]:
                index += 1
                continue
            for window in range(max(0, index - 3), index + 1):
                want = bytes(expected[window + j] if window + j < len(expected) else actual[window + j]
                             for j in range(4))
                value = struct.unpack("<i", want)[0]
                if struct.unpack_from("<i", actual, window)[0] - value != DATA_DELTA:
                    continue
                if is_data(pe.base + (value & 0xFFFFFFFF)) or any(
                        is_data(start + window + 4 + k + value) for k in (0, 1, 2, 4)):
                    index = window + 4
                    break
            else:
                return False
        return True

    totals = {"exact": 0, "tolerant": 0, "unmatched": 0}
    for path in sorted(SOURCE.rglob("*")):
        if path.suffix not in (".cpp", ".hpp") or "scene_surface_storage_contract" in path.name:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        addresses = sorted({int(m.group(), 16) for m in address.finditer(text)})
        for match in array.finditer(text):
            values = [int(v, 0) for v in re.split(r"\s*,\s*", match.group(1))]
            if any(v > 255 for v in values):
                continue
            expected = bytes(values)
            candidates = [a + k for a in addresses for k in range(-16, 17)]
            where = f"{path.relative_to(ROOT).as_posix()}:{text.count(chr(10), 0, match.start()) + 1}"
            if any(pe.read(c, len(expected)) == expected for c in candidates):
                totals["exact"] += 1
            elif hit := next((c for c in candidates if tolerant(c, expected)), None):
                totals["tolerant"] += 1
                if args.verbose:
                    print(f"tolerant  {where} @{hit:#x}")
            else:
                totals["unmatched"] += 1
                if args.verbose and len(values) >= 6 and len(set(values)) >= 4:
                    print(f"unmatched {where} {expected.hex()[:40]}")
    print(" ".join(f"{k}={v}" for k, v in totals.items()))
    print("unmatched includes data tables and patterns near no literal address; -v lists code-like ones.")
    return 0


# ---- binary -----------------------------------------------------------------------------------

def command_sections(args) -> int:
    pe = game_binary(args)
    print(f"{pe.path}  base={pe.base:#x} image size={pe.size:#x}")
    for name, rva, vsize, _, rsize, flags in pe.sections:
        print(f"  {name:<9} {pe.base + rva:#x}  virtual={vsize:#x} raw={rsize:#x}"
              f"{'  code' if flags & CODE else ''}")
    return 0


def command_disasm(args) -> int:
    pe = game_binary(args)
    disassembler = Disassembler(pe)
    for text in args.address:
        address = int(text, 16)
        function = pe.function(address)
        # Decode from the function start so the window is instruction-aligned.
        start = pe.base + function[0] if function else address - args.before
        end = pe.base + function[1] if function and args.function else address + args.length
        low = start if args.function else address - args.before
        print(f"== {address:#x}" + (f" in function {start:#x}" if function else " (no .pdata entry; may be misaligned)"))
        for instruction in disassembler.engine.disasm(pe.read(start, end - start) or b"", start):
            if instruction.address >= low:
                print((">> " if instruction.address == address else "   ") + disassembler.text(instruction))
    return 0


def command_refs(args) -> int:
    pe = game_binary(args)
    low = int(args.low, 16)
    high = int(args.high, 16) if args.high else low + 1
    for target, address, instruction in rip_references(pe, Disassembler(pe), lambda t: (t >= low) & (t < high)):
        function = pe.function(address)
        owner = f"{pe.base + function[0]:#x}" if function else "?"
        print(f"{address:#x} (function {owner}) {instruction.mnemonic} {instruction.op_str} -> {target:#x}")
    return 0


def command_callers(args) -> int:
    np = need("numpy")
    pe = game_binary(args)
    for text in args.address:
        target = int(text, 16)
        print(f"target {target:#x}")
        for start, code in pe.code():
            array = np.frombuffer(code, dtype=np.uint8)
            n = len(code) - 5
            if n <= 0:
                continue
            rel = (array[1:n + 1].astype(np.int64) | (array[2:n + 2].astype(np.int64) << 8) |
                   (array[3:n + 3].astype(np.int64) << 16) | (array[4:n + 4].astype(np.int64) << 24))
            rel = np.where(rel >= 2 ** 31, rel - 2 ** 32, rel)
            position = np.arange(n, dtype=np.int64)
            opcode = array[:n]
            for p in np.nonzero((start + position + 5 + rel == target) & ((opcode == 0xE8) | (opcode == 0xE9)))[0]:
                address = start + int(p)
                function = pe.function(address)
                owner = f"{pe.base + function[0]:#x}" if function else "?"
                print(f"  {'call' if code[p] == 0xE8 else 'jmp '} {address:#x} in function {owner}")
    return 0


def command_disp(args) -> int:
    pe = game_binary(args)
    disassembler = Disassembler(pe)
    for text in args.value:
        value = int(text, 16)
        pattern = struct.pack("<I", value & 0xFFFFFFFF)
        for start, code in pe.code():
            seen = set()
            index = code.find(pattern)
            while index >= 0:
                for back in range(1, 10):
                    instruction = disassembler.one(start + index - back, code[index - back:index - back + 15])
                    if instruction and instruction.size >= back + 4 and f"{value:#x}" in instruction.op_str \
                            and instruction.address not in seen:
                        seen.add(instruction.address)
                        function = pe.function(instruction.address)
                        owner = f"{pe.base + function[0]:#x}" if function else "?"
                        print(f"{instruction.address:#x} (function {owner}) {instruction.mnemonic} {instruction.op_str}")
                index = code.find(pattern, index + 1)
    return 0


def command_strings(args) -> int:
    pe = game_binary(args)
    disassembler = Disassembler(pe)
    for text in args.text:
        for match in re.finditer(re.escape(text.encode()), pe.data):
            start = match.start()
            while start > 0 and pe.data[start - 1] != 0:
                start -= 1
            address = pe.address_of_offset(start)
            if address is None:
                continue
            value = pe.data[start:pe.data.index(b"\0", start)]
            print(f"string {value[:120]!r} at {address:#x}")
            for _, site, instruction in rip_references(pe, disassembler, lambda t: t == address):
                function = pe.function(site)
                owner = f"{pe.base + function[0]:#x}" if function else "?"
                print(f"   {site:#x} (function {owner}) {instruction.mnemonic} {instruction.op_str}")
    return 0


# ---- run and crash ----------------------------------------------------------------------------

LOG_PATTERN = re.compile(r"error|fatal|fail|exception|com_error|assert|\[VR diag\]|warn", re.I)
STATUS_PATTERN = re.compile(r"^(runtime:|engine stereo bridge:)|strict_preflight|openxr_frame_submission")


def command_logs(args) -> int:
    directory = game_dir(args)
    log = directory / "overlord.log"
    if log.exists():
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        hits = [(n, l) for n, l in enumerate(lines, 1) if LOG_PATTERN.search(l)]
        print(f"== {log} ({len(lines)} lines, {len(hits)} matching; showing the last {args.limit})")
        for number, line in hits[-args.limit:]:
            print(f"{number:>6}: {line[:200]}")
        print(f"-- last {args.tail} lines")
        for line in lines[-args.tail:]:
            print(f"        {line[:200]}")
    else:
        print(f"no {log}")
    for status in (directory / "diagnose" / "overlord-status-latest.txt", directory / "overlord-status-latest.txt"):
        if status.exists():
            print(f"== {status}")
            for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
                if STATUS_PATTERN.search(line.strip()):
                    print(f"   {line.strip()[:200]}")
            break
    dumps = sorted((directory / "minidumps").glob("*.dmp"), key=lambda p: p.stat().st_mtime)
    print(f"== newest minidumps in {directory / 'minidumps'}")
    for dump in dumps[-3:]:
        print(f"   {dump.name}")
    return 0


def newest_dump(args) -> Path:
    if args.dump:
        return Path(args.dump)
    dumps = sorted((game_dir(args) / "minidumps").glob("*.dmp"), key=lambda p: p.stat().st_mtime)
    if not dumps:
        raise SystemExit("No minidumps found.")
    return dumps[-1]


def crashed_build(deployed: Path, dump: Path) -> Path:
    """The overlord.exe that wrote the dump: the deployed one, or, if it was replaced after the crash,
    the copy in the first tools/deploy_local.py backup made after the dump."""
    crashed_at = dump.stat().st_mtime
    if not deployed.exists() or deployed.stat().st_mtime <= crashed_at:
        return deployed
    import datetime
    for backup in sorted((ROOT / "output" / "deployments").glob("*Z-*")):
        stamp = datetime.datetime.strptime(backup.name.split("-")[0], "%Y%m%dT%H%M%SZ")
        if stamp.replace(tzinfo=datetime.timezone.utc).timestamp() >= crashed_at \
                and (backup / "overlord.exe").exists():
            return backup / "overlord.exe"
    print(f"warning: {deployed} is newer than the dump and no later backup has overlord.exe; "
          "pass --overlord with the crashed build")
    return deployed


class Symbols:
    """dbghelp lookups for overlord.exe; the PDB is searched beside the executable."""

    def __init__(self, executable: Path, base: int):
        self.ok = False
        if sys.platform != "win32" or not executable.exists():
            return
        from ctypes import wintypes
        self.wintypes = wintypes
        self.dbghelp = ctypes.WinDLL("dbghelp.dll")
        self.handle = wintypes.HANDLE(0x0BE1)
        self.dbghelp.SymSetOptions(0x2 | 0x10)  # UNDNAME | LOAD_LINES
        if not self.dbghelp.SymInitializeW(self.handle, ctypes.c_wchar_p(str(executable.parent)), False):
            return
        self.dbghelp.SymLoadModuleExW.restype = ctypes.c_uint64
        self.ok = bool(self.dbghelp.SymLoadModuleExW(self.handle, None, ctypes.c_wchar_p(str(executable)), None,
                                                     ctypes.c_uint64(base), 0, None, 0))

    def __call__(self, address: int) -> str:
        if not self.ok:
            return ""
        wintypes = self.wintypes

        class SymbolInfo(ctypes.Structure):
            _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG),
                        ("Reserved", ctypes.c_uint64 * 2), ("Index", wintypes.ULONG), ("Size", wintypes.ULONG),
                        ("ModBase", ctypes.c_uint64), ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64),
                        ("Address", ctypes.c_uint64), ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG),
                        ("Tag", wintypes.ULONG), ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG),
                        ("Name", ctypes.c_wchar * 512)]

        class Line(ctypes.Structure):
            _fields_ = [("SizeOfStruct", wintypes.DWORD), ("Key", ctypes.c_void_p), ("LineNumber", wintypes.DWORD),
                        ("FileName", ctypes.c_wchar_p), ("Address", ctypes.c_uint64)]

        symbol = SymbolInfo()
        symbol.SizeOfStruct = 88  # sizeof(SYMBOL_INFOW) with its one-character Name
        symbol.MaxNameLen = 512
        displacement = ctypes.c_uint64()
        text = ""
        if self.dbghelp.SymFromAddrW(self.handle, ctypes.c_uint64(address), ctypes.byref(displacement),
                                     ctypes.byref(symbol)):
            text = f"{symbol.Name}+{displacement.value:#x}"
        line = Line()
        line.SizeOfStruct = ctypes.sizeof(Line)
        line_displacement = wintypes.DWORD()
        if self.dbghelp.SymGetLineFromAddrW64(self.handle, ctypes.c_uint64(address), ctypes.byref(line_displacement),
                                              ctypes.byref(line)):
            text += f" ({Path(line.FileName).name}:{line.LineNumber})"
        return text


REGISTERS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]


def unwind_frame(pe: Pe, context: dict[str, int], read) -> int | None:
    """Unwind one frame with the image's .pdata/.xdata; returns the function start RVA."""
    function = pe.function(context["rip"])
    if function is None:  # leaf
        context["rip"] = read(context["rsp"])
        context["rsp"] += 8
        return None
    begin, _, info = function
    offset = context["rip"] - pe.base - begin
    first, machine_frame = True, False
    while True:
        header = pe.read_rva(info, 4)
        flags, count = header[0] >> 3, header[2]
        frame_register, frame_offset = header[3] & 0xF, (header[3] >> 4) * 16
        codes = pe.read_rva(info + 4, count * 2 + 4)
        index = 0
        while index < count:
            code_offset, operation = codes[index * 2], codes[index * 2 + 1]
            op, op_info = operation & 0xF, operation >> 4
            slots = {0: 1, 1: 3 if op_info else 2, 2: 1, 3: 1, 4: 2, 5: 3, 8: 2, 9: 3, 10: 1}[op]
            if not first or code_offset <= offset:
                if op == 0:
                    context[REGISTERS[op_info]] = read(context["rsp"])
                    context["rsp"] += 8
                elif op == 1:
                    context["rsp"] += (struct.unpack_from("<H", codes, index * 2 + 2)[0] * 8 if op_info == 0
                                       else struct.unpack_from("<I", codes, index * 2 + 2)[0])
                elif op == 2:
                    context["rsp"] += op_info * 8 + 8
                elif op == 3:
                    context["rsp"] = context[REGISTERS[frame_register]] - frame_offset
                elif op == 4:
                    context[REGISTERS[op_info]] = read(context["rsp"] + struct.unpack_from("<H", codes, index * 2 + 2)[0] * 8)
                elif op == 5:
                    context[REGISTERS[op_info]] = read(context["rsp"] + struct.unpack_from("<I", codes, index * 2 + 2)[0])
                elif op == 10:
                    base = context["rsp"] + (8 if op_info else 0)
                    context["rip"], context["rsp"] = read(base), read(base + 24)
                    machine_frame = True
            index += slots
        first = False
        if flags & 4:  # chained unwind info
            chained = info + 4 + ((count + 1) & ~1) * 2
            _, _, info = struct.unpack_from("<III", pe.read_rva(chained, 12))
            continue
        break
    if not machine_frame:
        context["rip"] = read(context["rsp"])
        context["rsp"] += 8
    return begin


def command_crash(args) -> int:
    need("minidump")
    from minidump.minidumpfile import MinidumpFile
    path = newest_dump(args)
    dump = MinidumpFile.parse(str(path))
    reader = dump.get_reader()
    print(f"== {path}")
    report = path.with_suffix(".txt")
    if report.exists():
        print(report.read_text(errors="replace").strip())
    if not dump.exception or not dump.exception.exception_records:
        raise SystemExit("The dump has no exception record.")
    record = dump.exception.exception_records[0]
    print(f"exception {record.ExceptionRecord.ExceptionCode} at {record.ExceptionRecord.ExceptionAddress:#x}"
          f" parameters {[hex(p) for p in record.ExceptionRecord.ExceptionInformation]}")
    raw = path.read_bytes()
    location = record.ThreadContext
    values = struct.unpack_from("<17Q", raw[location.Rva:location.Rva + location.DataSize], 0x78)
    context = dict(zip(REGISTERS + ["rip"], values))
    print("  ".join(f"{k}={v:#x}" for k, v in context.items()))

    modules = [(m.baseaddress, m.size, m.name) for m in dump.modules.modules]
    host = next(((b, s, n) for b, s, n in modules if Path(n).name.lower().startswith("overlord")), None)
    images = [(game_binary(args), "h2")]
    if host:
        executable = Path(args.overlord) if args.overlord else crashed_build(Path(host[2]), path)
        images.append((Pe(executable, host[0]), "overlord"))
        symbols = Symbols(executable, host[0])
        print(f"overlord.exe {executable} at {host[0]:#x}" + ("" if symbols.ok else " (no symbols)"))
    else:
        symbols = None

    def read(address: int) -> int:
        return struct.unpack("<Q", reader.read(address, 8))[0]

    def describe(address: int) -> str:
        for pe, tag in images:
            if pe.contains(address):
                if tag == "h2":
                    function = pe.function(address)
                    return f"h2 {address:#x}" + (f" (function {pe.base + function[0]:#x})" if function else "")
                name = symbols(address) if symbols else ""
                return f"overlord+{address - pe.base:#x} {name}"
        owner = next((Path(n).name for b, s, n in modules if b <= address < b + s), "?")
        return f"{owner} {address:#x}"

    print("-- unwound stack")
    for depth in range(args.depth):
        rip = context["rip"]
        image = next((pe for pe, _ in images if pe.contains(rip)), None)
        print(f"{depth:>3} {describe(rip)}")
        if image is None:
            print("    (frame outside MW2CR/overlord; use --scan)")
            break
        try:
            unwind_frame(image, context, read)
        except Exception as error:  # noqa: BLE001 - a broken frame ends the walk
            print(f"    (unwind failed: {error}; use --scan)")
            break
    if args.scan:
        print("-- stack scan (values that look like return addresses; may be stale)")
        rsp = values[4]
        data = b""
        while len(data) < 0x8000:
            try:
                data += reader.read(rsp + len(data), 0x1000 - ((rsp + len(data)) & 0xFFF))
            except Exception:  # noqa: BLE001 - end of captured stack
                break
        for offset in range(0, len(data) - 7, 8):
            value = struct.unpack_from("<Q", data, offset)[0]
            if any(pe.contains(value) and (tag != "h2" or pe.function(value)) for pe, tag in images):
                print(f"  {rsp + offset:#x}: {describe(value)}")
    return 0


def command_mem(args) -> int:
    need("minidump")
    from minidump.minidumpfile import MinidumpFile
    reader = MinidumpFile.parse(args.dump).get_reader()
    for item in args.range:
        address, size = (int(x, 16) for x in item.split(":"))
        try:
            print(f"{address:#x}  {reader.read(address, size).hex(' ', 4)}")
        except Exception as error:  # noqa: BLE001 - not captured in the dump
            print(f"{address:#x}  unavailable ({error})")
    return 0


def command_sym(args) -> int:
    executable = Path(args.overlord) if args.overlord else game_dir(args) / "overlord.exe"
    base = 0x160000000
    symbols = Symbols(executable, base)
    if not symbols.ok:
        raise SystemExit(f"Could not load symbols for {executable} (the PDB must sit beside it).")
    for text in args.offset:
        print(f"{text}  {symbols(base + int(text, 16))}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--game-dir", help="Game folder (default: %%OVERLORD_GAME_DIR%%)")
    parser.add_argument("--exe", help="MW2CR.exe to analyze (default: %%MW2CR_EXE%% or <game dir>/MW2CR.exe)")
    commands = parser.add_subparsers(dest="command", required=True)

    command = commands.add_parser("unwrapped", help="raw data literals in src/client")
    command.add_argument("--no-binary", action="store_true", help="Skip the reference check")
    command.set_defaults(run=command_unwrapped)
    command = commands.add_parser("data-refs", help="reference counts for data addresses")
    command.add_argument("address", nargs="*", help="Official addresses (default: all in src/client)")
    command.set_defaults(run=command_data_refs)
    command = commands.add_parser("hook-bytes", help="expected byte arrays vs the binary")
    command.add_argument("-v", "--verbose", action="store_true")
    command.set_defaults(run=command_hook_bytes)

    commands.add_parser("sections", help="PE sections").set_defaults(run=command_sections)
    command = commands.add_parser("disasm", help="disassemble around addresses")
    command.add_argument("address", nargs="+")
    command.add_argument("--before", type=lambda v: int(v, 0), default=0x30)
    command.add_argument("--length", type=lambda v: int(v, 0), default=0x40)
    command.add_argument("--function", action="store_true", help="Disassemble the whole containing function")
    command.set_defaults(run=command_disasm)
    command = commands.add_parser("refs", help="RIP-relative references to an address or range")
    command.add_argument("low")
    command.add_argument("high", nargs="?")
    command.set_defaults(run=command_refs)
    command = commands.add_parser("callers", help="direct call/jmp sites")
    command.add_argument("address", nargs="+")
    command.set_defaults(run=command_callers)
    command = commands.add_parser("disp", help="instructions encoding a 32-bit displacement")
    command.add_argument("value", nargs="+")
    command.set_defaults(run=command_disp)
    command = commands.add_parser("strings", help="strings and the code that loads them")
    command.add_argument("text", nargs="+")
    command.set_defaults(run=command_strings)

    command = commands.add_parser("logs", help="overlord.log, status report and dumps")
    command.add_argument("--limit", type=int, default=60)
    command.add_argument("--tail", type=int, default=15)
    command.set_defaults(run=command_logs)
    command = commands.add_parser("crash", help="analyze a minidump")
    command.add_argument("dump", nargs="?", help="Minidump (default: newest in <game dir>/minidumps)")
    command.add_argument("--overlord", help="overlord.exe of the crashed build (default: the dump's path)")
    command.add_argument("--depth", type=int, default=40)
    command.add_argument("--scan", action="store_true", help="Also scan the stack for return addresses")
    command.set_defaults(run=command_crash)
    command = commands.add_parser("mem", help="memory captured in a minidump")
    command.add_argument("dump")
    command.add_argument("range", nargs="+", metavar="ADDR:LEN")
    command.set_defaults(run=command_mem)
    command = commands.add_parser("sym", help="overlord.exe offsets to symbols")
    command.add_argument("offset", nargs="+")
    command.add_argument("--overlord", help="overlord.exe (default: <game dir>/overlord.exe)")
    command.set_defaults(run=command_sym)

    args = parser.parse_args()
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
