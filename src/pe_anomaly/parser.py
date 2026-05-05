"""PE file parser — PE32 and PE32+ (x64), no external deps."""

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple, Union


DOS_MAGIC = 0x5A4D  # 'MZ'
PE_SIGNATURE = 0x00004550  # 'PE\x00\x00'
PE32_MAGIC = 0x10B
PE32PLUS_MAGIC = 0x20B

# Data directory indices
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_SECURITY = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_TLS = 9
DIR_LOAD_CONFIG = 10
DIR_IAT = 12

DIR_NAMES = {
    0: "EXPORT", 1: "IMPORT", 2: "RESOURCE", 3: "EXCEPTION",
    4: "SECURITY", 5: "BASERELOC", 6: "DEBUG", 7: "ARCHITECTURE",
    8: "GLOBALPTR", 9: "TLS", 10: "LOAD_CONFIG", 11: "BOUND_IMPORT",
    12: "IAT", 13: "DELAY_IMPORT", 14: "COM_DESCRIPTOR",
}

# Section characteristics
class SecChar(IntFlag):
    TYPE_NO_PAD = 0x00000008
    CNT_CODE = 0x00000020
    CNT_INITIALIZED_DATA = 0x00000040
    CNT_UNINITIALIZED_DATA = 0x00000080
    MEM_EXECUTE = 0x20000000
    MEM_READ = 0x40000000
    MEM_WRITE = 0x80000000

# Known packer section names
KNOWN_PACKER_SECTIONS = {
    ".themida", ".boot", ".tsu", ".stub",
    "upx0", "upx1", "upx2", "UPX0", "UPX1", "UPX2",
    ".aspack", ".adata",
    ".petite",
    ".mpress1", ".mpress2",
    ".enigma1", ".enigma2",
    ".vmp0", ".vmp1", ".vmp2",
    ".obsidium",
    ".pklstb",
    ".pebundle",
    ".y0da",
    ".sforce",
    "nsp0", "nsp1", "nsp2",
    ".xscript",
    "Code",  # VMProtect
}


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & SecChar.MEM_EXECUTE)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & SecChar.MEM_WRITE)

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & SecChar.MEM_READ)

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & SecChar.CNT_CODE)

    @property
    def is_virtual(self) -> bool:
        return self.raw_size == 0 and self.virtual_size > 0

    @property
    def perms(self) -> str:
        p = ""
        p += "r" if self.is_readable else "-"
        p += "w" if self.is_writable else "-"
        p += "x" if self.is_executable else "-"
        return p


@dataclass
class ImportDLL:
    name: str
    functions: List[str] = field(default_factory=list)


@dataclass
class TLSCallback:
    address: int


@dataclass
class PEInfo:
    path: Path
    file_size: int
    is_64bit: bool
    machine: int
    number_of_sections: int
    entry_point: int
    image_base: int
    subsystem: int
    sections: List[Section] = field(default_factory=list)
    imports: List[ImportDLL] = field(default_factory=list)
    tls_callbacks: List[TLSCallback] = field(default_factory=list)
    data_directories: Dict[int, Tuple[int, int]] = field(default_factory=dict)


class PEParser:

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        self._file: Optional[BinaryIO] = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()

    def open(self):
        self._file = open(self.path, "rb")

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def _read(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        data = self._file.read(size)
        if len(data) < size:
            raise EOFError(f"Short read at 0x{offset:X}: expected {size}, got {len(data)}")
        return data

    def _read_cstr(self, offset: int, maxlen: int = 128) -> str:
        raw = self._read(offset, maxlen)
        end = raw.find(b"\x00")
        return raw[:end].decode("ascii", errors="replace") if end >= 0 else raw.decode("ascii", errors="replace")

    def parse(self) -> PEInfo:
        dos = self._read(0, 64)
        if struct.unpack_from("<H", dos, 0)[0] != DOS_MAGIC:
            raise ValueError("Not a PE file: missing 'MZ' signature")

        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        pe_sig = struct.unpack_from("<I", self._read(pe_offset, 4), 0)[0]
        if pe_sig != PE_SIGNATURE:
            raise ValueError("Not a PE file: missing 'PE\\x00\\x00' signature")

        coff_start = pe_offset + 4
        coff = self._read(coff_start, 20)
        machine = struct.unpack_from("<H", coff, 0)[0]
        num_sections = struct.unpack_from("<H", coff, 2)[0]
        opt_header_size = struct.unpack_from("<H", coff, 16)[0]

        opt_start = coff_start + 20
        opt = self._read(opt_start, opt_header_size)
        magic = struct.unpack_from("<H", opt, 0)[0]
        is_64bit = magic == PE32PLUS_MAGIC
        if magic not in (PE32_MAGIC, PE32PLUS_MAGIC):
            raise ValueError(f"Unknown PE optional header magic: 0x{magic:04X}")

        entry_point = struct.unpack_from("<I", opt, 16)[0]
        image_base = struct.unpack_from("<Q" if is_64bit else "<I", opt, 24 if is_64bit else 28)[0]
        subsystem = struct.unpack_from("<H", opt, 68 if is_64bit else 68)[0]

        # Data directories
        dd_offset = opt_start + (112 if is_64bit else 96)
        dd_count_offset = 108 if is_64bit else 92
        dd_count = struct.unpack_from("<I", opt, dd_count_offset)[0]
        dirs = {}
        for i in range(min(dd_count, 16)):
            va, size = struct.unpack_from("<I I", self._read(dd_offset + i * 8, 8), 0)
            if va and size:
                dirs[i] = (va, size)

        # Sections
        section_start = dd_offset + dd_count * 8
        sections = []
        for i in range(num_sections):
            sh = self._read(section_start + i * 40, 40)
            name = sh[:8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize = struct.unpack_from("<I", sh, 8)[0]
            vaddr = struct.unpack_from("<I", sh, 12)[0]
            rsize = struct.unpack_from("<I", sh, 16)[0]
            roff = struct.unpack_from("<I", sh, 20)[0]
            chars = struct.unpack_from("<I", sh, 36)[0]

            entropy = 0.0
            if rsize > 0:
                try:
                    entropy = _calc_entropy(self._read(roff, min(rsize, 1048576)))
                except EOFError:
                    pass

            sections.append(Section(
                name=name,
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_offset=roff,
                raw_size=rsize,
                characteristics=chars,
                entropy=entropy,
            ))

        # Imports
        imports = self._parse_imports(dirs, sections)

        # TLS
        tls_callbacks = self._parse_tls(dirs, sections, is_64bit)

        return PEInfo(
            path=self.path,
            file_size=Path(self.path).stat().st_size,
            is_64bit=is_64bit,
            machine=machine,
            number_of_sections=num_sections,
            entry_point=entry_point,
            image_base=image_base,
            subsystem=subsystem,
            sections=sections,
            imports=imports,
            tls_callbacks=tls_callbacks,
            data_directories=dirs,
        )

    def _rva_to_offset(self, rva: int, sections: List[Section]) -> Optional[int]:
        for s in sections:
            if s.virtual_address <= rva < s.virtual_address + s.virtual_size:
                return s.raw_offset + (rva - s.virtual_address)
        return None

    def _parse_imports(self, dirs: dict, sections: List[Section]) -> List[ImportDLL]:
        if DIR_IMPORT not in dirs:
            return []
        va, _ = dirs[DIR_IMPORT]
        imports = []

        try:
            off = self._rva_to_offset(va, sections)
            if off is None:
                return imports

            while True:
                desc = self._read(off, 20)
                name_rva = struct.unpack_from("<I", desc, 12)[0]
                iat_rva = struct.unpack_from("<I", desc, 16)[0]
                if name_rva == 0:
                    break

                name_off = self._rva_to_offset(name_rva, sections)
                dll_name = self._read_cstr(name_off) if name_off else "?"

                iat_off = self._rva_to_offset(iat_rva, sections) if iat_rva else None
                funcs = []
                if iat_off:
                    for _ in range(64):
                        entry = self._read(iat_off, 8)
                        addr = struct.unpack_from("<Q", entry, 0)[0]
                        if addr == 0:
                            break
                        if addr & 0x8000000000000000:
                            ordinal = addr & 0xFFFF
                            funcs.append(f"#{ordinal}")
                        iat_off += 8

                imports.append(ImportDLL(name=dll_name, functions=funcs))
                off += 20

        except (EOFError, struct.error):
            pass

        return imports

    def _parse_tls(self, dirs: dict, sections: List[Section], is_64bit: bool) -> List[TLSCallback]:
        if DIR_TLS not in dirs:
            return []
        va, _ = dirs[DIR_TLS]
        callbacks = []

        try:
            off = self._rva_to_offset(va, sections)
            if off is None:
                return callbacks

            tls = self._read(off, 64)
            cb_rva = struct.unpack_from("<Q" if is_64bit else "<I", tls,
                                        24 if is_64bit else 16)[0]
            if cb_rva == 0:
                return callbacks

            cb_off = self._rva_to_offset(cb_rva, sections)
            if cb_off is None:
                return callbacks

            for _ in range(32):
                addr = struct.unpack_from("<Q" if is_64bit else "<I",
                                          self._read(cb_off, 8), 0)[0]
                if addr == 0:
                    break
                callbacks.append(TLSCallback(address=addr))
                cb_off += 8

        except (EOFError, struct.error):
            pass

        return callbacks


def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
