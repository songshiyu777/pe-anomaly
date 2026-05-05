"""Tests for PE parser and anomaly scanner using synthetic PE files."""

import struct
import tempfile
from pathlib import Path

import pytest

from pe_anomaly.parser import PEParser
from pe_anomaly.scanner import scan, Severity


def _build_minimal_pe32(sections=None, imports=None, tls_addr=0, entry_rva=0x1000) -> bytes:
    """Build a minimal valid PE32 file (x86)."""
    buf = bytearray()

    # -- DOS Header --
    buf.extend(b"MZ")
    buf.extend(b"\x00" * 0x3A)
    buf.extend(struct.pack("<I", 64))  # e_lfanew → PE signature at offset 64
    assert len(buf) == 64

    # -- PE Signature --
    buf.extend(b"PE\x00\x00")

    # -- COFF Header (20 bytes) --
    num_sections = len(sections) if sections else 2
    coff = struct.pack("<H H I I I H H",
        0x014C,     # Machine: x86
        num_sections,
        0,          # TimeDateStamp
        0,          # PointerToSymbolTable
        0,          # NumberOfSymbols
        0xE0,       # SizeOfOptionalHeader (224 for PE32)
        0x0102,     # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )
    buf.extend(coff)

    # -- Optional Header (PE32, 224 bytes) --
    data_dir_count = 16
    opt = bytearray()

    def w(fmt, *args):
        opt.extend(struct.pack(fmt, *args))

    w("<H B B I", 0x10B, 0, 0, 0)             # Magic, linker ver (1+1), SizeOfCode
    w("<I", 0)                                  # SizeOfInitializedData
    w("<I", 0)                                  # SizeOfUninitializedData
    w("<I", entry_rva)                          # AddressOfEntryPoint
    w("<I", 0x1000)                             # BaseOfCode
    w("<I", 0)                                  # BaseOfData (PE32 only)
    w("<I", 0x00400000)                         # ImageBase
    w("<I", 0x1000)                             # SectionAlignment
    w("<I", 0x200)                              # FileAlignment
    w("<H", 4)                                  # MajorOperatingSystemVersion
    w("<H", 0)                                  # MinorOperatingSystemVersion
    w("<H", 0)                                  # MajorImageVersion
    w("<H", 0)                                  # MinorImageVersion
    w("<H", 4)                                  # MajorSubsystemVersion
    w("<H", 0)                                  # MinorSubsystemVersion
    w("<I", 0)                                  # Win32VersionValue (reserved)
    w("<I", 0)                                  # SizeOfImage
    w("<I", 0x200)                              # SizeOfHeaders
    w("<I", 0)                                  # CheckSum
    w("<H", 2)                                  # Subsystem (2=GUI)
    w("<H", 0x8000)                             # DllCharacteristics
    w("<I", 0x100000)                           # SizeOfStackReserve
    w("<I", 0x1000)                             # SizeOfStackCommit
    w("<I", 0x100000)                           # SizeOfHeapReserve
    w("<I", 0x1000)                             # SizeOfHeapCommit
    w("<I", 0)                                  # LoaderFlags (reserved)
    w("<I", data_dir_count)                     # NumberOfRvaAndSizes

    # Data directories (16 * 8 bytes)
    opt.extend(b"\x00" * (16 * 8))
    assert len(opt) == 224, f"Opt header size: {len(opt)}"

    buf.extend(opt)

    # -- Section headers (40 bytes each) --
    if not sections:
        sections = [
            (".text", 0x1000, 0x200, 0x200, 0x60000020),
            (".rdata", 0x2000, 0x200, 0x200, 0x40000040),
        ]

    for name, vaddr, vsize, rsize, chars in sections:
        sh = bytearray()
        name_bytes = name.encode("ascii")[:8]
        sh.extend(name_bytes + b"\x00" * (8 - len(name_bytes)))
        sh.extend(struct.pack("<I I I I I I H H I",
            vsize, vaddr, rsize, len(buf) + 40 * num_sections,
            0, 0, 0, 0, chars))
        assert len(sh) == 40
        buf.extend(sh)

    # Pad to FileAlignment
    while len(buf) < 0x200:
        buf.append(0)

    # -- Section data --
    for name, vaddr, vsize, rsize, chars in sections:
        data = b"\xCC" * min(rsize, 0x200)  # INT3 filler
        buf.extend(data)
        while len(buf) % 0x200 != 0:
            buf.append(0)

    return bytes(buf)


class TestPEParser:
    _tmp = None
    path = None

    @classmethod
    def setup_class(cls):
        data = _build_minimal_pe32()
        cls._tmp = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        cls._tmp.write(data)
        cls._tmp.close()
        cls.path = Path(cls._tmp.name)

    @classmethod
    def teardown_class(cls):
        if cls.path:
            try:
                cls.path.unlink(missing_ok=True)
            except OSError:
                pass

    def test_parse_valid_pe(self):
        with PEParser(self.path) as pe:
            info = pe.parse()
            assert not info.is_64bit
            assert info.machine == 0x014C
            assert info.number_of_sections == 2

    def test_sections(self):
        with PEParser(self.path) as pe:
            info = pe.parse()
            names = {s.name for s in info.sections}
            assert ".text" in names
            assert ".rdata" in names

    def test_entry_point(self):
        with PEParser(self.path) as pe:
            info = pe.parse()
            assert info.entry_point == 0x1000

    def test_not_pe(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"This is not a PE file!")
            bad = Path(f.name)
        try:
            with pytest.raises((ValueError, EOFError)):
                with PEParser(bad) as pe:
                    pe.parse()
        finally:
            try:
                bad.unlink(missing_ok=True)
            except OSError:
                pass


class TestScanner:
    _tmp = None
    path = None

    @classmethod
    def setup_class(cls):
        # Build a suspicious PE with anomalies
        sections = [
            (".text",   0x1000, 0x200, 0x200, 0x60000020),  # CODE + EXECUTE + READ
            (".themida", 0x2000, 0x500000, 0, 0xE0000020),  # Virtual section, EXECUTE+READ
            (".data",   0x502000, 0x200, 0x200, 0xC0000040),  # RWX
        ]
        data = _build_minimal_pe32(sections=sections)
        cls._tmp = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        cls._tmp.write(data)
        cls._tmp.close()
        cls.path = Path(cls._tmp.name)

    @classmethod
    def teardown_class(cls):
        if cls.path:
            try:
                cls.path.unlink(missing_ok=True)
            except OSError:
                pass

    def test_scan_suspicious(self):
        with PEParser(self.path) as pe:
            info = pe.parse()
            result = scan(info)
            assert len(result.findings) > 0
            assert result.risk_level in (Severity.HIGH, Severity.CRITICAL)

    def test_virtual_section_detected(self):
        with PEParser(self.path) as pe:
            info = pe.parse()
            result = scan(info)
            rules = {f.rule for f in result.findings}
            assert "virtual-section" in rules or "packer-section-name" in rules

    def test_rwx_detected(self):
        with PEParser(self.path) as pe:
            info = pe.parse()
            result = scan(info)
            rules = {f.rule for f in result.findings}
            assert "writable-executable" in rules

    def test_clean_pe(self):
        sections = [
            (".text", 0x1000, 0x200, 0x200, 0x60000020),
            (".rdata", 0x2000, 0x200, 0x200, 0x40000040),
        ]
        data = _build_minimal_pe32(sections=sections)
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(data)
            clean = Path(f.name)
        try:
            with PEParser(clean) as pe:
                info = pe.parse()
                result = scan(info)
                assert result.risk_level != Severity.CRITICAL
        finally:
            clean.unlink(missing_ok=True)
