from dataclasses import dataclass, field
from enum import Enum
from typing import List

from .parser import PEInfo, Section, DIR_TLS, KNOWN_PACKER_SECTIONS


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    rule: str
    severity: Severity
    summary: str
    detail: str = ""
    section_name: str = ""

    def format(self) -> str:
        labels = {
            Severity.LOW: "[LOW]",
            Severity.MEDIUM: "[MEDIUM]",
            Severity.HIGH: "[HIGH]",
            Severity.CRITICAL: "[CRIT]",
        }
        label = labels.get(self.severity, "[?]")
        ctx = f" ({self.section_name})" if self.section_name else ""
        return f"  {label} {self.summary}{ctx}"


@dataclass
class ScanResult:
    file_path: str
    summary: str
    findings: List[Finding] = field(default_factory=list)
    sections: List[Section] = field(default_factory=list)

    @property
    def risk_level(self) -> Severity:
        if any(f.severity == Severity.CRITICAL for f in self.findings):
            return Severity.CRITICAL
        if any(f.severity == Severity.HIGH for f in self.findings):
            return Severity.HIGH
        if any(f.severity == Severity.MEDIUM for f in self.findings):
            return Severity.MEDIUM
        if self.findings:
            return Severity.LOW
        return Severity.LOW

    def format_terminal(self) -> str:
        lines = []
        lines.append(f"File   : {self.file_path}")
        lines.append(f"Summary: {self.summary}")
        if not self.findings:
            lines.append("  No anomalies detected.")
            return "\n".join(lines)
        lines.append(f"Findings ({len(self.findings)}):")
        for f in self.findings:
            lines.append(f.format())
        lines.append(f"Risk   : {self.risk_level.name}")
        return "\n".join(lines)


def _check_virtual_sections(sections: List[Section]) -> List[Finding]:
    findings = []
    for s in sections:
        if s.is_virtual:
            findings.append(Finding(
                rule="virtual-section",
                severity=Severity.HIGH,
                summary=f"Virtual section: VSize={_fmt_size(s.virtual_size)}, RawSize=0",
                detail="This section exists only at runtime (decrypted/expanded in memory). "
                       "Common in Themida, WinLicense, and other code-virtualization protectors.",
                section_name=s.name,
            ))
    return findings


def _check_entropy(sections: List[Section]) -> List[Finding]:
    findings = []
    for s in sections:
        if s.entropy > 7.5:
            findings.append(Finding(
                rule="high-entropy",
                severity=Severity.HIGH,
                summary=f"High entropy: {s.entropy:.2f} (likely encrypted/compressed)",
                detail="Entropy above 7.5 strongly suggests encrypted or compressed payload. "
                       "Common in packed executables.",
                section_name=s.name,
            ))
        elif s.entropy > 6.8:
            findings.append(Finding(
                rule="elevated-entropy",
                severity=Severity.MEDIUM,
                summary=f"Elevated entropy: {s.entropy:.2f} (possibly packed)",
                detail="Entropy between 6.8 and 7.5 may indicate packing or obfuscation.",
                section_name=s.name,
            ))
    return findings


def _check_rwx_sections(sections: List[Section]) -> List[Finding]:
    findings = []
    for s in sections:
        if s.is_executable and s.is_writable and s.is_readable:
            if s.name in (".text", ".code", "CODE"):
                sev = Severity.MEDIUM
                extra = " Standard code section should not be writable."
            else:
                sev = Severity.CRITICAL
                extra = " This is a strong indicator of shellcode injection or JIT-based unpacking."
            findings.append(Finding(
                rule="writable-executable",
                severity=sev,
                summary=f"Section is RWX (read+write+execute){extra}",
                detail=f"Permissions: {s.perms}. "
                       f"Sections should not be both writable and executable.",
                section_name=s.name,
            ))
    return findings


def _check_sparse_imports(imports: list, sections: List[Section]) -> List[Finding]:
    if not imports:
        return []
    dll_count = len(imports)
    total_funcs = sum(len(d.functions) for d in imports)
    if dll_count <= 3 and total_funcs <= 15:
        return [Finding(
            rule="sparse-imports",
            severity=Severity.HIGH,
            summary=f"Sparse import table: {dll_count} DLLs, {total_funcs} functions",
            detail="Very few imports suggest the real code is packed/encrypted "
                   "and will be resolved at runtime. Common in Themida, VMProtect, etc.",
        )]
    if dll_count <= 5 and total_funcs <= 30:
        return [Finding(
            rule="sparse-imports",
            severity=Severity.MEDIUM,
            summary=f"Sparse import table: {dll_count} DLLs, {total_funcs} functions",
            detail="Relatively few imports — could indicate packing or a minimal executable.",
        )]
    return []


def _check_entry_point_section(info: PEInfo) -> List[Finding]:
    ep = info.entry_point
    containing = None
    for s in info.sections:
        if s.virtual_address <= ep < s.virtual_address + s.virtual_size:
            containing = s
            break

    if containing is None:
        return [Finding(
            rule="orphan-entry",
            severity=Severity.CRITICAL,
            summary=f"Entry point 0x{ep:X} not in any section",
            detail="The entry point RVA falls outside all section boundaries.",
        )]

    findings = []
    if containing.name.lower() in KNOWN_PACKER_SECTIONS:
        findings.append(Finding(
            rule="packer-entry-section",
            severity=Severity.HIGH,
            summary=f"Entry point in known packer section: {containing.name}",
            detail="The entry point lies within a section name commonly used by packers/protectors.",
            section_name=containing.name,
        ))

    if not containing.is_code and not containing.is_executable:
        findings.append(Finding(
            rule="entry-in-non-code",
            severity=Severity.MEDIUM,
            summary=f"Entry point in non-code section: {containing.name} ({containing.perms})",
            detail="Entry point should typically be in a code section with execute permission.",
            section_name=containing.name,
        ))

    return findings


def _check_section_names(sections: List[Section]) -> List[Finding]:
    findings = []
    names_lower = {s.name.lower() for s in sections}

    for s in sections:
        if s.name.lower() in KNOWN_PACKER_SECTIONS:
            findings.append(Finding(
                rule="packer-section-name",
                severity=Severity.MEDIUM,
                summary=f"Known packer section name: {s.name}",
                detail="This section name is associated with a known packer or protector.",
                section_name=s.name,
            ))

    # Check for non-standard section names
    standard = {".text", ".rdata", ".data", ".pdata", ".idata", ".edata",
                ".reloc", ".rsrc", ".tls", ".bss", ".crt", ".xdata"}
    for s in sections:
        if s.name.startswith(".") and s.name.lower() not in standard:
            if s.name.lower() not in KNOWN_PACKER_SECTIONS:
                findings.append(Finding(
                    rule="nonstandard-section",
                    severity=Severity.LOW,
                    summary=f"Non-standard section name: {s.name}",
                    detail="Unusual section name — may indicate a custom packer or toolchain.",
                    section_name=s.name,
                ))
                break  # only one of these

    return findings


def _check_tls_callbacks(info: PEInfo) -> List[Finding]:
    if not info.tls_callbacks:
        return []
    count = len(info.tls_callbacks)
    return [Finding(
        rule="tls-callbacks",
        severity=Severity.MEDIUM,
        summary=f"TLS callbacks: {count} callback(s)",
        detail="TLS callbacks execute before the entry point. "
               "Packers and some malware use TLS for anti-debug or early unpacking.",
    )]


def _check_size_mismatch(sections: List[Section]) -> List[Finding]:
    findings = []
    for s in sections:
        if s.raw_size > 0 and s.virtual_size > s.raw_size * 5 and s.virtual_size > 0x100000:
            findings.append(Finding(
                rule="size-mismatch",
                severity=Severity.MEDIUM,
                summary=f"Large VSize/RawSize mismatch: VSize={_fmt_size(s.virtual_size)}, "
                        f"RawSize={_fmt_size(s.raw_size)}",
                detail="The virtual size is much larger than the on-disk size. "
                       "This section expands significantly at runtime (unpacking).",
                section_name=s.name,
            ))
    return findings


def _check_executable_count(sections: List[Section]) -> List[Finding]:
    exec_sections = [s for s in sections if s.is_executable]
    if len(exec_sections) > 5:
        return [Finding(
            rule="many-exec-sections",
            severity=Severity.LOW,
            summary=f"Many executable sections: {len(exec_sections)}",
            detail="An unusually high number of executable sections.",
        )]
    return []


def scan(info: PEInfo) -> ScanResult:
    """Run all anomaly detection rules against a parsed PE file."""
    findings = []
    findings.extend(_check_virtual_sections(info.sections))
    findings.extend(_check_entropy(info.sections))
    findings.extend(_check_rwx_sections(info.sections))
    findings.extend(_check_sparse_imports(info.imports, info.sections))
    findings.extend(_check_entry_point_section(info))
    findings.extend(_check_section_names(info.sections))
    findings.extend(_check_tls_callbacks(info))
    findings.extend(_check_size_mismatch(info.sections))
    findings.extend(_check_executable_count(info.sections))

    # Build summary
    bits = "x64" if info.is_64bit else "x86"
    summary = f"PE{'+' if info.is_64bit else ''}  {info.number_of_sections} sections  " \
              f"{info.file_size:,} bytes  {bits}"

    return ScanResult(
        file_path=str(info.path),
        summary=summary,
        findings=findings,
        sections=info.sections,
    )


def _fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024**2):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n:,} B"
