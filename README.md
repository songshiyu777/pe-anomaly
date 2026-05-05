# PE Anomaly · PE 文件结构异常扫描器

> 纯 Python、零依赖的 PE 文件结构异常检测工具。不依赖签名库，用启发式规则识别加壳、加密段、RWX 权限等安全风险。支持 Linux、macOS、Windows。

A **pure-Python**, **zero-dependency** CLI tool to detect structural anomalies in Windows PE files. Uses heuristic rules — not signature databases — to identify packers, encrypted sections, RWX permissions, and other security risks.

## Features

- **9 detection rules** covering the most common PE anomalies
- **Zero dependencies** — only the Python standard library
- **No signature database** — detects unknown/new packers, not just known ones
- **Cross-platform** — parses PE format on Linux, macOS, Windows
- **JSON output** for integration with scripts and CI pipelines
- Supports PE32 (x86) and PE32+ (x64) formats

## Installation

```bash
pip install git+https://github.com/songshiyu777/pe-anomaly.git
```

Or clone and install:

```bash
git clone https://github.com/songshiyu777/pe-anomaly.git
cd pe-anomaly
pip install -e .
```

## Quick Start

```bash
# Scan a single file
pe-anomaly scan program.exe

# JSON output for automation
pe-anomaly scan program.exe --json
```

### Example output

```
$ pe-anomaly scan packed.exe

File   : packed.exe
Summary: PE  10 sections  92,192,768 bytes  x64
Findings (7):
  [HIGH] Virtual section: VSize=21.3 MB, RawSize=0 (.themida)
  [HIGH] High entropy: 7.94 (likely encrypted/compressed) (.boot)
  [MEDIUM] Elevated entropy: 7.12 (possibly packed) (.themida)
  [HIGH] Sparse import table: 3 DLLs, 12 functions
  [HIGH] Entry point in known packer section: .themida
  [MEDIUM] Known packer section name: .themida
  [MEDIUM] Large VSize/RawSize mismatch: VSize=40.1 MB, RawSize=11.2 MB
Risk   : HIGH
```

```
$ pe-anomaly scan clean.exe

File   : clean.exe
Summary: PE  4 sections  156,672 bytes  x86
Findings (0):
  No anomalies detected.
Risk   : LOW
```

## Detection Rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| **virtual-section** | HIGH | Sections with `RawSize=0` that expand at runtime (Themida, WinLicense) |
| **high-entropy** | HIGH | Entropy > 7.5 — encrypted/compressed payload |
| **elevated-entropy** | MEDIUM | Entropy 6.8-7.5 — possible packing |
| **writable-executable** | CRITICAL | RWX sections — shellcode injection risk |
| **sparse-imports** | HIGH | < 3 DLLs / < 15 functions — packed with runtime resolution |
| **packer-entry-section** | HIGH | Entry point inside a known packer section |
| **packer-section-name** | MEDIUM | Section named `.themida`, `upx0`, etc. |
| **size-mismatch** | MEDIUM | VSize >> RawSize — runtime expansion |
| **tls-callbacks** | MEDIUM | TLS callbacks execute before entry point |
| **entry-in-non-code** | MEDIUM | Entry point not in a code section |
| **nonstandard-section** | LOW | Unusual section names |

## Python API

```python
from pe_anomaly import PEParser, scan

with PEParser("program.exe") as pe:
    info = pe.parse()

    # Inspect sections
    for s in info.sections:
        print(f"{s.name:<10s}  {s.perms}  entropy={s.entropy:.2f}  "
              f"VSize={s.virtual_size:,}  RawSize={s.raw_size:,}")

    # Run anomaly scanner
    result = scan(info)
    for finding in result.findings:
        print(f"[{finding.severity.name}] {finding.summary}")

    print(f"Risk level: {result.risk_level.name}")
```

## License

MIT — see [LICENSE](LICENSE) for details.
