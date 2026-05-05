"""Command-line interface for pe-anomaly."""

import argparse
import json
import sys
import textwrap
from pathlib import Path

from .parser import PEParser
from .scanner import scan


def cmd_scan(parser_args):
    filepath = Path(parser_args.file)

    if not filepath.exists():
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    try:
        with PEParser(filepath) as pe:
            info = pe.parse()
            result = scan(info)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if parser_args.json:
        data = {
            "file": result.file_path,
            "summary": result.summary,
            "risk_level": result.risk_level.name,
            "findings": [
                {"rule": f.rule, "severity": f.severity.name,
                 "summary": f.summary, "section": f.section_name}
                for f in result.findings
            ],
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(result.format_terminal())

    sys.exit(0 if result.risk_level.name in ("LOW",) else 1)


def main():
    parser = argparse.ArgumentParser(
        prog="pe-anomaly",
        description="PE file structural anomaly scanner. "
                    "Detects packers, suspicious sections, and security risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          pe-anomaly scan program.exe
          pe-anomaly scan program.exe --json
          pe-anomaly scan *.exe
        """),
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")
    sub.required = True

    p = sub.add_parser("scan", help="Scan a PE file for anomalies")
    p.add_argument("file", help="Path to PE file (.exe, .dll, .sys)")
    p.add_argument("--json", action="store_true", help="Output results as JSON")
    p.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)
