from __future__ import annotations

import argparse
import json
from dataclasses import asdict
import sys
from pathlib import Path

from apk_sentinel import __version__
from apk_sentinel.core import scan_apk
from apk_sentinel.report import render_html, render_json


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _scan(args)
    if args.command == "dashboard":
        return _dashboard(args)
    if args.command == 'compare':
        from apk_sentinel.assessment import compare_results
        print(json.dumps(compare_results(asdict(scan_apk(args.before)), asdict(scan_apk(args.after))), indent=2))
        return 0
    if args.command == 'verify-signing':
        from apk_sentinel.external_tools import run_tool
        result = run_tool('apksigner', args.apk)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'verified' else 2

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk-sentinel",
        description="Defensive Android APK security analysis framework",
    )
    parser.add_argument("--version", action="version", version=f"APK Sentinel {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="analyze an APK file")
    scan.add_argument("apk", type=Path, help="path to the APK file")
    scan.add_argument(
        "--format",
        choices=("json", "html", "sarif"),
        default="json",
        help="report format",
    )
    scan.add_argument("--out", type=Path, help="write the report to this path")
    scan.add_argument(
        "--fail-on",
        choices=("info", "low", "medium", "high", "critical"),
        help="exit non-zero when a finding at or above this severity exists",
    )

    compare = subparsers.add_parser('compare', help='compare two APK releases of the same package')
    compare.add_argument('before', type=Path)
    compare.add_argument('after', type=Path)
    signing = subparsers.add_parser('verify-signing', help='verify with installed Android apksigner')
    signing.add_argument('apk', type=Path)
    dashboard = subparsers.add_parser("dashboard", help="run the local Flask dashboard")
    dashboard.add_argument("--host", default="127.0.0.1", help="dashboard bind host")
    dashboard.add_argument("--port", type=int, default=5050, help="dashboard bind port")
    dashboard.add_argument("--storage", type=Path, help="case storage directory")
    dashboard.add_argument("--debug", action="store_true", help="enable Flask debug mode")
    return parser


def _scan(args: argparse.Namespace) -> int:
    result = scan_apk(args.apk)
    rendered = render_html(result) if args.format == "html" else render_json(result)
    if args.format == 'sarif':
        from apk_sentinel.assessment import sarif
        rendered = json.dumps(sarif(asdict(result)), indent=2)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on and result.has_severity_at_or_above(args.fail_on):
        return 1
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    from apk_sentinel.dashboard import create_app

    app = create_app(storage_dir=args.storage)
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
