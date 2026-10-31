"""PhishLens TN command line.

    python cli.py analyze https://example.com [--json | --markdown] [--no-rdap]
    python cli.py batch urls.txt --out-dir results [--workers 4] [--no-rdap]
    python cli.py rules
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Sequence

from analyzer.errors import PhishLensError
from analyzer.pipeline import analyze_url
from analyzer.report import BATCH_CSV_FIELDS, csv_safe, render_batch_markdown, render_markdown, result_to_csv_row
from analyzer.scoring import LEVELS, get_rules

MAX_BATCH_URLS = 10_000


def read_url_file(path: Path) -> list[str]:
    """Read URLs, one per line. Blank lines and lines starting with # are ignored."""
    urls: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line in seen:
            continue
        seen.add(line)
        urls.append(line)
    return urls[:MAX_BATCH_URLS]


def analyze_one(url: str, use_rdap: bool) -> dict[str, Any]:
    """Analyze one URL; failures become error records instead of exceptions."""
    try:
        return analyze_url(url, use_rdap=use_rdap)
    except PhishLensError as exc:
        return {"url": url, "error": exc.to_dict()}
    except Exception:  # keep the batch alive whatever happens to one URL
        return {"url": url, "error": {"code": "internal_error", "message": "Unexpected failure", "hint": ""}}


def write_batch_outputs(items: Sequence[dict[str, Any]], out_dir: Path, source: str) -> tuple[Path, Path, Path]:
    """Write results.json, results.csv and summary.md into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, csv_path, md_path = out_dir / "results.json", out_dir / "results.csv", out_dir / "summary.md"
    json_path.write_text(json.dumps(list(items), indent=2, ensure_ascii=False), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=BATCH_CSV_FIELDS)
        writer.writeheader()
        for item in items:
            writer.writerow({k: csv_safe(v) for k, v in result_to_csv_row(item).items()})
    md_path.write_text(render_batch_markdown(items, source=source), encoding="utf-8")
    return json_path, csv_path, md_path


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        result = analyze_url(args.url, use_rdap=not args.no_rdap)
    except PhishLensError as exc:
        print(f"Error [{exc.code}]: {exc.message}\n{exc.hint}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.markdown:
        print(render_markdown(result))
    else:
        print(f"PhishLens TN: {result['url']}")
        print(f"Score: {result['score']}/100 ({result['level']})")
        print(f"Verdict: {result['verdict']}\n")
        for signal in result["signals"]:
            print(f"  {signal['weight']:+4d}  {signal['title']}\n        {signal['explanation']}")
        if not result["signals"]:
            print("  No indicators triggered.")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2
    urls = read_url_file(args.input)
    if not urls:
        print("The input file contains no URLs.", file=sys.stderr)
        return 2
    workers = max(1, min(args.workers, 16))
    print(f"Analyzing {len(urls)} URL(s) with {workers} worker(s)...", file=sys.stderr)
    items: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, item in enumerate(pool.map(lambda u: analyze_one(u, not args.no_rdap), urls), 1):
            items.append(item)
            label = f"{item['score']}/100 {item['level']}" if "score" in item else f"error: {item['error']['code']}"
            print(f"[{index}/{len(urls)}] {item.get('url', '')} -> {label}", file=sys.stderr)
    json_path, csv_path, md_path = write_batch_outputs(items, args.out_dir, str(args.input))
    print(f"Wrote {json_path}, {csv_path} and {md_path}")
    return 0


def cmd_rules(_: argparse.Namespace) -> int:
    print("Levels: " + ", ".join(f"{name} >= {minimum}" for name, minimum in LEVELS) + "\n")
    print(f"{'WEIGHT':>6}  {'RULE ID':<28} {'CATEGORY':<9} TITLE")
    for item in sorted(get_rules(), key=lambda r: (-r.weight, r.id)):
        print(f"{item.weight:>+6}  {item.id:<28} {item.category:<9} {item.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishlens", description="Static phishing page analyzer for Tunisian brands. Defensive use only.")
    sub = parser.add_subparsers(dest="command", required=True)
    single = sub.add_parser("analyze", help="analyze one URL")
    single.add_argument("url")
    fmt = single.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="print the full JSON result")
    fmt.add_argument("--markdown", action="store_true", help="print a Markdown report")
    single.add_argument("--no-rdap", action="store_true", help="skip the domain age lookup")
    single.set_defaults(func=cmd_analyze)
    batch = sub.add_parser("batch", help="analyze every URL in a file")
    batch.add_argument("input", type=Path, help="text file with one URL per line")
    batch.add_argument("--out-dir", type=Path, default=Path("phishlens-output"))
    batch.add_argument("--workers", type=int, default=4)
    batch.add_argument("--no-rdap", action="store_true")
    batch.set_defaults(func=cmd_batch)
    rules = sub.add_parser("rules", help="list scoring rules and weights")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
