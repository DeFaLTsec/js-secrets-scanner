from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .engine import load_rules, scan_text
from .reporters import to_console, to_html, to_json

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "default.yml"
BANNER = "jsscan %s - usar solo en sistemas con autorización expresa" % __version__


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="jsscan", description="Busca secretos y endpoints en JavaScript.")
    p.add_argument("targets", nargs="*", help="URLs, archivos .js o directorios")
    p.add_argument("-l", "--list", help="archivo con una URL por línea")
    p.add_argument("--stdin", action="store_true", help="leer URLs desde stdin")
    p.add_argument("--rules", default=str(DEFAULT_RULES))
    p.add_argument("--proxy", help="p. ej. http://127.0.0.1:8080 (Burp)")
    p.add_argument("-H", "--header", action="append", default=[], help="'Nombre: valor' (repetible)")
    p.add_argument("-c", "--concurrency", type=int, default=10)
    p.add_argument("-k", "--insecure", action="store_true", help="no verificar TLS")
    p.add_argument("--no-maps", action="store_true", help="no seguir source maps")
    p.add_argument("--show-secrets", action="store_true", help="no redactar valores")
    p.add_argument("--json", metavar="FILE")
    p.add_argument("--html", metavar="FILE")
    return p.parse_args(argv)


async def run(args) -> int:
    targets = list(args.targets)
    if args.list:
        targets += [l.strip() for l in Path(args.list).read_text().splitlines() if l.strip()]
    if args.stdin:
        targets += [l.strip() for l in sys.stdin if l.strip()]
    if not targets:
        print("Sin objetivos. Usa --help.", file=sys.stderr)
        return 2

    rules = load_rules(args.rules)
    findings = []
    remote = [t for t in targets if t.startswith(("http://", "https://"))]
    local = [t for t in targets if t not in remote]

    for t in local:
        p = Path(t)
        files = [p] if p.is_file() else list(p.rglob("*.js")) + list(p.rglob("*.map"))
        for f in files:
            findings += scan_text(f.read_text(errors="ignore"), str(f), rules, args.show_secrets)

    if remote:
        from .fetcher import Fetcher

        headers = {}
        for h in args.header:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
        fx = Fetcher(args.proxy, headers, args.concurrency, args.insecure)
        try:
            for sources in await asyncio.gather(*(fx.collect(t, not args.no_maps) for t in remote)):
                for src, content in sources.items():
                    findings += scan_text(content, src, rules, args.show_secrets)
        finally:
            await fx.close()

    to_console(findings)
    if args.json:
        to_json(findings, args.json)
    if args.html:
        to_html(findings, args.html)
    return 1 if findings else 0


def main():
    print(BANNER, file=sys.stderr)
    sys.exit(asyncio.run(run(parse_args())))


if __name__ == "__main__":
    main()
