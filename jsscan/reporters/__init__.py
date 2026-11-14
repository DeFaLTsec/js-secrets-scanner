import html
import json
from collections import Counter

COLORS = {"critical": "red", "high": "dark_orange", "medium": "yellow", "low": "cyan", "info": "blue"}


def to_console(findings):
    from rich.console import Console
    from rich.table import Table

    c = Console()
    if not findings:
        c.print("[green]Sin hallazgos.[/green]")
        return
    t = Table(title=f"{len(findings)} hallazgos")
    for col in ("Sev", "Regla", "Valor", "Línea", "Fuente"):
        t.add_column(col, overflow="fold")
    for f in findings:
        col = COLORS.get(f.severity, "white")
        t.add_row(f"[{col}]{f.severity}[/{col}]", f.name, f.match, str(f.line), f.source)
    c.print(t)
    c.print(dict(Counter(f.severity for f in findings)))


def to_json(findings, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2, ensure_ascii=False)


def to_html(findings, path):
    rows = "".join(
        f"<tr class='{f.severity}'><td>{f.severity}</td><td>{html.escape(f.name)}</td>"
        f"<td><code>{html.escape(f.match)}</code></td><td>{f.line}</td>"
        f"<td>{html.escape(f.source)}</td></tr>"
        for f in findings
    )
    doc = f"""<!doctype html><meta charset='utf-8'><title>jsscan report</title>
<style>body{{font-family:sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;word-break:break-all}}
.critical{{background:#ffd6d6}}.high{{background:#ffe5cc}}.medium{{background:#fff7cc}}
.info{{background:#e6f0ff}}</style>
<h1>jsscan report</h1><p>{len(findings)} hallazgos</p>
<table><tr><th>Sev</th><th>Regla</th><th>Valor</th><th>Línea</th><th>Fuente</th></tr>{rows}</table>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
