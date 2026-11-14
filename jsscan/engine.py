"""Motor de detección: reglas YAML + entropía + filtro de falsos positivos."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

import yaml

PLACEHOLDERS = re.compile(
    r"(example|your[_-]?(api|key|token|secret)|xxxx|changeme|placeholder|dummy|"
    r"test[_-]?key|sample|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\})",
    re.IGNORECASE,
)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Rule:
    id: str
    name: str
    regex: re.Pattern
    severity: str = "medium"
    group: int = 0
    min_entropy: float = 0.0


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    match: str  # ya redactado
    line: int
    source: str

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def redact(value: str, keep_start: int = 4, keep_end: int = 2) -> str:
    if len(value) <= keep_start + keep_end + 3:
        return value[:2] + "***"
    return f"{value[:keep_start]}***{value[-keep_end:]}"


def load_rules(path: str | Path) -> list[Rule]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules = []
    for r in data["rules"]:
        rules.append(
            Rule(
                id=r["id"],
                name=r["name"],
                regex=re.compile(r["regex"]),
                severity=r.get("severity", "medium"),
                group=r.get("group", 0),
                min_entropy=float(r.get("min_entropy", 0)),
            )
        )
    return rules


def scan_text(text: str, source: str, rules: list[Rule], show_secrets: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        for m in rule.regex.finditer(text):
            try:
                value = m.group(rule.group)
            except IndexError:
                continue
            if not value or PLACEHOLDERS.search(value):
                continue
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            key = (rule.id, value)
            if key in seen:
                continue
            seen.add(key)
            line = text.count("\n", 0, m.start()) + 1
            findings.append(
                Finding(rule.id, rule.name, rule.severity,
                        value if show_secrets else redact(value), line, source)
            )
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.source, f.line))
    return findings
