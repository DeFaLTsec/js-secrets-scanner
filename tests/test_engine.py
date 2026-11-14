from jsscan.engine import load_rules, scan_text, shannon_entropy
from jsscan.cli import DEFAULT_RULES

RULES = load_rules(DEFAULT_RULES)


def ids(text):
    return {f.rule_id for f in scan_text(text, "t.js", RULES)}


def test_detects_aws_and_google():
    js = 'const a="AKIAIOSFODNN7ABCDEFG"; const g="AIza' + "A" * 35 + '";'
    assert {"aws-access-key", "google-api-key"} <= ids(js)


def test_ignores_placeholders():
    assert "generic-secret" not in ids('const apiKey = "YOUR_API_KEY_HERE";')


def test_generic_secret_needs_entropy():
    assert "generic-secret" in ids('var password = "x9Fq2LmZp8Rt4Vb7";')
    assert "generic-secret" not in ids('var password = "aaaaaaaaaaaa";')


def test_redaction():
    f = scan_text('k="AKIAIOSFODNN7ABCDEFG"', "t", RULES)[0]
    assert "***" in f.match and "IOSFODNN7ABCD" not in f.match


def test_entropy():
    assert shannon_entropy("aaaa") == 0
