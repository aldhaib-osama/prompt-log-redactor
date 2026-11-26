"""Redact common secret and personal patterns from model interaction logs
before the logs are shared or archived. Pattern-based: it catches the shapes
it knows and misses the ones it does not. Always spot-check the output before
you treat a log as clean."""
import json
import re
import sys

PATTERNS = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("api_key", re.compile(r"\b(sk|pk|api|key|token)[-_][A-Za-z0-9]{16,}\b")),
    ("bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("phone", re.compile(r"\+?\d[\d\s-]{8,14}\d")),
    ("aws_key", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")),
]

MASK = "[REDACTED:{kind}]"


def redact_text(text):
    counts = {}
    out = text
    for kind, pat in PATTERNS:
        out, n = pat.subn(MASK.format(kind=kind), out)
        if n:
            counts[kind] = n
    return out, counts


def redact_log(doc):
    """Redact a log document: a string, or a dict/list containing strings.
    Returns (redacted_doc, counts)."""
    total = {}

    def walk(node):
        if isinstance(node, str):
            out, counts = redact_text(node)
            for k, v in counts.items():
                total[k] = total.get(k, 0) + v
            return out
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        return node

    return walk(doc), total


def main(argv):
    if len(argv) != 2:
        print("usage: python prompt_log_redactor.py <log.json>", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    redacted, counts = redact_log(doc)
    print(json.dumps({"redacted": redacted, "counts": counts}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
