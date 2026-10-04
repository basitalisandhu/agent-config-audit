"""Finding record, severity helpers, entropy and redaction."""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass

from .patterns import SECRET_PATTERNS, SEVERITIES


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    file: str
    line: int | None
    evidence: str
    recommendation: str

    def key(self) -> tuple[str, str, int | None, str]:
        return (self.id, self.file, self.line, self.evidence)

    def as_dict(self) -> dict:
        return asdict(self)


def severity_rank(severity: str) -> int:
    """0 for critical, 4 for info. Unknown values sort last."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def at_or_above(severity: str, threshold: str) -> bool:
    return severity_rank(severity) <= severity_rank(threshold)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(evidence: str) -> str:
    """Mask anything that looks like a credential so the report can be shared."""
    out = evidence
    for title, pattern, _ in SECRET_PATTERNS[:-1]:
        if title == "Private key block":
            continue
        out = pattern.sub(
            lambda m: m.group(0)[:6] + "****" + m.group(0)[-2:] if len(m.group(0)) > 10 else "****",
            out,
        )
    out = re.sub(
        r"(?i)((?:bearer|basic|token)\s+)(\S{12,})",
        lambda m: m.group(1) + m.group(2)[:4] + "****",
        out,
    )
    out = re.sub(
        r"(?i)((?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|api[_-]?token|password|passwd|secret)\b[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9_\-./+=]{8,})",
        lambda m: m.group(1) + m.group(2)[:4] + "****",
        out,
    )
    return out
