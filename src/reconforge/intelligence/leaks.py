"""High-signal client-side sensitive-data intelligence.

The detector is intentionally conservative: it prioritizes credential-like
formats with contextual evidence and returns redacted values by default.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re


@dataclass(frozen=True, slots=True)
class LeakCandidate:
    kind: str
    line: int
    confidence: float
    redacted: str
    rationale: str
    fingerprint: str


_PATTERNS = (
    ("splunk_hec", re.compile(r"(?i)\bSplunk\s+([A-Za-z0-9]{20,})\b"), 0.96, "Splunk HEC-style token context"),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.99, "AWS access-key identifier format"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), 0.98, "GitHub token format"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), 0.98, "Google API-key format"),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), 0.99, "Stripe live secret-key format"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"), 0.97, "Slack token format"),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b"), 0.98, "SendGrid API-key format"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0.92, "JWT-shaped credential/token"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 0.995, "private-key header"),
)

_CONTEXT = re.compile(r"(?i)(api[_-]?key|token|secret|authorization|bearer|credential|password|private[_-]?key|webhook|hec)")


def scan_script(script: str) -> list[LeakCandidate]:
    results: list[LeakCandidate] = []
    seen: set[tuple[str, int, str]] = set()
    lines = script.splitlines()
    for line_no, line in enumerate(lines, 1):
        context = bool(_CONTEXT.search(line))
        for kind, pattern, base_confidence, rationale in _PATTERNS:
            for match in pattern.finditer(line):
                token = match.group(0)
                key = (kind, line_no, token)
                if key in seen:
                    continue
                seen.add(key)
                confidence = min(0.995, base_confidence + (0.02 if context else 0.0))
                digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
                redacted = token[:4] + "…" + token[-4:] if len(token) > 10 else token[:2] + "…"
                results.append(LeakCandidate(kind, line_no, confidence, redacted, rationale, digest))
    return sorted(results, key=lambda item: (-item.confidence, item.line, item.kind))
