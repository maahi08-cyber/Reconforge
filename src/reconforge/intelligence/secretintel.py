"""High-signal client-side sensitive-data leakage detection.

The goal is not to dump every high-entropy string. ReconForge looks for
credential formats and strengthens them with surrounding context. Values are
redacted in findings so the intelligence layer can prioritize without copying
secrets into normal console output.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re


@dataclass(frozen=True, slots=True)
class SecretCandidate:
    kind: str
    confidence: float
    line: int
    redacted: str
    context: str
    rationale: str


_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.99),
    ("github_token", re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,255})\b"), 0.99),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.98),
    ("stripe_secret_key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), 0.99),
    ("stripe_restricted_key", re.compile(r"\brk_live_[0-9A-Za-z]{16,}\b"), 0.99),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 0.98),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"), 0.99),
    ("twilio_api_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 0.96),
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"), 0.93),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 1.00),
    ("splunk_hec_authorization", re.compile(r"(?:Authorization\s*[:=]\s*[\"']?Splunk\s+|splunk[_-]?hec[_-]?(?:token|key)\s*[:=]\s*[\"']?)([A-Za-z0-9-]{20,})", re.I), 0.97),
)

_SECRET_WORDS = re.compile(r"\b(?:api[_-]?key|api[_-]?token|access[_-]?token|secret|client[_-]?secret|password|passwd|authorization|bearer|hec|webhook[_-]?token)\b", re.I)
_HEX_OR_B64 = re.compile(r"^[A-Za-z0-9_\-/+=]{20,}$")


def scan_javascript(script: str, *, min_generic_entropy: float = 4.0) -> list[SecretCandidate]:
    """Return prioritized secret candidates without exposing raw values."""
    results: list[SecretCandidate] = []
    seen: set[tuple[str, int, str]] = set()

    for line_no, line in enumerate(script.splitlines(), 1):
        context = _compact_context(line)
        context_signal = bool(_SECRET_WORDS.search(line))
        for kind, pattern, base_confidence in _PATTERNS:
            for match in pattern.finditer(line):
                raw = match.group(1) if kind == "splunk_hec_authorization" and match.lastindex else match.group(0)
                if not raw:
                    continue
                confidence = min(1.0, base_confidence + (0.03 if context_signal else 0.0))
                if kind == "jwt" and _looks_like_public_example(raw):
                    confidence -= 0.15
                key = (kind, line_no, _fingerprint(raw))
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    SecretCandidate(
                        kind=kind,
                        confidence=max(0.0, confidence),
                        line=line_no,
                        redacted=_redact(raw),
                        context=context,
                        rationale=_rationale(kind, context_signal),
                    )
                )

        for raw in _generic_candidates(line):
            if _entropy(raw) < min_generic_entropy:
                continue
            kind = "generic_high_entropy_secret"
            confidence = 0.55 + (0.18 if context_signal else 0.0)
            key = (kind, line_no, _fingerprint(raw))
            if key in seen:
                continue
            seen.add(key)
            results.append(SecretCandidate(kind, confidence, line_no, _redact(raw), context, "high-entropy value near a secret-like identifier"))

    return sorted(results, key=lambda item: (item.confidence, item.kind), reverse=True)


def _generic_candidates(line: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"(?:api[_-]?key|token|secret|password|authorization|bearer|hec)[A-Za-z0-9_\- ]*[:=]\s*[\"']?([^\"'\s,;]{20,})", line, re.I):
        value = match.group(1).strip()
        if _HEX_OR_B64.match(value):
            found.append(value)
    return found


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact(value: str) -> str:
    if len(value) <= 10:
        return "<redacted>"
    return f"{value[:4]}…{value[-4:]}"


def _fingerprint(value: str) -> str:
    # Stable non-secret identity for deduplication in UI/logs.
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _compact_context(line: str) -> str:
    return " ".join(line.strip().split())[:240]


def _looks_like_public_example(value: str) -> bool:
    lowered = value.lower()
    return "example" in lowered or "dummy" in lowered or "test" in lowered


def _rationale(kind: str, context_signal: bool) -> str:
    if kind == "splunk_hec_authorization":
        return "Splunk HEC-style authorization token pattern detected" + (" with secret-related context" if context_signal else "")
    if kind == "generic_high_entropy_secret":
        return "high entropy plus secret-like context"
    return f"recognized {kind} credential format" + (" with contextual support" if context_signal else "")
