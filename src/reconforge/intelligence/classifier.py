"""Security-relevant endpoint and parameter classification."""
from __future__ import annotations

from dataclasses import dataclass
from re import search
from urllib.parse import parse_qsl, urlsplit


@dataclass(frozen=True, slots=True)
class EndpointProfile:
    categories: frozenset[str]
    identifiers: tuple[str, ...]
    sensitive_parameters: tuple[str, ...]
    state_changing: bool
    score: float


CATEGORY_RULES = {
    "graphql": (r"(?:^|/)graphql(?:/|$)", 5.0),
    "auth": (r"(?:^|/)(?:login|logout|signin|signup|register|oauth|sso|authorize|token)(?:/|$)", 4.0),
    "admin": (r"(?:^|/)(?:admin|administrator|manage|management|settings)(?:/|$)", 3.5),
    "file": (r"(?:^|/)(?:upload|download|files?|attachments?|export|import)(?:/|$)", 4.0),
    "invitation": (r"(?:^|/)(?:invite|invitation|members?|membership|roles?)(?:/|$)", 4.0),
    "billing": (r"(?:^|/)(?:billing|payment|payments|checkout|invoice|subscription)(?:/|$)", 3.5),
    "api": (r"(?:^|/)(?:api|v[0-9]+)(?:/|$)", 2.5),
}

IDENTIFIER_PATTERN = r"(?:^|/)(?:[a-f0-9]{8,}|[0-9]{2,})(?:/|$)"
SENSITIVE_PARAM_NAMES = {
    "id", "user_id", "account_id", "project_id", "team_id", "org_id", "organization_id",
    "file_id", "document_id", "member_id", "role", "redirect", "return_url", "callback", "url",
}


def classify_endpoint(url: str, method: str = "GET") -> EndpointProfile:
    parts = urlsplit(url)
    path = parts.path.lower()
    categories: set[str] = set()
    score = 0.0

    for category, (pattern, weight) in CATEGORY_RULES.items():
        if search(pattern, path):
            categories.add(category)
            score += weight

    identifiers = tuple(segment for segment in parts.path.split("/") if search(IDENTIFIER_PATTERN, "/" + segment + "/"))
    parameters = tuple(name for name, _ in parse_qsl(parts.query, keep_blank_values=True) if name.lower() in SENSITIVE_PARAM_NAMES)
    state_changing = method.upper() in {"POST", "PUT", "PATCH", "DELETE"}

    if identifiers:
        score += min(5.0, len(identifiers) * 2.0)
    if parameters:
        score += min(4.0, len(parameters) * 1.5)
    if state_changing:
        score += 1.5

    return EndpointProfile(frozenset(categories), identifiers, parameters, state_changing, min(score, 20.0))
