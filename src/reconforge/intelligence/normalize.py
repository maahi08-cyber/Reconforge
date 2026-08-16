"""Deterministic normalization utilities.

Normalization happens before scoring so aliases, URL formatting differences,
and repeated observations cannot inflate confidence.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def normalize_url(value: str) -> str:
    value = value.strip()
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    port = parts.port

    host = hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{hostname}:{port}"

    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")

    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, host, path, query, ""))
