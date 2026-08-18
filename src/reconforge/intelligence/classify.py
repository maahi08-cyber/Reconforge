"""Semantic endpoint and parameter classification."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, urlsplit

from reconforge.models import Observation, ObservationKind


@dataclass(frozen=True, slots=True)
class EndpointFeatures:
    is_api: bool = False
    is_graphql: bool = False
    is_auth: bool = False
    is_admin: bool = False
    is_file_operation: bool = False
    is_invitation: bool = False
    is_billing: bool = False
    is_account_or_team: bool = False
    has_object_reference: bool = False
    has_sensitive_parameter: bool = False
    is_state_changing: bool = False

_OBJECT = {"id", "uid", "uuid", "user_id", "account_id", "project_id", "team_id", "file_id", "document_id", "org_id", "member_id", "invite_id"}
_SENSITIVE = {"redirect", "url", "next", "callback", "return_url", "webhook", "dest", "destination"}


def classify_url(url: str, method: str = "GET") -> EndpointFeatures:
    parts = urlsplit(url)
    path = parts.path.lower()
    params = {key.lower() for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
    tokens = {token for token in path.split("/") if token}
    return EndpointFeatures(
        is_api="/api/" in path or path.startswith("/api") or path.rstrip("/").endswith("graphql"),
        is_graphql=path.rstrip("/").endswith("graphql"),
        is_auth=bool(tokens & {"login", "logout", "signin", "signup", "oauth", "sso", "session"}),
        is_admin=bool(tokens & {"admin", "administrator", "management", "manage", "console", "settings"}),
        is_file_operation=bool(tokens & {"file", "files", "upload", "uploads", "download", "downloads", "export", "import", "attachment", "attachments"}),
        is_invitation=bool(tokens & {"invite", "invites", "invitation", "invitations", "membership", "memberships"}),
        is_billing=bool(tokens & {"billing", "invoice", "invoices", "payment", "payments", "subscription", "subscriptions", "checkout"}),
        is_account_or_team=bool(tokens & {"account", "accounts", "user", "users", "team", "teams", "member", "members", "organization", "organizations", "org"}),
        has_object_reference=bool(params & _OBJECT) or any(token in _OBJECT or token.isdigit() for token in tokens),
        has_sensitive_parameter=bool(params & _SENSITIVE),
        is_state_changing=method.upper() in {"POST", "PUT", "PATCH", "DELETE"},
    )


def classify_observations(url: str, *, method: str = "GET", source: str, run_id: str) -> list[Observation]:
    f = classify_url(url, method)
    positive = {key: value for key, value in asdict(f).items() if value}
    return [Observation(ObservationKind.ENDPOINT, url, source, run_id, {"method": method.upper(), "features": positive})]
