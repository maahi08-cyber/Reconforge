"""Semantic endpoint and parameter classification.

The classifier emits features, never vulnerability verdicts. Rules are deliberately
conservative so keyword-only matches cannot dominate ranking.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit


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


def classify_url(url: str, method: str = "GET") -> EndpointFeatures:
    parts = urlsplit(url)
    path = parts.path.lower()
    params = {key.lower() for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
    path_tokens = {token for token in path.split("/") if token}

    object_names = {
        "id", "uid", "user_id", "account_id", "project_id", "team_id",
        "file_id", "document_id", "org_id", "member_id", "invite_id",
    }
    sensitive = {"redirect", "url", "next", "callback", "return_url", "webhook"}

    return EndpointFeatures(
        is_api="/api/" in path or path.startswith("/api"),
        is_graphql=path.rstrip("/").endswith("graphql"),
        is_auth=bool(path_tokens & {"login", "logout", "signin", "signup", "oauth", "sso", "session"}),
        is_admin="admin" in path_tokens or "management" in path_tokens,
        is_file_operation=bool(path_tokens & {"file", "files", "upload", "uploads", "download", "downloads", "export", "import"}),
        is_invitation=bool(path_tokens & {"invite", "invites", "invitation", "invitations"}),
        is_billing=bool(path_tokens & {"billing", "invoice", "invoices", "payment", "payments", "subscription", "subscriptions"}),
        is_account_or_team=bool(path_tokens & {"account", "accounts", "user", "users", "team", "teams", "member", "members", "organization", "org"}),
        has_object_reference=bool(params & object_names) or any(token in object_names for token in path_tokens),
        has_sensitive_parameter=bool(params & sensitive),
        is_state_changing=method.upper() in {"POST", "PUT", "PATCH", "DELETE"},
    )
