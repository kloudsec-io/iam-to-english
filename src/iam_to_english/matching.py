"""Shared IAM evaluation helpers: case-insensitive action matching and coarse grant/deny checks.

These are deliberately conservative approximations of the IAM evaluation logic. They answer
"could this identity policy allow action X?" without knowing the request context, so conditional
Deny statements are never assumed to apply, and NotResource is assumed to leave something allowed.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from .parser import ParsedPolicy, Statement

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def action_matches(pattern: str, action: str) -> bool:
    """IAM action names are case-insensitive and support '*' and '?' wildcards."""
    return fnmatchcase(action.lower(), pattern.lower())


def statement_matches_action(stmt: Statement, action: str) -> bool:
    """True if the statement's Action/NotAction element covers the concrete action."""
    if stmt.not_actions:
        return not any(action_matches(p, action) for p in stmt.not_actions)
    return any(action_matches(p, action) for p in stmt.actions)


def patterns_granting(stmt: Statement, action: str) -> list[str]:
    """The statement's own action patterns (as written) that grant the concrete action."""
    if stmt.not_actions:
        if statement_matches_action(stmt, action):
            return ["NotAction " + ", ".join(stmt.not_actions)]
        return []
    return [p for p in stmt.actions if action_matches(p, action)]


def resource_could_apply(stmt: Statement, service: str) -> bool:
    """Could any of the statement's resources belong to the given service?

    Lets us ignore e.g. ``"Action": "*"`` scoped to an S3 bucket when looking for IAM abuse.
    """
    if stmt.not_resources or not stmt.resources:
        return True
    for resource in stmt.resources:
        if resource == "*" or not resource.startswith("arn:"):
            return True
        parts = resource.split(":")
        if len(parts) < 3 or fnmatchcase(service.lower(), parts[2].lower()):
            return True
    return False


def is_explicitly_denied(policy: ParsedPolicy, action: str) -> bool:
    """True if an unconditional Deny on all resources blocks the action outright."""
    for stmt in policy.deny_statements:
        if stmt.has_conditions or stmt.is_resource_based or stmt.not_resources:
            continue
        if "*" in stmt.resources and statement_matches_action(stmt, action):
            return True
    return False


def granting_statements(policy: ParsedPolicy, action: str) -> list[Statement]:
    """Identity-policy Allow statements that could grant the action (minus explicit denies)."""
    if is_explicitly_denied(policy, action):
        return []
    service = action.split(":", 1)[0]
    return [
        s
        for s in policy.allow_statements
        if not s.is_resource_based and statement_matches_action(s, action) and resource_could_apply(s, service)
    ]


def is_effectively_unscoped(resource: str) -> bool:
    """e.g. '*', 'arn:aws:iam::123456789012:role/*' or 'arn:aws:lambda:*:*:function:*' cover every resource of a type."""
    parts = resource.split(":", 5)
    if len(parts) < 6:
        return resource == "*"
    service, rest = parts[2], parts[5]
    if service == "s3":
        return rest.split("/", 1)[0] == "*"
    if rest == "*":
        return True
    positions = [i for i in (rest.find("/"), rest.find(":")) if i > 0]
    return bool(positions) and rest[min(positions) + 1:] == "*"


def is_specifically_scoped(stmt: Statement) -> bool:
    """True if the statement only applies to explicitly listed (non-catch-all) resources."""
    if stmt.not_resources or not stmt.resources:
        return False
    return not any(is_effectively_unscoped(r) for r in stmt.resources)


def is_full_admin(stmt: Statement) -> bool:
    return stmt.is_allow and "*" in stmt.actions and "*" in stmt.resources and not stmt.has_conditions


_SELF_GRANT_ACTIONS = ("iam:PutUserPolicy", "iam:PutRolePolicy", "iam:AttachUserPolicy", "iam:AttachRolePolicy")


def is_admin_equivalent(stmt: Statement) -> bool:
    """Full admin, or an Allow+NotAction on "*" that leaves IAM writes allowed (it can grant itself anything)."""
    if is_full_admin(stmt):
        return True
    return (
        stmt.is_allow
        and bool(stmt.not_actions)
        and "*" in stmt.resources
        and not stmt.has_conditions
        and not stmt.is_resource_based
        and all(statement_matches_action(stmt, a) for a in _SELF_GRANT_ACTIONS)
    )


def max_severity(severities: list[str]) -> str | None:
    known = [s for s in severities if s in SEVERITY_ORDER]
    return min(known, key=SEVERITY_ORDER.__getitem__) if known else None
