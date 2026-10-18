from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

from .errors import PolicyError


@dataclass
class PolicyCondition:
    operator: str
    key: str
    values: list[str]


@dataclass
class Statement:
    sid: str | None
    effect: str
    actions: list[str]
    not_actions: list[str]
    resources: list[str]
    not_resources: list[str]
    principals: list[str]
    not_principals: list[str]
    conditions: list[PolicyCondition]
    index: int

    @property
    def is_allow(self) -> bool:
        return self.effect == "Allow"

    @property
    def uses_not_action(self) -> bool:
        return len(self.not_actions) > 0

    @property
    def uses_not_resource(self) -> bool:
        return len(self.not_resources) > 0

    @property
    def uses_not_principal(self) -> bool:
        return len(self.not_principals) > 0

    @property
    def has_wildcard_action(self) -> bool:
        return "*" in self.actions

    @property
    def has_wildcard_resource(self) -> bool:
        return "*" in self.resources

    @property
    def has_conditions(self) -> bool:
        return len(self.conditions) > 0

    @property
    def is_public(self) -> bool:
        """True if the statement's Principal is anonymous ("*" or {"AWS": "*"})."""
        return any(p in ("*", "AWS:*") for p in self.principals)

    @property
    def is_resource_based(self) -> bool:
        """Resource-based policies (trust, bucket, key policies) name a Principal."""
        return bool(self.principals or self.not_principals)

    def get_services(self) -> set[str]:
        services = set()
        for action in self.actions + self.not_actions:
            if ":" in action:
                services.add(action.split(":")[0].lower())
            elif action == "*":
                services.add("*")
        return services


@dataclass
class ParsedPolicy:
    version: str | None
    id: str | None
    statements: list[Statement]
    raw: dict
    source_label: str = ""

    @property
    def allow_statements(self) -> list[Statement]:
        return [s for s in self.statements if s.is_allow]

    @property
    def deny_statements(self) -> list[Statement]:
        return [s for s in self.statements if not s.is_allow]

    def get_all_services(self) -> set[str]:
        services = set()
        for stmt in self.statements:
            services.update(stmt.get_services())
        return services

    def get_allowed_services(self) -> set[str]:
        """Services referenced by Allow statements ("*" only if an Allow grants everything)."""
        services = set()
        for stmt in self.allow_statements:
            if stmt.not_actions:
                services.add("*")
            else:
                services.update(stmt.get_services())
        return services


def parse_policy(policy_dict: dict, source_label: str = "") -> ParsedPolicy:
    if not isinstance(policy_dict, dict):
        raise PolicyError("Invalid policy: expected a JSON/YAML object with a 'Statement' key")

    if "Statement" not in policy_dict:
        keys = ", ".join(sorted(str(k) for k in policy_dict)[:5]) or "none"
        raise PolicyError(
            f"Not an IAM policy: no 'Statement' key found (top-level keys: {keys}).\n"
            "Pass a policy document such as {\"Version\": \"2012-10-17\", \"Statement\": [...]}"
        )

    version = policy_dict.get("Version")
    if isinstance(version, (date, datetime)):
        version = version.isoformat()[:10]  # YAML reads an unquoted 2012-10-17 as a date
    elif version is not None:
        version = str(version)
    policy_id = policy_dict.get("Id")

    raw_statements = policy_dict.get("Statement")
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]

    if not isinstance(raw_statements, list):
        raise PolicyError("Invalid policy: 'Statement' must be a list or object")

    statements = []
    for i, raw_stmt in enumerate(raw_statements, start=1):
        statements.append(_parse_statement(raw_stmt, i))

    return ParsedPolicy(
        version=version,
        id=policy_id,
        statements=statements,
        raw=policy_dict,
        source_label=source_label,
    )


def _parse_statement(raw: dict, index: int) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyError(f"Statement #{index}: expected an object, got {type(raw).__name__}")

    effect = raw.get("Effect", "")
    if effect not in ("Allow", "Deny"):
        raise PolicyError(f"Statement #{index}: invalid Effect '{effect}' (must be 'Allow' or 'Deny')")

    if "Action" in raw and "NotAction" in raw:
        raise PolicyError(f"Statement #{index}: cannot have both 'Action' and 'NotAction'")
    if "Action" not in raw and "NotAction" not in raw:
        raise PolicyError(f"Statement #{index}: missing 'Action' (or 'NotAction')")

    return Statement(
        sid=raw.get("Sid"),
        effect=effect,
        actions=_ensure_str_list(raw.get("Action", []), "Action", index),
        not_actions=_ensure_str_list(raw.get("NotAction", []), "NotAction", index),
        resources=_ensure_str_list(raw.get("Resource", []), "Resource", index),
        not_resources=_ensure_str_list(raw.get("NotResource", []), "NotResource", index),
        principals=_parse_principal(raw.get("Principal", [])),
        not_principals=_parse_principal(raw.get("NotPrincipal", [])),
        conditions=_parse_conditions(raw.get("Condition", {})),
        index=index,
    )


def _ensure_str_list(value, field: str, index: int) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    raise PolicyError(f"Statement #{index}: '{field}' must be a string or a list of strings")


def _parse_principal(value) -> list[str]:
    if value == "*":
        return ["*"]
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        principals = []
        for principal_type, pvals in value.items():
            if isinstance(pvals, str):
                pvals = [pvals]
            if not isinstance(pvals, list):
                continue
            for pv in pvals:
                principals.append(f"{principal_type}:{pv}")
        return principals
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _parse_conditions(value: dict) -> list[PolicyCondition]:
    if not isinstance(value, dict):
        return []

    conditions = []
    for operator, condition_block in value.items():
        if not isinstance(condition_block, dict):
            continue
        for key, vals in condition_block.items():
            if not isinstance(vals, list):
                vals = [vals]
            conditions.append(PolicyCondition(operator=operator, key=key, values=[_condition_value(v) for v in vals]))

    return conditions


def _condition_value(value) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    return str(value)
