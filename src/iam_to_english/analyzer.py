from __future__ import annotations

import re
from dataclasses import dataclass, field

from .catalog import (
    DANGEROUS_PATTERNS,
    canonical_action_name,
    describe_action_by_pattern,
    get_action_description,
    get_dangerous_info,
    get_service_name,
)
from .escalation import EscalationFinding, detect_privilege_escalations
from .matching import (
    SEVERITY_ORDER,
    action_matches,
    is_admin_equivalent,
    is_effectively_unscoped,
    is_full_admin,
    max_severity,
)
from .parser import ParsedPolicy, PolicyCondition, Statement


@dataclass
class Warning:
    severity: str
    message: str
    statement_index: int | None = None
    action: str | None = None  # the action pattern the warning is about, used to avoid duplicates

    @property
    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 4)


@dataclass
class ActionExplanation:
    description: str
    category: str
    raw_actions: list[str]


@dataclass
class ResourceExplanation:
    description: str
    raw: str


@dataclass
class ConditionExplanation:
    description: str
    raw: PolicyCondition


@dataclass
class StatementExplanation:
    effect: str
    effect_label: str
    sid: str | None
    index: int
    actions: list[ActionExplanation]
    resources: list[ResourceExplanation]
    conditions: list[ConditionExplanation]
    principals: list[str]
    uses_not_action: bool
    uses_not_resource: bool
    uses_not_principal: bool
    summary: str = ""


@dataclass
class PolicyExplanation:
    statements: list[StatementExplanation]
    warnings: list[Warning]
    services: set[str]
    total_actions: int
    source_label: str
    escalations: list[EscalationFinding] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        """Highest severity across warnings and escalation findings, or 'CLEAN'."""
        severities = [w.severity for w in self.warnings] + [e.severity for e in self.escalations]
        return max_severity(severities) or "CLEAN"


_CONDITION_OPERATOR_MAP = {
    "StringEquals": "must equal",
    "StringNotEquals": "must not equal",
    "StringEqualsIgnoreCase": "must equal (case-insensitive)",
    "StringNotEqualsIgnoreCase": "must not equal (case-insensitive)",
    "StringLike": "must match pattern",
    "StringNotLike": "must not match pattern",
    "NumericEquals": "must equal",
    "NumericNotEquals": "must not equal",
    "NumericLessThan": "must be less than",
    "NumericGreaterThan": "must be greater than",
    "NumericLessThanEquals": "must be at most",
    "NumericGreaterThanEquals": "must be at least",
    "DateEquals": "must be on",
    "DateNotEquals": "must not be on",
    "DateLessThan": "must be before",
    "DateGreaterThan": "must be after",
    "Bool": "must be",
    "IpAddress": "must be in",
    "NotIpAddress": "must not be in",
    "ArnEquals": "ARN must equal",
    "ArnLike": "ARN must match",
    "ArnNotEquals": "ARN must not equal",
    "ArnNotLike": "ARN must not match",
    "BinaryEquals": "must equal (binary)",
}

_MULTI_VALUE_OPERATORS = {
    "must equal": "must equal one of",
    "must not equal": "must not equal any of",
    "must equal (case-insensitive)": "must equal one of (case-insensitive)",
    "must match pattern": "must match one of",
    "must not match pattern": "must not match any of",
    "must be in": "must be in one of",
    "must not be in": "must not be in any of",
    "ARN must equal": "ARN must equal one of",
    "ARN must match": "ARN must match one of",
}

_CONDITION_KEY_MAP = {
    "aws:SourceIp": "Source IP",
    "aws:SourceVpc": "Source VPC",
    "aws:SourceVpce": "Source VPC endpoint",
    "aws:SourceAccount": "Source account",
    "aws:SourceArn": "Source ARN",
    "aws:CurrentTime": "Current time",
    "aws:EpochTime": "Current epoch time",
    "aws:MultiFactorAuthPresent": "MFA",
    "aws:MultiFactorAuthAge": "MFA age (seconds)",
    "aws:PrincipalOrgID": "Organization ID",
    "aws:PrincipalOrgPaths": "Organization path",
    "aws:PrincipalAccount": "Principal account",
    "aws:PrincipalArn": "Principal ARN",
    "aws:PrincipalTag": "Principal tag",
    "aws:PrincipalType": "Principal type",
    "aws:PrincipalIsAWSService": "Principal is AWS service",
    "aws:RequestedRegion": "Requested region",
    "aws:SecureTransport": "Using HTTPS",
    "aws:TokenIssueTime": "Token issue time",
    "aws:UserAgent": "User agent",
    "aws:Referer": "HTTP referer",
    "aws:CalledVia": "Called via service",
    "aws:ViaAWSService": "Via AWS service",
    "aws:ResourceTag": "Resource tag",
    "aws:RequestTag": "Request tag",
    "aws:TagKeys": "Tag keys in request",
    "aws:SourceOrgID": "Source organization ID",
    "aws:ResourceAccount": "Resource account",
    "aws:ResourceOrgID": "Resource organization ID",
    "aws:userid": "Caller user ID",
    "aws:username": "Caller user name",
    "aws:SourceIdentity": "Source identity",
    "aws:FederatedProvider": "Federated identity provider",
    "s3:ResourceAccount": "S3 resource account",
    "s3:TlsVersion": "TLS version",
    "token.actions.githubusercontent.com:sub": "GitHub OIDC subject (repo/branch)",
    "token.actions.githubusercontent.com:aud": "GitHub OIDC audience",
    "ec2:ResourceTag": "EC2 resource tag",
    "ec2:Vpc": "EC2 VPC",
    "ec2:Subnet": "EC2 subnet",
    "ec2:InstanceType": "EC2 instance type",
    "s3:prefix": "S3 key prefix",
    "s3:x-amz-acl": "S3 ACL",
    "s3:x-amz-server-side-encryption": "S3 encryption",
    "kms:ViaService": "KMS via service",
    "iam:PassedToService": "Service receiving the role",
    "lambda:FunctionArn": "Lambda function ARN",
    "sts:ExternalId": "External ID",
    "sts:RoleSessionName": "Role session name",
}


def analyze(policy: ParsedPolicy) -> PolicyExplanation:
    warnings = []
    statement_explanations = []
    all_services = set()
    total_actions = 0

    for stmt in policy.statements:
        stmt_exp = _explain_statement(stmt)
        statement_explanations.append(stmt_exp)
        all_services.update(stmt.get_services())
        total_actions += len(stmt.actions) + len(stmt.not_actions)
        warnings.extend(_check_statement_warnings(stmt))

    # A Deny on "*" does not mean the policy touches every service; an Allow+NotAction does
    if "*" in policy.get_allowed_services():
        all_services.add("*")
    elif "*" in all_services:
        all_services.discard("*")

    warnings.extend(_check_global_warnings(policy, warnings))

    escalations = detect_privilege_escalations(policy)
    # A warning about an action that an escalation path already explains, on the same statement,
    # only repeats it
    covered = {
        (action.lower(), index)
        for esc in escalations
        for action in esc.involved_actions + esc.granted_by
        for index in esc.statement_indexes
    }
    warnings = [w for w in warnings if not (w.action and (w.action.lower(), w.statement_index) in covered)]
    warnings.sort(key=lambda w: w.severity_order)

    return PolicyExplanation(
        statements=statement_explanations,
        warnings=warnings,
        services=all_services,
        total_actions=total_actions,
        source_label=policy.source_label,
        escalations=escalations,
    )


def _explain_statement(stmt: Statement) -> StatementExplanation:
    effect_label = "ALLOW" if stmt.is_allow else "DENY"

    if stmt.not_actions:
        actions = _explain_actions(stmt.not_actions)
    else:
        actions = _explain_actions(stmt.actions)

    if stmt.not_resources:
        resources = _explain_resources(stmt.not_resources)
    else:
        resources = _explain_resources(stmt.resources)

    conditions = [_explain_condition(c) for c in stmt.conditions]
    principals = _explain_principals(stmt.principals, stmt.not_principals)

    explanation = StatementExplanation(
        effect=stmt.effect,
        effect_label=effect_label,
        sid=stmt.sid,
        index=stmt.index,
        actions=actions,
        resources=resources,
        conditions=conditions,
        principals=principals,
        uses_not_action=stmt.uses_not_action,
        uses_not_resource=stmt.uses_not_resource,
        uses_not_principal=stmt.uses_not_principal,
    )
    explanation.summary = _summarize_statement(stmt, explanation)
    return explanation


def _explain_actions(actions: list[str]) -> list[ActionExplanation]:
    explanations = []

    for action in actions:
        if action == "*":
            explanations.append(ActionExplanation(
                description="ALL actions on ALL AWS services (full admin)",
                category="admin",
                raw_actions=[action],
            ))
            continue

        if ":" not in action:
            explanations.append(ActionExplanation(
                description=f"Unrecognized action '{action}' (expected 'service:Action')",
                category="unknown",
                raw_actions=[action],
            ))
            continue

        prefix, action_part = action.split(":", 1)
        service = get_service_name(prefix)

        if action_part == "*":
            explanations.append(ActionExplanation(
                description=f"ALL actions on {service}",
                category="admin",
                raw_actions=[action],
            ))
            continue

        desc = get_action_description(action)
        if desc:
            category, _ = describe_action_by_pattern(canonical_action_name(action))
            explanations.append(ActionExplanation(description=desc, category=category, raw_actions=[action]))
            continue

        if "*" in action_part or "?" in action_part:
            explanations.append(_explain_wildcard_action(prefix, action_part, service))
            continue

        category, desc = describe_action_by_pattern(action)
        explanations.append(ActionExplanation(description=desc, category=category, raw_actions=[action]))

    return explanations


_CATEGORY_HINTS = {"read": "read-only", "write": "can modify", "delete": "can delete", "execute": "can execute"}


def _explain_wildcard_action(prefix: str, action_part: str, service: str) -> ActionExplanation:
    action = f"{prefix}:{action_part}"
    stem = action_part.rstrip("*")
    if stem and "*" not in stem and "?" not in stem:
        category, _ = describe_action_by_pattern(f"{prefix}:{stem}")
        hint = _CATEGORY_HINTS.get(category)
        hint_text = f" ({hint})" if hint else ""
        description = f"All {service} actions starting with '{stem}'{hint_text}"
    else:
        category = "other"
        description = f"All {service} actions matching '{action_part}'"

    sensitive = _dangerous_actions_matching(action)
    if sensitive:
        names = ", ".join(sensitive[:4]) + (", ..." if len(sensitive) > 4 else "")
        description = description.replace(" (read-only)", " (mostly read-only)")
        description += f", including the sensitive {names}"
    return ActionExplanation(description=description, category=category, raw_actions=[action])


def _explain_resources(resources: list[str]) -> list[ResourceExplanation]:
    explanations = []
    for resource in resources:
        if resource == "*":
            explanations.append(ResourceExplanation(description="All resources (no restriction)", raw=resource))
            continue
        explanations.append(ResourceExplanation(description=_describe_arn(resource), raw=resource))
    return explanations


def _describe_arn(arn: str) -> str:
    if not arn.startswith("arn:"):
        return arn

    parts = arn.split(":", 5)
    if len(parts) < 6:
        return arn

    service, region, account, resource = parts[2], parts[3], parts[4], parts[5]
    service_name = get_service_name(service)

    if service == "s3":
        return _describe_s3_resource(resource)

    if service == "iam" and account == "aws" and resource.startswith("policy/"):
        return f"AWS-managed policy '{resource[len('policy/'):]}'"
    if service == "iam" and resource in ("user/${aws:username}", "mfa/${aws:username}"):
        kind = "IAM user" if resource.startswith("user/") else "MFA device"
        return f"the caller's own {kind} (${{aws:username}})"

    if resource == "*":
        what = f"all {service_name} resources"
    elif service in ("sqs", "sns") and "/" not in resource and ":" not in resource:
        kind = "queue" if service == "sqs" else "topic"
        what = _named(kind, resource, service_name)
    else:
        resource_type, resource_id = _split_resource(resource)
        if resource_type is None:
            what = f"'{resource}' in {service_name}"
        else:
            if service == "logs" and resource_type == "log-group" and resource_id.endswith(":*"):
                resource_id = resource_id[:-2]  # ":*" means "and its log streams"
            what = _named(resource_type, resource_id, service_name)

    qualifiers = []
    if region:
        qualifiers.append("any region" if region == "*" else f"region {region}")
    if account:
        qualifiers.append("any account" if account == "*" else f"account {account}")
    if qualifiers:
        what += f" ({', '.join(qualifiers)})"
    return what


def _split_resource(resource: str) -> tuple[str | None, str]:
    """Split 'type/id' or 'type:id' (whichever separator comes first) into its parts."""
    positions = [i for i in (resource.find("/"), resource.find(":")) if i > 0]
    if not positions:
        return None, resource
    i = min(positions)
    return resource[:i], resource[i + 1:]


def _named(resource_type: str, resource_id: str, service_name: str) -> str:
    if resource_id in ("*", ""):
        return f"all {resource_type}s in {service_name}"
    if "*" in resource_id or "?" in resource_id:
        return f"{resource_type}s matching '{resource_id}' in {service_name}"
    return f"{resource_type} '{resource_id}' in {service_name}"


def _describe_s3_resource(resource: str) -> str:
    bucket, sep, key = resource.partition("/")
    bucket_wild = "*" in bucket or "?" in bucket
    if bucket == "*" and not sep:
        return "all S3 buckets"
    buckets = "any S3 bucket" if bucket == "*" else (
        f"S3 buckets matching '{bucket}'" if bucket_wild else f"S3 bucket '{bucket}'"
    )
    if not sep:
        return buckets
    in_bucket = "in " + buckets
    if key == "*":
        return f"all objects {in_bucket}"
    if key.endswith("/*") and "*" not in key[:-2]:
        return f"objects under '{key[:-1]}' {in_bucket}"
    if "*" in key or "?" in key or "${" in key:
        return f"objects matching '{key}' {in_bucket}"
    return f"object '{key}' {in_bucket}"


def _explain_condition(condition: PolicyCondition) -> ConditionExplanation:
    operator = condition.operator
    quantifier = ""
    if_exists = False

    if operator.startswith("ForAnyValue:"):
        quantifier = "at least one value of "
        operator = operator[len("ForAnyValue:"):]
    elif operator.startswith("ForAllValues:"):
        quantifier = "every value of "
        operator = operator[len("ForAllValues:"):]

    if operator.endswith("IfExists"):
        if_exists = True
        operator = operator[:-len("IfExists")]

    key_desc = _describe_condition_key(condition.key)
    suffix = " (if key exists in request)" if if_exists else ""

    bool_phrase = _BOOL_PHRASES.get(condition.key.lower()) if operator == "Bool" else None
    if bool_phrase and len(condition.values) == 1 and condition.values[0].lower() in ("true", "false"):
        desc = f"{bool_phrase[0] if condition.values[0].lower() == 'true' else bool_phrase[1]}{suffix}"
    elif operator == "Null":
        if "false" in str(condition.values).lower():
            desc = f"{quantifier}{key_desc} must be present{suffix}"
        else:
            desc = f"{quantifier}{key_desc} must be absent{suffix}"
    else:
        op_desc = _CONDITION_OPERATOR_MAP.get(operator, operator)
        if len(condition.values) > 1:
            op_desc = _MULTI_VALUE_OPERATORS.get(op_desc, op_desc)
        values_str = ", ".join(f"'{v}'" for v in condition.values)
        if op_desc.startswith("ARN ") and key_desc.endswith("ARN"):
            op_desc = op_desc[4:]
        desc = f"{quantifier}{key_desc} {op_desc} {values_str}{suffix}"
    return ConditionExplanation(description=desc, raw=condition)


_BOOL_PHRASES = {
    "aws:securetransport": ("Request uses HTTPS (TLS)", "Request does NOT use HTTPS (plain HTTP)"),
    "aws:multifactorauthpresent": ("Caller signed in with MFA", "Caller did NOT sign in with MFA"),
    "aws:viaawsservice": ("Request is made by an AWS service on the caller's behalf",
                          "Request is NOT made via an AWS service"),
    "aws:principalisawsservice": ("Caller is an AWS service principal", "Caller is NOT an AWS service principal"),
}


def _describe_condition_key(key: str) -> str:
    lowered = {k.lower(): v for k, v in _CONDITION_KEY_MAP.items()}
    if key.lower() in lowered:
        return lowered[key.lower()]

    for prefix, desc in _CONDITION_KEY_MAP.items():
        if key.lower().startswith(prefix.lower() + "/"):
            tag_name = key[len(prefix) + 1:]
            return f"{desc} '{tag_name}'"

    return key


def _explain_principals(principals: list[str], not_principals: list[str]) -> list[str]:
    result = []
    for p in principals:
        result.append(_format_principal(p))
    for p in not_principals:
        result.append(f"NOT: {_format_principal(p)}")
    return result


def _format_principal(p: str) -> str:
    if p == "*":
        return "Anyone (public access)"
    if ":" not in p:
        return p
    principal_type, value = p.split(":", 1)
    if principal_type == "AWS":
        if value == "*":
            return "Anyone (any AWS account -- public access)"
        if ":root" in value:
            parts = value.split(":")
            account = parts[4] if len(parts) > 4 else value
            return f"Root of account {account}"
        if ":role/" in value:
            return f"Role '{value.split('/')[-1]}'"
        if ":user/" in value:
            return f"User '{value.split('/')[-1]}'"
        if value.isdigit() and len(value) == 12:
            return f"AWS account {value}"
        return value
    if principal_type == "Service":
        return f"AWS service: {value}"
    if principal_type == "Federated":
        if "token.actions.githubusercontent.com" in value:
            return "GitHub Actions (OIDC)"
        if value in ("cognito-identity.amazonaws.com", "accounts.google.com", "graph.facebook.com", "www.amazon.com"):
            return f"Web identity from {value}"
        if ":saml-provider/" in value:
            return f"SAML identity provider '{value.split('/')[-1]}'"
        if ":oidc-provider/" in value:
            return f"OIDC identity provider '{value.split(':oidc-provider/', 1)[1]}'"
        return f"Federated identity: {value}"
    if principal_type == "CanonicalUser":
        return f"S3 canonical user {value[:12]}..."
    return f"{principal_type}: {value}"


def _check_statement_warnings(stmt: Statement) -> list[Warning]:
    warnings: list[Warning] = []

    def warn(severity: str, message: str, action: str | None = None) -> None:
        warnings.append(Warning(severity=severity, message=message, statement_index=stmt.index, action=action))

    if not stmt.is_allow:
        return warnings

    if is_full_admin(stmt) or (stmt.has_wildcard_action and stmt.has_wildcard_resource):
        if stmt.has_conditions:
            warn("HIGH", "Every action on every resource is allowed, limited only by the conditions")
        else:
            warn("CRITICAL", "Full administrator access: every action on every resource")
        _check_principal_warnings(stmt, warn)
        return warnings

    if stmt.has_wildcard_action:
        warn("HIGH", f"Every AWS action is allowed (\"Action\": \"*\"), {_scope_phrase(stmt)}")

    scope = _scope_phrase(stmt)
    self_scoped = _is_self_scoped(stmt)
    for action in stmt.actions:
        if action == "*" or ":" not in action:
            continue
        prefix, action_part = action.split(":", 1)

        if action_part == "*":
            service = get_service_name(prefix)
            sev = "HIGH" if prefix.lower() in ("iam", "sts", "kms", "organizations") else "MEDIUM"
            warn(sev, f"Full control of {service}: every read, write and delete action ({action}, {scope})", action)
            continue

        if "*" in action_part or "?" in action_part:
            sensitive = _dangerous_actions_matching(action)
            if len(sensitive) == 1:
                severity, message = DANGEROUS_PATTERNS[sensitive[0]]
                warn(_scoped_severity(stmt, severity),
                     f"{action} also grants {sensitive[0]}: {_lower_first(message)} ({scope})", action)
            elif sensitive:
                severity = max_severity([DANGEROUS_PATTERNS[a][0] for a in sensitive]) or "MEDIUM"
                names = ", ".join(sensitive[:5]) + (", ..." if len(sensitive) > 5 else "")
                warn(_scoped_severity(stmt, severity), f"{action} also grants sensitive actions: {names} ({scope})",
                     action)
            continue

        danger = get_dangerous_info(action)
        if not danger:
            continue
        if stmt.is_resource_based and action.lower().startswith("sts:assumerole"):
            continue  # In a trust policy this is who may assume the role, checked below
        severity, message = danger
        name = canonical_action_name(action)
        if self_scoped:
            if action.lower() in _SELF_SERVICE_SAFE:
                continue  # AWS's recommended "manage your own credentials" pattern
            warn(severity, f"{message} ({name}, on the caller's own identity)", action)
            continue
        warn(_scoped_severity(stmt, severity), f"{message} ({name}, {scope})", action)

    if stmt.has_wildcard_resource and not stmt.has_wildcard_action and not stmt.is_resource_based:
        # Least-privilege hint only: many actions (e.g. logs:CreateLogGroup) are routinely granted on "*"
        flagged = {w.action.lower() for w in warnings if w.action}
        changes = [a for a in stmt.actions if _is_write_action(a) and not a.endswith(":*") and a.lower() not in flagged]
        if changes:
            names = ", ".join(changes[:3]) + (", ..." if len(changes) > 3 else "")
            warn("LOW", f"These changes are allowed on every resource (\"Resource\": \"*\"): {names}. "
                        "Limit them to specific ARNs if possible")

    if stmt.uses_not_action:
        if is_admin_equivalent(stmt):
            warn("CRITICAL", f"Effectively full administrator access: everything is allowed except "
                             f"{', '.join(stmt.not_actions)}, including IAM, so it can grant itself any permission")
        else:
            warn("HIGH", "Every action is allowed except those listed (NotAction)"
                         + (" on all resources" if stmt.has_wildcard_resource else "")
                         + "; actions AWS adds later are allowed automatically")

    if stmt.uses_not_resource:
        warn("HIGH", "Applies to every resource except those listed (NotResource), including resources created later")

    _check_principal_warnings(stmt, warn)

    if not stmt.is_resource_based and not _has_mfa_condition(stmt) and not self_scoped:
        sensitive = [a for a in stmt.actions if _is_sensitive_action(a)]
        if sensitive:
            names = ", ".join(sensitive[:3]) + (", ..." if len(sensitive) > 3 else "")
            warn("LOW", f"High-impact actions do not require MFA: {names}. "
                        "Consider an aws:MultiFactorAuthPresent condition")

    return warnings


def _check_principal_warnings(stmt: Statement, warn) -> None:
    """Checks that only apply to resource-based policies (trust, bucket, key, queue policies)."""
    if stmt.uses_not_principal:
        warn("HIGH", "Grants access to everyone except the listed principals (NotPrincipal with Allow)")

    if stmt.is_public:
        assume = any(a.lower().startswith("sts:assumerole") or a == "*" for a in stmt.actions)
        read_only = bool(stmt.actions) and all(_is_read_action(a) for a in stmt.actions)
        if not stmt.has_conditions:
            if assume:
                warn("CRITICAL", "Anyone on the internet (any AWS account) can assume this role")
            elif read_only:
                warn("HIGH", f"Anyone on the internet can {_action_list(stmt)}. "
                             "Make sure this data is meant to be public")
            else:
                warn("CRITICAL", f"Anyone on the internet can {_action_list(stmt)}, with no conditions")
        elif not _has_restricting_condition(stmt):
            warn("MEDIUM", "Open to any principal: check that the conditions really restrict who gets in")

    for principal in stmt.principals:
        if not principal.startswith("Federated:"):
            continue
        if "token.actions.githubusercontent.com" in principal:
            sub = [c for c in stmt.conditions if c.key.lower() == "token.actions.githubusercontent.com:sub"]
            if not sub:
                warn("CRITICAL", "Any GitHub repository can assume this role: the trust has no "
                                 "'token.actions.githubusercontent.com:sub' condition")
            elif any(v.strip() in ("*", "repo:*", "repo:*/*") for c in sub for v in c.values):
                warn("HIGH", "Any GitHub repository can assume this role: the 'sub' condition allows any "
                             "repository. Restrict it to 'repo:<org>/<repo>:ref:refs/heads/<branch>' or an environment")
        elif ":oidc-provider/" in principal and not stmt.has_conditions:
            warn("HIGH", "Any token from this identity provider can assume the role: the trust has no conditions")


# Condition keys that genuinely narrow who can use a public statement
_RESTRICTING_KEYS = {
    "aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn",
    "aws:sourceaccount", "aws:sourcearn", "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip",
    "aws:sourceorgid", "aws:sourceorgpaths", "aws:userid", "aws:calledvia", "aws:resourceorgid",
    "kms:callerAccount".lower(), "kms:viaservice", "sts:externalid", "lambda:functionarn",
}


def _has_restricting_condition(stmt: Statement) -> bool:
    for cond in stmt.conditions:
        if cond.key.lower() in _RESTRICTING_KEYS and "*" not in cond.values:
            return True
        if cond.key.lower().endswith((":sub", ":aud")):
            return True
    return False


def _check_global_warnings(policy: ParsedPolicy, existing_warnings: list[Warning]) -> list[Warning]:
    warnings = []

    if not policy.statements:
        warnings.append(Warning(severity="LOW", message="The policy has no statements, so it grants nothing"))

    if policy.version != "2012-10-17":
        current = f"'{policy.version}'" if policy.version else "missing"
        warnings.append(Warning(
            severity="LOW",
            message=f"Policy version is {current}: use \"2012-10-17\", otherwise policy variables such as "
                    "${aws:username} do not work",
        ))

    return warnings


_SELF_SERVICE_SAFE = {"iam:createaccesskey", "iam:createloginprofile", "iam:updateloginprofile"}


def _is_self_scoped(stmt: Statement) -> bool:
    return bool(stmt.resources) and all("${aws:username}" in r for r in stmt.resources)


def _resource_count(stmt: Statement) -> str:
    if stmt.not_resources:
        return "all resources EXCEPT those listed"
    n = len(stmt.resources)
    return f"{n} resource{'s' if n != 1 else ''}"


def _scope_phrase(stmt: Statement) -> str:
    if stmt.has_wildcard_resource:
        return "on all resources"
    if stmt.not_resources:
        return "on all resources except those listed"
    if stmt.resources:
        return f"limited to {_resource_count(stmt)}"
    return "no Resource element"


def _scoped_severity(stmt: Statement, severity: str) -> str:
    """Dangerous actions limited to specific resources are one level less severe."""
    if stmt.has_wildcard_resource or stmt.not_resources or (not stmt.resources and not stmt.is_resource_based):
        return severity
    if any(is_effectively_unscoped(r) for r in stmt.resources):
        return severity
    return _lower_severity(severity)


def _dangerous_actions_matching(pattern: str) -> list[str]:
    """Known dangerous actions granted by a wildcard pattern like 'iam:Put*' or 'ec2:Get*'."""
    return [name for name in DANGEROUS_PATTERNS if action_matches(pattern, name)]


def _is_read_action(action: str) -> bool:
    if ":" not in action or "*" in action:
        return False
    if get_dangerous_info(action):
        return False
    category, _ = describe_action_by_pattern(canonical_action_name(action))
    return category == "read"


def _is_write_action(action: str) -> bool:
    """Actions that create, change or delete something (not read-only, not just running something)."""
    if ":" not in action:
        return False
    _, action_name = action.split(":", 1)
    change_verbs = ("put", "create", "update", "delete", "remove", "modify", "set", "attach", "detach",
                    "add", "revoke", "terminate", "stop", "tag", "untag", "replace", "reset", "restore")
    name = action_name.lower()
    return name.startswith(change_verbs) and not name.startswith(("setup",))


# High-impact, usually human-driven actions where an MFA condition is a sensible guardrail
_MFA_SENSITIVE = (
    "iam:CreateUser", "iam:DeleteUser", "iam:DeleteRole", "iam:CreateAccessKey", "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile", "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy", "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion", "iam:UpdateAssumeRolePolicy", "iam:AddUserToGroup", "iam:DeactivateMFADevice",
    "kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy",
    "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutBucketPublicAccessBlock",
    "ec2:TerminateInstances", "rds:DeleteDBInstance", "rds:DeleteDBCluster",
    "organizations:LeaveOrganization", "organizations:DeleteOrganization", "organizations:RemoveAccountFromOrganization",
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
)


def _is_sensitive_action(action: str) -> bool:
    return any(action_matches(action, a) for a in _MFA_SENSITIVE)


def _has_mfa_condition(stmt: Statement) -> bool:
    for cond in stmt.conditions:
        if cond.key.lower() in ("aws:multifactorauthpresent", "aws:multifactorauthage"):
            return True
    return False


def _lower_severity(severity: str) -> str:
    return {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}.get(severity, severity)


def _lower_first(text: str) -> str:
    """Lower-case a leading capitalized word ("Source IP" -> "source IP"), but keep "GitHub", "IAM", "S3"."""
    word = text.split(" ", 1)[0]
    if len(word) > 1 and word[0].isupper() and word[1:].islower():
        return text[0].lower() + text[1:]
    return text


def _action_list(stmt: Statement) -> str:
    descriptions = [_lower_first(a.description) for a in _explain_actions(stmt.actions)]
    return _join(descriptions[:3] + ([f"{len(descriptions) - 3} more"] if len(descriptions) > 3 else []))


def _join(items: list[str], conjunction: str = "and") -> str:
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} {conjunction} {items[-1]}"


# --- One-sentence summary of a statement ----------------------------------------------------------

_CATEGORY_VERBS = {"read": "read", "write": "change", "delete": "delete", "execute": "run", "admin": "full control"}

_CONDITION_REWRITES = (
    (" must not equal any of ", " is none of "),
    (" must equal one of ", " is one of "),
    (" must match one of ", " matches one of "),
    (" must not match any of ", " matches none of "),
    (" must not be in any of ", " is in none of "),
    (" must be in one of ", " is in one of "),
    (" must not match pattern ", " does not match "),
    (" must match pattern ", " matches "),
    (" must not equal ", " is not "),
    (" must equal ", " is "),
    (" must not be in ", " is not in "),
    (" must be in ", " is in "),
    (" must not be on ", " is not on "),
    (" must be on ", " is on "),
    (" must be present", " is present"),
    (" must be absent", " is absent"),
    (" must be ", " is "),
    (" must ", " "),
)


def _summarize_statement(stmt: Statement, exp: StatementExplanation) -> str:
    """One plain sentence, e.g. "Anyone (public access) can download objects from S3, on ..."."""
    assume = [a.lower() for a in stmt.actions if a.lower().startswith("sts:assumerole")]
    if stmt.not_actions:
        excluded = [
            f"{get_service_name(a.split(':', 1)[0])} actions" if a.endswith(":*") else a for a in stmt.not_actions
        ]
        what = f"do anything except {_join(excluded)}"
    elif stmt.is_resource_based and assume and len(assume) == len(stmt.actions):
        how = {"sts:assumerolewithwebidentity": " with a web identity (OIDC) token",
               "sts:assumerolewithsaml": " with a SAML assertion"}
        what = "assume this role" + (how.get(assume[0], "") if len(assume) == 1 else "")
    elif "*" in stmt.actions:
        what = "do anything in any AWS service"
    else:
        what = _summarize_actions(exp.actions)

    subject = _summarize_principals(stmt)
    verb = "can" if stmt.is_allow else "cannot"
    sentence = f"{subject} {verb} {what}" if subject else f"{verb.capitalize()} {what}"

    where = _summarize_resources(stmt, exp)
    if where:
        sentence += f", {where}"

    if len(exp.conditions) == 1:
        condition = _lower_first(exp.conditions[0].description)
        for old, new in _CONDITION_REWRITES:
            condition = condition.replace(old, new)
        sentence += f", {'only if' if stmt.is_allow else 'when'} {condition}"
    elif exp.conditions:
        sentence += f", {'only if' if stmt.is_allow else 'when'} {len(exp.conditions)} conditions are all true"
    return sentence + "."


def _summarize_actions(actions: list[ActionExplanation]) -> str:
    """Verb phrase for the actions: listed one by one when few, grouped by service when many."""
    # "ec2:Describe*" + "ec2:Get*" -> "use all EC2 actions starting with 'Describe' or 'Get'"
    prefixed: dict[str, list[ActionExplanation]] = {}
    singles: list[ActionExplanation] = []
    for a in actions:
        match = re.match(r"All (.+) actions starting with '([^']+)'", a.description)
        if match:
            prefixed.setdefault(match.group(1), []).append(a)
        else:
            singles.append(a)

    wildcard_phrases = []
    for service, items in prefixed.items():
        stems = [re.match(r"All .+ actions starting with '([^']+)'", a.description).group(1) for a in items]
        sensitive = [d for a in items for d in _dangerous_actions_matching(a.raw_actions[0])]
        phrase = f"use all {service} actions starting with {_join([chr(39) + x + chr(39) for x in stems], 'or')}"
        if sensitive:
            phrase += f" (including the sensitive {_join(sensitive[:3])})"
        wildcard_phrases.append(phrase)

    if len(singles) + len(wildcard_phrases) <= 4:
        phrases = []
        for a in singles:
            text = a.description.split(", including the sensitive")[0]
            if text.startswith("ALL actions on "):
                text = "do anything in " + text[len("ALL actions on "):]
            elif text.startswith(("All ", "Unrecognized")):
                text = "use " + _lower_first(text)
            phrases.append(_lower_first(text))
        return _join(phrases + wildcard_phrases)

    by_service: dict[str, list[ActionExplanation]] = {}
    for a in actions:
        raw = a.raw_actions[0]
        service = get_service_name(raw.split(":", 1)[0]) if ":" in raw else raw
        by_service.setdefault(service, []).append(a)
    if len(by_service) > 4:
        return f"use {_count_actions(actions, f'actions across {len(by_service)} services')}"

    phrases = []
    for service, items in by_service.items():
        if any(a.category == "admin" for a in items):
            phrases.append(f"do anything in {service}")
            continue
        phrases.append(f"use {_count_actions(items, service + (' actions' if len(items) != 1 else ' action'))}")
    return _join(phrases)


def _count_actions(actions: list[ActionExplanation], noun: str) -> str:
    """'4 read-only IAM actions', '5 Lambda actions (change, run and read)'..."""
    reads = sum(1 for a in actions if a.category == "read")
    if reads == len(actions):
        return f"{len(actions):,} read-only {noun}"
    if reads >= 0.9 * len(actions):
        return f"{len(actions):,} mostly read-only {noun}"
    verbs = []
    for a in actions:
        verb = _CATEGORY_VERBS.get(a.category)
        if verb and verb not in verbs:
            verbs.append(verb)
    return f"{len(actions):,} {noun}" + (f" ({_join(verbs)})" if verbs else "")


def _summarize_resources(stmt: Statement, exp: StatementExplanation) -> str:
    if stmt.not_resources:
        return f"on every resource except {exp.resources[0].description}" + (
            f" and {len(exp.resources) - 1} more" if len(exp.resources) > 1 else "")
    if stmt.has_wildcard_resource:
        return "on all resources"
    if not exp.resources:
        return ""
    first = exp.resources[0].description
    return f"on {first}" + (f" and {len(exp.resources) - 1} more" if len(exp.resources) > 1 else "")


def _summarize_principals(stmt: Statement) -> str:
    if stmt.is_public:
        return "Anyone (public access)"
    names = [_who(p) for p in stmt.principals]
    if stmt.not_principals:
        names.append("everyone except " + _join([_who(p) for p in stmt.not_principals], "or"))
    if not names:
        return ""
    shown = names[:2] + ([f"{len(names) - 2} other principals"] if len(names) > 2 else [])
    subject = _join(shown, "or")
    return subject[:1].upper() + subject[1:]


def _who(principal: str) -> str:
    text = _format_principal(principal)
    if text.startswith("AWS service: "):
        return "the AWS service " + text[len("AWS service: "):]
    if text.startswith(("Root of", "Role ", "User ")):
        return "the " + _lower_first(text) if text.startswith("Root") else _lower_first(text)
    return text
