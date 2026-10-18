from __future__ import annotations

import json
from dataclasses import dataclass, field

from .analyzer import Warning, _explain_actions, _explain_condition, analyze
from .escalation import EscalationFinding
from .formatter import _SEVERITY_COLORS, _colorize
from .matching import SEVERITY_ORDER
from .parser import ParsedPolicy, Statement

_RISK_ORDER = {**SEVERITY_ORDER, "CLEAN": 4}


@dataclass
class PolicyDiff:
    old_label: str
    new_label: str
    actions_added: list[str]
    actions_removed: list[str]
    resources_widened: list[str]
    resources_narrowed: list[str]
    conditions_removed: list[str]
    conditions_added: list[str]
    new_warnings: list[Warning]
    resolved_warnings: list[Warning]
    new_escalations: list[EscalationFinding]
    resolved_escalations: list[EscalationFinding]
    old_risk_level: str
    new_risk_level: str
    permissions_added: dict[str, list[str]] = field(default_factory=dict)
    permissions_removed: dict[str, list[str]] = field(default_factory=dict)
    denies_added: dict[str, list[str]] = field(default_factory=dict)
    denies_removed: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.permissions_added
            or self.permissions_removed
            or self.denies_added
            or self.denies_removed
            or self.conditions_removed
            or self.conditions_added
            or self.new_warnings
            or self.resolved_warnings
            or self.new_escalations
            or self.resolved_escalations
        )

    @property
    def risk_escalated(self) -> bool:
        return _RISK_ORDER.get(self.new_risk_level, 4) < _RISK_ORDER.get(self.old_risk_level, 4)


def _grants(policy: ParsedPolicy, allow: bool) -> dict[tuple[str, str], tuple[str, str]]:
    """Flatten statements into {(action_key, resource_key): (action_display, resource_display)}.

    Keys are lower-cased for actions (IAM is case-insensitive there); NotAction/NotResource and
    Principal are kept in the key so that a semantic change is never hidden.
    """
    grants: dict[tuple[str, str], tuple[str, str]] = {}
    for stmt in policy.statements:
        if stmt.is_allow != allow:
            continue
        for action in _action_labels(stmt):
            for resource in _resource_labels(stmt):
                grants.setdefault((action.lower(), resource), (action, resource))
    return grants


def _action_labels(stmt: Statement) -> list[str]:
    principal = f" [for {', '.join(stmt.principals)}]" if stmt.principals else ""
    if stmt.not_actions:
        return [f"everything except {', '.join(stmt.not_actions)}{principal}"]
    return [f"{a}{principal}" for a in stmt.actions]


def _resource_labels(stmt: Statement) -> list[str]:
    if stmt.not_resources:
        return [f"everything except {', '.join(stmt.not_resources)}"]
    return stmt.resources or ["(no Resource element)"]


def _group(pairs: list[tuple[str, str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for action, resource in sorted(pairs, key=lambda p: (p[0].lower(), p[1])):
        grouped.setdefault(action, []).append(resource)
    return grouped


def _allowed_actions(policy: ParsedPolicy) -> dict[str, str]:
    actions: dict[str, str] = {}
    for stmt in policy.allow_statements:
        for a in stmt.actions:
            actions.setdefault(a.lower(), a)
    return actions


def _conditions(policy: ParsedPolicy) -> dict[tuple, str]:
    conds: dict[tuple, str] = {}
    for stmt in policy.statements:
        for c in stmt.conditions:
            key = (stmt.effect, c.operator, c.key.lower(), tuple(sorted(c.values)))
            conds.setdefault(key, f"{stmt.effect}: {_explain_condition(c).description}")
    return conds


def diff_policies(old_policy: ParsedPolicy, new_policy: ParsedPolicy) -> PolicyDiff:
    """Compare two IAM policies and compute their semantic difference in plain English."""
    old_exp = analyze(old_policy)
    new_exp = analyze(new_policy)

    old_actions = _allowed_actions(old_policy)
    new_actions = _allowed_actions(new_policy)
    actions_added = sorted((new_actions[k] for k in new_actions.keys() - old_actions.keys()), key=str.lower)
    actions_removed = sorted((old_actions[k] for k in old_actions.keys() - new_actions.keys()), key=str.lower)

    old_allow, new_allow = _grants(old_policy, True), _grants(new_policy, True)
    old_deny, new_deny = _grants(old_policy, False), _grants(new_policy, False)

    permissions_added = _group([new_allow[k] for k in new_allow.keys() - old_allow.keys()])
    permissions_removed = _group([old_allow[k] for k in old_allow.keys() - new_allow.keys()])
    denies_added = _group([new_deny[k] for k in new_deny.keys() - old_deny.keys()])
    denies_removed = _group([old_deny[k] for k in old_deny.keys() - new_deny.keys()])

    # An action that now applies to "*" but did not before is the most important resource change
    resources_widened = []
    resources_narrowed = []
    old_keys = {k for k, _ in old_allow}
    new_keys = {k for k, _ in new_allow}
    for action, resources in permissions_added.items():
        if "*" in resources and action.lower() in old_keys:
            resources_widened.append(f"{_describe_action(action)} now applies to all resources")
    for action, resources in permissions_removed.items():
        if "*" in resources and action.lower() in new_keys:
            resources_narrowed.append(f"{_describe_action(action)} no longer applies to all resources")

    old_conds, new_conds = _conditions(old_policy), _conditions(new_policy)
    conditions_added = sorted(new_conds[k] for k in new_conds.keys() - old_conds.keys())
    conditions_removed = sorted(old_conds[k] for k in old_conds.keys() - new_conds.keys())

    old_warn_msgs = {w.message for w in old_exp.warnings}
    new_warn_msgs = {w.message for w in new_exp.warnings}
    new_warnings = [w for w in new_exp.warnings if w.message not in old_warn_msgs]
    # A warning is only "resolved" if its action is no longer flagged at all (not by a warning, not by
    # an escalation path that absorbed it)
    still_flagged = {w.action.lower() for w in new_exp.warnings if w.action}
    still_flagged |= {a.lower() for e in new_exp.escalations for a in e.involved_actions + e.granted_by}
    resolved_warnings = [
        w for w in old_exp.warnings
        if w.message not in new_warn_msgs and not (w.action and w.action.lower() in still_flagged)
    ]

    old_esc_ids = {e.id or e.name for e in old_exp.escalations}
    new_esc_ids = {e.id or e.name for e in new_exp.escalations}
    new_escalations = [e for e in new_exp.escalations if (e.id or e.name) not in old_esc_ids]
    resolved_escalations = [e for e in old_exp.escalations if (e.id or e.name) not in new_esc_ids]

    return PolicyDiff(
        old_label=old_policy.source_label or "original",
        new_label=new_policy.source_label or "target",
        actions_added=actions_added,
        actions_removed=actions_removed,
        resources_widened=resources_widened,
        resources_narrowed=resources_narrowed,
        conditions_removed=conditions_removed,
        conditions_added=conditions_added,
        new_warnings=new_warnings,
        resolved_warnings=resolved_warnings,
        new_escalations=new_escalations,
        resolved_escalations=resolved_escalations,
        old_risk_level=old_exp.risk_level,
        new_risk_level=new_exp.risk_level,
        permissions_added=permissions_added,
        permissions_removed=permissions_removed,
        denies_added=denies_added,
        denies_removed=denies_removed,
    )


def _describe_action(label: str) -> str:
    """'s3:GetObject [for X]' -> 'Download objects from S3 (s3:GetObject) [for X]'."""
    action, sep, principal = label.partition(" [for ")
    if action.startswith("everything except") or " " in action:
        return label
    description = _explain_actions([action])[0].description.split(", including the sensitive")[0]
    if description.startswith("ALL actions on ALL AWS services"):
        description = "Every action in every AWS service"
    elif description.startswith("ALL actions on "):
        description = "Every " + description[len("ALL actions on "):] + " action"
    return f"{description} ({action})" + (f" [for {principal}" if sep else "")


def _grant_line(action: str, resources: list[str]) -> str:
    shown = ["all resources" if r == "*" else r for r in resources]
    return f"{_describe_action(action)}, on {', '.join(shown)}"


def format_diff_text(diff: PolicyDiff) -> str:
    """Format the policy diff as human-readable colorized terminal output."""
    lines = []
    lines.append(f"IAM Policy Diff: {diff.old_label} -> {diff.new_label}")
    lines.append("=" * len(lines[0]))

    if not diff.has_changes:
        lines.append("\nNo semantic changes detected between the policies.")
        return "\n".join(lines)

    lines.append("")
    if diff.risk_escalated:
        lines.append(
            _colorize(
                f"RISK INCREASED: {diff.old_risk_level} -> {diff.new_risk_level}",
                "red",
                bold=True,
            )
        )
    else:
        lines.append(f"Risk: {diff.old_risk_level} -> {diff.new_risk_level}")
    lines.append("")

    def section(title: str, color: str, items: list[str], marker: str) -> None:
        if not items:
            return
        lines.append(_colorize(title, color, bold=True))
        for item in items:
            lines.append(f"  {_colorize(marker, color)} {item}")
        lines.append("")

    if diff.new_escalations:
        lines.append(_colorize("NEW PRIVILEGE ESCALATION PATHS:", "red", bold=True))
        for esc in diff.new_escalations:
            lines.append(f"  + [{_colorize(esc.severity, 'red', bold=True)}] {_colorize(esc.name, 'bold')}")
            lines.append(f"    Risk: {esc.description}")
            lines.append(f"    Permissions involved: {', '.join(esc.involved_actions)}")
        lines.append("")

    section("Escalation Paths Removed:", "green", [f"[{e.severity}] {e.name}" for e in diff.resolved_escalations], "-")
    section("Permissions Added (+):", "green", [_grant_line(a, r) for a, r in diff.permissions_added.items()], "+")
    section("Permissions Removed (-):", "red", [_grant_line(a, r) for a, r in diff.permissions_removed.items()], "-")
    section("Widened to All Resources (!):", "yellow", diff.resources_widened, "!")
    section("Narrowed from All Resources:", "blue", diff.resources_narrowed, "-")
    section("Deny Guardrails Removed (!):", "yellow", [_grant_line(a, r) for a, r in diff.denies_removed.items()], "-")
    section("Deny Guardrails Added:", "green", [_grant_line(a, r) for a, r in diff.denies_added.items()], "+")
    section("Conditions Removed (restrictions relaxed):", "yellow", diff.conditions_removed, "-")
    section("Conditions Added (new restrictions):", "green", diff.conditions_added, "+")

    if diff.new_warnings:
        lines.append(_colorize("New Warnings Introduced:", "yellow", bold=True))
        for w in diff.new_warnings:
            col = _SEVERITY_COLORS.get(w.severity, "yellow")
            lines.append(f"  ! [{_colorize(w.severity, col, bold=True)}] {w.message}")
        lines.append("")

    section("Warnings Resolved:", "green", [f"[{w.severity}] {w.message}" for w in diff.resolved_warnings], "-")

    return "\n".join(lines)


def format_diff_markdown(diff: PolicyDiff) -> str:
    """Format the policy diff as GitHub-flavored Markdown (ideal for PR comments)."""
    lines = []
    lines.append(f"# IAM Policy Diff: `{diff.old_label}` -> `{diff.new_label}`")
    lines.append("")

    if not diff.has_changes:
        lines.append("No semantic changes detected between the policies.")
        return "\n".join(lines)

    if diff.risk_escalated:
        lines.append(f"> [!WARNING]\n> Risk increased from **{diff.old_risk_level}** to **{diff.new_risk_level}**.")
    else:
        lines.append(f"**Risk:** `{diff.old_risk_level}` -> `{diff.new_risk_level}`")
    lines.append("")

    def section(title: str, items: list[str]) -> None:
        if not items:
            return
        lines.append(f"### {title}")
        lines.extend(f"- {item}" for item in items)
        lines.append("")

    def grants(grouped: dict[str, list[str]]) -> list[str]:
        return [
            f"{_describe_action(a)}, on {', '.join('all resources' if r == '*' else f'`{r}`' for r in res)}"
            for a, res in grouped.items()
        ]

    if diff.new_escalations:
        lines.append("### New Privilege Escalation Paths")
        for esc in diff.new_escalations:
            lines.append(f"- **[{esc.severity}] {esc.name}**")
            lines.append(f"  - *Actions:* {', '.join(f'`{a}`' for a in esc.involved_actions)}")
            lines.append(f"  - *Risk:* {esc.description}")
            lines.append(f"  - *Fix:* {esc.remediation}")
        lines.append("")

    section("Escalation Paths Removed", [f"[{e.severity}] {e.name}" for e in diff.resolved_escalations])
    section("Permissions Added", grants(diff.permissions_added))
    section("Permissions Removed", grants(diff.permissions_removed))
    section("Widened to All Resources", [f"`{r}`" for r in diff.resources_widened])
    section("Narrowed from All Resources", [f"`{r}`" for r in diff.resources_narrowed])
    section("Deny Guardrails Removed", grants(diff.denies_removed))
    section("Deny Guardrails Added", grants(diff.denies_added))
    section("Conditions Removed (restrictions relaxed)", diff.conditions_removed)
    section("Conditions Added (new restrictions)", diff.conditions_added)
    section("New Security Warnings", [f"**[{w.severity}]** {w.message}" for w in diff.new_warnings])
    section("Warnings Resolved", [f"[{w.severity}] {w.message}" for w in diff.resolved_warnings])

    return "\n".join(lines)


def format_diff_json(diff: PolicyDiff) -> str:
    """Format the policy diff as JSON for automated pipelines."""

    def esc(e: EscalationFinding) -> dict:
        return {
            "id": e.id,
            "name": e.name,
            "severity": e.severity,
            "involved_actions": e.involved_actions,
            "description": e.description,
            "remediation": e.remediation,
        }

    def warn(w: Warning) -> dict:
        return {"severity": w.severity, "message": w.message, "statement": w.statement_index}

    data = {
        "old_label": diff.old_label,
        "new_label": diff.new_label,
        "has_changes": diff.has_changes,
        "risk_levels": {
            "old": diff.old_risk_level,
            "new": diff.new_risk_level,
            "escalated": diff.risk_escalated,
        },
        "permissions_added": diff.permissions_added,
        "permissions_removed": diff.permissions_removed,
        "denies_added": diff.denies_added,
        "denies_removed": diff.denies_removed,
        "actions_added": diff.actions_added,
        "actions_removed": diff.actions_removed,
        "resources_widened": diff.resources_widened,
        "resources_narrowed": diff.resources_narrowed,
        "conditions_added": diff.conditions_added,
        "conditions_removed": diff.conditions_removed,
        "new_escalations": [esc(e) for e in diff.new_escalations],
        "resolved_escalations": [esc(e) for e in diff.resolved_escalations],
        "new_warnings": [warn(w) for w in diff.new_warnings],
        "resolved_warnings": [warn(w) for w in diff.resolved_warnings],
    }
    return json.dumps(data, indent=2)
