from __future__ import annotations

import json
import os
import shutil
import textwrap

from .analyzer import PolicyExplanation, StatementExplanation
from .catalog import get_service_name

_COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

_SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


def _colorize(text: str, color: str, bold: bool = False) -> str:
    prefix = ""
    if bold:
        prefix += _COLORS["bold"]
    if color in _COLORS:
        prefix += _COLORS[color]
    if prefix:
        return f"{prefix}{text}{_COLORS['reset']}"
    return text


def _service_names(explanation: PolicyExplanation, limit: int = 0) -> list[str]:
    if "*" in explanation.services:
        return ["ALL services"]
    names = sorted({get_service_name(s) for s in explanation.services}, key=str.lower)
    if limit and len(names) > limit:
        return names[:limit] + [f"and {len(names) - limit} more ({len(names)} services)"]
    return names


def _risk_summary(explanation: PolicyExplanation) -> str:
    n_esc = len(explanation.escalations)
    n_warn = len(explanation.warnings)
    parts = []
    if n_esc:
        parts.append(f"{n_esc} privilege escalation path{'s' if n_esc != 1 else ''}")
    if n_warn:
        parts.append(f"{n_warn} warning{'s' if n_warn != 1 else ''}")
    return ", ".join(parts) or "no findings"


def _stmt_label(index: int, sids: dict[int, str | None]) -> str:
    sid = sids.get(index)
    return f"Statement #{index} ({sid})" if sid else f"Statement #{index}"


def _width() -> int:
    """Wrap width: the terminal width (or $COLUMNS), between 60 and 120 columns."""
    columns = shutil.get_terminal_size((100, 24)).columns
    if os.environ.get("COLUMNS", "").isdigit():
        columns = int(os.environ["COLUMNS"])
    return max(60, min(columns, 120))


def _wrap(prefix: str, text: str, indent: int, width: int, colored_prefix: str | None = None) -> list[str]:
    """Wrap `prefix + text`, continuation lines indented; `colored_prefix` replaces the prefix afterwards."""
    lines = textwrap.wrap(prefix + text, width=width, subsequent_indent=" " * indent,
                          break_long_words=False, break_on_hyphens=False) or [prefix.rstrip()]
    if colored_prefix is not None and lines[0].startswith(prefix):
        lines[0] = colored_prefix + lines[0][len(prefix):]
    return lines


def format_text(explanation: PolicyExplanation, verbose: bool = False) -> str:
    width = _width()
    sids = {st.index: st.sid for st in explanation.statements}
    lines = []

    if explanation.source_label and explanation.source_label not in ("stdin", "inline policy"):
        lines.append(f"Policy: {explanation.source_label}")
    n_stmt = len(explanation.statements)
    service_names = _service_names(explanation, limit=10)
    lines.append(f"{n_stmt} statement{'s' if n_stmt != 1 else ''}"
                 + (f" | Services: {', '.join(service_names)}" if service_names else ""))
    risk = explanation.risk_level
    risk_text = _colorize(risk, _SEVERITY_COLORS.get(risk, "green"), bold=True)
    lines.append(f"Risk: {risk_text} ({_risk_summary(explanation)})")
    lines.append("")

    if explanation.statements:
        lines.append(_colorize("IN SHORT:", "bold", bold=True))
        for st in explanation.statements:
            label = f"  #{st.index}{f' {st.sid}' if st.sid else ''}: "
            lines.extend(_wrap(label, st.summary, 6, width))
        lines.append("")
        lines.append(_colorize("STATEMENT BY STATEMENT:", "bold", bold=True))
        lines.append("")

    for stmt_exp in explanation.statements:
        lines.extend(_format_statement_text(stmt_exp, width))
        lines.append("")

    if explanation.escalations:
        lines.append(_colorize("PRIVILEGE ESCALATION PATHS (ways to gain more access than granted):", "red",
                               bold=True))
        lines.append("")
        for esc in explanation.escalations:
            color = _SEVERITY_COLORS.get(esc.severity, "red")
            header = f"  [{esc.severity}] {esc.name}"
            lines.extend(_wrap(header, "", 4, width,
                               f"  [{_colorize(esc.severity, color, bold=True)}] {_colorize(esc.name, 'bold')}"))
            where = ", ".join(_stmt_label(i, sids) for i in esc.statement_indexes)
            lines.extend(_wrap("    Found in: ", where, 6, width))
            lines.extend(_wrap("    Risk: ", esc.description, 6, width))
            lines.extend(_wrap("    Permissions involved: ", ", ".join(esc.involved_actions), 6, width))
            if esc.granted_by:
                lines.extend(_wrap("    Granted by: ", ", ".join(esc.granted_by), 6, width))
            if esc.note:
                lines.extend(_wrap("    Note: ", esc.note, 6, width))
            if verbose:
                lines.append("    Attack path:")
                for step in esc.attack_path.split("\n"):
                    lines.extend(_wrap("      ", step, 9, width))
            lines.extend(_wrap("    How to fix: ", esc.remediation, 6, width))
            lines.append("")
        if not verbose:
            lines.append(_colorize("  Run with --verbose to see the attack steps.", "dim"))
            lines.append("")

    if explanation.warnings:
        title = "OTHER WARNINGS:" if explanation.escalations else "WARNINGS:"
        lines.append(_colorize(title, "yellow", bold=True))
        for w in explanation.warnings:
            where = f"{_stmt_label(w.statement_index, sids)}: " if w.statement_index is not None else ""
            prefix = f"  [{w.severity}] {where}"
            colored = f"  [{_colorize(w.severity, _SEVERITY_COLORS.get(w.severity, 'dim'))}] {where}"
            lines.extend(_wrap(prefix, w.message, 6, width, colored))
        lines.append("")

    return "\n".join(lines)


def _format_statement_text(stmt: StatementExplanation, width: int = 100) -> list[str]:
    lines = []

    color = "green" if stmt.effect == "Allow" else "red"
    sid_part = f" ({stmt.sid})" if stmt.sid else ""
    lines.append(_colorize(f"{stmt.effect_label} #{stmt.index}{sid_part}", color, bold=True))

    if stmt.principals:
        lines.append("   Who:")
        for p in stmt.principals:
            lines.extend(_wrap("     - ", p, 7, width))

    if stmt.actions:
        lines.append("   Actions: every action EXCEPT:" if stmt.uses_not_action else "   Actions:")
        for a in stmt.actions:
            lines.extend(_wrap("     - ", a.description, 7, width))
            if len(a.raw_actions) == 1 and a.raw_actions[0] != "*":
                lines.append(f"       {_colorize(a.raw_actions[0], 'dim')}")

    if stmt.resources:
        lines.append("   Resources: every resource EXCEPT:" if stmt.uses_not_resource else "   Resources:")
        for r in stmt.resources:
            lines.extend(_wrap("     - ", r.description, 7, width))
            if r.raw != "*":
                lines.append(f"       {_colorize(r.raw, 'dim')}")

    if stmt.conditions:
        lines.append("   Conditions (all must be true):" if len(stmt.conditions) > 1 else "   Condition:")
        for c in stmt.conditions:
            lines.extend(_wrap("     - ", c.description, 7, width))

    return lines


def format_json(explanation: PolicyExplanation) -> str:
    data = {
        "source": explanation.source_label,
        "summary": {
            "risk_level": explanation.risk_level,
            "total_statements": len(explanation.statements),
            "services": sorted(explanation.services),
            "total_actions": explanation.total_actions,
            "privilege_escalation_count": len(explanation.escalations),
            "warning_count": len(explanation.warnings),
        },
        "statements": [_statement_to_dict(s) for s in explanation.statements],
        "privilege_escalations": [
            {
                "id": e.id,
                "name": e.name,
                "severity": e.severity,
                "involved_actions": e.involved_actions,
                "granted_by": e.granted_by,
                "statement_indexes": e.statement_indexes,
                "description": e.description,
                "note": e.note,
                "attack_path": e.attack_path.split("\n"),
                "remediation": e.remediation,
            }
            for e in explanation.escalations
        ],
        "warnings": [
            {"severity": w.severity, "message": w.message, "statement": w.statement_index}
            for w in explanation.warnings
        ],
    }
    return json.dumps(data, indent=2)


def _statement_to_dict(stmt: StatementExplanation) -> dict:
    return {
        "index": stmt.index,
        "sid": stmt.sid,
        "effect": stmt.effect,
        "principals": stmt.principals,
        "actions": [
            {"description": a.description, "category": a.category, "raw": a.raw_actions}
            for a in stmt.actions
        ],
        "resources": [
            {"description": r.description, "raw": r.raw}
            for r in stmt.resources
        ],
        "conditions": [
            {"description": c.description, "operator": c.raw.operator, "key": c.raw.key, "values": c.raw.values}
            for c in stmt.conditions
        ],
        "uses_not_action": stmt.uses_not_action,
        "uses_not_resource": stmt.uses_not_resource,
        "uses_not_principal": stmt.uses_not_principal,
        "summary": stmt.summary,
    }


def format_markdown(explanation: PolicyExplanation) -> str:
    lines = []

    service_names = _service_names(explanation, limit=15)

    n_stmt = len(explanation.statements)
    title = f"IAM Policy Analysis: `{explanation.source_label}`" if explanation.source_label else "IAM Policy Analysis"
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Risk:** **{explanation.risk_level}** "
                 f"({_risk_summary(explanation)}) | **Statements:** {n_stmt} | "
                 f"**Services:** {', '.join(service_names) or 'N/A'}")
    lines.append("")
    sids = {st.index: st.sid for st in explanation.statements}

    if explanation.statements:
        lines.append("## In short")
        lines.append("")
        for st in explanation.statements:
            lines.append(f"- **#{st.index}{f' {st.sid}' if st.sid else ''}:** {st.summary}")
        lines.append("")

    for stmt_exp in explanation.statements:
        lines.extend(_format_statement_markdown(stmt_exp))
        lines.append("")

    if explanation.escalations:
        lines.append("## Privilege Escalation Paths")
        lines.append("")
        for esc in explanation.escalations:
            lines.append(f"### [{esc.severity}] {esc.name}")
            lines.append("")
            lines.append(f"**Found in:** {', '.join(_stmt_label(i, sids) for i in esc.statement_indexes)}")
            lines.append("")
            lines.append(f"**Risk:** {esc.description}")
            lines.append("")
            lines.append(f"**Permissions involved:** {', '.join(f'`{a}`' for a in esc.involved_actions)}"
                         + (f" (granted by {', '.join(f'`{g}`' for g in esc.granted_by)})" if esc.granted_by else ""))
            lines.append("")
            if esc.note:
                lines.append(f"> **Note:** {esc.note}")
                lines.append("")
            lines.append("<details><summary>Attack path</summary>")
            lines.append("")
            for step in esc.attack_path.split("\n"):
                lines.append(f"{step}  ")
            lines.append("")
            lines.append("</details>")
            lines.append("")
            lines.append(f"**How to fix:** {esc.remediation}")
            lines.append("")

    if explanation.warnings:
        lines.append("## Other warnings" if explanation.escalations else "## Warnings")
        lines.append("")
        for w in explanation.warnings:
            where = f" {_stmt_label(w.statement_index, sids)}" if w.statement_index is not None else ""
            lines.append(f"- **{w.severity}**{where}: {w.message}")
        lines.append("")

    return "\n".join(lines)


def _format_statement_markdown(stmt: StatementExplanation) -> list[str]:
    lines = []

    sid_part = f" ({stmt.sid})" if stmt.sid else ""
    lines.append(f"### {stmt.effect_label} #{stmt.index}{sid_part}")
    lines.append("")

    if stmt.principals:
        lines.append(f"**Who:** {', '.join(stmt.principals)}")
        lines.append("")

    prefix = "**Actions:** every action EXCEPT:" if stmt.uses_not_action else "**Actions:**"
    if stmt.actions:
        lines.append(prefix)
        for a in stmt.actions:
            raw = f" (`{a.raw_actions[0]}`)" if len(a.raw_actions) == 1 and a.raw_actions[0] != "*" else ""
            lines.append(f"- {a.description}{raw}")
        lines.append("")

    res_prefix = "**Resources:** every resource EXCEPT:" if stmt.uses_not_resource else "**Resources:**"
    if stmt.resources:
        lines.append(res_prefix)
        for r in stmt.resources:
            raw = f" (`{r.raw}`)" if r.raw != "*" else ""
            lines.append(f"- {r.description}{raw}")
        lines.append("")

    if stmt.conditions:
        lines.append("**Conditions (all must be true):**" if len(stmt.conditions) > 1 else "**Condition:**")
        for c in stmt.conditions:
            lines.append(f"- {c.description}")
        lines.append("")

    return lines
