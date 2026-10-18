from __future__ import annotations

import click


class PolicyError(click.ClickException):
    """Operational error: bad input, invalid policy, or an AWS / AI backend failure.

    Exits with code 2 so CI pipelines can tell input errors apart from
    ``--fail-on`` findings, which exit with code 1.
    """

    exit_code = 2
