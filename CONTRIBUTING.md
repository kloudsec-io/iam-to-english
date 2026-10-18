# Contributing

Bug reports and pull requests are welcome.

- **Wrong or noisy result?** Open an issue with a sanitized policy (replace account IDs and names), the output you got, and what you expected. This is the most useful contribution.
- **Security problem?** Do not open an issue. See [SECURITY.md](SECURITY.md).

## Pull requests

```bash
git clone https://github.com/kloudsec-io/iam-to-english && cd iam-to-english
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q && ruff check .
```

Keep changes small, add a test (including a case that must **not** trigger a new finding), and make sure `pytest` and `ruff` pass.

By contributing, you agree that your work is released under the [MIT License](LICENSE).
