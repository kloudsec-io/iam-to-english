import json

import click
import pytest

from iam_to_english.loader import load_policy


def test_load_json_file(tmp_path):
    f = tmp_path / "policy.json"
    content = {"Version": "2012-10-17", "Statement": []}
    f.write_text(json.dumps(content))

    loaded = load_policy(str(f))
    assert loaded["Version"] == "2012-10-17"
    assert loaded["Statement"] == []

def test_load_yaml_file(tmp_path):
    f = tmp_path / "policy.yaml"
    f.write_text(
        "Version: '2012-10-17'\n"
        "Statement:\n"
        "  - Effect: Allow\n"
        "    Action: s3:GetObject\n"
        "    Resource: '*'\n"
    )
    loaded = load_policy(str(f))
    assert loaded["Version"] == "2012-10-17"
    assert len(loaded["Statement"]) == 1

def test_load_inline_json():
    raw = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}'
    loaded = load_policy(raw)
    assert loaded["Version"] == "2012-10-17"
    assert loaded["Statement"][0]["Action"] == "s3:*"

def test_load_inline_yaml():
    raw = (
        "Version: '2012-10-17'\n"
        "Statement:\n"
        "  - Effect: Allow\n"
        "    Action: 's3:*'\n"
        "    Resource: '*'\n"
    )
    loaded = load_policy(raw)
    assert loaded["Version"] == "2012-10-17"

def test_load_nonexistent_file():
    with pytest.raises(click.ClickException) as exc:
        load_policy("nonexistent_policy_file_xyz_123.json")
    assert "File not found" in str(exc.value)

def test_load_invalid_content(tmp_path):
    f = tmp_path / "invalid.txt"
    f.write_text("not json and not valid yaml dict: [")
    with pytest.raises(click.ClickException) as exc:
        load_policy(str(f))
    assert "Invalid policy format" in str(exc.value)
