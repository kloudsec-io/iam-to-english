import pytest


@pytest.fixture
def s3_readonly_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    "arn:aws:s3:::my-bucket",
                    "arn:aws:s3:::my-bucket/*"
                ]
            }
        ]
    }

@pytest.fixture
def admin_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

@pytest.fixture
def passrole_lambda_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PassRole",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/WorkerRole"
            },
            {
                "Sid": "CreateAndInvokeLambda",
                "Effect": "Allow",
                "Action": [
                    "lambda:CreateFunction",
                    "lambda:InvokeFunction"
                ],
                "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-function"
            }
        ]
    }

@pytest.fixture
def passrole_ec2_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*"
            }
        ]
    }


@pytest.fixture(autouse=True)
def wide_terminal(monkeypatch):
    # Keep text output on one line per item so assertions don't depend on the real terminal width
    monkeypatch.setenv("COLUMNS", "250")
