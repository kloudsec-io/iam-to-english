FROM python:3.12-slim

LABEL maintainer="KloudSec <tarek@kloudsec.io>"
LABEL description="Translate AWS IAM policies into plain English and detect privilege escalation"
LABEL version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["iam-to-english"]
CMD ["--help"]
