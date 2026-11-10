FROM python:3.11-slim

LABEL org.opencontainers.image.title="Aysal-Scan"
LABEL org.opencontainers.image.description="Find leaked secrets in git repos, verify which are live, and score how urgent each one is"
LABEL org.opencontainers.image.source="https://github.com/Rolex-1905/aysal-scan"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# git is required for history and staged scanning
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY aysal_scan/ ./aysal_scan/
RUN pip install --no-cache-dir .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# NOTE: this image intentionally runs as root. GitHub mounts the workspace owned by the runner's
# uid and documents that Docker actions must use the default user; a non-root USER cannot write
# the report files there and git refuses the "dubious ownership" checkout. entrypoint.sh
# marks the workspace as a safe git directory instead.
ENTRYPOINT ["/entrypoint.sh"]
