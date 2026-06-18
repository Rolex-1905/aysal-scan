FROM python:3.11-slim

LABEL org.opencontainers.image.title="Aysal-Scan"
LABEL org.opencontainers.image.description="Scan git repos for leaked secrets and estimate blast radius"
LABEL org.opencontainers.image.source="https://github.com/Rolex-1905/aysal-scan"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install git (required for git history scanning)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps via pyproject.toml
COPY pyproject.toml ./
COPY aysal_scan/ ./aysal_scan/

RUN pip install --no-cache-dir .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run as non-root for security
RUN useradd --create-home --shell /bin/sh scanner
USER scanner

ENTRYPOINT ["/entrypoint.sh"]