# docs/collector-design.md §10-§11 in victor-recon-console: python:3.12-slim
# base, Linux x86_64 + arm64, Docker as the only officially supported
# deployment path.
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/musashiandy/victor-collector"
LABEL org.opencontainers.image.description="Open-source recon agent for VICTOR Recon"
LABEL org.opencontainers.image.licenses="MIT"

# nmap is required for the service-inventory plugin, invoked as a
# subprocess - it's GPL-licensed, so it's a system package dependency,
# never vendored into the image's Python layer (collector-architecture.md's
# licensing note).
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what the build needs before the source tree, so dependency
# installation layers cache independently of application code changes.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Persistent state - enrollment credentials, local SQLite findings/
# observations, the redaction mapping DB, package-baseline-diff
# credential files - all live under ~/.victor. Meant to be volume- or
# bind-mounted; see README.md's docker run examples.
VOLUME ["/root/.victor"]

# victor ui's default port (Standalone Mode). Documentation only - the
# actual bind still needs `-p 127.0.0.1:8787:8787` at `docker run` time,
# since victor ui refuses non-loopback binds by default regardless.
EXPOSE 8787

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["victor", "run"]
