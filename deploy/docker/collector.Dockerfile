# syntax=docker/dockerfile:1
#
# The optional collector as an image. Build from the repository root:
#
#   docker build -f deploy/docker/collector.Dockerfile -t guardana-collector:dev .
#   docker run --rm -e GUARDANA_DATABASE_URL=... -p 8000:8000 guardana-collector:dev
#
# The collector does not depend on `guardana-core` and this image proves it: only
# `guardana-server` is installed here. `[serve]` adds the ASGI server, which is an
# extra precisely so a deployment that runs its own is not made to carry two.
#
# Migrations are NOT run on start. A rolling deploy would otherwise run two
# versions of the code against one schema, and the operator undoing that at three
# in the morning wants one instruction (`guardana-collector rollback`), not a
# restart with a different environment variable.

FROM python:3.14-slim-bookworm AS builder

WORKDIR /src
COPY packages/guardana-server packages/guardana-server
COPY LICENSE LICENSE

RUN python -m venv /opt/guardana \
    && /opt/guardana/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/guardana/bin/pip install --no-cache-dir "./packages/guardana-server[serve]"

FROM python:3.14-slim-bookworm

ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="guardana-collector" \
      org.opencontainers.image.description="Guardana collector: ingests runs and findings from many agents." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/guardana/guardana" \
      org.opencontainers.image.documentation="https://github.com/guardana/guardana/blob/main/docs/usage-collector.md" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /opt/guardana /opt/guardana
COPY --from=builder /src/LICENSE /usr/share/licenses/guardana/LICENSE

RUN useradd --system --uid 10001 --user-group --create-home guardana
USER 10001

ENV PATH="/opt/guardana/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Liveness only: `/healthz` says the process answers. Readiness is a separate
# endpoint on purpose — `/readyz` fails while a migration is pending, and an
# orchestrator must be able to tell "starting" from "will never be ready".
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

ENTRYPOINT ["guardana-collector"]
# Binding every interface is right inside a container and wrong on a laptop, so
# the image says it and the command does not default to it.
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
