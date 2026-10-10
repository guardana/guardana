# syntax=docker/dockerfile:1
#
# The Guardana CLI as an image, for pipelines that run containers rather than
# Python. Build from the repository root:
#
#   docker build -f deploy/docker/cli.Dockerfile -t guardana-cli:dev .
#   docker run --rm -v "$PWD:/work:ro" guardana-cli:dev scan /work
#
# Two stages so the shipped image carries no build tooling, and a non-root user
# because a scanner reads other people's code and never needs to own it.

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed AS builder

WORKDIR /src
COPY deploy/docker/build-requirements.txt deploy/docker/cli-requirements.txt ./
COPY packages/guardana-core packages/guardana-core
COPY packages/guardana-rules packages/guardana-rules
COPY packages/guardana-report packages/guardana-report
COPY packages/guardana-cli packages/guardana-cli
COPY LICENSE LICENSE

# Every third-party version and hash comes from uv.lock, the set CI tests, so pip
# resolves nothing. The four packages are built from this tree by the locked backend
# in a separate venv, so the shipped one carries no build tooling; `pip check` fails
# the build if the locked set does not satisfy what the packages declare.
RUN python -m venv /opt/build \
    && /opt/build/bin/pip install --no-cache-dir --require-hashes --no-deps \
        -r build-requirements.txt \
    && /opt/build/bin/pip wheel --no-cache-dir --no-deps --no-build-isolation \
        --wheel-dir /src/wheels \
        ./packages/guardana-core \
        ./packages/guardana-rules \
        ./packages/guardana-report \
        ./packages/guardana-cli \
    && python -m venv /opt/guardana \
    && /opt/guardana/bin/pip install --no-cache-dir --require-hashes --no-deps \
        -r cli-requirements.txt \
    && /opt/guardana/bin/pip install --no-cache-dir --no-deps /src/wheels/*.whl \
    && /opt/guardana/bin/pip check

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed

ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="guardana" \
      org.opencontainers.image.description="Guardana CLI: verify AI artifacts, endpoints and agents." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/guardana/guardana" \
      org.opencontainers.image.documentation="https://github.com/guardana/guardana/blob/main/docs/index.md" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /opt/guardana /opt/guardana
COPY --from=builder /src/LICENSE /usr/share/licenses/guardana/LICENSE

# A fixed non-root uid, so a mounted volume's permissions are predictable and a
# deployment can pin `runAsUser` to the same number.
RUN useradd --system --uid 10001 --user-group --create-home guardana
USER 10001

ENV PATH="/opt/guardana/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Where a pipeline mounts the thing under test. Deliberately not the root.
WORKDIR /work

ENTRYPOINT ["guardana"]
CMD ["--help"]
