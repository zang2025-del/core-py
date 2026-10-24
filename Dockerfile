# Two stages, because the build toolchain has no business in the runtime image.
#
# The runtime stage runs as a non-root user and carries no compiler. That is not
# hygiene for its own sake: a container that can be written to can be made to
# persist something, and the audit table is only worth having if the code that
# writes it cannot be edited by whatever it is auditing.

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Dependencies first, in their own layer: application code changes far more
# often than the dependency set does, and rebuilding the world on every source
# edit makes the image build the slowest part of a deploy.
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install .


FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PERMGATE_HOST=0.0.0.0 \
    PERMGATE_DATABASE_URL=sqlite+pysqlite:////data/permgate.db

COPY --from=build /opt/venv /opt/venv

# /data is where the SQLite file lives and is meant to be a volume. /app is the
# working directory so that `permgate` resolves a project root sensibly when the
# console script is run from inside the container.
#
# WORKDIR is set *before* the COPYs below, and that ordering is load-bearing. A
# COPY's relative destination resolves against the working directory in effect at
# that line, and a new stage starts from the base image's -- which is not /app.
# Written the other way round, `COPY alembic.ini ./` put the file at the
# container root while the process ran in /app, and `alembic upgrade head` failed
# with "No 'script_location' key found in configuration". That message reads like
# a malformed ini file; it actually means "there is no alembic.ini in this
# directory". The ini was fine, and had the key on its first line.
WORKDIR /app

RUN useradd --create-home --uid 10001 permgate \
 && mkdir -p /data /app \
 && chown -R permgate:permgate /data /app

COPY --chown=permgate:permgate alembic.ini ./
COPY --chown=permgate:permgate migrations ./migrations

USER permgate

EXPOSE 8000

# Readiness, not liveness. A liveness probe that fails when the database is slow
# gets the container killed and restarted, which does not fix the database and
# does lose the in-flight audit rows.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2).status == 200 else 1)"

# Migrations run before the server, and a failure stops the container rather
# than leaving a process serving traffic against a schema it does not expect.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn permgate.main:app --host 0.0.0.0 --port 8000"]
