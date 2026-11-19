FROM python:3.11-slim AS builder
WORKDIR /app
# The base image's bundled pip/setuptools/wheel carry known CVEs
# (jaraco.context path traversal, wheel arbitrary code execution via a
# malicious wheel file) — upgrading before installing anything else keeps
# them off the image, not just off our own declared dependencies.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir --prefix=/install .
# opentelemetry pulls in an older, CVE-affected msgpack transitively —
# force the patched version explicitly rather than relying on the
# resolver to pick it on its own. (setuptools is deliberately NOT
# force-installed here: nothing in the actual import graph needs it at
# runtime — verified by importing app.main and checking sys.modules for
# setuptools/pkg_resources — so the correct fix is not shipping it at
# all, not patching a copy nothing uses.)
RUN pip install --no-cache-dir --prefix=/install --upgrade "msgpack>=1.2.1"

FROM python:3.11-slim
# Pick up Debian security fixes released after the base image was built.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# pip vendors its OWN internal copies of msgpack/setuptools at fixed old
# versions (pip/_vendor/vendor.txt) for pip's own bootstrap use, isolated
# in the pip._vendor namespace and never imported by app code — but a
# vulnerability scanner reading that manifest still reports them as
# "installed" msgpack/setuptools, and no amount of `pip install --upgrade`
# changes what a given pip release vendors internally. Since pip (and
# setuptools/wheel, which exist here only to support pip) are build-time
# tools with no runtime role once dependencies are installed, the correct
# fix is not to ship them in the runtime image at all — smaller image,
# smaller attack surface, and this class of false-positive-but-technically-
# present finding goes away by construction.
RUN rm -rf /usr/local/lib/python3.11/site-packages/pip \
           /usr/local/lib/python3.11/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.11/site-packages/setuptools \
           /usr/local/lib/python3.11/site-packages/setuptools-*.dist-info \
           /usr/local/lib/python3.11/site-packages/wheel \
           /usr/local/lib/python3.11/site-packages/wheel-*.dist-info \
           /usr/local/lib/python3.11/ensurepip \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.11
COPY --from=builder /install /usr/local
RUN useradd --system --uid 10001 --no-create-home aegis
COPY --chown=aegis alembic.ini ./
COPY --chown=aegis alembic ./alembic
COPY --chown=aegis static ./static
USER aegis
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=20 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" || exit 1
# MIGRATE_ON_START=true (default) runs migrations before serving. Alembic
# serialises concurrent upgrades with an advisory lock (alembic/env.py), so
# this is safe with several replicas; set it to false and run
# `alembic upgrade head` as a one-off job if you prefer. WORKERS sets
# uvicorn worker processes (default 1); see docs/guide/deployment.md for why
# replicas are usually the better way to scale.
CMD ["sh", "-c", "if [ \"${MIGRATE_ON_START:-true}\" = \"true\" ]; then alembic upgrade head; fi && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-1}"]
