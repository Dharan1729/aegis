FROM python:3.11-slim AS builder
WORKDIR /app
# See aegis-server/Dockerfile for why pip/setuptools/wheel are upgraded
# before installing anything else.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir --prefix=/install "fastapi>=0.115" "uvicorn[standard]>=0.30"
# setuptools deliberately NOT force-installed — nothing in this service's
# import graph needs it at runtime; see aegis-server/Dockerfile for why.
RUN pip install --no-cache-dir --prefix=/install --upgrade "msgpack>=1.2.1"

FROM python:3.11-slim
WORKDIR /app
# See aegis-server/Dockerfile for why pip/setuptools/wheel are stripped
# from the runtime image rather than just upgraded: pip vendors its own
# fixed-version internal copies of msgpack/setuptools regardless of what
# `pip install --upgrade` does to the real site-packages ones, and a
# vulnerability scanner picks those up as if installed. Removing the
# build-time-only tools from the runtime image resolves it by construction.
RUN rm -rf /usr/local/lib/python3.11/site-packages/pip \
           /usr/local/lib/python3.11/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.11/site-packages/setuptools \
           /usr/local/lib/python3.11/site-packages/setuptools-*.dist-info \
           /usr/local/lib/python3.11/site-packages/wheel \
           /usr/local/lib/python3.11/site-packages/wheel-*.dist-info \
           /usr/local/lib/python3.11/ensurepip \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.11
COPY --from=builder /install /usr/local
COPY main.py ./
EXPOSE 8090
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8090"]
