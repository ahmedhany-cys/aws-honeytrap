# HoneyTrap Cowrie sensor image.
# Built from the official Python image + Cowrie from PyPI (pinned), so every
# layer is auditable. Runs as an unprivileged user; designed for
#   --read-only --cap-drop ALL --security-opt no-new-privileges
FROM python:3.12.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 cowrie \
 && useradd --system --uid 10001 --gid cowrie --home-dir /cowrie --shell /usr/sbin/nologin cowrie

COPY requirements-honeypot.txt requirements-cowrie.txt /tmp/
RUN pip install -r /tmp/requirements-honeypot.txt \
 && pip install --no-deps -r /tmp/requirements-cowrie.txt \
 && rm /tmp/requirements-*.txt

COPY honeypot/cowrie/etc/ /cowrie/etc/
COPY --chmod=0755 honeypot/entrypoint.sh /usr/local/bin/honeytrap-entrypoint
COPY honeypot/configuration/build_fs.py /tmp/build_fs.py
RUN python /tmp/build_fs.py /cowrie/etc/fs.pickle && rm /tmp/build_fs.py \
 && mkdir -p /cowrie/var/log/cowrie /cowrie/var/lib/cowrie/tty /cowrie/var/lib/cowrie/downloads /cowrie/var/run \
 && chown -R cowrie:cowrie /cowrie/var

WORKDIR /cowrie
USER cowrie
EXPOSE 2222 2223
VOLUME ["/cowrie/var"]

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import socket; socket.create_connection(('127.0.0.1', 2222), 2).close()"

ENTRYPOINT ["/usr/local/bin/honeytrap-entrypoint"]
