FROM python:3.12-slim

ARG APP_VERSION=dev
ARG APP_ENV=production

WORKDIR /app

# iputils-ping backs the device reachability feature.
# curl backs the container HEALTHCHECK below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 0.8.0: the image is built from the committed source. Earlier versions ran a
# chain of sixteen `build_*.py` scripts here that rewrote app.py during the
# build, which meant the image and the repository were never the same program.
COPY app.py VERSION /app/
COPY static /app/static
# app.py imports scripts/geoip_updater.py directly (Issue #42 / 0.8.5.5) for
# the automatic DB-IP Lite updater -- it must ship in the image, not just be
# available for an operator to run manually from a repo checkout.
COPY scripts /app/scripts

RUN mkdir -p /data

LABEL org.opencontainers.image.title="DNS Inspector" \
      org.opencontainers.image.description="Read-only local DNS visibility tool for AdGuard Home" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.environment="$APP_ENV"

ENV PYTHONUNBUFFERED=1 \
    DNS_INSPECTOR_ENV=$APP_ENV

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT:-8080}/health" || exit 1

CMD ["python", "/app/app.py"]
