FROM python:3.12-slim
ARG APP_VERSION=dev
ARG RUNTIME_ENV=production
WORKDIR /app
COPY requirements.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt
COPY app.py analytics_report.py report_scheduler.py VERSION /app/
COPY static /app/static
RUN mkdir -p /data /data/reports
LABEL org.opencontainers.image.title="DNS Inspector" \
      org.opencontainers.image.description="Read-only local DNS visibility tool for AdGuard Home" \
      org.opencontainers.image.version="$APP_VERSION"
ENV PYTHONUNBUFFERED=1 \
    DNS_INSPECTOR_ENV=$RUNTIME_ENV
EXPOSE 8080
CMD ["python","/app/app.py"]
