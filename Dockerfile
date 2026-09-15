FROM python:3.12-slim
ARG APP_VERSION=dev

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py VERSION /app/
COPY dev_runtime.py /app/dev_runtime.py
COPY static /app/static

RUN mkdir -p /data \
    && python -m py_compile /app/app.py /app/dev_runtime.py

LABEL org.opencontainers.image.title="DNS Inspector" \
      org.opencontainers.image.description="Read-only local DNS visibility tool for AdGuard Home" \
      org.opencontainers.image.version="$APP_VERSION"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

CMD ["gunicorn", "--worker-class", "gthread", "--workers", "1", "--threads", "8", "--timeout", "90", "--graceful-timeout", "15", "--bind", "0.0.0.0:8080", "dev_runtime:app"]
