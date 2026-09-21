FROM python:3.12-slim
ARG APP_VERSION=dev
ARG RUNTIME_ENV=production
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py VERSION /app/
COPY static /app/static
RUN mkdir -p /data
LABEL org.opencontainers.image.title="DNS Inspector" \
      org.opencontainers.image.description="Read-only local DNS visibility tool for AdGuard Home" \
      org.opencontainers.image.version="$APP_VERSION"
ENV PYTHONUNBUFFERED=1 \
    DNS_INSPECTOR_ENV=$RUNTIME_ENV
EXPOSE 8080
CMD ["python","/app/app.py"]
