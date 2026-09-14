FROM python:3.12-slim
ARG APP_VERSION=dev
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py VERSION /app/
COPY static /app/static
COPY build_perf_patch.py build_perf_hardcap.py build_memory_patch.py build_device_labels_patch_v2.py build_enrichment_retry_patch.py build_ui_followup_patch.py build_device_ip_retention_patch.py build_ip_ping_patch.py build_observability_patch.py build_memory_diagnostics_patch.py build_debug_bundle_deep_patch.py /app/
RUN python /app/build_perf_patch.py && python /app/build_perf_hardcap.py && python /app/build_memory_patch.py && python /app/build_device_labels_patch_v2.py && python /app/build_enrichment_retry_patch.py && python /app/build_ui_followup_patch.py && python /app/build_device_ip_retention_patch.py && python /app/build_ip_ping_patch.py && python /app/build_observability_patch.py && python /app/build_memory_diagnostics_patch.py && python /app/build_debug_bundle_deep_patch.py && rm /app/build_perf_patch.py /app/build_perf_hardcap.py /app/build_memory_patch.py /app/build_device_labels_patch_v2.py /app/build_enrichment_retry_patch.py /app/build_ui_followup_patch.py /app/build_device_ip_retention_patch.py /app/build_ip_ping_patch.py /app/build_observability_patch.py /app/build_memory_diagnostics_patch.py /app/build_debug_bundle_deep_patch.py
RUN mkdir -p /data
LABEL org.opencontainers.image.title="DNS Inspector" \
      org.opencontainers.image.description="Read-only local DNS visibility tool for AdGuard Home" \
      org.opencontainers.image.version="$APP_VERSION"
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python","/app/app.py"]
