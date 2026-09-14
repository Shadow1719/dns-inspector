FROM python:3.12-slim
ARG APP_VERSION=dev
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py VERSION /app/
COPY static /app/static
COPY build_perf_patch.py build_perf_hardcap.py build_memory_patch.py build_device_labels_patch_v2.py build_enrichment_retry_patch.py build_ui_followup_patch.py build_device_ip_retention_patch.py build_ip_ping_patch.py build_observability_patch.py build_memory_diagnostics_patch.py build_debug_bundle_deep_patch.py build_debug_bundle_resilience_patch.py build_debug_bundle_deep_fix_patch.py build_sqlite_close_patch.py build_observability_ui_hotfix.py build_0_7_14_features.py build_dev_ui_patch.py build_0_8_adguard_explain_v3.py build_0_8_adguard_explain_v4.py /app/
RUN python /app/build_perf_patch.py && python /app/build_perf_hardcap.py && python /app/build_memory_patch.py && python /app/build_device_labels_patch_v2.py && python /app/build_enrichment_retry_patch.py && python /app/build_ui_followup_patch.py && python /app/build_device_ip_retention_patch.py && python /app/build_ip_ping_patch.py && python /app/build_observability_patch.py && python /app/build_memory_diagnostics_patch.py && python /app/build_debug_bundle_deep_patch.py && python /app/build_debug_bundle_resilience_patch.py && python /app/build_debug_bundle_deep_fix_patch.py && python /app/build_sqlite_close_patch.py && python /app/build_observability_ui_hotfix.py && python /app/build_0_7_14_features.py && if [ "$APP_VERSION" = "0.8.0-dev" ]; then python /app/build_dev_ui_patch.py; python /app/build_0_8_adguard_explain_v3.py; python /app/build_0_8_adguard_explain_v4.py; fi && rm /app/build_perf_patch.py /app/build_perf_hardcap.py /app/build_memory_patch.py /app/build_device_labels_patch_v2.py /app/build_enrichment_retry_patch.py /app/build_ui_followup_patch.py /app/build_device_ip_retention_patch.py /app/build_ip_ping_patch.py /app/build_observability_patch.py /app/build_memory_diagnostics_patch.py /app/build_debug_bundle_deep_patch.py /app/build_debug_bundle_resilience_patch.py /app/build_debug_bundle_deep_fix_patch.py /app/build_sqlite_close_patch.py /app/build_observability_ui_hotfix.py /app/build_0_7_14_features.py /app/build_dev_ui_patch.py /app/build_0_8_adguard_explain_v3.py /app/build_0_8_adguard_explain_v4.py
RUN mkdir -p /data
LABEL org.opencontainers.image.title="DNS Inspector" \
      org.opencontainers.image.description="Read-only local DNS visibility tool for AdGuard Home" \
      org.opencontainers.image.version="$APP_VERSION"
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python","/app/app.py"]
