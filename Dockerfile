FROM python:3.12-slim
ARG APP_VERSION=dev
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py VERSION /app/
COPY static /app/static
COPY build_perf_patch.py build_perf_hardcap.py build_memory_patch.py /app/
RUN python /app/build_perf_patch.py && python /app/build_perf_hardcap.py && python /app/build_memory_patch.py && rm /app/build_perf_patch.py /app/build_perf_hardcap.py /app/build_memory_patch.py
RUN mkdir -p /data
LABEL org.opencontainers.image.title="DNS Inspector" \
      org.opencontainers.image.description="Read-only local DNS visibility tool for AdGuard Home" \
      org.opencontainers.image.version="$APP_VERSION"
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python","/app/app.py"]
