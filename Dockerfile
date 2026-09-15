FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt VERSION ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY dnsinspector ./dnsinspector
COPY static ./static
RUN mkdir -p /data && python -m compileall -q app.py dnsinspector
CMD ["gunicorn","--worker-class","gthread","--workers","1","--threads","8","--timeout","90","--graceful-timeout","15","--bind","0.0.0.0:8080","app:app"]
