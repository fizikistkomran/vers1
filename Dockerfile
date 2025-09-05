# ---- Base image
FROM python:3.11-slim

# ---- Python defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ---- Runtime deps (psycopg2-binary & Pillow için)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libjpeg62-turbo \
    zlib1g \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# ---- Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- App code
COPY . .

# ---- Defaults (Railway’de env ile override edilebilir)
ENV PORT=8000 \
    WEB_CONCURRENCY=2 \
    GTHREADS=4 \
    GUNICORN_TIMEOUT=60 \
    DB_POOL_SIZE=5 \
    DB_MAX_OVERFLOW=5 \
    DB_POOL_RECYCLE=280 \
    DB_CONNECT_ATTEMPTS=20

EXPOSE 8000

# ---- Start command (Railway $PORT’u otomatik geçer)
# gthread + threads: concurrency, timeout: 60s (30s default’tan büyük)
CMD ["/bin/sh","-lc","exec gunicorn -w ${WEB_CONCURRENCY} -k gthread --threads ${GTHREADS} --timeout ${GUNICORN_TIMEOUT} -b 0.0.0.0:${PORT} app:app"]

