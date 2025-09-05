FROM python:3.11-slim

# Python davranışları
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Derleme araçları (gereken minimum)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# Bağımlılıklar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyaları
COPY . .

# Lokal test için bilgi amaçlı
EXPOSE 8000

# Gunicorn: module:variable => app.py içindeki "app"
# Railway $PORT verir; yoksa 8000 kullan
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT:-8000} app:app --workers=2 --timeout=90"]

