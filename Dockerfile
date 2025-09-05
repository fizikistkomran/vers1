FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Pillow için zorunlu sistem bağımlılıkları (jpeg, png, zlib, webp, tiff, openjp2)
# (psycopg2 kullanacaksan ayrıca: libpq-dev)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    libpq-dev \
    libjpeg62-turbo-dev zlib1g-dev libpng-dev libwebp-dev libtiff-dev libopenjp2-7-dev \
    && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8000
EXPOSE 8000
CMD ["gunicorn","-b","0.0.0.0:8000","app:app","--workers=2","--timeout=90"]

