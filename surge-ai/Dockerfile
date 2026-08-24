# syntax=docker/dockerfile:1
FROM python:3.12-slim

# nmap is the scan engine; gcc/build deps cover any source-built wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# sentence-transformers pulls torch — force the CPU-only build so the image
# doesn't balloon with CUDA libraries the server won't use.
RUN pip install --extra-index-url https://download.pytorch.org/whl/cpu torch

COPY requirements.txt requirements-api.txt ./
RUN pip install -r requirements.txt -r requirements-api.txt

COPY . .

# Runtime write targets (also mounted as volumes in compose so data survives restarts).
RUN mkdir -p log scan_results output data

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
