FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
# Sentence Transformers runs CPU-only in this deployment. Installing PyTorch from
# the CPU wheel index prevents pip from pulling multi-gigabyte CUDA runtime packages.
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --retries 5 --timeout 300 --index-url https://download.pytorch.org/whl/cpu torch==2.5.1 \
    && pip install --no-cache-dir --retries 5 --timeout 300 -r requirements.txt
COPY . .
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
