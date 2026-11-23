FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ALPHAALGO_HOST=0.0.0.0 \
    ALPHAALGO_DB_PATH=/data/receipts.db \
    ALPHAALGO_JSONL_LOG=/data/events.jsonl \
    ALPHAALGO_ASYNC_HANDLERS=true

WORKDIR /app

COPY pyproject.toml README.md ./
COPY alphaalgo_receiver ./alphaalgo_receiver
COPY examples ./examples
COPY scripts ./scripts

RUN mkdir -p /data && chmod 700 /data

EXPOSE 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import os, urllib.request; port = os.environ.get('ALPHAALGO_PORT') or os.environ.get('PORT') or '9091'; urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3)" || exit 1

CMD ["python3", "-m", "alphaalgo_receiver"]
