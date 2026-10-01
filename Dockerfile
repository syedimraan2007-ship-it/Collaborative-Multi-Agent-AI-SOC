# Multi-stage production build for SOC API
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY soc/ /app/soc/
COPY tests/ /app/tests/

EXPOSE 8880

CMD ["uvicorn", "soc.api.app:app", "--host", "0.0.0.0", "--port", "8880"]
