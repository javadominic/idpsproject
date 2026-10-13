# Multi-stage production build for IDPS
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY shared/ shared/
COPY services/ services/
COPY idps_platform/ idps_platform/
COPY configs/ configs/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

FROM python:3.12-slim AS runner

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY shared/ shared/
COPY services/ services/
COPY idps_platform/ idps_platform/
COPY configs/ configs/

EXPOSE 8080 2222 8088

CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
