# Build from Python with all dnstwist features
FROM python:3.11-slim

WORKDIR /app

# Install build tools and system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dnstwist with ALL optional dependencies + API
RUN pip install --no-cache-dir \
    "dnstwist[full]" \
    fastapi \
    uvicorn \
    httpx

# Copy API and dictionaries
COPY api.py .
COPY dictionaries/ ./dictionaries/

# Set dictionaries path
ENV DNSTWIST_DICTIONARIES=/app/dictionaries

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
