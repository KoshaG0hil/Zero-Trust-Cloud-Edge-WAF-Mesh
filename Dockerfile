# Production Dockerfile for Zero-Trust Edge Security Engine
FROM python:3.12-slim

WORKDIR /app

# Install security packages and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run simulation by default
ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["simulate"]
