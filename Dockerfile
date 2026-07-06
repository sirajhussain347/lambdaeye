# LambdaEye — modular recon tool for authorized pentesting engagements
# Build:  docker build -t lambdaeye .
# Run:    docker run --rm lambdaeye example.com --all --report
# (add -v "$PWD/reports:/app/reports" to persist reports on the host)

FROM python:3.11-slim

# Avoid .pyc files and force stdout/stderr to be unbuffered so logs show up live
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so Docker can cache this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the tool
COPY . .

# Reports are written here — mount a volume to keep them after the container exits
RUN mkdir -p /app/reports
VOLUME ["/app/reports"]

# Run as a non-root user
RUN useradd -m lambdaeye && chown -R lambdaeye:lambdaeye /app
USER lambdaeye

ENTRYPOINT ["python3", "recon.py"]
CMD ["-h"]
