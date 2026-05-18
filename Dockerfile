# syntax=docker/dockerfile:1.7
# ---------- builder ---------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Install dependencies first so they cache independently of source changes.
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# Copy the package and install it (uses pyproject.toml; produces a real
# `mcpscan-api` console script under /install/bin).
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --prefix=/install --no-deps .


# ---------- runtime ---------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCPSCAN_HOST=0.0.0.0 \
    MCPSCAN_PORT=8000

# Non-root user — the scanner makes outbound HTTP only; no need for root.
RUN useradd --create-home --uid 10001 mcpscan
USER mcpscan
WORKDIR /home/mcpscan

# Copy the installed packages + scripts from the builder stage.
COPY --from=builder --chown=mcpscan:mcpscan /install /usr/local

EXPOSE 8000

# Use the installed console script. Equivalent to
#   python -m mcpscan.api
# but goes through the entrypoint declared in pyproject.toml.
CMD ["mcpscan-api"]
