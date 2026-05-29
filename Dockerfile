# =============================================================================
# Bluesky - Bluetooth Security Auditing Framework
# Dockerfile multi-etapa
#
# USO:
#   # Desarrollo (sin Bluetooth)
#   docker build --target dev -t bluesky:dev .
#   docker run -it bluesky:dev bluesky list
#
#   # Full (con Bluetooth - necesita --privileged)
#   docker build --target full -t bluesky:full .
#   docker run -it --privileged --net=host bluesky:full bluesky scan
#
#   # Tests
#   docker build --target test -t bluesky:test .
#   docker run bluesky:test
# =============================================================================

# ─── Etapa base ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

LABEL maintainer="Bluesky Project"
LABEL description="Bluetooth Security Auditing Framework"
LABEL version="0.1.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    BLUESKY_HOME=/bluesky

WORKDIR /bluesky

# Dependencias base Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir bleak rich click colorama

# Copiar código
COPY bluesky/ bluesky/
COPY tests/ tests/
COPY scripts/ scripts/
COPY README.md setup.py .

# Instalar Bluesky
RUN pip install -e .

# ─── Etapa de desarrollo (sin Bluetooth) ─────────────────────────────────────
FROM base AS dev

RUN useradd -m -u 1000 bluesky && chown -R bluesky:bluesky /bluesky
USER bluesky

ENTRYPOINT ["bluesky"]
CMD ["help"]

# ─── Etapa full (con Bluetooth stack) ────────────────────────────────────────
FROM base AS full

# Instalar BlueZ tools y dependencias Bluetooth
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez \
    bluez-tools \
    bluez-hcidump \
    libbluetooth-dev \
    libusb-dev \
    rfkill \
    usbutils \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python extra para ataques avanzados
RUN pip install --no-cache-dir \
    pybluez2 \
    pyserial \
    scapy \
    pycryptodome

# Verificar instalación
RUN bluesky list && echo "✓ Bluesky full instalado"

ENTRYPOINT ["bluesky"]
CMD ["console"]

# ─── Etapa de tests ──────────────────────────────────────────────────────────
FROM base AS test

# Instalar dependencias de testing
RUN pip install --no-cache-dir pytest pytest-cov pytest-asyncio

# Ejecutar tests
COPY .coveragerc .
RUN python -m pytest tests/ -v --cov=bluesky --cov-report=term-missing && \
    echo "✓ Todos los tests pasaron"

ENTRYPOINT ["python", "-m", "pytest", "tests/", "-v"]

# ─── Etapa de producción (imagen mínima) ────────────────────────────────────
FROM python:3.12-alpine AS production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BLUESKY_HOME=/bluesky

WORKDIR /bluesky

# Copiar solo lo necesario desde base
COPY --from=base /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=base /usr/local/bin/bluesky /usr/local/bin/bluesky
COPY bluesky/ bluesky/

RUN adduser -D -u 1000 bluesky && chown -R bluesky:bluesky /bluesky
USER bluesky

ENTRYPOINT ["bluesky"]
CMD ["help"]
