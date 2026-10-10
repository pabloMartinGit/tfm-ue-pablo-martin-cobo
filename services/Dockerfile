# Imagen común para los microservicios y el BFF. Se construye con:
#   docker build -f services/Dockerfile --build-arg SERVICE=orders services/
FROM python:3.13-slim

ARG SERVICE
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY common/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY common/workload_identity.py /app/workload_identity.py
COPY common/zt_security /app/zt_security
COPY ${SERVICE}/main.py /app/main.py

USER 10001
# 8443: API por mTLS (TLS 1.3 + HTTP/2) con el SVID montado en /run/svid.
# 8000: solo en 127.0.0.1, sin TLS, para el healthcheck del propio contenedor.
EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

CMD ["python", "-m", "workload_identity", "main:app"]
