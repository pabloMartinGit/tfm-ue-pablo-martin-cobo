FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /tests

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin tester

COPY . .
USER 10002

CMD ["pytest", "-v", "-p", "no:cacheprovider"]
