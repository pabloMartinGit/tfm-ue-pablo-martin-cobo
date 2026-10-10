"""Registro de auditoría estructurado (JSON por línea) para consumo SecOps/SIEM (RU-06)."""

import json
import logging
import sys
from datetime import datetime, timezone

from .config import settings

_logger = logging.getLogger("zt_security.audit")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def audit_log(event: str, **fields) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": settings.service_name,
        "event": event,
        **fields,
    }
    _logger.info(json.dumps(record, default=str, ensure_ascii=False))
