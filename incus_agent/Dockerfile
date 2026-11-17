FROM python:3.14-alpine

ARG BUILD_ARCH
LABEL io.hass.name="Incus Agent Diagnostics" \
      io.hass.description="Read-only Incus guest agent host diagnostics" \
      io.hass.type="addon" \
      io.hass.version="0.1.0" \
      io.hass.arch="${BUILD_ARCH}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY diagnostics.py /app/diagnostics.py
ENTRYPOINT ["python3", "/app/diagnostics.py"]
