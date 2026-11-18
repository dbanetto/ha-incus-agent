FROM python:3.14-alpine

RUN apk add --no-cache util-linux

ARG BUILD_ARCH
LABEL io.hass.name="Incus Agent Diagnostics" \
      io.hass.description="Read-only Incus guest agent host diagnostics" \
      io.hass.type="addon" \
      io.hass.version="0.2.0" \
      io.hass.arch="${BUILD_ARCH}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY diagnostics.py /app/diagnostics.py
COPY source_check.py /app/source_check.py
ENTRYPOINT ["python3", "/app/diagnostics.py"]
