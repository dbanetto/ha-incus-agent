FROM python:3.14-alpine

RUN apk add --no-cache util-linux

ARG BUILD_ARCH
LABEL io.hass.name="Incus Agent Diagnostics" \
      io.hass.description="Incus guest agent diagnostics and opt-in supervision" \
      io.hass.type="addon" \
      io.hass.version="0.3.0" \
      io.hass.arch="${BUILD_ARCH}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY diagnostics.py /app/diagnostics.py
COPY source_check.py /app/source_check.py
COPY manager.py /app/manager.py
ENTRYPOINT ["python3", "/app/diagnostics.py"]
