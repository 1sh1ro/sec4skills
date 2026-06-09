FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app
COPY engine /app/engine
COPY skillmri /app/skillmri

ENTRYPOINT ["python", "/app/engine/engine.py"]
