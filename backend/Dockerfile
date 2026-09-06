FROM python:3.12.4-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --requirement requirements.lock
COPY src ./src
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
ENV PYTHONPATH=/app/src

RUN useradd --create-home --uid 10001 rift
USER rift

CMD ["uvicorn", "rift.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
