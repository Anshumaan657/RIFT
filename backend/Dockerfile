FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --upgrade pip==26.2.1 \
    && python -m pip install --no-cache-dir --requirement requirements.lock \
    && python -m pip uninstall --yes pip
COPY src ./src
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations
ENV PYTHONPATH=/app/src

RUN useradd --create-home --uid 10001 rift
USER rift

CMD ["uvicorn", "rift.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
