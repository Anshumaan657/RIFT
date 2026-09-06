FROM python:3.12.4-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/lab/src

WORKDIR /lab
COPY backend/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --requirement /tmp/requirements.lock
COPY lab/src ./src
COPY lab/fixtures ./fixtures

RUN useradd --create-home --uid 10002 rift-lab
USER rift-lab
EXPOSE 8080
CMD ["uvicorn", "lab_app.main:app", "--host", "0.0.0.0", "--port", "8080"]
