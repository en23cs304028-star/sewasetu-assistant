FROM python:3.11.8-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends cron \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN groupadd -g 10001 sewasetu && useradd -u 10001 -g sewasetu -m -s /bin/bash sewasetu \
    && mkdir -p /var/sewasetu/uploads /var/log/sewasetu \
    && chown -R sewasetu:sewasetu /app /var/sewasetu /var/log/sewasetu \
    && crontab /app/deploy/crontab

USER sewasetu

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "30", "app:app"]
