FROM python:3.11.8-slim-bookworm
WORKDIR /app
RUN pip install --no-cache-dir Flask==2.2.5
COPY app.py .
RUN groupadd -g 10001 sewasetu && useradd -u 10001 -g sewasetu -m -s /bin/bash sewasetu \
    && chown -R sewasetu:sewasetu /app
USER sewasetu
EXPOSE 8025
CMD ["python", "app.py"]
