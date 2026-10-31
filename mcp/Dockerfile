FROM python:3.11.8-slim-bookworm

WORKDIR /workspace

COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /workspace/app/
COPY mcp/ /workspace/mcp/
COPY evals/ /workspace/evals/

ENV PYTHONPATH="/workspace/app:/workspace/mcp"
ENV MCP_PORT=8010

RUN groupadd -g 10001 sewasetu && useradd -u 10001 -g sewasetu -m -s /bin/bash sewasetu \
    && mkdir -p /var/sewasetu/uploads /var/log/sewasetu \
    && chown -R sewasetu:sewasetu /workspace /var/sewasetu /var/log/sewasetu

USER sewasetu

EXPOSE 8010
CMD ["gunicorn", "--bind", "0.0.0.0:8010", "--workers", "2", "--threads", "4", "--timeout", "30", "server:app"]
