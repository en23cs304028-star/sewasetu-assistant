FROM python:3.11-slim

WORKDIR /workspace

COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /workspace/app/
COPY mcp/ /workspace/mcp/
COPY evals/ /workspace/evals/

ENV PYTHONPATH="/workspace/app:/workspace/mcp"
ENV MCP_PORT=8010

RUN mkdir -p /var/sewasetu/uploads /var/log/sewasetu

EXPOSE 8010
CMD ["python", "mcp/server.py"]
