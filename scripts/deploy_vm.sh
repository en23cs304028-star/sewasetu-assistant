#!/usr/bin/env bash
# ==============================================================================
# scripts/deploy_vm.sh: Idempotent VM Deployment Script for Sewa Setu
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "=========================================================="
echo " Starting Sewa Setu VM Production Deployment"
echo "=========================================================="

NEWLY_GENERATED=0
ENV_FILE="${REPO_ROOT}/.env"

# 1. Idempotent Environment Generation (Never overwrite existing .env)
if [ -f "${ENV_FILE}" ]; then
    echo "[INFO] Existing .env file found. Preserving existing secrets."
else
    echo "[INFO] No .env file found. Generating secure production secrets..."
    ADMIN_PWD=$(openssl rand -hex 16)
    PG_PWD=$(openssl rand -hex 16)
    HOST_DOMAIN="${1:-$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")}"

    cat > "${ENV_FILE}" <<EOF
# Production Environment Configuration
ENV=production
DOMAIN=${HOST_DOMAIN}
PUBLIC_BASE_URL=https://${HOST_DOMAIN}

ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PWD}

POSTGRES_DB=sewasetu
POSTGRES_USER=sewasetu
POSTGRES_PASSWORD=${PG_PWD}
PGHOST=db
PGPORT=5432
PGDATABASE=sewasetu
PGUSER=sewasetu
PGPASSWORD=${PG_PWD}

TRUSTED_PROXY_CIDRS=127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,::1/128
CLIENT_METADATA_FETCH=true
DEMO_GATEWAY=false
EOF
    chmod 600 "${ENV_FILE}"
    NEWLY_GENERATED=1

    echo "----------------------------------------------------------"
    echo " [ATTENTION] NEW PRODUCTION CREDENTIALS GENERATED (PRINTED ONCE)"
    echo " ADMIN USERNAME : admin"
    echo " ADMIN PASSWORD : ${ADMIN_PWD}"
    echo " Saved to: ${ENV_FILE} (permissions 600)"
    echo "----------------------------------------------------------"
fi

# 2. Build Docker images
echo "[INFO] Building Docker container images..."
docker compose build

# 3. Start containers in detached mode
echo "[INFO] Launching containers..."
docker compose --profile caddy up -d

# 4. Wait for services to become healthy
echo "[INFO] Waiting for services to reach healthy status..."
MAX_WAIT=60
WAITED=0
SERVICES=("db" "app" "mcp")

for svc in "${SERVICES[@]}"; do
    echo -n "Checking health for $svc..."
    while [ $WAITED -lt $MAX_WAIT ]; do
        STATUS=$(docker compose ps "$svc" --format '{{.Health}}' 2>/dev/null || echo "")
        if [[ "$STATUS" == *"healthy"* ]]; then
            echo " [OK: healthy]"
            break
        fi
        sleep 2
        WAITED=$((WAITED + 2))
        echo -n "."
    done
    if [ $WAITED -ge $MAX_WAIT ]; then
        echo " [WARNING: timed out waiting for $svc health]"
    fi
done

# 5. Execute deployment verification
echo "[INFO] Invoking verification checks..."
if [ -x "${SCRIPT_DIR}/verify_deploy.sh" ]; then
    "${SCRIPT_DIR}/verify_deploy.sh"
else
    bash "${SCRIPT_DIR}/verify_deploy.sh"
fi

echo "=========================================================="
echo " Deployment completed successfully."
echo "=========================================================="
