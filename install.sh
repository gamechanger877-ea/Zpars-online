#!/usr/bin/env bash
# Zpars-online Expert Installer
# Usage (recommended):
#   curl -fsSL https://raw.githubusercontent.com/<you>/Zpars-online/main/install.sh | sudo bash
#
# This installer will:
# - Show a nice ASCII banner
# - Ensure it's run as root
# - Detect the OS and install Docker + Docker Compose plugin
# - Clone the Zpars-online repository (default: your GitHub account) OR generate a local scaffold if clone fails
# - Prompt for essential secrets (ADMIN email/password, JWT secret, DB password) or accept env vars
# - Create .env from .env.example
# - Launch the stack using Docker Compose
#
# Notes:
# - Review the script before running on any production host.
# - The script avoids embedding passwords in shell history and asks interactively if not provided via env.
# - Default repo: https://github.com/gamechanger877-ea/Zpars-online.git (change REPO_URL below)
set -euo pipefail

# ------------------------------------------------------------------
# Configuration (edit defaults by setting env variables before running)
# ------------------------------------------------------------------
APP_DIR="${APP_DIR:-/opt/zpars-online}"
REPO_URL="${REPO_URL:-https://github.com/gamechanger877-ea/Zpars-online.git}"
BRANCH="${BRANCH:-main}"
DOCKER_COMPOSE_TIMEOUT="${DOCKER_COMPOSE_TIMEOUT:-120}" # seconds to wait for compose services

# Non-interactive mode detection
CI_MODE=${CI_MODE:-0} # set to 1 to avoid interactive prompts (must provide env vars)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

banner() {
cat <<'EOF'
███████ ███████ ██████   █████  ██████  ███████      ██████   ██████  ██ ████████  ██████  ██ ███    ██
██      ██      ██   ██ ██   ██ ██   ██ ██          ██   ██ ██    ██ ██ ██      ██   ██ ██ ████   ██
███████ █████   ██████  ███████ ██████  █████       ██████  ██    ██ ██ ██      ██████  ██ ██ ██  ██
     ██ ██      ██   ██ ██   ██ ██      ██          ██   ██ ██    ██ ██ ██      ██   ██ ██ ██  ██   ██
███████ ███████ ██   ██ ██   ██ ██      ███████     ██████  ‚██████  ██ ██      ██   ██ ██ ██   ██    (Zpars-online)
EOF
echo
}

log() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "This installer must be run as root. Run with sudo or as root."
    exit 1
  fi
}

detect_os() {
  OS_ID=""
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-}${VERSION_ID:+-}${VERSION_ID:-}"
    OS_NAME="${NAME:-}"
  else
    OS_ID="$(uname -s)"
    OS_NAME="$OS_ID"
  fi
  log "Detected OS: ${OS_NAME} (${OS_ID})"
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    log "Docker is already installed."
  else
    log "Installing Docker..."
    # Use official convenience script for portability
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    log "Docker installed."
  fi

  # Install docker compose plugin if missing
  if docker compose version >/dev/null 2>&1; then
    log "Docker Compose plugin is available (docker compose)."
  else
    if command -v docker-compose >/dev/null 2>&1; then
      log "Legacy docker-compose binary found."
    else
      log "Installing Docker Compose v2 plugin..."
      # Try distro package first (Debian/Ubuntu)
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y || true
        apt-get install -y docker-compose-plugin || true
      fi
      # Fallback to direct download
      if ! docker compose version >/dev/null 2>&1; then
        DC_VER="v2.20.2"
        ARCH="$(uname -m)"
        case "$ARCH" in
          x86_64|amd64) ARCH="x86_64" ;;
          aarch64|arm64) ARCH="aarch64" ;;
        esac
        curl -fsSL "https://github.com/docker/compose/releases/download/${DC_VER}/docker-compose-$(uname -s)-${ARCH}" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        log "Downloaded docker-compose to /usr/local/bin/docker-compose"
      fi
    fi
  fi
  # Ensure current user can run docker (we run as root, but helpful info)
  if ! groups 2>/dev/null | grep -q docker; then
    warn "Current user is not in the 'docker' group. You may need to add users to 'docker' to run without sudo."
  fi
}

prompt_secret() {
  # usage: prompt_secret VAR_NAME "Prompt message" default_value
  local var_name="$1"; shift
  local prompt_msg="$1"; shift
  local default_val="${1:-}"
  local out
  if [ "${CI_MODE}" = "1" ]; then
    # Non interactive: read from env var or fail
    out="${!var_name:-$default_val}"
    if [ -z "$out" ]; then
      err "CI_MODE is set and $var_name is not provided in environment. Aborting."
      exit 1
    fi
  else
    # Interactive
    if [ -n "${!var_name:-}" ]; then
      out="${!var_name}"
      log "Using ${var_name} from environment (not echoing secret)."
    else
      if [ -n "$default_val" ]; then
        read -p "$prompt_msg [$default_val]: " tmp
        tmp="${tmp:-$default_val}"
      else
        read -p "$prompt_msg: " tmp
      fi
      # For password-like fields, hide input
      case "$var_name" in
        ADMIN_PASSWORD|DB_PASSWORD|JWT_SECRET)
          # hide input
          if [ -z "${!var_name:-}" ]; then
            read -s -p "${prompt_msg}: " tmp
            echo
          fi
          ;;
      esac
      out="$tmp"
    fi
  fi
  # export for later use
  export "$var_name"="$out"
}

clone_or_generate_repo() {
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"

  # If repo already exists and contains docker-compose.yml, offer to update
  if [ -d ".git" ] && [ -f "docker-compose.yml" ]; then
    warn "A git repository already exists at $APP_DIR"
    if [ "${CI_MODE}" = "1" ]; then
      log "CI mode: keeping existing repository."
    else
      read -p "Do you want to pull latest from remote? (y/N): " yn
      if [[ "$yn" =~ ^[Yy] ]]; then
        git pull origin "$BRANCH" || true
      fi
    fi
    return
  fi

  # Try to clone the project from REPO_URL
  log "Attempting to clone repository from $REPO_URL (branch: $BRANCH)"
  if command -v git >/dev/null 2>&1; then
    if git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR" 2>/dev/null; then
      log "Cloned repository successfully."
      return
    else
      warn "Failed to clone repository. Falling back to local scaffold generation."
    fi
  else
    warn "git not installed; will generate a local scaffold."
  fi

  generate_scaffold
}

generate_scaffold() {
  log "Generating local Zpars-online scaffold in $APP_DIR"

  # Create directory layout
  mkdir -p "$APP_DIR"/{backend/src,frontend,nginx,volumes/wireguard,volumes/db}
  mkdir -p "$APP_DIR"/backend/src/routes
  mkdir -p "$APP_DIR"/backend/data

  # Write docker-compose.yml
  cat > "$APP_DIR/docker-compose.yml" <<'YML'
version: '3.8'
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: "${DB_PASSWORD:-rootpassword}"
      MYSQL_DATABASE: zpars
      MYSQL_USER: zpars
      MYSQL_PASSWORD: "${DB_PASSWORD:-rootpassword}"
    volumes:
      - db_data:/var/lib/mysql
    networks:
      - znet

  redis:
    image: redis:7
    volumes:
      - redis_data:/data
    networks:
      - znet

  wireguard:
    image: linuxserver/wireguard
    container_name: wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=UTC
      - SERVERURL=auto
      - SERVERPORT=51820
      - PEERS=0
      - PEERDNS=1.1.1.1
    ports:
      - "51820:51820/udp"
    volumes:
      - ./volumes/wireguard:/config
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
    networks:
      - znet

  backend:
    build: ./backend
    environment:
      - PORT=4000
      - JWT_SECRET=${JWT_SECRET:-replace_me}
      - ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD:-changeme}
      - DB_CONN=sqlite://./data/db.json
      - WG_CONFIG_DIR=/wg-config
    volumes:
      - ./volumes/wireguard:/wg-config:rw
      - ./backend/data:/app/data
    ports:
      - "4000:4000"
    depends_on:
      - redis
      - db
    networks:
      - znet

  frontend:
    build: ./frontend
    environment:
      - REACT_APP_API_URL=http://localhost:4000/api
    ports:
      - "3000:3000"
    networks:
      - znet

  nginx:
    image: nginx:stable
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - frontend
      - backend
    networks:
      - znet

volumes:
  db_data:
  redis_data:

networks:
  znet:
    driver: bridge
YML

  # Write .env.example
  cat > "$APP_DIR/.env.example" <<'ENV'
# Copy to .env and set your production values
PORT=4000
JWT_SECRET=very_secret_replace_me
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme
DB_PASSWORD=rootpassword
DB_CONN=sqlite://./data/db.json
WG_CONFIG_DIR=./volumes/wireguard
ENV

  # nginx config
  cat > "$APP_DIR/nginx/default.conf" <<'NGINX'
server {
    listen 80 default_server;
    server_name _;

    location / {
        proxy_pass http://frontend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location /api/ {
        proxy_pass http://backend:4000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
NGINX

  # backend Dockerfile
  cat > "$APP_DIR/backend/Dockerfile" <<'DOCK'
FROM node:18-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    curl \
    iproute2 \
    wireguard-tools \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production

COPY . .

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "src/index.js"]
DOCK

  # backend package.json
  cat > "$APP_DIR/backend/package.json" <<'JSON'
{
  "name": "zpars-backend",
  "version": "0.1.0",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "body-parser": "^1.20.2",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "lowdb": "^6.0.1",
    "nanoid": "^4.0.0"
  }
}
JSON

  # backend src/index.js
  cat > "$APP_DIR/backend/src/index.js" <<'NODE'
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const vpnRoutes = require('./routes/vpn');
const usersRoutes = require('./routes/users');
const { ensureAdmin } = require('./utils/bootstrap');

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use('/api/auth', authRoutes);
app.use('/api/vpn', vpnRoutes);
app.use('/api/users', usersRoutes);

const port = process.env.PORT || 4000;

ensureAdmin().then(() => {
  app.listen(port, () => {
    console.log(`Zpars-online API listening on port ${port}`);
  });
});
NODE

  # backend db.js
  cat > "$APP_DIR/backend/src/db.js" <<'NODE'
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const path = require('path');
const fs = require('fs');

let db;

function initDB() {
  if (db) return db;
  const dataDir = path.resolve(__dirname, '../data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  const adapter = new FileSync(path.join(dataDir, 'db.json'));
  db = low(adapter);
  db.defaults({ users: [], peers: [] }).write();
  return db;
}

function getDB() {
  if (!db) initDB();
  return db;
}

module.exports = { initDB, getDB };
NODE

  # backend utils/bootstrap.js
  mkdir -p "$APP_DIR/backend/src/utils"
  cat > "$APP_DIR/backend/src/utils/bootstrap.js" <<'NODE'
const { initDB, getDB } = require('../db');

async function ensureAdmin() {
  const db = await initDB();
  const users = getDB().get('users').value();
  if (!users || users.length === 0) {
    // create default admin from env
    const email = process.env.ADMIN_EMAIL || 'admin@example.com';
    const password = process.env.ADMIN_PASSWORD || 'secret';
    const bcrypt = require('bcrypt');
    const id = require('nanoid').nanoid();
    const hash = await bcrypt.hash(password, 10);
    getDB().get('users')
      .push({ id, email, password: hash, role: 'admin', createdAt: new Date().toISOString() })
      .write();
    console.log('Created default admin:', email);
  }
}

module.exports = { ensureAdmin };
NODE

  # backend routes/auth.js
  cat > "$APP_DIR/backend/src/routes/auth.js" <<'NODE'
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getDB } = require('../db');

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const db = getDB();
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

module.exports = router;
NODE

  # backend routes/users.js (minimal)
  cat > "$APP_DIR/backend/src/routes/users.js" <<'NODE'
const express = require('express');
const router = express.Router();
const { getDB } = require('../db');

router.get('/', (req, res) => {
  const db = getDB();
  res.json(db.get('users').value().map(u => ({ id: u.id, email: u.email, role: u.role, createdAt: u.createdAt })));
});

module.exports = router;
NODE

  # backend routes/vpn.js (stub)
  cat > "$APP_DIR/backend/src/routes/vpn.js" <<'NODE'
const express = require('express');
const router = express.Router();
const { getDB } = require('../db');
const { nanoid } = require('nanoid');
const fs = require('fs');
const path = require('path');

router.post('/create', async (req, res) => {
  // Create a simple stub peer entry
  const db = getDB();
  const id = nanoid();
  const peer = { id, name: req.body.name||'peer-'+id, createdAt: new Date().toISOString() };
  db.get('peers').push(peer).write();
  res.json({ ok: true, peer });
});

router.get('/peers', (req, res) => {
  const db = getDB();
  res.json(db.get('peers').value());
});

module.exports = router;
NODE

  # frontend Dockerfile (simple static server)
  cat > "$APP_DIR/frontend/Dockerfile" <<'DOCK'
FROM nginx:stable
COPY ./dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
DOCK

  # frontend dist/index.html (simple admin placeholder)
  mkdir -p "$APP_DIR/frontend/dist"
  cat > "$APP_DIR/frontend/dist/index.html" <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Zpars-online Admin</title>
  <style>
    body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; background:#0f172a; color:#e2e8f0; padding:2rem; }
    .card { max-width:860px; margin:2rem auto; background:#0b1220; padding:1.5rem; border-radius:8px; box-shadow:0 4px 30px rgba(2,6,23,0.6); }
    h1 { color:#7dd3fc; }
    pre { background:#020617; padding:1rem; border-radius:6px; overflow:auto; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Zpars-online</h1>
    <p>Welcome to the Zpars-online admin UI (placeholder). The API is available at <code>/api</code>.</p>
    <h3>Quick actions</h3>
    <ul>
      <li>Login: POST /api/auth/login</li>
      <li>List users: GET /api/users</li>
      <li>Create peer: POST /api/vpn/create { "name": "client1" }</li>
    </ul>

    <h3>Reminder</h3>
    <pre>
  - Change defaults in .env before production
  - Secure TLS (nginx) - this is a scaffold
  - Read documentation in the repo for advanced features
    </pre>
  </div>
</body>
</html>
HTML

  # top-level README
  cat > "$APP_DIR/README.md" <<'MD'
# Zpars-online (local scaffold)
This is a generated local scaffold for Zpars-online — WireGuard-focused VPN panel.
Use `docker compose up -d --build` to run the services.
MD

  log "Scaffold generated."
}

create_env_file() {
  cd "$APP_DIR"
  if [ -f .env ]; then
    warn ".env already exists; not overwriting."
    return
  fi
  # Use values already exported: ADMIN_EMAIL, ADMIN_PASSWORD, JWT_SECRET, DB_PASSWORD
  cat > .env <<EOF
PORT=4000
JWT_SECRET=${JWT_SECRET}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
DB_PASSWORD=${DB_PASSWORD}
WG_CONFIG_DIR=./volumes/wireguard
EOF
  log "Wrote .env file with provided secrets (kept locally at $APP_DIR/.env)."
  chmod 600 .env || true
}

start_stack() {
  cd "$APP_DIR"
  # Choose compose command
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    COMPOSE_CMD="docker compose"
  fi

  log "Building and starting services with ${COMPOSE_CMD}..."
  # shellcheck disable=SC2086
  $COMPOSE_CMD up -d --build

  log "Waiting for services to be healthy (up to ${DOCKER_COMPOSE_TIMEOUT}s)..."
  local waited=0
  while [ $waited -lt "$DOCKER_COMPOSE_TIMEOUT" ]; do
    # basic check: backend container listening on 4000
    if curl -fsS --max-time 2 http://127.0.0.1:4000/api/auth 2>/dev/null || curl -fsS --max-time 2 http://127.0.0.1:4000/ 2>/dev/null; then
      log "Backend appears to be reachable."
      break
    fi
    sleep 2
    waited=$((waited+2))
  done

  if [ $waited -ge "$DOCKER_COMPOSE_TIMEOUT" ]; then
    warn "Timeout waiting for the backend to start. Check logs: cd $APP_DIR && ${COMPOSE_CMD} logs -f"
  fi

  log "Zpars-online should now be running. Frontend: http://<server-ip>/  API: http://<server-ip>:4000/api/"
  log "Default admin user: ${ADMIN_EMAIL} (password not displayed). Change it after first login."
}

show_post_install_notes() {
  cat <<-NOTES

  Installation complete.

  Next steps and recommendations:
  - Visit your server IP in a browser to access the admin UI (placeholder).
  - Review and rotate secrets stored in $APP_DIR/.env
  - Configure TLS: replace nginx/default.conf and obtain certificates (certbot) or route through a proper reverse proxy.
  - For production, consider:
      * Use a real database (MySQL/Postgres) and update DB_CONN
      * Enable monitoring (Prometheus, Grafana, Netdata)
      * Harden host kernel and firewall (iptables/nftables)
      * Set up automatic backups of DB and WireGuard configs
  - To view logs:
      cd "$APP_DIR" && docker compose logs -f

NOTES
}

main() {
  banner
  ensure_root
  detect_os
  install_docker

  # Prompt secrets
  prompt_secret ADMIN_EMAIL "Admin email" "admin@example.com"
  prompt_secret ADMIN_PASSWORD "Admin password (will be hidden when typed)" ""
  prompt_secret JWT_SECRET "JWT secret (long random string recommended)" ""
  prompt_secret DB_PASSWORD "Database root password (for MySQL service)" "rootpassword"

  # Clone or generate repo
  clone_or_generate_repo

  # create env file
  create_env_file

  # start the stack
  start_stack

  show_post_install_notes
}

# Run
main "$@"
