#!/usr/bin/env bash
# Zpars-online Non-interactive Expert Installer
# Installs Docker + Compose (if missing), clones the repo (or generates a scaffold),
# creates .env automatically (no prompts), and launches the stack.
#
# This installer purposely does NOT prompt for input. It will:
#  - Use environment variables ADMIN_EMAIL and ADMIN_PASSWORD if provided,
#    otherwise it defaults ADMIN_EMAIL=admin@example.com and generates a secure random password.
#  - Generate a secure JWT secret automatically.
#  - Generate a DB password automatically.
#  - Start the stack with docker compose.
#
# Usage:
#  curl -fsSL https://raw.githubusercontent.com/gamechanger877-ea/Zpars-online/main/install.sh | sudo bash
#
# You can predefine credentials before running:
#  export ADMIN_EMAIL="you@domain.tld"
#  export ADMIN_PASSWORD="YourPasswordHere"
#  curl -fsSL ... | sudo bash
#
# SECURITY NOTE:
#  - The script will print the auto-generated admin credentials at the end.
#  - Change secrets after installation. Review the code before running on a production host.

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/zpars-online}"
REPO_URL="${REPO_URL:-https://github.com/gamechanger877-ea/Zpars-online.git}"
BRANCH="${BRANCH:-main}"
DOCKER_COMPOSE_TIMEOUT="${DOCKER_COMPOSE_TIMEOUT:-120}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
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

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "This installer must be run as root. Re-run with sudo or as root."
    exit 1
  fi
}

detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${NAME:-}"
    OS_VER="${VERSION_ID:-}"
  else
    OS_NAME="$(uname -s)"
    OS_VER="$(uname -r)"
  fi
  log "Detected OS: ${OS_NAME} ${OS_VER}"
}

generate_random() {
  # $1 length
  local len="${1:-16}"
  tr -dc 'A-Za-z0-9!@#$%&*()_+~' </dev/urandom | head -c "$len" || true
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    log "Docker already installed."
  else
    log "Installing Docker (official script)..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    log "Docker installed."
  fi

  # ensure docker compose plugin or CLI present
  if docker compose version >/dev/null 2>&1; then
    log "Docker Compose (v2+) available."
  elif command -v docker-compose >/dev/null 2>&1; then
    log "Legacy docker-compose binary available."
  else
    log "Installing Docker Compose plugin/binary..."
    # Try apt-get first (Debian/Ubuntu)
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y || true
      apt-get install -y docker-compose-plugin || true
    fi
    # Fallback to binary download
    if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
      DC_VER="v2.20.2"
      ARCH="$(uname -m)"
      case "$ARCH" in
        x86_64|amd64) ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
      esac
      curl -fsSL "https://github.com/docker/compose/releases/download/${DC_VER}/docker-compose-$(uname -s)-${ARCH}" -o /usr/local/bin/docker-compose
      chmod +x /usr/local/bin/docker-compose
      log "Installed docker-compose to /usr/local/bin/docker-compose"
    fi
  fi
}

clone_or_generate_repo() {
  mkdir -p "$APP_DIR"
  # If repo already looks present (docker-compose.yml), keep it
  if [ -f "$APP_DIR/docker-compose.yml" ]; then
    log "Existing project found in $APP_DIR; using it."
    return 0
  fi

  # Attempt to clone
  if command -v git >/dev/null 2>&1; then
    log "Cloning repository $REPO_URL (branch $BRANCH) into $APP_DIR..."
    if git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR" 2>/dev/null; then
      log "Cloned repository."
      return 0
    else
      warn "Clone failed or repository not available. Generating local scaffold."
    fi
  else
    warn "git not found. Generating local scaffold."
  fi

  generate_scaffold
}

generate_scaffold() {
  log "Generating scaffold in $APP_DIR ..."
  mkdir -p "$APP_DIR"/{backend/src,frontend/dist,nginx,volumes/wireguard,backend/data}

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

  cat > "$APP_DIR/.env.example" <<'ENV'
PORT=4000
JWT_SECRET=very_secret_replace_me
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme
DB_PASSWORD=rootpassword
DB_CONN=sqlite://./data/db.json
WG_CONFIG_DIR=./volumes/wireguard
ENV

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

  # minimal backend Dockerfile + files
  cat > "$APP_DIR/backend/Dockerfile" <<'DOCK'
FROM node:18-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git curl iproute2 wireguard-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production || true
COPY . .
ENV NODE_ENV=production
EXPOSE 4000
CMD ["node", "src/index.js"]
DOCK

  cat > "$APP_DIR/backend/package.json" <<'JSON'
{
  "name": "zpars-backend",
  "version": "0.1.0",
  "main": "src/index.js",
  "scripts": { "start": "node src/index.js" },
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

  mkdir -p "$APP_DIR/backend/src/utils"
  cat > "$APP_DIR/backend/src/utils/bootstrap.js" <<'BOOT'
const { initDB, getDB } = require('../db');
async function ensureAdmin() {
  const db = await initDB();
  const users = getDB().get('users').value();
  if (!users || users.length === 0) {
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
BOOT

  cat > "$APP_DIR/backend/src/db.js" <<'DB'
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
DB

  mkdir -p "$APP_DIR/backend/src/routes"
  cat > "$APP_DIR/backend/src/routes/auth.js" <<'AUTH'
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
AUTH

  cat > "$APP_DIR/backend/src/routes/users.js" <<'USERS'
const express = require('express');
const router = express.Router();
const { getDB } = require('../db');

router.get('/', (req, res) => {
  const db = getDB();
  res.json(db.get('users').value().map(u => ({ id: u.id, email: u.email, role: u.role, createdAt: u.createdAt })));
});

module.exports = router;
USERS

  cat > "$APP_DIR/backend/src/routes/vpn.js" <<'VPN'
const express = require('express');
const router = express.Router();
const { getDB } = require('../db');
const { nanoid } = require('nanoid');

router.post('/create', async (req, res) => {
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
VPN

  # frontend
  cat > "$APP_DIR/frontend/Dockerfile" <<'FDOCK'
FROM nginx:stable
COPY ./dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
FDOCK

  cat > "$APP_DIR/frontend/dist/index.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Zpars-online Admin</title></head><body style="font-family:system-ui;background:#071029;color:#cfe8ff;padding:2rem;">
  <h1>Zpars-online</h1>
  <p>Admin UI placeholder. API at /api</p>
</body></html>
HTML

  log "Scaffold generation completed."
}

create_env_file() {
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"

  if [ -f ".env" ]; then
    warn ".env already exists; not overwriting."
    return 0
  fi

  # Use provided env vars or defaults
  ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
  if [ -n "${ADMIN_PASSWORD:-}" ]; then
    ADMIN_PWD="${ADMIN_PASSWORD}"
  else
    ADMIN_PWD="$(generate_random 12)"
  fi
  JWT_SECRET="${JWT_SECRET:-$(generate_random 32)}"
  DB_PASSWORD="${DB_PASSWORD:-$(generate_random 16)}"

  cat > .env <<EOF
PORT=4000
JWT_SECRET=${JWT_SECRET}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PWD}
DB_PASSWORD=${DB_PASSWORD}
DB_CONN=sqlite://./data/db.json
WG_CONFIG_DIR=./volumes/wireguard
EOF

  chmod 600 .env || true

  # Export values for immediate use in this script
  export ADMIN_EMAIL="${ADMIN_EMAIL}"
  export ADMIN_PASSWORD="${ADMIN_PWD}"
  export JWT_SECRET="${JWT_SECRET}"
  export DB_PASSWORD="${DB_PASSWORD}"

  log ".env created at $APP_DIR/.env"
}

start_stack() {
  cd "$APP_DIR"
  # choose compose command
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    COMPOSE_CMD="docker compose"
  fi

  log "Starting stack using: ${COMPOSE_CMD} up -d --build"
  # shellcheck disable=SC2086
  $COMPOSE_CMD up -d --build

  log "Waiting up to ${DOCKER_COMPOSE_TIMEOUT}s for backend to respond..."
  local waited=0
  while [ $waited -lt "${DOCKER_COMPOSE_TIMEOUT}" ]; do
    if curl -fsS --max-time 2 http://127.0.0.1:4000/ >/dev/null 2>&1 || curl -fsS --max-time 2 http://127.0.0.1:4000/api/ >/dev/null 2>&1; then
      log "Backend reachable."
      break
    fi
    sleep 2
    waited=$((waited + 2))
  done

  if [ $waited -ge "${DOCKER_COMPOSE_TIMEOUT}" ]; then
    warn "Backend did not become reachable within timeout. Check logs: cd $APP_DIR && ${COMPOSE_CMD} logs -f"
  fi
}

final_report() {
  cat <<EOF

${GREEN}Installation finished.${NC}

Web UI: http://<server-ip>/  (nginx proxy)
API: http://<server-ip>:4000/api/

Admin credentials (saved to ${APP_DIR}/.env):
  Email: ${ADMIN_EMAIL}
  Password: ${ADMIN_PASSWORD}

IMPORTANT:
 - Change the admin password immediately after first login.
 - Review ${APP_DIR}/.env and rotate secrets if required.
 - For production, replace SQLite with a proper DB, enable TLS, and harden the host.

To view logs:
  cd ${APP_DIR} && docker compose logs -f

EOF
}

main() {
  banner
  ensure_root
  detect_os
  install_docker

  # Non-interactive: clone or generate without asking
  clone_or_generate_repo

  # Create .env using env vars or defaults (no prompts)
  create_env_file

  # Start the stack
  start_stack

  final_report
}

main "$@"
