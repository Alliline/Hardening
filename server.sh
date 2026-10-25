#!/usr/bin/env bash
# =============================================================================
# server.sh
# Ultimate Security Hardening + LEMP + Redis + Advanced WAF for Fedora Server 44/45+
# Version: 1.0 (Final Production Edition)
# =============================================================================
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION='0.1'
MODE='audit'
FORCE_SSH_KEEP=true

# Defaults for interactive --apply mode
INSTALL_LEMP=true
SECURE_MARIADB=true
HARDEN_NGINX_PHP=true
ENABLE_FAIL2BAN=true
SETUP_FIREWALL_HTTP=true
SSH_PORT=4444
AGGRESSIVE_USERNS=false

# ---------------------------------------------------------------------------
# Command-line argument parsing
# ---------------------------------------------------------------------------
VHOST_ACTION=""
VHOST_DOMAIN=""
VHOST_TYPE="php"          # php | static | redirect
VHOST_TARGET_URL=""
DB_ACTION=""
DB_NAME=""
DB_USER=""
DB_PASS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)          MODE='apply'; shift ;;
    --audit)          MODE='audit'; shift ;;
    --vhost-add)      MODE='vhost'; VHOST_ACTION='add'; shift ;;
    --vhost-del)      MODE='vhost'; VHOST_ACTION='del'; shift ;;
    --vhost-list)     MODE='vhost'; VHOST_ACTION='list'; shift ;;
    --db-add)         MODE='db'; DB_ACTION='add'; shift ;;
    --db-del)         MODE='db'; DB_ACTION='del'; shift ;;
    --db-list)        MODE='db'; DB_ACTION='list'; shift ;;
    --type)           VHOST_TYPE="$2"; shift 2 ;;
    --target)         VHOST_TARGET_URL="$2"; shift 2 ;;
    --db-name)        DB_NAME="$2"; shift 2 ;;
    --db-user)        DB_USER="$2"; shift 2 ;;
    --db-pass)        DB_PASS="$2"; shift 2 ;;
    --help|-h)
      cat <<'HELP'
Usage: sudo ./server.sh [OPTION]

Modes:
  --audit                  Report current security posture (default, no changes)
  --apply                  Apply full system hardening, LEMP stack & security rules

Virtual Host Management:
  --vhost-add DOMAIN       Create vhost [--type php|static|redirect] [--target URL]
  --vhost-del DOMAIN       Remove vhost, system user and directories
  --vhost-list             List all configured virtual hosts

Database Management (MariaDB):
  --db-add                 Create isolated database + user
                           --db-name NAME [--db-user USER] [--db-pass PASS]
  --db-del                 Drop database and associated user
                           --db-name NAME [--db-user USER]
  --db-list                List databases and users managed by this script

  --help, -h               Show this help message

Designed exclusively for Fedora Server (compatible with 44/45+).
HELP
      exit 0
      ;;
    *)
      if [[ -z "$VHOST_DOMAIN" && "$MODE" == "vhost" ]]; then
        VHOST_DOMAIN="$1"
      elif [[ -z "$DB_NAME" && "$MODE" == "db" && "$DB_ACTION" != "list" ]]; then
        DB_NAME="$1"
      else
        echo "Unknown argument: $1. Use --help." >&2
        exit 2
      fi
      shift
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Colours and helpers
# ---------------------------------------------------------------------------
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

ok()     { printf '%s[OK]%s      %s\n' "$GREEN"  "$NC" "$*"; }
fixed()  { printf '%s[APPLIED]%s %s\n' "$BLUE"   "$NC" "$*"; }
warn()   { printf '%s[WARN]%s    %s\n' "$YELLOW" "$NC" "$*"; }
fail()   { printf '%s[FAIL]%s    %s\n' "$RED"    "$NC" "$*"; }
info()   { printf '          %s\n' "$*"; }
section(){ printf '\n%s=== %s ===%s\n' "$CYAN" "$*" "$NC"; }

die() { fail "$*"; exit 1; }

ask_yn() {
  local prompt_msg="$1"
  local default_val="${2:-y}"
  local ans
  if [[ "$MODE" != "apply" && "$MODE" != "vhost" && "$MODE" != "db" ]]; then
    [[ "$default_val" =~ ^[yY] ]] && return 0 || return 1
  fi
  local hint="Y/n"
  [[ "$default_val" =~ ^[nN]$ ]] && hint="y/N"
  read -rp "$prompt_msg [$hint]: " ans || true
  ans="${ans:-$default_val}"
  [[ "$ans" =~ ^[yY][eE]?[sS]?$ ]]
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if (( EUID != 0 )); then
  die "This script must be run as root or via sudo."
fi

if [[ ! -r /etc/os-release ]] || ! grep -qE '^ID=fedora$' /etc/os-release; then
  die "This script is designed exclusively for Fedora Linux."
fi

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups/server/$STAMP"
LOG_FILE="/var/log/server.log"
VHOSTS_BASE="/home/vhosts"
NGINX_SITES="/etc/nginx/conf.d"
PHP_FPM_POOL_DIR="/etc/php-fpm.d"
PHP_SOCK_DIR="/run/php-fpm"
GEOIP_DIR="/etc/nginx/geoip"
GEOIP_COUNTRY="$GEOIP_DIR/GeoLite2-Country.mmdb"
GEOIP_HASH_FILE="$GEOIP_DIR/.GeoLite2-Country.mmdb.sha256"
DB_CREDENTIALS_DIR="/root/.secure-fedora-dbs"
NGINX_DENY_CONF="/etc/nginx/deny.conf"

if [[ $MODE == apply ]]; then
  install -d -m 0700 "$BACKUP_DIR"
  touch "$LOG_FILE"
  chmod 0600 "$LOG_FILE"
  exec 3>&1
  exec > >(tee -a "$LOG_FILE" >&3) 2>&1
  info "Backup directory : $BACKUP_DIR"
  info "Log file         : $LOG_FILE"
fi

backup_file() {
  local f=$1
  if [[ -e $f || -L $f ]]; then
    install -d -m 0700 "$BACKUP_DIR$(dirname "$f")"
    cp -a -- "$f" "$BACKUP_DIR$f" 2>/dev/null || true
  fi
}

write_managed() {
  local dest=$1 mode=$2
  local tmp
  install -d -m 0755 "$(dirname "$dest")"
  tmp=$(mktemp "$(dirname "$dest")/.secure-hardening.XXXXXX")
  cat > "$tmp"
  chmod "$mode" "$tmp"
  if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    ok "Already up-to-date: $dest"
    return 0
  fi
  backup_file "$dest"
  install -o root -g root -m "$mode" "$tmp" "$dest"
  rm -f "$tmp"
  fixed "Updated: $dest"
}

printf '\n=== Fedora Server Ultimate Hardening + LEMP + WAF v%s ===\n' "$VERSION"
printf 'Mode: %s | Date: %s | Host: %s | Kernel: %s\n' \
  "$MODE" "$(date -Is)" "$(hostname)" "$(uname -r)"

# ===========================================================================
# 1. /ETC/NGINX/DENY.CONF HANDLING
# ===========================================================================
section '1. Initializing /etc/nginx/deny.conf'
if [[ ! -f "$NGINX_DENY_CONF" ]]; then
  install -d -m 0755 /etc/nginx
  touch "$NGINX_DENY_CONF"
  chmod 0644 "$NGINX_DENY_CONF"
  fixed "Created empty $NGINX_DENY_CONF"
else
  ok "$NGINX_DENY_CONF already exists, left untouched."
fi

# ===========================================================================
# SINGLE SOURCE OF TRUTH – VIRTUAL HOST TEMPLATES (WITH ADVANCED WAF)
# ===========================================================================

get_php_vhost_template() {
  local domain="$1"
  local site_root="$2"
  local site_user="$3"
  local sock="$4"
  cat <<EOF
# Managed by server.sh – do not edit manually
server {
    listen 80;
    server_name $domain www.$domain;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen 443 quic;
    http2 on;
    http3 on;
    merge_slashes on;

    server_name $domain www.$domain;

    ssl_certificate     /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    root $site_root/public;
    index index.php;

    access_log $site_root/logs/access.log main;
    error_log  $site_root/logs/error.log warn;
    access_log /var/log/nginx/probe.log combined if=\$is_bad_ua;
    access_log /var/log/nginx/probe.log combined if=\$is_bad_probe;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header X-XSS-Protection "0" always;

    # Built-in WAF / Bad traffic blocking
    if (\$is_bad_ip)    { return 444; }
    if (\$is_bad_subnet) { return 444; }
    if (\$is_bad_ua)     { return 444; }
    if (\$is_bad_probe)  { return 444; }
    if (\$is_bad_method) { return 444; }

    if (\$http_user_agent = "")             { return 444; }
    if (\$http_user_agent ~ "^.{0,10}$")    { return 444; }
    if (\$http_user_agent ~ "^.{400,}$")    { return 444; }

    if (\$request_uri ~ "/{3,}")            { return 444; }
    if (\$request_uri ~ "^.{1000,}")        { return 444; }

    # Hide all dotfiles / sensitive files globally
    location ~ /\\. {
        deny all;
        access_log off;
        log_not_found off;
        return 404;
    }
    location ~* (?:\\.env|composer\\.(json|lock)|package\\.json|yarn\\.lock|\\.git|\\.svn|\\.hg|\\.htaccess|\\.htpasswd)\$ {
        deny all;
        return 404;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location = /index.php {
        try_files \$uri =404;
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_pass unix:$sock;
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;
        fastcgi_read_timeout 60s;
        fastcgi_send_timeout 60s;
        fastcgi_param HTTPS on;
        fastcgi_param SERVER_PORT 443;
        fastcgi_param SCRIPT_FILENAME \$document_root/index.php;
        fastcgi_param SCRIPT_NAME /index.php;
        fastcgi_param DOCUMENT_ROOT \$document_root;

        fastcgi_param REQUEST_URI \$request_uri;
        fastcgi_param REMOTE_ADDR \$remote_addr;
        fastcgi_param INBOUND_HTTP_PROTOCOL \$server_protocol;
        fastcgi_param TLS_SNI \$ssl_server_name;
        fastcgi_param TLS_PROTOCOL \$ssl_protocol;
        fastcgi_param TLS_CIPHER \$ssl_cipher;
        fastcgi_param TLS_CURVES \$ssl_curves;
        fastcgi_param TLS_CLIENT_S_DN \$ssl_client_s_dn;
    }

    location ~* \\.(?:jpg|jpeg|png|gif|ico|css|js|woff2?|svg|webp|avif|ttf|eot)\$ {
        access_log off;
        log_not_found off;
        expires 30d;
        add_header Cache-Control "public, immutable, no-transform";
        add_header X-Content-Type-Options "nosniff" always;
        try_files \$uri =404;
    }

    # Block direct access to any other PHP file except index.php
    location ~ \\.php\$ {
        return 404;
    }

    client_max_body_size 32M;
    client_body_timeout 30s;
    client_header_timeout 30s;
    send_timeout 30s;
    server_tokens off;
}
EOF
}

get_static_vhost_template() {
  local domain="$1"
  local site_root="$2"
  cat <<EOF
# Managed by server.sh – do not edit manually
server {
    listen 80;
    server_name $domain www.$domain;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    http3 on;

    server_name $domain www.$domain;

    ssl_certificate     /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    root $site_root/public;
    index index.html;

    access_log $site_root/logs/access.log main;
    error_log  $site_root/logs/error.log warn;
    access_log /var/log/nginx/probe.log combined if=\$is_bad_ua;
    access_log /var/log/nginx/probe.log combined if=\$is_bad_probe;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    if (\$is_bad_ip)    { return 444; }
    if (\$is_bad_subnet) { return 444; }
    if (\$is_bad_ua)     { return 444; }
    if (\$is_bad_probe)  { return 444; }
    if (\$is_bad_method) { return 444; }

    if (\$http_user_agent = "")             { return 444; }
    if (\$http_user_agent ~ "^.{0,10}$")    { return 444; }
    if (\$http_user_agent ~ "^.{400,}$")    { return 444; }

    if (\$request_uri ~ "/{3,}")            { return 444; }
    if (\$request_uri ~ "^.{1000,}")        { return 444; }

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~* \\.(?:jpg|jpeg|png|gif|ico|css|js|woff2?|svg|webp|avif)\$ {
        access_log off;
        log_not_found off;
        expires 30d;
        add_header Cache-Control "public, immutable, no-transform";
    }

    location ~ /\\. {
        deny all;
        access_log off;
        log_not_found off;
        return 404;
    }

    client_max_body_size 32M;
    server_tokens off;
}
EOF
}

get_redirect_vhost_template() {
  local domain="$1"
  local target_url="$2"
  cat <<EOF
# Managed by server.sh – do not edit manually
server {
    listen 80;
    listen 443 ssl;
    server_name $domain www.$domain;

    access_log /var/log/nginx/probe.log combined if=\$is_bad_ua;
    access_log /var/log/nginx/probe.log combined if=\$is_bad_probe;

    ssl_certificate     /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    if (\$is_bad_ip)    { return 444; }
    if (\$is_bad_subnet) { return 444; }
    if (\$is_bad_ua)     { return 444; }
    if (\$is_bad_probe)  { return 444; }
    if (\$is_bad_method) { return 444; }

    if (\$http_user_agent = "")             { return 444; }
    if (\$http_user_agent ~ "^.{0,10}$")    { return 444; }
    if (\$http_user_agent ~ "^.{400,}$")    { return 444; }

    if (\$request_uri ~ "/{3,}")            { return 444; }
    if (\$request_uri ~ "^.{1000,}")        { return 444; }

    return 301 $target_url\$request_uri;
}
EOF
}

get_php_pool_template() {
  local pool_name="$1"
  local site_user="$2"
  local site_root="$3"
  local sock="$4"
  cat <<EOF
; Managed by server.sh – do not edit manually
[${pool_name}]
user  = ${site_user}
group = ${site_user}
listen = ${sock}
listen.owner = nginx
listen.group = nginx
listen.mode  = 0660

pm = dynamic
pm.max_children = 100
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 8
pm.max_requests = 500
pm.process_idle_timeout = 10s

php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,phpinfo
php_admin_value[open_basedir]      = ${site_root}:/tmp:/var/tmp:/usr/share/php:/usr/share/pear
php_admin_flag[allow_url_fopen]    = off
php_admin_flag[allow_url_include]  = off
php_admin_value[session.save_path] = ${site_root}/sessions
php_admin_value[upload_tmp_dir]    = ${site_root}/tmp
php_admin_value[memory_limit]      = 256M
php_admin_value[max_execution_time]= 60
php_admin_value[max_input_time]    = 60
php_admin_flag[expose_php]         = off
php_admin_value[error_log]         = ${site_root}/logs/php-error.log
php_admin_flag[log_errors]         = on
php_admin_flag[display_errors]     = off
php_admin_value[max_input_vars]    = 1000
php_admin_value[max_file_uploads]  = 10
php_admin_value[max_multipart_body_parts] = 200
php_admin_flag[session.upload_progress.enabled] = off
security.limit_extensions          = .php
clear_env = yes
catch_workers_output = yes
request_terminate_timeout = 60s
request_slowlog_timeout = 5s
slowlog = ${site_root}/logs/php-slow.log
EOF
}

# ===========================================================================
# DATABASE & REDIS MANAGEMENT
# ===========================================================================
ensure_db_credentials_dir() {
  install -d -m 0700 "$DB_CREDENTIALS_DIR"
}

create_database() {
  local db_name="$1"
  local db_user="${2:-}"
  local db_pass="${3:-}"

  ensure_db_credentials_dir

  db_name=$(echo "$db_name" | tr -cd 'a-zA-Z0-9_')
  [[ -z "$db_name" ]] && die "Invalid database name."

  if [[ -z "$db_user" ]]; then
    db_user="u_${db_name}"
  fi
  db_user=$(echo "$db_user" | tr -cd 'a-zA-Z0-9_')

  if [[ -z "$db_pass" ]]; then
    db_pass=$(openssl rand -base64 24 | tr -d '=+/' | cut -c1-24)
  fi

  if mysql -Nse "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='$db_name';" 2>/dev/null | grep -q .; then
    die "Database '$db_name' already exists."
  fi

  info "Creating database '$db_name' and user '$db_user'..."

  mysql -e "CREATE DATABASE \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" || die "Failed to create database."
  mysql -e "CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';" || die "Failed to create user."
  mysql -e "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, EVENT, TRIGGER ON \`${db_name}\`.* TO '${db_user}'@'localhost';"
  mysql -e "FLUSH PRIVILEGES;"

  local cred_file="$DB_CREDENTIALS_DIR/${db_name}.env"
  cat > "$cred_file" <<EOF
DB_NAME=${db_name}
DB_USER=${db_user}
DB_PASS=${db_pass}
DB_HOST=localhost
DB_PORT=3306
EOF
  chmod 0600 "$cred_file"

  fixed "Database '${db_name}' created."
  info "Credentials stored in: $cred_file"
}

drop_database() {
  local db_name="$1"
  local db_user="${2:-}"

  db_name=$(echo "$db_name" | tr -cd 'a-zA-Z0-9_')
  [[ -z "$db_name" ]] && die "Invalid database name."

  if [[ -z "$db_user" ]]; then
    db_user="u_${db_name}"
  fi

  info "Dropping database '$db_name' and user '$db_user'..."
  mysql -e "DROP DATABASE IF EXISTS \`${db_name}\`;" 2>/dev/null || true
  mysql -e "DROP USER IF EXISTS '${db_user}'@'localhost';" 2>/dev/null || true
  mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
  rm -f "$DB_CREDENTIALS_DIR/${db_name}.env"
  fixed "Database '${db_name}' removed."
}

list_databases() {
  section "Managed databases"
  if [[ -d "$DB_CREDENTIALS_DIR" ]]; then
    for f in "$DB_CREDENTIALS_DIR"/*.env; do
      [[ -f "$f" ]] || continue
      # shellcheck source=/dev/null
      source "$f"
      printf "  • %-30s  user=%s\n" "$DB_NAME" "$DB_USER"
    done
  else
    info "No managed databases found."
  fi
}

if [[ $MODE == db ]]; then
  section "Database management"
  case "$DB_ACTION" in
    list) list_databases; exit 0 ;;
    add)
      [[ -z "$DB_NAME" ]] && die "Specify database name: --db-add --db-name NAME"
      create_database "$DB_NAME" "$DB_USER" "$DB_PASS"
      exit 0
      ;;
    del)
      [[ -z "$DB_NAME" ]] && die "Specify database name: --db-del --db-name NAME"
      drop_database "$DB_NAME" "$DB_USER"
      exit 0
      ;;
  esac
fi

# ===========================================================================
# VIRTUAL HOST MANAGEMENT
# ===========================================================================
if [[ $MODE == vhost ]]; then
  section "Virtual host management"

  case "$VHOST_ACTION" in
    list)
      echo "Configured virtual hosts:"
      if [[ -d "$NGINX_SITES" ]]; then
        ls -1 "$NGINX_SITES"/*.conf 2>/dev/null | while read -r f; do
          domain=$(basename "$f" .conf)
          [[ "$domain" == "default" || "$domain" == "00-default" ]] && continue
          printf "  • %s\n" "$domain"
        done
      fi
      exit 0
      ;;
    add)
      [[ -z "$VHOST_DOMAIN" ]] && die "Specify domain: --vhost-add domain.tld [--type php|static|redirect]"
      DOMAIN="$VHOST_DOMAIN"
      SITE_USER="web_$(echo "$DOMAIN" | tr '.-' '_')"
      SITE_ROOT="$VHOSTS_BASE/$DOMAIN"
      POOL_NAME=$(echo "$DOMAIN" | tr '.-' '_')
      SOCK="$PHP_SOCK_DIR/${POOL_NAME}.sock"

      if [[ -f "$NGINX_SITES/${DOMAIN}.conf" ]]; then
        die "Virtual host $DOMAIN already exists."
      fi

      info "Creating isolated system user: $SITE_USER"
      if ! id "$SITE_USER" &>/dev/null; then
        useradd -r -d "$SITE_ROOT" -s /sbin/nologin -g nginx "$SITE_USER" || die "Failed to create user."
      fi

      install -d -o "$SITE_USER" -g nginx -m 0750 "$SITE_ROOT"
      install -d -o "$SITE_USER" -g nginx -m 0750 "$SITE_ROOT/public"
      install -d -o "$SITE_USER" -g nginx -m 0750 "$SITE_ROOT/logs"

      if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
        info "Generating temporary self-signed certificate for $DOMAIN..."
        install -d -m 0700 /etc/nginx/ssl-self
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
          -keyout "/etc/nginx/ssl-self/$DOMAIN.key" \
          -out "/etc/nginx/ssl-self/$DOMAIN.crt" \
          -subj "/CN=$DOMAIN" &>/dev/null || true
      fi

      case "$VHOST_TYPE" in
        php)
          info "Type: PHP Virtual Host (isolated pool)"
          install -d -o "$SITE_USER" -g nginx -m 0750 "$SITE_ROOT/sessions" "$SITE_ROOT/tmp"
          printf '%s\n' "<?php echo '<h1>Site $DOMAIN is working! PHP ' . phpversion() . '</h1>';" > "$SITE_ROOT/public/index.php"
          chown "$SITE_USER:nginx" "$SITE_ROOT/public/index.php"
          chmod 0640 "$SITE_ROOT/public/index.php"

          write_managed "$PHP_FPM_POOL_DIR/${POOL_NAME}.conf" 0644 \
            "$(get_php_pool_template "$POOL_NAME" "$SITE_USER" "$SITE_ROOT" "$SOCK")"

          write_managed "$NGINX_SITES/${DOMAIN}.conf" 0644 \
            "$(get_php_vhost_template "$DOMAIN" "$SITE_ROOT" "$SITE_USER" "$SOCK")"

          if ask_yn "Also create an isolated MariaDB database for this site?" "y"; then
            local_db_name=$(echo "$DOMAIN" | tr '.-' '_')
            create_database "$local_db_name"
          fi
          ;;
        static)
          info "Type: Static Virtual Host"
          printf '<h1>Static site: %s</h1>\n' "$DOMAIN" > "$SITE_ROOT/public/index.html"
          chown "$SITE_USER:nginx" "$SITE_ROOT/public/index.html"
          chmod 0640 "$SITE_ROOT/public/index.html"

          write_managed "$NGINX_SITES/${DOMAIN}.conf" 0644 \
            "$(get_static_vhost_template "$DOMAIN" "$SITE_ROOT")"
          ;;
        redirect)
          [[ -z "$VHOST_TARGET_URL" ]] && die "For redirect type specify --target https://example.com"
          info "Type: Redirect → $VHOST_TARGET_URL"
          write_managed "$NGINX_SITES/${DOMAIN}.conf" 0644 \
            "$(get_redirect_vhost_template "$DOMAIN" "$VHOST_TARGET_URL")"
          ;;
        *)
          die "Unknown vhost type: $VHOST_TYPE. Allowed: php, static, redirect"
          ;;
      esac

      if command -v restorecon &>/dev/null; then
        restorecon -Rv "$SITE_ROOT" 2>/dev/null || true
      fi

      systemctl reload php-fpm 2>/dev/null || true
      if nginx -t; then
        systemctl reload nginx
        fixed "Virtual host $DOMAIN created successfully."
      else
        fail "nginx configuration test failed – please inspect."
      fi
      exit 0
      ;;
    del)
      [[ -z "$VHOST_DOMAIN" ]] && die "Specify domain: --vhost-del domain.tld"
      DOMAIN="$VHOST_DOMAIN"
      SITE_USER="web_$(echo "$DOMAIN" | tr '.-' '_')"
      POOL_NAME=$(echo "$DOMAIN" | tr '.-' '_')

      info "Removing virtual host: $DOMAIN"
      rm -f "$NGINX_SITES/${DOMAIN}.conf"
      rm -f "$PHP_FPM_POOL_DIR/${POOL_NAME}.conf"
      rm -rf "$VHOSTS_BASE/$DOMAIN"
      id "$SITE_USER" &>/dev/null && userdel -r "$SITE_USER" 2>/dev/null || true

      systemctl reload php-fpm 2>/dev/null || true
      nginx -t && systemctl reload nginx
      fixed "Virtual host $DOMAIN removed."
      exit 0
      ;;
  esac
fi

# ===========================================================================
# INTERACTIVE SETTINGS FOR --apply
# ===========================================================================
if [[ $MODE == apply ]]; then
  section 'Interactive installation options'
  if ask_yn "1. Install and configure LEMP stack + Redis (nginx + PHP-FPM + MariaDB + Redis)?" "y"; then INSTALL_LEMP=true; else INSTALL_LEMP=false; fi
  if ask_yn "2. Perform secure tuning of MariaDB & Redis (RAM & performance)?" "y"; then SECURE_MARIADB=true; else SECURE_MARIADB=false; fi
  if ask_yn "3. Apply aggressive nginx + PHP hardening & WAF filters?" "y"; then HARDEN_NGINX_PHP=true; else HARDEN_NGINX_PHP=false; fi
  if ask_yn "4. Install and configure fail2ban jails?" "y"; then ENABLE_FAIL2BAN=true; else ENABLE_FAIL2BAN=false; fi
  if ask_yn "5. Open HTTP/HTTPS ports in firewalld?" "y"; then SETUP_FIREWALL_HTTP=true; else SETUP_FIREWALL_HTTP=false; fi

  read -rp "6. New SSH port (default 4444): " custom_ssh_port || true
  SSH_PORT="${custom_ssh_port:-4444}"
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1024 || SSH_PORT > 65535 )); then
    warn "Invalid port – falling back to 4444."
    SSH_PORT=4444
  fi
fi

# ===========================================================================
# 1. KERNEL & BOOTLOADER HARDENING
# ===========================================================================
section '1. Kernel and bootloader security parameters'

KARGS_CORE=(
  slab_nomerge
  init_on_alloc=1
  init_on_free=1
  page_alloc.shuffle=1
  randomize_kstack_offset=on
  iommu=force
  iommu.strict=1
  iommu.passthrough=0
  pti=on
  vsyscall=none
  random.trust_cpu=off
  random.trust_bootloader=off
  oops=panic
  tsx=off
  debugfs=off
  kvm.nx_huge_pages=force
  spectre_v2_user=on
  spec_rstack_overflow=safe-ret
  l1tf=full,force
)

KARGS_EXTRA=(
  spectre_v2=on
  spec_store_bypass_disable=on
  l1d_flush=on
  gather_data_sampling=force
)

if command -v grubby &>/dev/null; then
  if grubby --info=DEFAULT 2>/dev/null | grep -qE 'rhgb|quiet'; then
    if [[ $MODE == apply ]]; then
      grubby --update-kernel=ALL --remove-args="rhgb quiet" && \
        fixed "Removed rhgb/quiet from kernel command line"
    else
      warn "rhgb/quiet present (will be removed with --apply)"
    fi
  else
    ok "rhgb/quiet already absent"
  fi

  current=$(grubby --info=DEFAULT 2>/dev/null || true)
  missing_args=()

  for arg in "${KARGS_CORE[@]}" "${KARGS_EXTRA[@]}"; do
    if grep -Fq -- "$arg" <<<"$current"; then
      ok "Kernel arg present: $arg"
    else
      warn "Missing kernel arg: $arg"
      missing_args+=("$arg")
    fi
  done

  if [[ $MODE == apply && ${#missing_args[@]} -gt 0 ]]; then
    joined_args=$(IFS=' '; echo "${missing_args[*]}")
    if grubby --update-kernel=ALL --args="$joined_args"; then
      fixed "Added missing kernel args: $joined_args"
    else
      fail "Failed to add missing kernel args"
    fi
  fi

  if [[ $MODE == apply ]]; then
    all_current_args=$(grubby --info=DEFAULT 2>/dev/null | grep '^args=' | cut -d= -f2- | tr -d '"' || true)
    if [[ -n "$all_current_args" ]]; then
      echo "$all_current_args" > /etc/kernel/cmdline
      chmod 0600 /etc/kernel/cmdline
      fixed "Updated /etc/kernel/cmdline for kernel-install persistence"
    fi
  fi
else
  warn "grubby not found – skipping kernel argument hardening"
fi

# ===========================================================================
# 2. DISABLE UNNECESSARY SERVICES + INSTALL TOOLS
# ===========================================================================
section '2. Service optimisation and package installation'

if [[ $MODE == apply ]]; then
  if systemctl is-masked --quiet gssproxy.service 2>/dev/null; then
    systemctl unmask gssproxy.service 2>/dev/null || true
    fixed "Unmasked gssproxy service"
  fi
  systemctl mask var-lib-nfs-rpc_pipefs.mount 2>/dev/null || true
  fixed "Masked var-lib-nfs-rpc_pipefs.mount to prevent boot errors"
fi

services_to_mask=(
  wsdd.service wsdd.socket avahi-daemon.service avahi-daemon.socket
  abrtd.service abrt-journal-core.service abrt-oops.service abrt-vmcore.service abrt-xorg.service
  livesys.service livesys-late.service flatpak-add-fedora-repos.service
  cups.service cups.socket cups.path pcscd.service ModemManager.service geoclue.service
  rpcbind.service nfs-client.target nfs-server.service rpc-statd.service rpc-gssd.service rpc-svcgssd.service
  gssproxy.service mcelog.service kdump.service plymouth-start.service plymouth-quit.service plymouth-quit-wait.service
  systemd-coredump.socket systemd-coredump@.service debug-shell.service emergency.service rescue.service
  iscsid.service iscsi.service lvm2-monitor.service dm-event.service mdmonitor.service raid-check.timer
  hypervkvpd.service hypervvssd.service hypervfcopyd.service bluetooth.service postfix.service sendmail.service exim.service dovecot.service
)

for srv in "${services_to_mask[@]}"; do
  if systemctl is-enabled --quiet "$srv" 2>/dev/null || \
     systemctl is-active  --quiet "$srv" 2>/dev/null; then
    if [[ $MODE == apply ]]; then
      systemctl disable --now "$srv" 2>/dev/null || true
      systemctl mask "$srv" 2>/dev/null || true
      fixed "Masked: $srv"
    else
      warn "Active/enabled: $srv"
    fi
  else
    ok "Already disabled/absent: $srv"
  fi
done

if [[ $MODE == apply ]]; then
  info "Installing useful server utilities and packages..."
  dnf install -y \
    curl wget htop mc sysbench mediainfo ffmpeg ImageMagick detox atool \
    zip p7zip p7zip-plugins inxi atop nvme-cli smartmontools \
    certbot python3-certbot-nginx redis \
    2>/dev/null || warn "Some packages could not be installed (non-fatal)."
  fixed "Base packages installed"
fi

# ===========================================================================
# 3. SYSTEMD TIMEOUTS & IPv6 CONFIG
# ===========================================================================
section '3. Systemd Timeouts & Network Disablement Options'

TIMEOUT_CONF="/etc/systemd/system.conf.d/99-timeout.conf"
if [[ -f $TIMEOUT_CONF ]] && grep -q 'DefaultTimeoutStopSec=5s' "$TIMEOUT_CONF"; then
  ok "DefaultTimeoutStopSec=5s already set"
elif [[ $MODE == apply ]]; then
  write_managed "$TIMEOUT_CONF" 0644 <<'EOF'
[Manager]
DefaultTimeoutStopSec=5s
DefaultTimeoutStartSec=15s
EOF
  systemctl daemon-reload
else
  warn "DefaultTimeoutStopSec not hardened"
fi

# ===========================================================================
# 4. SSH HARDENING & ADMIN USER
# ===========================================================================
section '4. SSH hardening and administrative user'

SSH_DIR="/etc/ssh/sshd_config.d"
SSH_HARDEN_FILE="$SSH_DIR/99-server-hardening.conf"

if [[ $MODE == apply ]]; then
  write_managed "$SSH_HARDEN_FILE" 0600 <<EOF
# Managed by server.sh
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 5
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF

  info "SSH public-key setup..."
  read -rp "Paste your public SSH key (leave empty to configure later): " user_ssh_key || true

  read -rp "Create a new sudo user (e.g. admin) [leave empty to skip]: " new_sudo_user || true
  if [[ -n "$new_sudo_user" ]]; then
    if ! id "$new_sudo_user" &>/dev/null; then
      useradd -m -s /bin/bash "$new_sudo_user"
      passwd "$new_sudo_user"
      usermod -aG wheel "$new_sudo_user"
      fixed "User $new_sudo_user created and added to wheel (sudo)."
    fi

    if [[ -n "$user_ssh_key" ]]; then
      user_home=$(eval echo "~$new_sudo_user")
      install -d -o "$new_sudo_user" -g "$new_sudo_user" -m 0700 "$user_home/.ssh"
      auth_keys="$user_home/.ssh/authorized_keys"
      touch "$auth_keys"
      chown "$new_sudo_user:$new_sudo_user" "$auth_keys"
      chmod 0600 "$auth_keys"

      if ! grep -qF "$user_ssh_key" "$auth_keys"; then
        echo "$user_ssh_key" >> "$auth_keys"
        fixed "SSH key added for $new_sudo_user."
      fi
    fi
  fi

  systemctl reload sshd 2>/dev/null || systemctl restart sshd
  fixed "SSH moved to port $SSH_PORT. Root login disabled. Password auth disabled."
  warn "CRITICAL: Open a second terminal and verify SSH connectivity on port $SSH_PORT BEFORE closing this session!"
fi

# ===========================================================================
# 5. FIREWALLD CONFIGURATION
# ===========================================================================
section '5. Firewalld configuration (idempotent rules)'

if command -v firewall-cmd &>/dev/null; then
  if ! systemctl is-active --quiet firewalld; then
    if [[ $MODE == apply ]]; then
      systemctl enable --now firewalld
      fixed "firewalld started and enabled"
    else
      warn "firewalld is not active"
    fi
  else
    ok "firewalld is active"
  fi

  if [[ $MODE == apply ]]; then
    firewall-cmd --permanent --zone=public --set-target=DROP 2>/dev/null || true
    firewall-cmd --permanent --zone=public --remove-service=ssh 2>/dev/null || true
    firewall-cmd --permanent --zone=public --remove-service=mdns 2>/dev/null || true

    firewall-cmd --permanent --zone=public \
      --add-rich-rule="rule family=ipv4 port port=\"${SSH_PORT}\" protocol=tcp accept" 2>/dev/null || true

    for p in 3306 6379 5432 11211 27017; do
      firewall-cmd --permanent --zone=public \
        --add-rich-rule="rule family=ipv4 port port=\"$p\" protocol=tcp drop" 2>/dev/null || true
    done

    if [[ $SETUP_FIREWALL_HTTP == true ]]; then
      firewall-cmd --permanent --zone=public --add-service=http 2>/dev/null || true
      firewall-cmd --permanent --zone=public --add-service=https 2>/dev/null || true
    fi

    for zone in public; do
      firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule='rule family=ipv4 destination address=224.0.0.0/4 drop' 2>/dev/null || true
      firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule='rule family=ipv6 destination address=ff00::/8 drop' 2>/dev/null || true
    done

    firewall-cmd --reload >/dev/null
    fixed "Firewalld rules applied. Publicly reachable: SSH:$SSH_PORT, HTTP, HTTPS only."
  fi
else
  warn "firewall-cmd not installed"
fi

# ===========================================================================
# 6. KERNEL SYSCTL HARDENING & HIGH-LOAD RESILIENCE
# ===========================================================================
section '6. Kernel network / security sysctl parameters'

SYSCTL_FILE="/etc/sysctl.d/99-secure-server.conf"
SYSCTL_CONTENT=$(cat <<'SYSCTL_EOF'
# === Network (anti-recon + anti-spoof + high DDoS resilience) ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv4.tcp_fastopen = 3
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.default.arp_ignore = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

# === Kernel self-protection ===
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
kernel.kexec_load_disabled = 1
kernel.io_uring_disabled = 2
kernel.oops_limit = 100
kernel.warn_limit = 100
kernel.panic = -1
kernel.panic_on_oops = 1
kernel.modules_disabled = 0
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
kernel.randomize_va_space = 2
kernel.core_pattern = |/bin/false
kernel.printk = 3 3 3 3
fs.suid_dumpable = 0
fs.protected_regular = 2
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_symlinks_create = 1
fs.protected_hardlinks_create = 1

# === Server high-load limits & buffers ===
kernel.pid_max = 65536
vm.mmap_min_addr = 65536
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
SYSCTL_EOF
)

if [[ $MODE == apply ]]; then
  write_managed "$SYSCTL_FILE" 0644 <<<"$SYSCTL_CONTENT"
  sysctl --system >/dev/null 2>&1 || true
  fixed "sysctl parameters applied cleanly"
fi

# ===========================================================================
# 7. LEMP INSTALLATION + DYNAMIC RAM ALLOCATION (REDIS & MARIADB)
# ===========================================================================
section '7. LEMP stack, Redis & Dynamic RAM Tuning'

if [[ $INSTALL_LEMP == true && $MODE == apply ]]; then
  info "Installing LEMP packages (nginx, php-fpm, mariadb-server, redis)..."
  dnf install -y \
    nginx \
    php-cli php-fpm php-mysqlnd php-gd php-intl php-mbstring \
    php-xml php-bcmath php-sodium php-pecl-zip php-pecl-apcu php-opcache \
    mariadb-server mariadb redis \
    2>/dev/null || die "LEMP installation failed."

  systemctl enable --now nginx php-fpm mariadb redis
  fixed "LEMP & Redis services started and enabled."
fi

# Compute safe RAM shares (~25% MariaDB InnoDB, ~25% Redis maxmemory)
TOTAL_RAM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))

if (( TOTAL_RAM_MB >= 24000 )); then
  # 32GB server profile
  INNODB_POOL="8G"
  REDIS_MAXMEM="6G"
  MAX_CONNS="500"
elif (( TOTAL_RAM_MB >= 12000 )); then
  # 16GB server profile
  INNODB_POOL="4G"
  REDIS_MAXMEM="3G"
  MAX_CONNS="300"
elif (( TOTAL_RAM_MB >= 6000 )); then
  # 8GB server profile
  INNODB_POOL="2G"
  REDIS_MAXMEM="1500M"
  MAX_CONNS="200"
else
  # 2-4GB low-end server profile
  INNODB_POOL="512M"
  REDIS_MAXMEM="256M"
  MAX_CONNS="100"
fi

info "Detected System RAM: ${TOTAL_RAM_MB}MB. Tuned profiles -> InnoDB Buffer: $INNODB_POOL | Redis MaxMem: $REDIS_MAXMEM"

if [[ $SECURE_MARIADB == true && $MODE == apply ]]; then
  write_managed /etc/my.cnf.d/99-secure-server.cnf 0644 <<EOF
# Managed by server.sh (Optimized for high performance)
[mysqld]
bind-address = 127.0.0.1
skip-networking = 0
socket = /var/lib/mysql/mysql.sock
log_error = /var/log/mariadb/mariadb.log
slow_query_log = 1
slow_query_log_file = /var/log/mariadb/slow.log
long_query_time = 2

max_connections = $MAX_CONNS
max_allowed_packet = 64M
table_open_cache = 4000
innodb_buffer_pool_size = $INNODB_POOL
innodb_log_file_size = 512M
innodb_flush_log_at_trx_commit = 1
innodb_file_per_table = 1

local_infile = 0
symbolic-links = 0

innodb_flush_method = O_DIRECT
innodb_io_capacity = 4000
innodb_io_capacity_max = 4000
innodb_read_io_threads = 8
innodb_write_io_threads = 8
innodb_buffer_pool_instances = 8

thread_handling = pool-of-threads
thread_pool_size = 16
thread_pool_max_threads = 2000
innodb_thread_concurrency = 0

local_infile = 0
skip-name-resolve
max_allowed_packet = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
EOF

  systemctl restart mariadb

  mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
  mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
  mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
  mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true
  mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true

  fixed "MariaDB secured and tuned."
fi

if [[ $INSTALL_LEMP == true && $MODE == apply ]]; then
  write_managed /etc/redis/redis.conf 0644 <<EOF
# Managed by server.sh (High-security & Performance Redis Config)
bind 127.0.0.1 -::1
protected-mode yes
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300
daemonize no
supervised systemd
loglevel notice
databases 16
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command KEYS ""
rename-command DEBUG ""
tcp-backlog 4096
tcp-keepalive 300
io-threads 8
io-threads-do-reads yes
activedefrag yes
active-defrag-threshold-lower 20
active-defrag-threshold-upper 40
maxmemory $REDIS_MAXMEM
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
rdbcompression yes
dbfilename dump.rdb
dir /var/lib/redis
EOF

  systemctl restart redis
  fixed "Redis secured and tuned with maxmemory=$REDIS_MAXMEM."
fi

# ===========================================================================
# 8. ADVANCED NGINX WAF & HARDENING CONFIGURATION
# ===========================================================================
section '8. Nginx Hardening & Custom WAF Rules Integration'

if [[ $HARDEN_NGINX_PHP == true && $MODE == apply ]]; then
  dnf install -y nginx-mod-http-brotli 2>/dev/null || true

  write_managed /etc/nginx/nginx.conf 0644 <<'EOF'
# Managed by server.sh
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 8192;
    multi_accept on;
    use epoll;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" rt=$request_time '
                    'ua="$upstream_addr" us="$upstream_status"';

    access_log /var/log/nginx/access.log main;
    error_log  /var/log/nginx/error.log warn;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 4096;
    server_tokens       off;
    port_in_redirect    off;
    access_log          off;
    disable_symlinks    if_not_owner from=/home/;

    client_body_buffer_size     32k;
    client_header_buffer_size   4k;
    large_client_header_buffers 4 8k;
    client_max_body_size        32M;
    server_names_hash_bucket_size 128;

    client_body_timeout   30s;
    client_header_timeout 30s;
    send_timeout          30s;
    keepalive_requests    500;

    worker_rlimit_nofile 65535;
    worker_shutdown_timeout 30s;

    ssl_buffer_size 4k;

    open_file_cache max=10000 inactive=60s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # Real IP extraction
    set_real_ip_from 127.0.0.1;
    set_real_ip_from ::1;
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    real_ip_recursive on;
    real_ip_header X-Forwarded-For;

    # Brotli Compression
    brotli            on;
    brotli_comp_level 6;
    brotli_static     on;
    brotli_types      text/plain text/css application/json application/javascript
                      text/xml application/xml application/xml+rss text/javascript
                      image/svg+xml application/x-font-ttf font/opentype;
    gzip off;

    # TLS 1.2 & 1.3 hardening
    ssl_protocols             TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache         shared:SSL:10m;
    ssl_session_timeout       1d;
    ssl_session_tickets       off;
    ssl_stapling              on;
    ssl_stapling_verify       on;

    limit_req_zone  $binary_remote_addr zone=req_per_ip:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;

    server {
        listen 80 default_server;
        server_name _;
        return 444;
    }

    # === WAF GEO & MAP BLOCKS ===
    geo $is_bad_ip {
        default         0;
        127.0.0.1       1;
        0.0.0.0         1;
        ::1             1;
        10.0.0.0/8      1;
        172.16.0.0/12   1;
        192.168.0.0/16  1;
        169.254.0.0/16  1;
    }

    geo $is_bad_subnet {
        default 0;
        include /etc/nginx/deny.conf;
    }

    map $uri $is_bad_probe {
        default 0;
        ~*^/.*\.(flv|mpg|mpeg|wmv|avi|asf|rm|ram)$ 1;
        ~*/(?:wp-load|wp-activate|xmlrpc|wp-cron|wp-config|wp-configs)\.php(?:\?.*)?$ 1;
        ~*^/(?:api/v1|v1/courses|engine/classes/min)(?:/|$) 1;
        ~*^/(?:info|phpinfo|pinfo|xmlrpc|info|lite|about|wp|bolt|file|rip|cache|themes|abc|wpb|as|a|i|l|o|q|past|qq|p|w|x|u|adminer|inputs|adminfuns|alpha|alfacgiapi|BDKR28WP|bengi|gettest|x1da|ftde|less|oij98gy|turkshell|php|php8|kikikoko|fine|ass|zample|goods|bless4|fvvff|hplfuns|no18|byrgo|2026w|bthil|sadcut1|w2025|xqq|plss3|sbhu|file48|cabs|chosen|xwx1|class20|file18|file21|class19|simple|alfashell|motu|gssdd|bal|prv8|abcd|makeasmtp|hhxc|wkogn|ws80|fetch|eFpU3yHnriNNLtvdefault|oircv|xltt|4GrJSiwkF3A|hwjtry0zd1fzeakcuzn8Cdefault|cilus|oLEzRVqmJJPFSucdefault|wwdgl|option|num|nine2code|BhqKs28Cw94|3Cr1w6dfjTK|beerd|blnux|2nzyHnOkEg|7logs|maintura|wxeyc|n3yUmQ6Q9xwQ8ocdefault|fyflv|Geforces3FiyJ2WGCnF0p1default|p14rAeWytPdH5hZcscCFdefault|iee52ruz0s81ndrdefault|nvwf4svpvqohxdjtbjCdefault|xxiviLDIot|upll22|5tdwvyWnTbRiMS8f18HXNBbALHKB5t4j|CDX1|gvg1bvpsgtot1rpklCdefault|tx79|wtiiy|Sanskrit|amax|jga|ta0ol|classwithtostring|gecko|xmrlpc|byp403|bypass|byps|atomlib|anonsec|anons79|alfanew|alwso|alfa123|batm|autoload|compat|dropdown|db|docindex|doc|dev|eagle|exploit|evil|fierza|hello|idx|haxor|green|flame|foxx|filemanager|indoxploit|jindex|install|leaf|mail|MARIJUANA|minishellfile2|moon|anon|base|black|config|content|xleet|radio|qindex|readme|send|seo|shx|shl|unknown|upfile|tinyfilemanager|vuln|plugins|wso|about|zone|gelay|mrjn|priv|root|style|symlink|upgrade|flower|lock360|wsanon)(?:\.php.*)?$ 1;
        ~*^/(?:_?phpinfo(?:\.php.*)?|server-info)$ 1;
        ~*^/(?:wp-admin|wp-config|gecko-new|autoload_classmap|gravitysmtp-settings|wp-fmfile|wpsite|old|wp|main|new|test|shop|wp-content|swagger|webjars|v2|v3|debug|wp-includes|console|backup|wordpress|cms|checkout|cart|loader|panel|laravel|administrator|adminstrator|server|yii|zend|vendor|rss|feed|blog|fileupload|tinymce|webroot|editor|filemanager|ckeditor|kcfinder|assets|asset|blog|plugins|cgi-bin)/ 1;
        ~*^/(?:wp-access|wp-conctent|wp-atom|wp-files|wp-mails|wp-trackback|wp-signup|wp-blog|wp-update|wp-login|wpsite)(?:\.php.*)?$ 1;
        ~*^/(?:config|configuration|settings|database|secrets|webresource)(?:\.(?:php|json|ini|yml|yaml|axd).*)?$ 1;
        ~*^/.+/(?:config|configuration|settings|database|secrets|webresource)(?:\.(?:php|json|ini|yml|yaml|axd).*)?$ 1;
        ~*^/\.env(?:[._-].*)?$ 1;
        ~*^/.+/\.(?:env)(?:[._-].*)?$ 1;
        ~*^/\.aws/(?:credentials|config).*$ 1;
        ~*^/\.(?:git|bzr|pgpass|gitconfig|git-credentials|ftpconfig|ssh|cache|dockerignore|boto|amplifyrc|axd)(?:/|$) 1;
        ~*^/(?:storage/logs/laravel\.log|bootstrap/cache/config\.php|bin/login|xwiki/bin|composer\.lock|server\.key)$ 1;
        ~*(isMatchIgnored|toUpperCase|addSublanguage|toLowerCase|XWikiLogin|closeAllNodes|redirect_probe|redirect_base|abn_shadow|mcp_token|xhr_content|iscssurlinjected|telerik|websocket|shark_bite|rest_route|absolute_url_processed|message_markdown_url|use_xbridge3|product_oosn) 1;
    }

    map $http_user_agent $is_bad_ua {
        default 0;
        ""              1;
        "~^.{0,12}$"    1;
        "~^.{450,}$"    1;
        "~*\""          1;
        "~*(bingbot|googlebot|yandexbot|applebot|duckduckbot|coccocbot)" 0;
        "~*(spider_bot|xaldon|wayback_machine|adbeat(_bot|\.com)|commoncrawl|bidtellect|pwaminicanvas|rddocuments|sonic|spotify|atcontent|falcontag|bullettag|openwave|kyvys|thunder|metaiab|jssdk|bytelocale|acvxyjv|voxelum|sessionid|minecraft|cachepos|vxldsihsp|sitecheck|sitecrawl|cherrystudio|opengraph|alamofire|qtwebengine|aippy|v2raytun|liebaofast|undici|deepseek|arenaunfurl|businessname|activedomaincollector|celturbo|imagefetcher|cravingexplorer|oai-search|adint-transparency|manus-user|wap-|check-access|wp-|dnt-policy|pr-cy|3gpp-gba|rwth-aachen|iab-tech|ttd-content|psi-exam|cms-checker|gvfs/|ptst/|boring-searchbot|unity)" 1;
        "~*(ibou(bot|\.io)|comscore|halobot|sirdata|weborama|b11pre|kraken|pubmagadscanner|tineye|jusprogdns|slurp|taboola|jobboerse|voilabot|jyxobot|exabot|zgrab|proximi|sosospider|photon|ultrablock|loilonote|remo|voluumdsp|kozmonavt|domainsbot|academicbotrtu|accoona|aihitbot|genieo|onespot|bytedance|becomebot|cyberokinspect|aliyun|nerdybot|embedly|doesitrunon|subscribe|slbchan|backrub|blowfishi|thresselscanner|cherrypicker|cyberspyder|emailcollector|foobot|geturl|links|vizio|fancyplayer|watchfree|saucenao|notebooklm|letsearch|openbot|snooper|superbot|heritrix|urlspider|mazbot|echoboxbot|serendeputy|zoombot|ffzbot|manictime|infopath|palmsource|libmpv|msie|twitter|foremedia|nimbostratus|bidswitch|statsbot|telegram|cfnetwork|inetdex|openvas|kazbtbot|anytypebot|pocket|githack|sindresorhus|sonyericsson|nokiae|nutch|snapshot|b4pre|slack|cincraw|dalvik|viber|presto|senutobot|imagesift|nokian|windvane|barkrowler|syncsearch|sitemap|nicheiq|geedoproduct|adfitpm|analytics|sffeedreader|generator|riddler|ezlynx|fullstorybot|internetmeasurement|dataxu|shikimori|newsai|metasr|tattoo-ai|dataset|portalmmm|itunes|jigsaw|emailwolf|netfront|everyfeed|censysinspect|smtbot|similartech|teletalk|abevalbot|sucrose|openintel|blexbot|obsidian|seranking|flyriverbot|zoominfobot|yak|freebsd|iaskbot|skype|sleep|nbertaupete95|outclicksbot|jikespider|gigabot|catchbot|chatglm|huaweisymantec|aitcsroboti|bpimagewalker|checkhost|check-host|hanaleibot|bitsightbot|brightbot|securityheaders|nuclei|arachnophilia|livelapbot|linkfluence|tweetmemebot|linkisbot|crowdtanglebot|sitesnagger|teleportpro|webcopier|zerohitman|webreaper|webstripper|priecobot|arquivo|crawler|notion|urllib|yeti|netcraft|startmebot|xenforo|youbot|seekport|pandalytics|feedburner|amazon|diffbot|backupland|dlvr|openbsd|netbsd|code|revoltchat|yisouspider|validator|getintent|snapchat|embarcadero|seopult|textrazor|scholarbot|mojeekbot|slbvpv|micromessenger|wechat|quarkpc|bitrix|contxbot|plurkbot|paperlibot|bomborabot|observer|leikibot|wpsmoffice|urldetails|comcastappplatform|firebolt|ntentbot|headline|clickagy|aspiegelbot|tkbot|checkmarknetwork|ccbot|mauibot|gumgum|thinkchaos|kstandbot|warc|zeno|nmap|signalrgbclient|statdom|admantx|seokicks|dotbot|cliqzbot|nintendo|scrap|builtwith|timpibot|sentibot|vagabondo|piccollage|instagram|netestate|steamchat|csscheck|awariosmart|semantici|eyeotabot)" 1;
        "~*(azureai|nextcloud|fmhymonitor|precisionbot|chatgpt|beanserver|google-apps-script|2ip|bilateralnavigator|imgproxy|kakaotalk|windows 98|windows 95|windows ce|pinterest|shapbot|tiktok|ttspider|bytespider|vkshare|vkrobot|whatsapp|externalagent|foobar2000|shortpixel|checker|ct-wp-scanner|hubseedsbot|seznam|paloaltonetworks|development|queritbot|baidu|multi_src_crapper|turnitin|postmanruntime|reyilbot|perplexitybot|mistral(\.ai|ai)|observation|brightedge|ezoicbot|powershell|symbian|musicbee|hyperhost|xwebdata|livescanner|msoffice|spiderling|surdotly|bgpagent|github|iframely|freeconvert|petalbot|awariobot|fbrv|viettel|fastcrawl|dingtalk|wordpress|surlibot|quantcast|openai|serpstat|classification|trendiction|toutiao|zhanzhang|claude|oracle|alittle)" 1;
        "~*(curl|wget|ddg_win|go-resty|measureboard|commixproject|linkup|blackveil|scanhawk|sppb-rce|webcache|seitenreport|anthropic|qwantbot|gptbot|facebook|semrush|markdownworker|logohub|leakix|l9scan|musical_ly|org_bot|es_bot|uk_lddc|clipto-ai|go-camo|go-http|python|keys-so|ktor-client|http-client|udv-ai|java|user-agent|perl|httpie|axios|node-fetch|okhttp|guzzlehttp|php|wpbot|backdoor|headless|phantomjs|lwp|webdav|davclnt|firephp|fasthttp|restclient|pycurl|ahrefs|mj12bot|mj13bot|megaindex|nghttp2|lychee|libssh|libidn2|openssl|apache|linkdex|libcurl|opensiteexplorer|aiohttp|scannerbot|libwww|httplib|httrack|httpclient|dubkovstudio|webzip|winhttp|linkscan|seobility|contentdonor|dataforseo|hydrus|hybrid|mcpsee)" 1;
        "~*(asset proxy|screaming frog|http client|site audit|audit-scanner|internet explorer|fuzz faster|ls session|download master|offline explorer|local engine|research project|web screen|rome client|snap url|net clr|pale moon)" 1;
        "~*(arena\.ai|bot\.ai|visionheight\.com|bnf\.fr|leak\.info|moz\.com|iprojects\.ru|snap\.com|larus\.wolf|umich\.edu|mmcdn\.com|xmcl\.app|archive\.org|seolik\.ru)" 1;
    }

    map $request_method $is_bad_method {
        default 1;
        GET    0;
        HEAD   0;
        POST   0;
    }

    include /etc/nginx/conf.d/*.conf;
}
EOF

  write_managed /etc/php.d/99-security.ini 0644 <<'EOF'
; Managed by server.sh
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
allow_url_fopen = Off
allow_url_include = Off
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Strict
session.use_strict_mode = 1
session.use_only_cookies = 1
session.sid_length = 48
session.sid_bits_per_character = 6
session.upload_progress.enabled = Off
opcache.memory_consumption = 256
opcache.interned_strings_buffer = 32
opcache.max_accelerated_files = 20000
opcache.validate_timestamps = 0
opcache.revalidate_freq = 0
opcache.jit = 1255
opcache.jit_buffer_size = 64M
EOF
  systemctl reload php-fpm 2>/dev/null || true
  fixed "Global PHP security settings applied."
fi

# ===========================================================================
# 9. FAIL2BAN CONFIGURATION & FILTERS DEPLOYMENT
# ===========================================================================
section '10. Fail2ban configuration & Filter setup'

if [[ $ENABLE_FAIL2BAN == true && $MODE == apply ]]; then
  dnf install -y fail2ban fail2ban-firewalld 2>/dev/null || true

  # Creating fail2ban filter definitions securely
  write_managed /etc/fail2ban/filter.d/nginx-anyrequest.conf 0644 <<'EOF'
[Definition]
failregex = access forbidden by rule, client: <HOST>
ignoreregex =
EOF

  write_managed /etc/fail2ban/filter.d/nginx-ddos.conf 0644 <<'EOF'
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] ".*?" (?:200|301|302|304) \S+ ".*?" ".*?"
ignoreregex = (?i)^<HOST> \S+ \S+ \[.*?\] ".*?" (?:200|301|302|304) \S+ ".*?" ".*?(?:yandexbot|googlebot|bingbot|duckduckbot|coccocbot).*"
EOF

  write_managed /etc/fail2ban/filter.d/nginx-download.conf 0644 <<'EOF'
[Definition]
failregex = ^<HOST> - .*? "(GET|POST|HEAD|OPTIONS|PROPFIND) \S+ HTTP/\d\.\d" (498|499|414|403|429|405) \d+ .*$
ignoreregex = ^<HOST> - .*? "(GET|POST|HEAD) \S+ HTTP/\d\.\d" (498|499|414|403|429|405) \d+ .* "(?:[^"]*(?:Googlebot|coccocbot|bingbot|YandexBot|DuckDuckBot)[^"]*)"
EOF

  write_managed /etc/fail2ban/filter.d/nginx-guard.conf 0644 <<'EOF'
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] ".*?" (?:409) \S+ ".*?" ".*?"
ignoreregex = (?i)^<HOST> \S+ \S+ \[.*?\] ".*?" (?:409) \S+ ".*?" ".*?(?:yandexbot|googlebot|bingbot|coccocbot|duckduckbot).*"
EOF

  write_managed /etc/fail2ban/filter.d/nginx-probe.conf 0644 <<'EOF'
[Definition]
failregex = ^<HOST> - .*? "(GET|POST|HEAD|OPTIONS|PROPFIND) \S+ HTTP/\d\.\d" (444|400) \d+ .*$
ignoreregex = ^<HOST> - .*? "(GET|POST|HEAD|OPTIONS|PROPFIND) \S+ HTTP/\d\.\d" (444|400) \d+ .* "(?:[^"]*(?:Googlebot|coccocbot|bingbot|YandexBot|DuckDuckBot)[^"]*)"
EOF

  write_managed /etc/fail2ban/jail.local 0644 <<EOF
# Managed by server.sh
[DEFAULT]
bantime  = 2h
findtime = 10m
maxretry = 4
banaction = firewallcmd-rich-rules
backend  = systemd

[sshd]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 4h

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10

[nginx-anyrequest]
enabled  = true
port     = http,https
filter   = nginx-anyrequest
logpath  = /home/*/logs/nginx/error.log
backend  = auto
findtime = 20m
maxretry = 100
bantime  = 12h
ignoreip = 127.0.0.1/8 ::1

[nginx-ddos]
enabled  = true
port     = http,https
filter   = nginx-ddos
logpath  = /home/*/logs/nginx/access.log
backend  = auto
findtime = 10m
maxretry = 500
bantime  = 6h
ignoreip = 127.0.0.1/8 ::1

[nginx-download]
enabled  = true
port     = http,https
filter   = nginx-download
logpath  = /home/*/logs/nginx/access.log
backend  = auto
findtime = 10m
maxretry = 300
bantime  = 12h
ignoreip = 127.0.0.1/8 ::1

[nginx-guard]
enabled  = true
port     = http,https
filter   = nginx-guard
logpath  = /home/*/logs/nginx/access.log
backend  = auto
findtime = 10m
maxretry = 100
bantime  = 2h
ignoreip = 127.0.0.1/8 ::1

[nginx-probe]
enabled  = true
port     = http,https
filter   = nginx-probe
logpath  = /var/log/nginx/probe.log
findtime = 10m
maxretry = 5
bantime  = 48h
ignoreip = 127.0.0.1/8 ::1
EOF

  systemctl enable --now fail2ban
  fixed "Fail2ban active with all custom WAF/DDoS filters."
fi

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
section 'Execution summary'

if [[ $MODE == apply ]]; then
  info "Hardening completed successfully."
  info "Backups stored in : $BACKUP_DIR"
  info "Execution log     : $LOG_FILE"
  info ""
  info "IMPORTANT REMINDERS:"
  info "  1. SSH port set to $SSH_PORT. Test connectivity in another window before exit."
  info "  2. Virtual host CLI usage:"
  info "       sudo $0 --vhost-add domain.tld --type php"
  info "       sudo $0 --vhost-del domain.tld"
  info "       sudo $0 --vhost-list"
  info "  3. Database CLI usage:"
  info "       sudo $0 --db-add --db-name appname"
  info "       sudo $0 --db-del --db-name appname"
  info "       sudo $0 --db-list"
  info "  4. Reboot recommended for kernel arguments and module blacklists."
else
  info "Audit finished. No changes were made."
  info "To apply hardening run: sudo $0 --apply"
fi
echo
