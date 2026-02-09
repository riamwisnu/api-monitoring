#!/bin/bash
set -euo pipefail

############################################
# GLOBAL CONFIG
############################################
BASE="/opt/banking-soc"
COMPOSE="$BASE/docker-compose.yml"
mkdir -p "$BASE"/{grafana,dashboards,logs}

############################################
# FIREWALL (SILENT, TI READY)
############################################
ipset create bank_ip hash:ip timeout 86400 -exist >/dev/null 2>&1
iptables -C INPUT -m set --match-set bank_ip src -j DROP >/dev/null 2>&1 || \
iptables -I INPUT -m set --match-set bank_ip src -j DROP >/dev/null 2>&1

############################################
# DOCKER INSTALL (SAFE)
############################################
if ! command -v docker >/dev/null; then
  apt-get update -y >/dev/null
  apt-get install -y ca-certificates curl gnupg lsb-release >/dev/null
  curl -fsSL https://get.docker.com | sh >/dev/null
fi

############################################
# EXECUTIVE DASHBOARD (AUTO)
############################################
cat <<'JSON' > "$BASE/dashboards/executive-risk.json"
{
  "title": "Executive Risk Dashboard",
  "timezone": "browser",
  "schemaVersion": 38,
  "version": 1,
  "panels": [
    {
      "type": "stat",
      "title": "Blocked IPs",
      "targets": [{ "query": "BLOCK" }],
      "gridPos": { "x": 0, "y": 0, "w": 6, "h": 4 }
    },
    {
      "type": "stat",
      "title": "WAF Blocks",
      "targets": [{ "query": "coraza" }],
      "gridPos": { "x": 6, "y": 0, "w": 6, "h": 4 }
    },
    {
      "type": "stat",
      "title": "Threat Intel Hits",
      "targets": [{ "query": "misp OR opencti" }],
      "gridPos": { "x": 0, "y": 4, "w": 6, "h": 4 }
    },
    {
      "type": "stat",
      "title": "High Risk Accounts",
      "targets": [{ "query": "risk:HIGH OR risk:CRITICAL" }],
      "gridPos": { "x": 6, "y": 4, "w": 6, "h": 4 }
    }
  ]
}
JSON

############################################
# DOCKER COMPOSE (FINAL VALID)
############################################
cat <<'EOF' > "$COMPOSE"
version: "3.9"

networks:
  soc-net: {}

volumes:
  kong_data:
  graylog_data:
  grafana_data:

services:

  kong:
    image: kong:3.6
    networks: [soc-net]
    ports: ["8000:8000","8001:8001"]
    environment:
      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: /kong/kong.yml
      KONG_PLUGINS: bundled,coraza
    volumes:
      - kong_data:/kong
    command: >
      sh -c "
      apk add --no-cache git &&
      git clone https://github.com/coreruleset/coreruleset /crs &&
      printf '%s\n' \
      '_format_version: \"3.0\"' \
      'services:' \
      '  - name: api' \
      '    url: http://httpbin.org' \
      '    routes:' \
      '      - paths:' \
      '          - /api' \
      'plugins:' \
      '  - name: coraza' \
      '    config:' \
      '      rules:' \
      '        - SecRuleEngine On' \
      '        - Include /crs/crs-setup.conf.example' \
      '        - Include /crs/rules/*.conf' \
      > /kong/kong.yml
      && kong docker-start
      "

  graylog:
    image: graylog/graylog:5.2
    networks: [soc-net]
    environment:
      GRAYLOG_PASSWORD_SECRET: secret
      GRAYLOG_ROOT_PASSWORD_SHA2: 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918
      GRAYLOG_HTTP_EXTERNAL_URI: http://127.0.0.1:9000/
    volumes:
      - graylog_data:/usr/share/graylog/data
    ports: ["9000:9000","12201:12201/udp"]

  grafana:
    image: grafana/grafana
    networks: [soc-net]
    volumes:
      - grafana_data:/var/lib/grafana
      - ./dashboards:/var/lib/grafana/dashboards
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH: /var/lib/grafana/dashboards/executive-risk.json
    ports: ["3000:3000"]

  auto-blocker:
    image: alpine
    privileged: true
    networks: [soc-net]
    volumes:
      - /sbin/ipset:/sbin/ipset
    command: >
      sh -c "
      apk add --no-cache curl jq &&
      while true; do
        curl -s -u admin:admin http://graylog:9000/api/search/universal/relative?query=coraza\\&range=300 |
        jq -r '.messages[].message.source_ip' |
        sort -u |
        while read ip; do
          ipset add bank_ip \$ip timeout 86400 -exist >/dev/null 2>&1
        done
        sleep 60
      done
      "
EOF

############################################
# VALIDATION
############################################
cd "$BASE"
docker compose config >/dev/null || { echo "[FATAL] YAML INVALID"; exit 1; }

############################################
# START
############################################
docker compose up -d

echo "=========================================="
echo " BANKING SOC STACK ACTIVE"
echo "=========================================="
echo " API        : http://localhost:8000/api"
echo " Grafana    : http://localhost:3000"
echo " Graylog    : http://localhost:9000"
echo " WAF        : Coraza + OWASP CRS ENABLED"
echo " Auto-Block : Graylog → IPSET ACTIVE"
echo "=========================================="
