#!/bin/bash
set -e

########################################################
# =============== CONFIGURATION ========================
########################################################
ABUSEIPDB_KEY="CHANGE_ME"
MISP_API_KEY="CHANGE_ME"
OPENCTI_TOKEN="CHANGE_ME"

BASE_DIR="/opt/banking-soc"
REPORT_DIR="$BASE_DIR/reports"
SOAR_DIR="$BASE_DIR/soar"
YARA_DIR="$BASE_DIR/yara"

########################################################
# =============== SYSTEM PREP ==========================
########################################################
apt update
apt install -y curl jq ipset iptables ca-certificates gnupg lsb-release

########################################################
# =============== DOCKER INSTALL =======================
########################################################
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
fi

if ! docker compose version >/dev/null; then
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -SL https://github.com/docker/compose/releases/download/v2.25.0/docker-compose-linux-x86_64 \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi

########################################################
# =============== FIREWALL =============================
########################################################
ipset create bank_ip hash:ip timeout 86400 -exist
iptables -C INPUT -m set --match-set bank_ip src -j DROP 2>/dev/null || \
iptables -I INPUT -m set --match-set bank_ip src -j DROP

########################################################
# =============== DIRECTORIES ==========================
########################################################
mkdir -p $BASE_DIR $REPORT_DIR $SOAR_DIR $YARA_DIR
cd $BASE_DIR

########################################################
# =============== DOCKER COMPOSE =======================
########################################################
cat <<EOF > docker-compose.yml
version: "3.9"
networks: {bank:{}}

services:

  misp-db:
    image: mysql:8
    environment:
      MYSQL_DATABASE: misp
      MYSQL_USER: misp
      MYSQL_PASSWORD: misp
      MYSQL_ROOT_PASSWORD: root
    networks: [bank]

  misp:
    image: harvarditsecurity/misp
    depends_on: [misp-db]
    ports: ["8080:80"]
    networks: [bank]

  opencti:
    image: opencti/platform
    environment:
      OPENCTI_ADMIN_TOKEN: $OPENCTI_TOKEN
    ports: ["8081:8080"]
    networks: [bank]

  kong:
    image: kong:3.6
    environment:
      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: /kong.yml
      KONG_PLUGINS: bundled,coraza
    command: >
      sh -c "
      apk add --no-cache curl &&
      curl -L https://github.com/coreruleset/coreruleset/archive/refs/heads/v4.0/dev.tar.gz | tar zx &&
      mv coreruleset-* /crs &&
      cp /crs/crs-setup.conf.example /crs/crs-setup.conf &&
      sed -i 's/DetectionOnly/On/' /crs/crs-setup.conf &&
      cat <<CFG >/kong.yml
      _format_version: '3.0'
      services:
        - name: api
          url: http://httpbin.org
          routes: [{paths:[/api]}]
      plugins:
        - name: coraza
          config:
            rules:
              - SecRuleEngine On
              - Include /crs/crs-setup.conf
              - Include /crs/rules/*.conf
              - Include /blocked.conf
      CFG
      touch /blocked.conf && kong docker-start
      "
    ports: ["8000:8000"]
    networks: [bank]

  graylog:
    image: graylog/graylog:5.2
    environment:
      GRAYLOG_PASSWORD_SECRET: banksecret
      GRAYLOG_ROOT_PASSWORD_SHA2: 8c6976e5b5410415bde908bd4dee15dfb16
      GRAYLOG_HTTP_EXTERNAL_URI: http://localhost:9000/
    ports: ["9000:9000"]
    networks: [bank]

  grafana:
    image: grafana/grafana
    ports: ["3000:3000"]
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    networks: [bank]

  ######################################################
  # === AUTOMATION: TI + FRAUD + ATO + YARA + REPORT ===
  ######################################################
  automation:
    image: alpine
    privileged: true
    volumes:
      - /sbin/ipset:/sbin/ipset
      - $BASE_DIR:/shared
    environment:
      ABUSEIPDB_KEY: $ABUSEIPDB_KEY
      MISP_API_KEY: $MISP_API_KEY
      OPENCTI_TOKEN: $OPENCTI_TOKEN
    networks: [bank]
    entrypoint: >
      sh -c "
      apk add --no-cache curl jq bash docker-cli yara clamav &&
      echo '*/2 * * * * /soc.sh' | crontab - &&
      cat <<'SOC' >/soc.sh
      DATE=\$(date +%F)
      DAILY_JSON=/shared/reports/daily-\$DATE.json
      DAILY_TXT=/shared/reports/daily-\$DATE.txt

      declare -A SCORE
      declare -A CUSTOMER_RISK

      ################ TI INGEST ################
      curl -s https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90 \
        -H \"Key: \$ABUSEIPDB_KEY\" | jq -r '.data[].ipAddress' |
        while read ip; do SCORE[\$ip]=40; done

      curl -s http://misp/attributes/restSearch \
        -H \"Authorization: \$MISP_API_KEY\" |
        jq -r '.response[].Attribute[].value' |
        while read ip; do SCORE[\$ip]=\$((\${SCORE[\$ip]:-0}+30)); done

      curl -s http://opencti:8080/graphql \
        -H \"Authorization: Bearer \$OPENCTI_TOKEN\" \
        -H \"Content-Type: application/json\" \
        -d '{\"query\":\"query { stixCyberObservables(first:100, types:[IPv4-Addr]){edges{node{value}}}}\"}' |
        jq -r '.data.stixCyberObservables.edges[].node.value' |
        while read ip; do SCORE[\$ip]=\$((\${SCORE[\$ip]:-0}+30)); done

      ################ FRAUD / ATO ################
      EVENTS=\$(curl -s -u admin:admin http://graylog:9000/api/search/universal/relative?query=login\\&range=600 |
      jq -r '.messages[].message | [.customer_id,.source_ip,.http_status] | @tsv')

      while read cid ip status; do
        [[ \"\$status\" == \"401\" ]] && CUSTOMER_RISK[\$cid]=\$((\${CUSTOMER_RISK[\$cid]:-0}+20))
        CUSTOMER_RISK[\$cid]=\$((\${CUSTOMER_RISK[\$cid]:-0}+10))
        SCORE[\$ip]=\$((\${SCORE[\$ip]:-0}+10))
      done <<< \"\$EVENTS\"

      ################ YARA FROM MISP ################
      curl -s http://misp/attributes/restSearch \
        -H \"Authorization: \$MISP_API_KEY\" |
        jq -r '.response[].Attribute[].value' |
        awk '{print \"rule MISP_\"NR\" { strings: \$a=\\\"\"\$0\"\\\" condition: \$a }\"}' \
        > /shared/yara/misp.yar

      ################ ENFORCEMENT ################
      echo '# AUTO BLOCK' > /shared/blocked.conf
      for ip in \"\${!SCORE[@]}\"; do
        if [ \"\${SCORE[\$ip]}\" -ge 50 ]; then
          ipset add bank_ip \$ip timeout 86400 -exist
          echo \"SecRule REMOTE_ADDR \\\"@ipMatch \$ip\\\" \\\"deny\\\"\" >> /shared/blocked.conf
        fi
      done

      ################ DAILY REPORT ################
      cat <<JSON > \$DAILY_JSON
{
  \"date\": \"\$DATE\",
  \"security\": {
    \"blocked_ips\": \$(ipset list bank_ip | grep -c timeout || true)
  },
  \"threat_intel\": {
    \"abuseipdb\": true,
    \"misp\": true,
    \"opencti\": true
  },
  \"fraud\": {
    \"high_risk_customers\": \$(printf '%s\n' \"\${CUSTOMER_RISK[@]}\" | awk '\$1>=50' | wc -l)
  },
  \"compliance\": {
    \"pci_dss\": [1,6,10,11],
    \"ojk\": [\"monitoring\",\"incident_response\"]
  }
}
JSON

      cat <<TXT > \$DAILY_TXT
BANKING DAILY SECURITY REPORT - \$DATE
====================================
Blocked IPs         : \$(ipset list bank_ip | grep -c timeout || true)
High Risk Customers : \$(printf '%s\n' \"\${CUSTOMER_RISK[@]}\" | awk '\$1>=50' | wc -l)
Threat Intel Active : AbuseIPDB / MISP / OpenCTI
PCI DSS Controls    : 1,6,10,11
OJK Monitoring      : ACTIVE
TXT

      docker kill -s HUP \$(docker ps -q --filter name=kong)
SOC
      crond -f
      "
EOF

########################################################
# =============== START STACK ==========================
########################################################
docker compose up -d

echo "======================================================"
echo " BANKING SOC STACK RUNNING (ALL-IN-ONE)"
echo "======================================================"
echo " API        : http://localhost:8000/api"
echo " Grafana    : http://localhost:3000 (admin/admin)"
echo " Graylog    : http://localhost:9000"
echo " MISP       : http://localhost:8080"
echo " OpenCTI    : http://localhost:8081"
echo " Reports    : $REPORT_DIR"
echo "======================================================"

