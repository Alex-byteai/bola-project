#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════
# API Comparator - Vulnerable vs Secure
# Demuestra la diferencia entre ambas implementaciones
# ═══════════════════════════════════════════════════════════

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_FILE_DEFAULT=".compare-apis.env"
CONFIG_FILE="$CONFIG_FILE_DEFAULT"
DEFAULT_VULN_API="http://localhost:3000"
DEFAULT_SECURE_API="http://localhost:3001"
DEFAULT_EMAIL="alice@example.com"
DEFAULT_PASSWORD="password123"
DEFAULT_TARGET_ORDER_ID=3
DEFAULT_TIMEOUT=12
DEFAULT_RESULTS_DIR="compare_results"
DEFAULT_SLEEP=1.2

VULN_API="${VULN_API:-$DEFAULT_VULN_API}"
SECURE_API="${SECURE_API:-$DEFAULT_SECURE_API}"
EMAIL="${BOLA_EMAIL:-$DEFAULT_EMAIL}"
PASSWORD="${BOLA_PASSWORD:-$DEFAULT_PASSWORD}"
TARGET_ORDER_ID="${TARGET_ORDER_ID:-$DEFAULT_TARGET_ORDER_ID}"
REQUEST_TIMEOUT="${COMPARE_TIMEOUT:-$DEFAULT_TIMEOUT}"
RESULTS_DIR="${COMPARE_RESULTS_DIR:-$DEFAULT_RESULTS_DIR}"
SLEEP_TIME="${COMPARE_SLEEP:-$DEFAULT_SLEEP}"

banner() {
  echo -e "${CYAN}"
  cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║          API COMPARATOR - Vulnerable vs Secure           ║
║          Demonstrating BOLA Protection                   ║
╚══════════════════════════════════════════════════════════╝
EOF
  echo -e "${NC}"
}
usage() {
  cat <<'EOF'
Uso: compare_apis.sh [opciones]

Opciones:
  -v, --vuln <url>          URL base API vulnerable (default http://localhost:3000)
  -s, --secure <url>        URL base API segura (default http://localhost:3001)
  -e, --email <correo>      Email de login (default alice@example.com)
  -p, --password <pass>     Password (default password123)
  -o, --order-id <id>       ID de orden víctima (default 3)
  -t, --timeout <seg>       Timeout curl (default 12)
  -r, --results-dir <dir>   Carpeta para logs (default compare_results)
  --sleep <seg>             Delay entre fases (default 1.2)
  -c, --config <archivo>    Archivo env opcional (.compare-apis.env)
  -h, --help                Mostrar ayuda

Variables: VULN_API, SECURE_API, BOLA_EMAIL, BOLA_PASSWORD,
TARGET_ORDER_ID, COMPARE_TIMEOUT, COMPARE_RESULTS_DIR, COMPARE_SLEEP.
EOF
}

require_bins() {
  for bin in curl jq; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo -e "${RED}[✗] Necesitas instalar '${bin}'.${NC}" >&2
      exit 1
    fi
  done
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    VULN_API="${BOLA_VULN_API:-${VULN_API}}"
    SECURE_API="${BOLA_SECURE_API:-${SECURE_API}}"
    EMAIL="${BOLA_EMAIL:-$EMAIL}"
    PASSWORD="${BOLA_PASSWORD:-$PASSWORD}"
    TARGET_ORDER_ID="${BOLA_TARGET_ORDER_ID:-$TARGET_ORDER_ID}"
    REQUEST_TIMEOUT="${COMPARE_TIMEOUT:-$REQUEST_TIMEOUT}"
    RESULTS_DIR="${COMPARE_RESULTS_DIR:-$RESULTS_DIR}"
    SLEEP_TIME="${COMPARE_SLEEP:-$SLEEP_TIME}"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v|--vuln) VULN_API="$2"; shift 2 ;;
      -s|--secure) SECURE_API="$2"; shift 2 ;;
      -e|--email) EMAIL="$2"; shift 2 ;;
      -p|--password) PASSWORD="$2"; shift 2 ;;
      -o|--order-id) TARGET_ORDER_ID="$2"; shift 2 ;;
      -t|--timeout) REQUEST_TIMEOUT="$2"; shift 2 ;;
      -r|--results-dir) RESULTS_DIR="$2"; shift 2 ;;
      --sleep) SLEEP_TIME="$2"; shift 2 ;;
      -c|--config) CONFIG_FILE="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo -e "${YELLOW}[?] Opción desconocida: $1${NC}" >&2; usage; exit 1 ;;
    esac
  done
}

normalize_base() {
  VULN_API="${VULN_API%/}"
  SECURE_API="${SECURE_API%/}"
}

# Login en API vulnerable
TOKEN_VULN=$(curl -s -X POST "$VULN_API/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
    | jq -r '.token // empty')

if [ -z "$TOKEN_VULN" ]; then
    echo -e "${RED}[✗] Error al autenticar en API vulnerable${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Token API Vulnerable obtenido: ${TOKEN_VULN:0:30}...${NC}"

# Login en API segura (mismo token debería funcionar)
TOKEN_SECURE=$(curl -s -X POST "$SECURE_API/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
    | jq -r '.token // empty')

if [ -z "$TOKEN_SECURE" ]; then
    echo -e "${RED}[✗] Error al autenticar en API segura${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Token API Segura obtenido: ${TOKEN_SECURE:0:30}...${NC}"
echo ""

sleep 1

# ═══════════════════════════════════════════════════════════
# FASE 2: Obtener Órdenes Propias
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}FASE 2: ÓRDENES PROPIAS (Comportamiento Normal)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}[*] Obteniendo órdenes de Alice...${NC}"

# API Vulnerable
ORDERS_VULN=$(curl -s "$VULN_API/api/orders" \
    -H "Authorization: Bearer $TOKEN_VULN")

COUNT_VULN=$(echo "$ORDERS_VULN" | jq -r '.count // 0')
echo -e "${GREEN}[✓] API Vulnerable: $COUNT_VULN órdenes propias${NC}"
echo "$ORDERS_VULN" | jq -r '.orders[] | "    └─ Orden #\(.id): \(.product)"'

# API Segura
ORDERS_SECURE=$(curl -s "$SECURE_API/api/orders" \
    -H "Authorization: Bearer $TOKEN_SECURE")

COUNT_SECURE=$(echo "$ORDERS_SECURE" | jq -r '.count // 0')
echo -e "${GREEN}[✓] API Segura: $COUNT_SECURE órdenes propias${NC}"
echo "$ORDERS_SECURE" | jq -r '.orders[] | "    └─ Orden #\(.id): \(.product)"'

echo ""
sleep 2

# ═══════════════════════════════════════════════════════════
# FASE 3: ATAQUE BOLA - Intentar Acceder a Orden de Bob
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}FASE 3: ATAQUE BOLA - Acceder a Orden #${TARGET_ORDER_ID} (de Bob)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Contador de éxitos
VULN_SUCCESS=0
SECURE_SUCCESS=0

# ─────────────────────────────────────────────────────────
# Atacar API Vulnerable
# ─────────────────────────────────────────────────────────

echo -e "${RED}[!] ATACANDO API VULNERABLE...${NC}"
echo -e "${YELLOW}    Request: GET /api/orders/${TARGET_ORDER_ID}${NC}"

RESPONSE_VULN=$(curl -s -w "\n%{http_code}" "$VULN_API/api/orders/$TARGET_ORDER_ID" \
    -H "Authorization: Bearer $TOKEN_VULN")

HTTP_CODE_VULN=$(echo "$RESPONSE_VULN" | tail -n1)
BODY_VULN=$(echo "$RESPONSE_VULN" | sed '$d')

echo -e "    Status: ${HTTP_CODE_VULN}"

if [ "$HTTP_CODE_VULN" == "200" ]; then
    echo -e "${RED}    [💀] VULNERABILIDAD CONFIRMADA!${NC}"
    echo -e "${RED}    [💀] Se obtuvo acceso a datos de otro usuario${NC}"
    echo ""
    echo -e "${YELLOW}    Datos expuestos:${NC}"
    
    USER_ID=$(echo "$BODY_VULN" | jq -r '.order.userId // "N/A"')
    PRODUCT=$(echo "$BODY_VULN" | jq -r '.order.product // "N/A"')
    AMOUNT=$(echo "$BODY_VULN" | jq -r '.order.amount // "N/A"')
    CARD=$(echo "$BODY_VULN" | jq -r '.order.creditCard // "N/A"')
    ADDRESS=$(echo "$BODY_VULN" | jq -r '.order.address // "N/A"')
    PHONE=$(echo "$BODY_VULN" | jq -r '.order.phone // "N/A"')
    
    echo -e "      └─ Usuario víctima ID: ${RED}${USER_ID}${NC}"
    echo -e "      └─ Producto: ${PRODUCT}"
    echo -e "      └─ Monto: ${AMOUNT}"
    echo -e "      └─ 💳 Tarjeta: ${RED}${CARD}${NC}"
    echo -e "      └─ 📍 Dirección: ${RED}${ADDRESS}${NC}"
    echo -e "      └─ 📞 Teléfono: ${RED}${PHONE}${NC}"
    
    VULN_SUCCESS=1
else
    echo -e "${GREEN}    [✓] Acceso denegado (Inesperado)${NC}"
fi

echo ""
sleep 2

# ─────────────────────────────────────────────────────────
# Atacar API Segura
# ─────────────────────────────────────────────────────────

echo -e "${GREEN}[!] ATACANDO API SEGURA...${NC}"
echo -e "${YELLOW}    Request: GET /api/orders/${TARGET_ORDER_ID}${NC}"

RESPONSE_SECURE=$(curl -s -w "\n%{http_code}" "$SECURE_API/api/orders/$TARGET_ORDER_ID" \
    -H "Authorization: Bearer $TOKEN_SECURE")

HTTP_CODE_SECURE=$(echo "$RESPONSE_SECURE" | tail -n1)
BODY_SECURE=$(echo "$RESPONSE_SECURE" | sed '$d')

echo -e "    Status: ${HTTP_CODE_SECURE}"

if [ "$HTTP_CODE_SECURE" == "403" ] || [ "$HTTP_CODE_SECURE" == "404" ]; then
    echo -e "${GREEN}    [🛡️] ACCESO BLOQUEADO CORRECTAMENTE${NC}"
    ERROR_MSG=$(echo "$BODY_SECURE" | jq -r '.error // "No tienes permiso"')
    echo -e "${GREEN}    [🛡️] Mensaje: ${ERROR_MSG}${NC}"
    SECURE_SUCCESS=1
else
    echo -e "${RED}    [✗] FALLO: La API no bloqueó el acceso (Verificar)${NC}"
fi

echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# FASE 4: Resumen y Conclusiones
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                  RESUMEN DE COMPARACIÓN${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Tabla comparativa
printf "%-30s | %-15s | %-15s\n" "Aspecto" "API Vulnerable" "API Segura"
echo "─────────────────────────────────────────────────────────────────"

if [ $VULN_SUCCESS -eq 1 ]; then
    printf "%-30s | ${RED}%-15s${NC} | ${GREEN}%-15s${NC}\n" "Autenticación" "✓ Funciona" "✓ Funciona"
    printf "%-30s | ${RED}%-15s${NC} | ${GREEN}%-15s${NC}\n" "Órdenes propias" "✓ Acceso OK" "✓ Acceso OK"
    printf "%-30s | ${RED}%-15s${NC} | ${GREEN}%-15s${NC}\n" "BOLA (Orden ajena)" "💀 VULNERABLE" "🛡️ BLOQUEADO"
    printf "%-30s | ${RED}%-15s${NC} | ${GREEN}%-15s${NC}\n" "Datos expuestos" "SÍ (crítico)" "NO"
    printf "%-30s | ${RED}%-15s${NC} | ${GREEN}%-15s${NC}\n" "Nivel de seguridad" "BAJO" "ALTO"
else
    echo -e "${YELLOW}[!] Resultados inesperados. Verificar configuración.${NC}"
fi

echo ""

# Conclusión final
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                       CONCLUSIÓN${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [ $VULN_SUCCESS -eq 1 ] && [ $SECURE_SUCCESS -eq 1 ]; then
    echo -e "${GREEN}✅ DEMOSTRACIÓN EXITOSA${NC}"
    echo ""
    echo "La comparación demuestra claramente:"
    echo ""
    echo -e "  ${RED}⚠️  API Vulnerable:${NC}"
    echo "     • Permite acceso a órdenes de otros usuarios"
    echo "     • Expone información sensible (tarjetas, direcciones)"
    echo "     • No valida ownership de recursos"
    echo ""
    echo -e "  ${GREEN}✅ API Segura:${NC}"
    echo "     • Bloquea acceso no autorizado"
    echo "     • Valida que user_id coincida con el token"
    echo "     • Protege información sensible"
    echo ""
    echo -e "${YELLOW}Diferencia clave en el código:${NC}"
    echo ""
    echo -e "${RED}  Vulnerable:${NC}"
    echo "    SELECT * FROM orders WHERE id = ?"
    echo ""
    echo -e "${GREEN}  Segura:${NC}"
    echo "    SELECT * FROM orders WHERE id = ? AND user_id = ?"
    echo ""
    
    exit 0
else
    echo -e "${YELLOW}⚠️  Verificar la configuración de las APIs${NC}"
    exit 1
fi
