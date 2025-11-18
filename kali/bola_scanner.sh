#!/usr/bin/env bash

set -uo pipefail

# ═══════════════════════════════════════════════════════════
# BOLA Scanner - Automatic Object Level Authorization Tester
# Adaptado al proyecto BOLA-VULNERABILITY (APIs segura/vulnerable)
# - Auto login (JWT) con credenciales del seed
# - Descubrimiento dinámico de IDs y endpoints
# - Resultados enriquecidos (texto + JSON) sin hardcodear valores
# ═══════════════════════════════════════════════════════════

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

CONFIG_FILE_DEFAULT=".bola-scanner.env"
CONFIG_FILE="$CONFIG_FILE_DEFAULT"
DEFAULT_TARGET="http://localhost:3000"          # app_vulnerable por defecto
DEFAULT_RESOURCE="orders"
DEFAULT_LOGIN_PATH="/api/auth/login"
DEFAULT_LIST_PATH="/api/orders"
DEFAULT_ITEM_PATH="/api/orders"
DEFAULT_SCAN_PADDING=15
DEFAULT_MISS_THRESHOLD=8
DEFAULT_RESULTS_DIR="scan-results"
DEFAULT_SLEEP="0.08"

TARGET="${BOLA_TARGET:-$DEFAULT_TARGET}"
EMAIL="${BOLA_EMAIL:-}"
PASSWORD="${BOLA_PASSWORD:-}"
TOKEN="${BOLA_TOKEN:-}"
RESOURCE="${BOLA_RESOURCE:-$DEFAULT_RESOURCE}"
MAX_ID="${BOLA_MAX_ID:-0}"
SCAN_PADDING="${BOLA_SCAN_PADDING:-$DEFAULT_SCAN_PADDING}"
MISS_THRESHOLD="${BOLA_MISS_THRESHOLD:-$DEFAULT_MISS_THRESHOLD}"
RESULTS_DIR="${BOLA_RESULTS_DIR:-$DEFAULT_RESULTS_DIR}"
SLEEP_TIME="${BOLA_SLEEP:-$DEFAULT_SLEEP}"
LOGIN_PATH="${BOLA_LOGIN_PATH:-$DEFAULT_LOGIN_PATH}"
LIST_PATH="${BOLA_LIST_PATH:-}" # se construye tras parsear args
ITEM_PATH="${BOLA_ITEM_PATH:-}"
METHODS="${BOLA_METHODS:-GET}"

print_banner() {
  echo -e "${RED}"
  echo "╔═══════════════════════════════════════════════════════════╗"
  echo "║           BOLA SCANNER - Automated Testing                ║"
  echo "║        Broken Object Level Authorization Detector         ║"
  echo "╚═══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

usage() {
  cat <<'EOF'
Uso: bola_scanner.sh [opciones]

Opciones principales:
  -t, --target <url>        Base URL (http://localhost:3000 para vulnerable, 3001 segura)
  -e, --email <email>       Email para login (por defecto alice@example.com)
  -p, --password <pass>     Password para login
  -k, --token <jwt>         Token JWT existente (omite login)
  -r, --resource <nombre>   Recurso a evaluar (orders, users, etc.)
  -m, --max-id <n>          Límite superior de IDs a escanear (auto si se omite)
  --methods <lista>         Métodos a probar (por ahora solo GET soportado, default GET)
  --login-path <ruta>       Ruta de login (default /api/auth/login)
  --list-path <ruta>        Ruta para listar recursos propios (default /api/<resource>)
  --item-path <ruta>        Ruta base para acceder a un ID (default /api/<resource>)
  -c, --config <archivo>    Archivo .env opcional (default .bola-scanner.env)
  -h, --help                Mostrar ayuda

Variables soportadas en .bola-scanner.env:
  BOLA_TARGET, BOLA_EMAIL, BOLA_PASSWORD, BOLA_RESOURCE, BOLA_MAX_ID,
  BOLA_SCAN_PADDING, BOLA_MISS_THRESHOLD, BOLA_RESULTS_DIR, BOLA_METHODS

Dependencias: curl, jq
EOF
}

require_binaries() {
  for bin in curl jq; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo -e "${RED}[!] Necesitas instalar '$bin' para usar el scanner.${NC}" >&2
      exit 1
    fi
  done
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    TARGET="${BOLA_TARGET:-$TARGET}"
    EMAIL="${BOLA_EMAIL:-$EMAIL}"
    PASSWORD="${BOLA_PASSWORD:-$PASSWORD}"
    TOKEN="${BOLA_TOKEN:-$TOKEN}"
    RESOURCE="${BOLA_RESOURCE:-$RESOURCE}"
    MAX_ID="${BOLA_MAX_ID:-$MAX_ID}"
    SCAN_PADDING="${BOLA_SCAN_PADDING:-$SCAN_PADDING}"
    MISS_THRESHOLD="${BOLA_MISS_THRESHOLD:-$MISS_THRESHOLD}"
    RESULTS_DIR="${BOLA_RESULTS_DIR:-$RESULTS_DIR}"
    METHODS="${BOLA_METHODS:-$METHODS}"
    LOGIN_PATH="${BOLA_LOGIN_PATH:-$LOGIN_PATH}"
    LIST_PATH="${BOLA_LIST_PATH:-$LIST_PATH}"
    ITEM_PATH="${BOLA_ITEM_PATH:-$ITEM_PATH}"
    SLEEP_TIME="${BOLA_SLEEP:-$SLEEP_TIME}"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target)
        TARGET="$2"; shift 2 ;;
      -e|--email)
        EMAIL="$2"; shift 2 ;;
      -p|--password)
        PASSWORD="$2"; shift 2 ;;
      -k|--token)
        TOKEN="$2"; shift 2 ;;
      -r|--resource)
        RESOURCE="$2"; shift 2 ;;
      -m|--max-id)
        MAX_ID="$2"; shift 2 ;;
      --methods)
        METHODS="$2"; shift 2 ;;
      --login-path)
        LOGIN_PATH="$2"; shift 2 ;;
      --list-path)
        LIST_PATH="$2"; shift 2 ;;
      --item-path)
        ITEM_PATH="$2"; shift 2 ;;
      -c|--config)
        CONFIG_FILE="$2"; shift 2 ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        echo -e "${YELLOW}[?] Opción desconocida: $1${NC}" >&2
        usage
        exit 1 ;;
    esac
  done
}

normalize_paths() {
  TARGET="${TARGET%/}"
  local lower_resource
  lower_resource="${RESOURCE#/}"
  lower_resource="${lower_resource%/}"
  RESOURCE="$lower_resource"
  LIST_PATH="${LIST_PATH:-/api/${RESOURCE}}"
  ITEM_PATH="${ITEM_PATH:-/api/${RESOURCE}}"
}

login_if_needed() {
  if [[ -n "$TOKEN" ]]; then
    return
  fi

  local login_email="${EMAIL:-alice@example.com}"
  local login_password="${PASSWORD:-password123}"

  if [[ -z "$login_email" || -z "$login_password" ]]; then
    echo -e "${RED}[!] Se requiere token o credenciales (email/password).${NC}" >&2
    exit 1
  fi

  local payload
  payload=$(jq -n --arg email "$login_email" --arg password "$login_password" '{email: $email, password: $password}')
  local response
  response=$(curl -sS -X POST -H 'Content-Type: application/json' -d "$payload" "${TARGET}${LOGIN_PATH}" -w '\n%{http_code}' || true)
  local code
  code=$(echo "$response" | tail -n1)
  local body
  body=$(echo "$response" | sed '$d')

  if [[ "$code" != "200" ]]; then
    echo -e "${RED}[!] Login falló (${code}). Respuesta:${NC} $body" >&2
    exit 1
  fi

  TOKEN=$(echo "$body" | jq -r '.token // empty')
  if [[ -z "$TOKEN" ]]; then
    echo -e "${RED}[!] No se pudo extraer el token del login.${NC}" >&2
    exit 1
  fi
}

request_with_code() {
  local method="$1" url="$2" data="${3:-}"
  shift 3 || true
  local curl_args=(-sS -X "$method" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
  if [[ -n "$data" ]]; then
    curl_args+=(-d "$data")
  fi
  curl_args+=("$url" -w '\n%{http_code}')
  curl "${curl_args[@]}" 2>/dev/null || printf '\n000'
}

KNOWN_MAX_ID=0
SCAN_LIMIT=0

discover_scan_limit() {
  if [[ "$MAX_ID" =~ ^[0-9]+$ && "$MAX_ID" -gt 0 ]]; then
    SCAN_LIMIT="$MAX_ID"
    KNOWN_MAX_ID="$MAX_ID"
    return
  fi

  local list_response
  list_response=$(request_with_code GET "${TARGET}${LIST_PATH}")
  local code body
  code=$(echo "$list_response" | tail -n1)
  body=$(echo "$list_response" | sed '$d')

  if [[ "$code" == "200" ]]; then
    KNOWN_MAX_ID=$(echo "$body" | jq '[.orders[]?.id] | max // 0' 2>/dev/null)
    if [[ -z "$KNOWN_MAX_ID" || "$KNOWN_MAX_ID" == "null" ]]; then
      KNOWN_MAX_ID=0
    fi
  else
    echo -e "${YELLOW}[~] No se pudo obtener listado propio (${code}). Se usará padding ${SCAN_PADDING}.${NC}"
    KNOWN_MAX_ID=0
  fi

  if [[ "$KNOWN_MAX_ID" -eq 0 ]]; then
    SCAN_LIMIT=$SCAN_PADDING
  else
    SCAN_LIMIT=$((KNOWN_MAX_ID + SCAN_PADDING))
  fi
}

RESULTS_FILE=""
RESULTS_JSON=""

prepare_output() {
  mkdir -p "$RESULTS_DIR"
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)
  RESULTS_FILE="${RESULTS_DIR}/bola_scan_${timestamp}.log"
  RESULTS_JSON="${RESULTS_DIR}/bola_scan_${timestamp}.jsonl"
  {
    echo "BOLA Scan Results - $(date)"
    echo "Target: ${TARGET}"
    echo "Resource: ${RESOURCE}"
    echo "Methods: ${METHODS}"
    echo "=================================="
  } > "$RESULTS_FILE"
  : > "$RESULTS_JSON"
}

append_result() {
  local status="$1" id="$2" message="$3" payload="$4"
  printf '%s | %-11s | ID %s | %s\n' "$(date '+%H:%M:%S')" "$status" "$id" "$message" >> "$RESULTS_FILE"
  if [[ -n "$payload" ]]; then
    printf '    %s\n' "$payload" >> "$RESULTS_FILE"
  fi
  jq -n --arg status "$status" --arg id "$id" --arg message "$message" --argjson meta "$payload" '{timestamp: now, status: $status, id: ($id|tonumber), message: $message, meta: (try $meta catch $meta)}' >> "$RESULTS_JSON" 2>/dev/null || true
}

scan_id_get() {
  local id="$1"
  local response code body
  response=$(request_with_code GET "${TARGET}${ITEM_PATH}/${id}")
  code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | sed '$d')
  [[ -z "$body" ]] && body='{}'

  case "$code" in
    200)
      local should_block blocked enforcement note attacker victim
      should_block=$(echo "$body" | jq -r '.should_block // .shouldBlock // false' 2>/dev/null)
      blocked=$(echo "$body" | jq -r '.blocked // false' 2>/dev/null)
      enforcement=$(echo "$body" | jq -r '.enforcement // empty' 2>/dev/null)
      note=$(echo "$body" | jq -r '.security_note // empty' 2>/dev/null)
      attacker=$(echo "$body" | jq -c '{userId: .order.userId // .userId, attacker: .attacker}' 2>/dev/null)
      if { [[ "$should_block" == "true" && "$blocked" == "false" ]] || [[ "$enforcement" == "not_blocked" ]]; } || [[ "$note" == *"VULNERABLE"* ]]; then
        echo -e "${RED}[🚨] ID $id: VULNERABLE (lectura de orden ajena)${NC}"
        append_result "VULNERABLE" "$id" "HTTP 200 sin bloqueo" "$body"
        return 0
      fi
      echo -e "${GREEN}[✓] ID $id: Acceso autorizado (orden propia)${NC}"
      append_result "OWNED" "$id" "HTTP 200 propietario" "$attacker"
      return 0
      ;;
    403)
      echo -e "${GREEN}[✓] ID $id: Bloqueado correctamente (403)${NC}"
      append_result "PROTECTED" "$id" "HTTP 403" "$body"
      return 0
      ;;
    401)
      echo -e "${RED}[!] Token inválido o expirado (401). Abortando.${NC}"
      append_result "ERROR" "$id" "401 unauthorized" "$body"
      exit 1
      ;;
    404)
      echo -e "${YELLOW}[~] ID $id: No encontrado (404)${NC}"
      append_result "NOT_FOUND" "$id" "HTTP 404" "$body"
      return 4
      ;;
    0|000)
      echo -e "${YELLOW}[?] ID $id: Error de red (sin respuesta)${NC}"
      append_result "ERROR" "$id" "Sin respuesta" "$body"
      return 5
      ;;
    *)
      echo -e "${YELLOW}[?] ID $id: Error HTTP ${code}${NC}"
      append_result "ERROR" "$id" "HTTP ${code}" "$body"
      return 6
      ;;
  esac
}

run_scan() {
  local methods_csv="$METHODS"
  IFS=',' read -r -a method_list <<< "$methods_csv"
  local id consecutive_404=0
  local vuln=0 protected=0 notfound=0 errors=0 own=0

  for ((id=1; id<=SCAN_LIMIT; id++)); do
    for method in "${method_list[@]}"; do
      case "${method^^}" in
        GET)
          if scan_id_get "$id"; then
            local last_status
            last_status=$(tail -n1 "$RESULTS_FILE")
            if [[ "$last_status" == *"VULNERABLE"* ]]; then
              ((vuln++))
            elif [[ "$last_status" == *"OWNED"* ]]; then
              ((own++))
            elif [[ "$last_status" == *"PROTECTED"* ]]; then
              ((protected++))
            fi
            consecutive_404=0
          else
            local exit_code=$?
            if [[ $exit_code -eq 4 ]]; then
              ((notfound++))
              if (( id > KNOWN_MAX_ID )) && (( ++consecutive_404 >= MISS_THRESHOLD )); then
                echo -e "${BLUE}[*] Se alcanzó el umbral de ${MISS_THRESHOLD} 404 consecutivos. Fin del escaneo.${NC}"
                summarize "$id" "$vuln" "$protected" "$notfound" "$errors" "$own"
                return
              fi
            else
              ((errors++))
            fi
          fi
          ;;
        *)
          echo -e "${YELLOW}[~] Método ${method} aún no implementado. Se ignora.${NC}"
          ;;
      esac
    done
    sleep "$SLEEP_TIME"
  done

  summarize "$SCAN_LIMIT" "$vuln" "$protected" "$notfound" "$errors" "$own"
}

summarize() {
  local total="$1" vuln="$2" protected="$3" notfound="$4" errors="$5" own="$6"
  echo "" >> "$RESULTS_FILE"
  {
    echo "=================================="
    echo "RESUMEN:"
    echo "Total evaluado: $total"
    echo "Vulnerables:    $vuln"
    echo "Protegidos:     $protected"
    echo "Propios:        $own"
    echo "No encontrados: $notfound"
    echo "Errores:        $errors"
  } >> "$RESULTS_FILE"

  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${BLUE}                    RESUMEN DEL ESCANEO${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
  echo "Total evaluado:  ${BLUE}${total}${NC}"
  echo -e "🚨 Vulnerables:   ${RED}${vuln}${NC}"
  echo -e "✅ Protegidos:    ${GREEN}${protected}${NC}"
  echo -e "👤 Propios:       ${GREEN}${own}${NC}"
  echo -e "⚠️  No encontrados: ${YELLOW}${notfound}${NC}"
  echo -e "❌ Errores:       ${YELLOW}${errors}${NC}"
  echo "Resultados guardados en: ${RESULTS_FILE} (texto) y ${RESULTS_JSON} (JSONL)"

  if (( vuln > 0 )); then
    exit 1
  fi

  exit 0
}

main() {
  require_binaries
  parse_args "$@"
  load_config
  normalize_paths
  print_banner
  login_if_needed
  discover_scan_limit
  prepare_output

  echo -e "${BLUE}[*] Target: ${TARGET}${NC}"
  if [[ -n "$EMAIL" ]]; then
    echo -e "${BLUE}[*] Usuario: ${EMAIL:-alice@example.com}${NC}"
  fi
  echo -e "${BLUE}[*] Token: ${TOKEN:0:20}...${NC}"
  echo -e "${BLUE}[*] Recurso: /api/${RESOURCE} | Rango dinámico hasta ID ${SCAN_LIMIT}${NC}"
  echo -e "${YELLOW}[*] Escaneo iniciado...${NC}"

  run_scan
}

main "$@"
