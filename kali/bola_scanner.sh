#!/bin/bash

# ═══════════════════════════════════════════════════════════
# BOLA Scanner - Automatic Object Level Authorization Tester
# Detecta endpoints vulnerables a BOLA
# ═══════════════════════════════════════════════════════════

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           BOLA SCANNER - Automated Testing                ║"
echo "║        Broken Object Level Authorization Detector         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar argumentos
if [ $# -lt 2 ]; then
    echo -e "${YELLOW}Uso: $0 <TARGET_URL> <JWT_TOKEN> [MAX_ID]${NC}"
    echo ""
    echo "Ejemplos:"
    echo "  $0 http://192.168.1.50:3000 eyJhbGc..."
    echo "  $0 http://192.168.1.50:3000 eyJhbGc... 50"
    echo ""
    exit 1
fi

TARGET="$1"
TOKEN="$2"
MAX_ID="${3:-20}"  # Default 20 si no se especifica

echo -e "${BLUE}[*] Target: ${TARGET}${NC}"
echo -e "${BLUE}[*] Token: ${TOKEN:0:20}...${NC}"
echo -e "${BLUE}[*] Scanning IDs: 1 to ${MAX_ID}${NC}"
echo ""

# Contadores
VULNERABLE=0
PROTECTED=0
NOT_FOUND=0
ERRORS=0

# Crear archivo de resultados
RESULTS_FILE="bola_scan_$(date +%Y%m%d_%H%M%S).txt"
echo "BOLA Scan Results - $(date)" > "$RESULTS_FILE"
echo "Target: $TARGET" >> "$RESULTS_FILE"
echo "==================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Progreso
echo -e "${YELLOW}[*] Iniciando escaneo...${NC}"
echo ""

# Escanear IDs
for id in $(seq 1 $MAX_ID); do
    # Hacer request
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        --connect-timeout 5 \
        --max-time 10 \
        "$TARGET/api/orders/$id" 2>/dev/null)
    
    # Analizar respuesta
    if [ "$response" == "200" ]; then
        echo -e "${RED}[🚨] ID $id: VULNERABLE (200 OK)${NC}"
        echo "ID $id: VULNERABLE (200 OK)" >> "$RESULTS_FILE"
        ((VULNERABLE++))
        
        # Obtener detalles
        details=$(curl -s \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            "$TARGET/api/orders/$id" | jq -r '.order.userId, .order.product' 2>/dev/null)
        
        if [ ! -z "$details" ]; then
            echo "  → $details" >> "$RESULTS_FILE"
        fi
        
    elif [ "$response" == "403" ]; then
        echo -e "${GREEN}[✓] ID $id: Protegido (403 Forbidden)${NC}"
        echo "ID $id: Protected (403)" >> "$RESULTS_FILE"
        ((PROTECTED++))
        
    elif [ "$response" == "404" ]; then
        echo -e "${YELLOW}[~] ID $id: No encontrado (404)${NC}"
        ((NOT_FOUND++))
        
    elif [ "$response" == "401" ]; then
        echo -e "${RED}[!] ID $id: Token inválido (401)${NC}"
        echo "ERROR: Token inválido. Verifica el JWT." >> "$RESULTS_FILE"
        break
        
    else
        echo -e "${YELLOW}[?] ID $id: Error (HTTP $response)${NC}"
        echo "ID $id: Error HTTP $response" >> "$RESULTS_FILE"
        ((ERRORS++))
    fi
    
    # Delay para no saturar
    sleep 0.1
done

# Resumen
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                    RESUMEN DEL ESCANEO${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Total escaneado:  ${BLUE}${MAX_ID}${NC}"
echo -e "🚨 Vulnerables:   ${RED}${VULNERABLE}${NC}"
echo -e "✅ Protegidos:    ${GREEN}${PROTECTED}${NC}"
echo -e "⚠️  No encontrados: ${YELLOW}${NOT_FOUND}${NC}"
echo -e "❌ Errores:       ${YELLOW}${ERRORS}${NC}"
echo ""

# Guardar resumen
echo "" >> "$RESULTS_FILE"
echo "==================================" >> "$RESULTS_FILE"
echo "RESUMEN:" >> "$RESULTS_FILE"
echo "Total: $MAX_ID" >> "$RESULTS_FILE"
echo "Vulnerables: $VULNERABLE" >> "$RESULTS_FILE"
echo "Protegidos: $PROTECTED" >> "$RESULTS_FILE"
echo "No encontrados: $NOT_FOUND" >> "$RESULTS_FILE"
echo "Errores: $ERRORS" >> "$RESULTS_FILE"

# Evaluación final
if [ $VULNERABLE -gt 0 ]; then
    echo -e "${RED}⚠️  CRÍTICO: Se encontraron $VULNERABLE endpoints vulnerables a BOLA${NC}"
    echo -e "${YELLOW}Revisa el archivo: $RESULTS_FILE${NC}"
    exit 1
else
    echo -e "${GREEN}✅ La API está protegida contra BOLA${NC}"
    echo -e "${YELLOW}Resultados guardados en: $RESULTS_FILE${NC}"
    exit 0
fi
