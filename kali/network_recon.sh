#!/bin/bash

# ═══════════════════════════════════════════════════════════
# Network Reconnaissance - Escaneo inicial del entorno
# Descubre servicios y puertos del proyecto BOLA
# ═══════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║         NETWORK RECONNAISSANCE - BOLA Project            ║
║              Service Discovery & Enumeration             ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Verificar que nmap esté instalado
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}[✗] nmap no está instalado${NC}"
    echo -e "${YELLOW}[*] Instalar con: sudo apt install nmap${NC}"
    exit 1
fi

# Target IP
if [ -z "$1" ]; then
    echo -e "${YELLOW}[*] Uso: $0 <TARGET_IP>${NC}"
    echo -e "${YELLOW}[*] Ejemplo: $0 192.168.1.50${NC}"
    echo ""
    read -p "Ingresa la IP del host: " TARGET
else
    TARGET="$1"
fi

echo -e "${BLUE}[*] Target: ${TARGET}${NC}"
echo ""

# Crear directorio de resultados
RESULTS_DIR="recon_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${YELLOW}[*] Guardando resultados en: $RESULTS_DIR/${NC}"
echo ""

# ═══════════════════════════════════════════════════════════
# FASE 1: Ping Sweep
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}FASE 1: Verificando conectividad${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

if ping -c 3 "$TARGET" &> /dev/null; then
    echo -e "${GREEN}[✓] Host está online${NC}"
else
    echo -e "${RED}[✗] Host no responde a ping${NC}"
    echo -e "${YELLOW}[!] Puede estar protegido por firewall, continuando...${NC}"
fi

echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# FASE 2: Port Scan (Quick)
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}FASE 2: Escaneo rápido de puertos comunes${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}[*] Escaneando puertos del proyecto BOLA (3000, 3001, 8080, 8081)...${NC}"

nmap -p 3000,3001,8080,8081 -T4 "$TARGET" -oN "$RESULTS_DIR/quick_scan.txt"

echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# FASE 3: Service Detection
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}FASE 3: Detección de servicios${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}[*] Identificando versiones de servicios...${NC}"

nmap -sV -p 3000,3001,8080,8081 "$TARGET" -oN "$RESULTS_DIR/service_detection.txt"

echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# FASE 4: HTTP Enumeration
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}FASE 4: Enumeración HTTP${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Health checks
echo -e "${YELLOW}[*] Verificando endpoints de salud...${NC}"

for port in 3000 3001 8080; do
    echo ""
    echo -e "${BLUE}Puerto $port:${NC}"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET:$port/health" 2>/dev/null)
    
    if [ "$response" == "200" ]; then
        echo -e "${GREEN}  [✓] /health → 200 OK${NC}"
        curl -s "http://$TARGET:$port/health" | jq '.' 2>/dev/null || echo "  (respuesta no es JSON)"
    else
        echo -e "${YELLOW}  [~] /health → HTTP $response${NC}"
    fi
done

echo ""
sleep 1

# ═══════════════════════════════════════════════════════════
# FASE 5: API Endpoint Discovery
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}FASE 5: Descubrimiento de endpoints API${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

ENDPOINTS=(
    "api/auth/login"
    "api/orders"
    "api/users"
    "api/logs"
)

echo -e "${YELLOW}[*] Probando endpoints comunes...${NC}"
echo ""

for port in 3000 3001; do
    echo -e "${BLUE}API en puerto $port:${NC}"
    
    for endpoint in "${ENDPOINTS[@]}"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET:$port/$endpoint" 2>/dev/null)
        
        if [ "$response" == "401" ] || [ "$response" == "200" ]; then
            echo -e "${GREEN}  [✓] /$endpoint → HTTP $response (existe)${NC}"
        elif [ "$response" == "404" ]; then
            echo -e "${YELLOW}  [-] /$endpoint → 404 (no existe)${NC}"
        else
            echo -e "${RED}  [?] /$endpoint → HTTP $response${NC}"
        fi
    done
    echo ""
done

# ═══════════════════════════════════════════════════════════
# FASE 6: Resumen y Recomendaciones
# ═══════════════════════════════════════════════════════════

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                    RESUMEN${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Parsear resultados
OPEN_PORTS=$(grep "open" "$RESULTS_DIR/service_detection.txt" | wc -l)

echo -e "${BLUE}Target: $TARGET${NC}"
echo -e "${BLUE}Puertos abiertos: $OPEN_PORTS${NC}"
echo ""

echo "Servicios detectados:"
grep "open" "$RESULTS_DIR/service_detection.txt" | while read line; do
    echo "  $line"
done

echo ""
echo -e "${YELLOW}Próximos pasos recomendados:${NC}"
echo ""
echo "  1. Autenticación:"
echo "     curl -X POST http://$TARGET:3000/api/auth/login \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"email\":\"alice@example.com\",\"password\":\"password123\"}'"
echo ""
echo "  2. Escaneo BOLA:"
echo "     ./bola_scanner.sh http://$TARGET:3000 <TOKEN>"
echo ""
echo "  3. Ataque con Burp Suite:"
echo "     ./burp_setup.sh"
echo ""
echo "  4. Comparación de APIs:"
echo "     ./compare_apis.sh"
echo ""

echo -e "${GREEN}✅ Reconocimiento completado${NC}"
echo -e "${YELLOW}Resultados guardados en: $RESULTS_DIR/${NC}"
echo ""

# Crear archivo de resumen
cat > "$RESULTS_DIR/RESUMEN.txt" << EOF
═══════════════════════════════════════════════════════════
RESUMEN DE RECONOCIMIENTO - BOLA Project
═══════════════════════════════════════════════════════════

Fecha: $(date)
Target: $TARGET

Puertos Escaneados:
  • 3000 - API Vulnerable
  • 3001 - API Segura
  • 8080 - Dashboard Web
  • 8081 - WebSocket Server

Servicios Detectados:
$(grep "open" "$RESULTS_DIR/service_detection.txt")

Endpoints Descubiertos:
  • /api/auth/login (POST)
  • /api/orders (GET)
  • /api/orders/:id (GET) ⚠️ VULNERABLE
  • /api/users (GET)
  • /health (GET)

Credenciales de Prueba:
  • alice@example.com:password123
  • bob@example.com:password123
  • charlie@example.com:password123

Próximos Pasos:
  1. Autenticarse y obtener JWT
  2. Ejecutar bola_scanner.sh
  3. Usar Burp Suite para fuzzing
  4. Comparar API vulnerable vs segura
  5. Documentar hallazgos

═══════════════════════════════════════════════════════════
EOF

echo -e "${BLUE}[*] Resumen también guardado en: $RESULTS_DIR/RESUMEN.txt${NC}"
echo ""
