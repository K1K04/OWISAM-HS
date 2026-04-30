#!/bin/bash
# captive_detector.sh — Detecta portales cautivos y analiza si son maliciosos
# Uso: bash captive_detector.sh [interfaz]  (por defecto auto-detecta)

set -e

# ─── Colores ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
BLU='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLU}[*]${NC} $1"; }
ok()    { echo -e "${GRN}[+]${NC} $1"; }
warn()  { echo -e "${YEL}[!]${NC} $1"; }
bad()   { echo -e "${RED}[-]${NC} $1"; }

# ─── Dependencias ──────────────────────────────────────────────────────────
for cmd in curl nmcli grep awk sed python3; do
    command -v $cmd &>/dev/null || { bad "Falta dependencia: $cmd"; exit 1; }
done

# ─── Detectar interfaz WiFi activa ─────────────────────────────────────────
if [ -n "$1" ]; then
    IFACE="$1"
else
    IFACE=$(nmcli -t -f DEVICE,TYPE,STATE dev | grep ':wifi:connected' | cut -d: -f1 | head -1)
fi

if [ -z "$IFACE" ]; then
    bad "No se encontró interfaz WiFi conectada."
    exit 1
fi

# ─── Info de la red conectada ──────────────────────────────────────────────
SSID=$(nmcli -t -f active,ssid dev wifi | grep '^yes' | cut -d: -f2)
BSSID=$(nmcli -t -f active,bssid dev wifi | grep '^yes' | cut -d: -f2)
GW=$(ip route show dev $IFACE default 2>/dev/null | awk '{print $3}' | head -1)
MY_IP=$(ip -4 addr show $IFACE | grep inet | awk '{print $2}' | head -1)

echo ""
echo -e "${BLU}══════════════════════════════════════════${NC}"
echo -e "${BLU}   Captive Portal Detector — Análisis     ${NC}"
echo -e "${BLU}══════════════════════════════════════════${NC}"
echo ""
info "Interfaz : $IFACE"
info "SSID     : ${SSID:-desconocido}"
info "BSSID    : ${BSSID:-desconocido}"
info "IP local : ${MY_IP:-desconocida}"
info "Gateway  : ${GW:-no detectado}"
echo ""

# ─── Paso 1: Detectar portal cautivo ───────────────────────────────────────
info "Paso 1/4 — Detectando portal cautivo..."

PORTAL_DETECTED=false
PORTAL_URL=""

# Endpoints de connectivity check usados por cada OS
CHECKS=(
    "http://connectivitycheck.gstatic.com/generate_204"
    "http://www.msftconnecttest.com/connecttest.txt"
    "http://captive.apple.com/hotspot-detect.html"
    "http://detectportal.firefox.com/success.txt"
    "http://neverssl.com"
)

for URL in "${CHECKS[@]}"; do
    RESP=$(curl -s -o /tmp/cp_body.html -w "%{http_code}|%{redirect_url}|%{url_effective}" \
           --max-time 5 -L "$URL" 2>/dev/null || echo "000||")
    CODE=$(echo $RESP | cut -d'|' -f1)
    REDIR=$(echo $RESP | cut -d'|' -f2)
    EFFECTIVE=$(echo $RESP | cut -d'|' -f3)

    if [ "$CODE" = "200" ] && grep -qi "captive\|portal\|login\|accept\|terms\|connect\|wifi\|hotspot\|registro\|register" /tmp/cp_body.html 2>/dev/null; then
        PORTAL_DETECTED=true
        PORTAL_URL="$EFFECTIVE"
        warn "Portal detectado vía: $URL"
        warn "URL efectiva: $EFFECTIVE"
        break
    elif [ "$CODE" = "302" ] || [ "$CODE" = "301" ]; then
        PORTAL_DETECTED=true
        PORTAL_URL="$REDIR"
        warn "Redirección detectada: $URL → $REDIR"
        break
    fi
done

if [ "$PORTAL_DETECTED" = false ]; then
    ok "No se detectó portal cautivo (acceso directo a internet)"
    echo ""
    info "Red aparentemente limpia. Sin más análisis necesarios."
    exit 0
fi

echo ""
# ─── Paso 2: Descargar y analizar el HTML del portal ───────────────────────
info "Paso 2/4 — Descargando portal para análisis..."

# Descargar el portal
curl -s -o /tmp/portal_page.html --max-time 10 -A \
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
    "$PORTAL_URL" 2>/dev/null || true

if [ ! -s /tmp/portal_page.html ]; then
    warn "No se pudo descargar el contenido del portal"
else
    ok "Portal descargado ($(wc -c < /tmp/portal_page.html) bytes)"
fi

echo ""
# ─── Paso 3: Análisis de indicadores maliciosos ────────────────────────────
info "Paso 3/4 — Analizando indicadores de malicia..."
echo ""

SCORE=0
ISSUES=()

# 3.1 ¿Pide datos personales?
if grep -qiE 'type="email"|name="email"|type="password"|name="password"|name="phone"|name="telefono"|name="nombre"|name="name"' /tmp/portal_page.html 2>/dev/null; then
    bad "DATO PERSONAL: El formulario recopila email, contraseña, teléfono o nombre"
    ISSUES+=("Recopila datos personales (email/password/nombre/teléfono)")
    SCORE=$((SCORE+3))
else
    ok "No se detectan campos de datos personales sensibles"
fi

# 3.2 ¿El formulario envía a un servidor externo?
FORM_ACTION=$(grep -oiE 'action="[^"]*"' /tmp/portal_page.html 2>/dev/null | head -5)
if [ -n "$FORM_ACTION" ]; then
    info "Acción del formulario: $FORM_ACTION"
    if echo "$FORM_ACTION" | grep -qiE 'http[s]?://' ; then
        # Extrae el host destino
        FORM_HOST=$(echo "$FORM_ACTION" | grep -oiE 'https?://[^/"]+' | head -1)
        PORTAL_HOST=$(echo "$PORTAL_URL" | grep -oiE 'https?://[^/"]+' | head -1)
        if [ "$FORM_HOST" != "$PORTAL_HOST" ] && [ -n "$FORM_HOST" ]; then
            bad "EXFILTRACIÓN: El formulario envía datos a un host diferente: $FORM_HOST"
            ISSUES+=("Formulario envía datos a host externo: $FORM_HOST")
            SCORE=$((SCORE+4))
        fi
    fi
fi

# 3.3 ¿Hay scripts externos sospechosos?
EXT_SCRIPTS=$(grep -oiE 'src="https?://[^"]*"' /tmp/portal_page.html 2>/dev/null | grep -v \
    'jquery\|bootstrap\|cloudflare\|googleapis\|gstatic\|ajax' | head -5)
if [ -n "$EXT_SCRIPTS" ]; then
    warn "Scripts externos no reconocidos:"
    echo "$EXT_SCRIPTS" | while read l; do warn "  → $l"; done
    SCORE=$((SCORE+1))
    ISSUES+=("Carga scripts externos no reconocidos")
fi

# 3.4 ¿Certificado HTTPS o HTTP plano?
if echo "$PORTAL_URL" | grep -q "^https://"; then
    ok "Portal usa HTTPS"
else
    warn "Portal en HTTP plano — los datos viajarán sin cifrar"
    ISSUES+=("HTTP sin cifrado — datos en texto claro")
    SCORE=$((SCORE+2))
fi

# 3.5 ¿DNS hijack activo? (resuelve todo a la misma IP)
DNS_TEST_1=$(python3 -c "import socket; print(socket.gethostbyname('google.com'))" 2>/dev/null || echo "error")
DNS_TEST_2=$(python3 -c "import socket; print(socket.gethostbyname('amazon.com'))" 2>/dev/null || echo "error")
if [ "$DNS_TEST_1" = "$DNS_TEST_2" ] && [ "$DNS_TEST_1" != "error" ]; then
    warn "DNS HIJACK: google.com y amazon.com resuelven a la misma IP ($DNS_TEST_1)"
    ISSUES+=("DNS hijack activo — todo resuelve a $DNS_TEST_1")
    SCORE=$((SCORE+2))
else
    ok "DNS resuelve correctamente (sin hijack global)"
fi

# 3.6 ¿El gateway responde en puertos sospechosos?
if command -v nc &>/dev/null && [ -n "$GW" ]; then
    for PORT in 8080 8443 3000 4000; do
        if nc -z -w 1 $GW $PORT 2>/dev/null; then
            warn "Gateway responde en puerto inusual: $GW:$PORT"
            SCORE=$((SCORE+1))
            ISSUES+=("Gateway activo en puerto $PORT")
        fi
    done
fi

# 3.7 ¿Pide aceptar términos con checkbox oculto o pre-marcado?
if grep -qiE 'checked|hidden.*accept|accept.*hidden' /tmp/portal_page.html 2>/dev/null; then
    warn "Consentimiento pre-marcado o campo oculto de aceptación detectado"
    ISSUES+=("Consentimiento pre-marcado o aceptación automática")
    SCORE=$((SCORE+1))
fi

echo ""
# ─── Paso 4: Veredicto ─────────────────────────────────────────────────────
info "Paso 4/4 — Veredicto final..."
echo ""
echo -e "${BLU}──────────────────────────────────────────${NC}"
echo -e "  SSID     : ${SSID}"
echo -e "  Portal   : ${PORTAL_URL}"
echo -e "  Score    : ${SCORE}/13"

if [ $SCORE -ge 5 ]; then
    echo ""
    echo -e "${RED}  ⚠  PORTAL POSIBLEMENTE MALICIOSO  ⚠${NC}"
    echo -e "${BLU}──────────────────────────────────────────${NC}"
    echo ""
    bad "Problemas detectados:"
    for issue in "${ISSUES[@]}"; do
        bad "  • $issue"
    done
    echo ""
    bad "RECOMENDACIÓN: Desconéctate de esta red."
    bad "No introduzcas ningún dato personal."
elif [ $SCORE -ge 2 ]; then
    echo ""
    echo -e "${YEL}  ⚠  PORTAL SOSPECHOSO — Precaución  ${NC}"
    echo -e "${BLU}──────────────────────────────────────────${NC}"
    echo ""
    warn "Indicadores de riesgo:"
    for issue in "${ISSUES[@]}"; do
        warn "  • $issue"
    done
    echo ""
    warn "RECOMENDACIÓN: Usa VPN si necesitas conectarte."
    warn "Evita introducir contraseñas reales."
else
    echo ""
    echo -e "${GRN}  ✓  Portal aparentemente legítimo  ${NC}"
    echo -e "${BLU}──────────────────────────────────────────${NC}"
    ok "No se detectaron indicadores maliciosos relevantes."
fi

echo ""
# ─── Guardar reporte ───────────────────────────────────────────────────────
REPORT="/tmp/captive_report_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "=== Captive Portal Report ==="
    echo "Fecha   : $(date)"
    echo "SSID    : $SSID"
    echo "BSSID   : $BSSID"
    echo "Portal  : $PORTAL_URL"
    echo "Score   : $SCORE/13"
    echo ""
    echo "=== Indicadores ==="
    for issue in "${ISSUES[@]}"; do echo "  - $issue"; done
    echo ""
    echo "=== HTML del portal ==="
    cat /tmp/portal_page.html 2>/dev/null
} > "$REPORT"

info "Reporte guardado en: $REPORT"
echo ""
