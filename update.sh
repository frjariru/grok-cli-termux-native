#!/data/data/com.termux/files/usr/bin/bash
# update.sh — Actualiza tu fork de grok-cli-termux-native desde el original

echo "========================================"
echo "🔄 Actualizador de grok-cli-termux-native"
echo "========================================"

cd "$(dirname "$0")" || { echo "❌ Error: No se pudo acceder a la carpeta"; exit 1; }

if [ ! -d .git ]; then
    echo "❌ Este script debe ejecutarse desde dentro de grok-cli-termux-native"
    exit 1
fi

if ! git remote | grep -q '^upstream$'; then
    echo "📌 Añadiendo upstream (repositorio original)..."
    git remote add upstream https://github.com
    echo "✅ upstream añadido"
fi

echo "📥 Obteniendo últimas actualizaciones del autor original..."
git fetch upstream

echo ""
echo "🔀 Intentando combinar los cambios..."
if git --no-pager merge upstream/main --no-edit 2>&1; then
    echo ""
    echo "✅ ¡Actualización completada con éxito!"
    echo ""
    echo "📊 Últimos commits:"
    git --no-pager log --oneline --graph -8
    echo ""
    echo "📁 Estado del repositorio:"
    git status --short
else
    echo ""
    echo "⚠️  Se detectaron conflictos durante el merge."
    echo "   Debes resolverlos manualmente."
    echo "   Después ejecuta: git add . && git commit -m 'Merge upstream'"
    exit 1
fi

# ========================================================
# AUTOMATIZACIÓN DE CLAMAV OPTIMIZADA (ÚLTIMOS 7 DÍAS)
# ========================================================
echo ""
echo "========================================"
VERDE='\033[0;32m'
ROJO='\033[0;31m'
AMARILLO='\033[1;33m'
NC='\033[0m'

echo -e "${AMARILLO}[*] Iniciando mantenimiento de seguridad con ClamAV...${NC}"

# Intentar actualizar firmas de virus silenciosamente
freshclam --quiet

LOG_FILE="$HOME/clamav_scan.log"
echo -e "${AMARILLO}[*] Escaneando SOLO archivos nuevos o modificados en los últimos 7 días...${NC}"

# Buscamos archivos modificados en los últimos 7 días en HOME
find "$HOME" -type f -mtime -7 \
    ! -path "*/.git/*" \
    ! -path "*/proc/*" \
    ! -path "*/sys/*" \
    -print0 | xargs -0 clamscan -i --log="$LOG_FILE" 2>/dev/null

STATUS=$?

if [ $STATUS -eq 0 ]; then
    echo -e "${VERDE}[+] ¡Escaneo rápido completado! Todo limpio.${NC}"
elif [ $STATUS -eq 1 ]; then
    echo -e "${ROJO}[⚡] ¡ALERTA! Se detectó malware en los archivos nuevos. Revisa: $LOG_FILE${NC}"
else
    echo -e "${VERDE}[+] No hay archivos nuevos críticos que analizar. Sistema seguro.${NC}"
fi

echo "========================================"
echo "✅ Proceso completo terminado."
echo "========================================"
echo ""
echo "========================================"
echo "[*] Iniciando auditoría de Rootkits con rkhunter..."
echo "========================================"
rkhunter --check --rwo 2>/dev/null | grep -Ev "passwd|warning|immutable"
echo "[*] Auditoría de rkhunter completada."
echo "========================================"
