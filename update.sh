#!/data/data/com.termux/files/usr/bin/bash
# update.sh — Actualiza tu fork de grok-cli-termux-native desde el original

echo "========================================"
echo "🔄 Actualizador de grok-cli-termux-native"
echo "========================================"

# Ir a la carpeta correcta
cd "$(dirname "$0")" || { echo "❌ Error: No se pudo acceder a la carpeta"; exit 1; }

if [ ! -d .git ]; then
    echo "❌ Este script debe ejecutarse desde dentro de grok-cli-termux-native"
    exit 1
fi

# Asegurar que upstream esté configurado
if ! git remote | grep -q '^upstream$'; then
    echo "📌 Añadiendo upstream (repositorio original)..."
    git remote add upstream https://github.com/Thr45hx/grok-cli-termux-native.git
    echo "✅ upstream añadido"
fi

echo "📥 Obteniendo últimas actualizaciones del autor original..."
git fetch upstream

echo ""
echo "🔀 Intentando combinar los cambios..."
if git merge upstream/main --no-edit 2>&1; then
    echo ""
    echo "✅ ¡Actualización completada con éxito!"
    echo ""
    echo "📊 Últimos commits:"
    git log --oneline --graph -8
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

echo ""
echo "========================================"
echo "✅ Tu fork está actualizado."
echo "   Puedes ejecutar este script cuando quieras actualizar."
echo "========================================"
