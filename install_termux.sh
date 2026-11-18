#!/usr/bin/env bash
# =============================================================================
#  Instalador rápido do FindPort para Termux (Android)
# =============================================================================
set -e

echo "📦 Instalando dependências recomendadas no Termux..."
pkg update -y || apt-get update -y
pkg install -y iproute2 procps grep gawk || apt-get install -y iproute2 procps grep gawk

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "${SCRIPT_DIR}/findport.sh"

PREFIX_BIN="${PREFIX:-/data/data/com.termux/files/usr}/bin"

if [ -d "$PREFIX_BIN" ]; then
    echo "🔗 Criando atalho global 'findport'..."
    ln -sf "${SCRIPT_DIR}/findport.sh" "${PREFIX_BIN}/findport"
    echo ""
    echo "✅ Instalação concluída com sucesso!"
    echo "👉 Agora você pode executar o comando digitando apenas:"
    echo "   findport"
else
    echo "✅ Dependências instaladas!"
    echo "👉 Para executar, use:"
    echo "   ./findport.sh"
fi
