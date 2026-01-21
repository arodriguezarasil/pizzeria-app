#!/bin/bash

# Script para iniciar la app de pizzería con zrok automático

set -e

echo "🍕 Iniciando Pizzería App..."
echo ""

# Verificar si zrok está configurado en el host
if [ -d "$HOME/.zrok" ] && [ -f "$HOME/.zrok/environments.json" ]; then
    echo "✅ zrok está configurado en el host"
    
    # Verificar el estado del volumen
    VOLUME_EXISTS=$(docker volume ls -q -f name=pizzeria-app_zrok-env)
    VOLUME_HAS_ENV=$(docker run --rm -v pizzeria-app_zrok-env:/dest alpine sh -c "if [ -f /dest/environments.json ]; then echo yes; fi" 2>/dev/null || true)

    if [ -z "$VOLUME_EXISTS" ] || [ -z "$VOLUME_HAS_ENV" ]; then
        echo "📦 Inicializando volumen zrok-env desde configuración del host..."
        # Crear un contenedor temporal para copiar la configuración
        docker run --rm -v "$HOME/.zrok:/source:ro" -v pizzeria-app_zrok-env:/dest alpine sh -c "rm -rf /dest/* && cp -r /source/* /dest/ 2>/dev/null || true"
        echo "✅ Volumen inicializado"
    else
        echo "✅ Volumen zrok-env ya existe y tiene configuración"
    fi
else
    echo "⚠️  zrok no está configurado en el host"
    echo ""
    echo "Para configurar zrok, ejecuta:"
    echo "  zrok enable <TU_TOKEN>"
    echo ""
    echo "Luego ejecuta este script nuevamente."
    echo ""
    echo "O si prefieres configurar zrok dentro del contenedor:"
    echo "  1. Levanta los servicios: docker compose up -d"
    echo "  2. Ejecuta: docker exec -it pizzeria-zrok zrok enable <TU_TOKEN>"
    echo "  3. Reinicia: docker compose restart zrok"
    echo ""
    read -p "¿Continuar de todas formas? (s/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        exit 1
    fi
fi

# Crear la red si no existe
docker network create pizzeria-network 2>/dev/null || true

# Levantar los servicios
echo ""
echo "🚀 Levantando contenedores..."
docker compose up -d --build

echo ""
echo "⏳ Esperando que los servicios estén listos..."
sleep 5

echo ""
echo "✅ ¡Listo! La app debería estar disponible en:"
echo "   🌍 https://meinfuhrer.share.zrok.io/"
echo ""
echo "Para ver los logs de zrok:"
echo "   docker compose logs -f zrok"
echo ""
echo "Para ver todos los logs:"
echo "   docker compose logs -f"
echo ""
echo "Para detener:"
echo "   docker compose down"
echo ""
