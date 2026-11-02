#!/usr/bin/env bash

# Orquestador OSINT.
# Utilizar únicamente con identificadores propios o con autorización.

set -euo pipefail
umask 077

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DOMAIN=""
USERNAME=""
EMAIL=""
OUTPUT_DIR="$BASE_DIR/results"

usage() {
    cat <<'EOF'
Uso:
  ./main.sh [opciones]

Entradas:
  -d DOMINIO      Consultar un dominio.
  -u USERNAME     Buscar un nombre de usuario.
  -e EMAIL        Consultar brechas de un correo.

Opciones:
  -o DIRECTORIO   Carpeta de resultados.
  -h              Mostrar ayuda.

Sin entradas se consulta example.org.

Ejemplos:
  ./main.sh -d example.org
  ./main.sh -u mi_usuario
  ./main.sh -e usuario@example.org
  ./main.sh -d example.org -u mi_usuario
EOF
}

error() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

# Leer opciones.
while getopts ":d:u:e:o:h" option; do
    case "$option" in
        d) DOMAIN="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        e) EMAIL="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        :) error "La opción -$OPTARG necesita un valor." ;;
        \?) error "Opción desconocida: -$OPTARG." ;;
    esac
done

shift "$((OPTIND - 1))"

[[ $# -eq 0 ]] || error "Argumentos inesperados. Consulta -h."
[[ -n "$OUTPUT_DIR" ]] || error "El directorio de salida está vacío."

# Entrada predeterminada.
if [[ -z "$DOMAIN" && -z "$USERNAME" && -z "$EMAIL" ]]; then
    DOMAIN="example.org"
fi

# Comprobar los archivos necesarios antes de empezar.
command -v python3 >/dev/null 2>&1 \
    || error "Se necesita Python 3."

[[ -f "$BASE_DIR/report.py" ]] \
    || error "No se encuentra report.py."

if [[ -n "$DOMAIN" ]]; then
    [[ -f "$BASE_DIR/modules/domain.py" ]] \
        || error "No se encuentra modules/domain.py."
fi

if [[ -n "$USERNAME" ]]; then
    [[ -f "$BASE_DIR/modules/usernames.py" ]] \
        || error "No se encuentra modules/usernames.py."
fi

if [[ -n "$EMAIL" ]]; then
    [[ -f "$BASE_DIR/modules/breaches.py" ]] \
        || error "No se encuentra modules/breaches.py."
fi

# Crear una carpeta independiente para esta ejecución.
mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"
RUN_DIR="$(mktemp -d "$OUTPUT_DIR/run-XXXXXXXX")"

# Ejecutar únicamente los módulos solicitados.
if [[ -n "$DOMAIN" ]]; then
    python3 "$BASE_DIR/modules/domain.py" "$DOMAIN" \
        > "$RUN_DIR/domain.json"
fi

if [[ -n "$USERNAME" ]]; then
    python3 "$BASE_DIR/modules/usernames.py" "$USERNAME" \
        > "$RUN_DIR/usernames.json"
fi

if [[ -n "$EMAIL" ]]; then
    python3 "$BASE_DIR/modules/breaches.py" "$EMAIL" \
        > "$RUN_DIR/breaches.json"
fi

# Consolidar los resultados.
python3 "$BASE_DIR/report.py" "$RUN_DIR"

printf 'Informe: %s/report.json\n' "$RUN_DIR"
