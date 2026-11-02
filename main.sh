#!/usr/bin/env bash

# Orquestador OSINT.
# Utilizar únicamente con identificadores propios o con autorización.

set -euo pipefail
umask 077

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DOMAIN=""
USERNAME=""
EMAIL=""

SAVE_REPORT=0
OUTPUT_DIR="$BASE_DIR/results"
WORK_DIR=""

usage() {
    cat <<'EOF'
Uso:
  ./main.sh [entradas] [opciones]

Entradas:
  -d DOMINIO      Consultar un dominio.
  -u USERNAME     Buscar un nombre de usuario.
  -e EMAIL        Consultar brechas de un correo.

Opciones:
  -r              Guardar también un informe JSON.
  -o DIRECTORIO   Directorio de salida. Requiere -r.
  -h              Mostrar ayuda.

Por defecto:
  Los resultados se muestran en pantalla.
  No se guardan archivos permanentes.
  Sin entradas se consulta example.org.

Ejemplos:
  ./main.sh -d example.org
  ./main.sh -u mi_usuario
  ./main.sh -e usuario@example.org -r
  ./main.sh -d example.org -r -o ./informes
EOF
}

error() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

cleanup() {
    if [[ "$SAVE_REPORT" -eq 0 && -n "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR"
    fi
}

OUTPUT_SELECTED=0

while getopts ":d:u:e:ro:h" option; do
    case "$option" in
        d) DOMAIN="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        e) EMAIL="$OPTARG" ;;
        r) SAVE_REPORT=1 ;;
        o)
            OUTPUT_DIR="$OPTARG"
            OUTPUT_SELECTED=1
            ;;
        h) usage; exit 0 ;;
        :) error "La opción -$OPTARG necesita un valor." ;;
        \?) error "Opción desconocida: -$OPTARG." ;;
    esac
done

shift "$((OPTIND - 1))"

[[ $# -eq 0 ]] || error "Argumentos inesperados. Consulta -h."
[[ -n "$OUTPUT_DIR" ]] || error "El directorio de salida está vacío."

if [[ "$OUTPUT_SELECTED" -eq 1 && "$SAVE_REPORT" -eq 0 ]]; then
    error "La opción -o requiere -r."
fi

if [[ -z "$DOMAIN" && -z "$USERNAME" && -z "$EMAIL" ]]; then
    DOMAIN="example.org"
fi

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

# Limpiar los archivos temporales al terminar o recibir una interrupción.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$SAVE_REPORT" -eq 1 ]]; then
    mkdir -p -- "$OUTPUT_DIR"
    OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"
    WORK_DIR="$(mktemp -d "$OUTPUT_DIR/run-XXXXXXXX")"
else
    WORK_DIR="$(mktemp -d)"
fi

if [[ -n "$DOMAIN" ]]; then
    python3 "$BASE_DIR/modules/domain.py" "$DOMAIN" \
        > "$WORK_DIR/domain.json"
fi

if [[ -n "$USERNAME" ]]; then
    python3 "$BASE_DIR/modules/usernames.py" "$USERNAME" \
        > "$WORK_DIR/usernames.json"
fi

if [[ -n "$EMAIL" ]]; then
    python3 "$BASE_DIR/modules/breaches.py" "$EMAIL" \
        > "$WORK_DIR/breaches.json"
fi

if [[ "$SAVE_REPORT" -eq 1 ]]; then
    python3 "$BASE_DIR/report.py" "$WORK_DIR" --save
else
    python3 "$BASE_DIR/report.py" "$WORK_DIR"
fi
