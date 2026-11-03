#!/usr/bin/env bash

# Orquestador OSINT.
# Utilizar únicamente con identificadores propios o con autorización.

set -euo pipefail
umask 077

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DNS_DOMAIN=""
WHOIS_DOMAIN=""
USERNAME=""
EMAIL=""

DNS_REQUESTED=0
WHOIS_REQUESTED=0

SAVE_REPORT=0
OUTPUT_SELECTED=0
OUTPUT_DIR="$BASE_DIR/results"

usage() {
    cat <<'EOF'
Uso:
  ./main.sh [entradas] [opciones]

Entradas:
  -d DOMINIO      Consultar registros DNS.
  -w DOMINIO      Consultar información WHOIS.
  -u USERNAME     Buscar perfiles con WhatsMyName.
  -e EMAIL        Consultar brechas mediante HIBP.

Opciones:
  -r              Guardar resultados e informe JSON.
  -o DIRECTORIO   Directorio de salida. Requiere -r.
  -h              Mostrar ayuda.

Sin -r:
  Los resultados se muestran por stdout.
  No se crean archivos de resultados.

Sin -d ni -w:
  Se consulta example.org en DNS y WHOIS.

Ejemplos:
  ./main.sh -d example.org
  ./main.sh -w example.org
  ./main.sh -u mi_usuario
  ./main.sh -e usuario@example.org
  ./main.sh -d example.org -w example.org
  ./main.sh -u mi_usuario -r
  ./main.sh -d example.org -w example.org -r -o ./informes
EOF
}

error() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi


while getopts ":d:w:u:e:ro:h" option; do
    case "$option" in
        d)
            DNS_DOMAIN="$OPTARG"
            DNS_REQUESTED=1
            ;;
        w)
            WHOIS_DOMAIN="$OPTARG"
            WHOIS_REQUESTED=1
            ;;
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

if [[ "$OUTPUT_SELECTED" -eq 1 && "$SAVE_REPORT" -eq 0 ]]; then
    error "La opción -o requiere -r."
fi

# Si no se ha pedido DNS ni WHOIS, se consulta example.org en ambos.
if [[ "$DNS_REQUESTED" -eq 0 && "$WHOIS_REQUESTED" -eq 0 ]]; then
    DNS_DOMAIN="example.org"
    WHOIS_DOMAIN="example.org"
fi

command -v python3 >/dev/null 2>&1 \
    || error "Se necesita Python 3."

MODULES=()
TARGETS=()

if [[ "$DNS_REQUESTED" -eq 1 ]]; then
    MODULES+=("dns_lookup")
    TARGETS+=("$DNS_DOMAIN")
fi

if [[ "$WHOIS_REQUESTED" -eq 1 ]]; then
    MODULES+=("whois_lookup")
    TARGETS+=("$WHOIS_DOMAIN")
fi

if [[ -n "$USERNAME" ]]; then
    MODULES+=("whatsmyname")
    TARGETS+=("$USERNAME")

    [[ -f "$BASE_DIR/data/wmn-data.json" ]] \
        || error "No se encuentra data/wmn-data.json."
fi

if [[ -n "$EMAIL" ]]; then
    MODULES+=("breaches")
    TARGETS+=("$EMAIL")
fi

for module in "${MODULES[@]}"; do
    [[ -f "$BASE_DIR/modules/$module.py" ]] \
        || error "No se encuentra modules/$module.py."
done

if [[ "$SAVE_REPORT" -eq 0 ]]; then
    # Salida bonita directa; sin archivos de resultados.
    for index in "${!MODULES[@]}"; do
        python3 "$BASE_DIR/modules/${MODULES[$index]}.py" \
            "${TARGETS[$index]}" --live
    done
else
    [[ -n "$OUTPUT_DIR" ]] \
        || error "El directorio de salida está vacío."

    [[ -f "$BASE_DIR/report.py" ]] \
        || error "No se encuentra report.py."

    mkdir -p -- "$OUTPUT_DIR"
    OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"
    RUN_DIR="$(mktemp -d "$OUTPUT_DIR/run-XXXXXXXX")"

    for index in "${!MODULES[@]}"; do
        python3 "$BASE_DIR/modules/${MODULES[$index]}.py" \
            "${TARGETS[$index]}" \
            > "$RUN_DIR/${MODULES[$index]}.json"
    done

    python3 "$BASE_DIR/report.py" "$RUN_DIR" --save
fi
