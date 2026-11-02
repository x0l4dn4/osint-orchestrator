#!/usr/bin/env bash
#
# Orquestador modular OSINT.
# Utilizar únicamente sobre identificadores propios o con autorización.
#
# Dependencias: Bash >= 4, jq y Python 3 para generar informes.
#
# Los módulos reciben:
#   --target IDENTIFICADOR
#
# Los módulos deben devolver un único objeto JSON por stdout:
#   {"module":"nombre","status":"ok|skipped|error","data":{}}
#
# El generador recibe:
#   --input DIRECTORIO --format json|html --output ARCHIVO

set -euo pipefail
umask 077

if (( BASH_VERSINFO[0] < 4 )); then
    printf 'Error: se requiere Bash 4 o superior.\n' >&2
    exit 1
fi

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$BASE_DIR/modules"
REPORT_GENERATOR="$BASE_DIR/reports/generate_report.py"

NAME=""
EMAIL=""
USERNAME=""
PHONE=""
DOMAIN=""

MODULE_SELECTION="auto"
REPORT_FORMAT="json"
OUTPUT_DIR="$BASE_DIR/results"

RUN_DIR=""
HAS_ERRORS=0

declare -a SELECTED_MODULES=()

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Uso:
  ./main.sh [entradas] [opciones]

Entradas:
  -n NOMBRE       Nombre completo.
  -e EMAIL        Correo electrónico.
  -u USERNAME     Nombre de usuario.
  -t TELEFONO     Teléfono internacional sin espacios.
  -d DOMINIO      Dominio sin protocolo ni rutas.

Opciones:
  -m MODULOS      Lista separada por comas:
                  usernames,breaches,domain,harvester
                  Predeterminado: auto.

  -r FORMATO      json, html o none.
                  Predeterminado: json.

  -o DIRECTORIO   Directorio base de resultados.
                  Predeterminado: results junto al script.

  -h              Mostrar ayuda.

Selección automática:
  -u activa usernames.
  -e activa breaches.
  -d activa domain.
  harvester requiere selección explícita.

Sin entradas se utiliza example.org.
Nombre y teléfono se conservan como metadatos; no activan módulos.

Ejemplos:
  ./main.sh -u mi_usuario
  ./main.sh -e usuario@example.org -r html
  ./main.sh -d example.org -m domain,harvester
  ./main.sh -d example.org -r none
EOF
}

parse_arguments() {
    local option

    while getopts ":n:e:u:t:d:m:r:o:h" option; do
        case "$option" in
            n) NAME="$OPTARG" ;;
            e) EMAIL="$OPTARG" ;;
            u) USERNAME="${OPTARG#@}" ;;
            t) PHONE="$OPTARG" ;;
            d) DOMAIN="${OPTARG,,}" ;;
            m) MODULE_SELECTION="$OPTARG" ;;
            r) REPORT_FORMAT="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            h) usage; exit 0 ;;
            :) fail "La opción -$OPTARG requiere un valor." ;;
            \?) fail "Opción desconocida: -$OPTARG." ;;
        esac
    done

    shift "$((OPTIND - 1))"
    (( $# == 0 )) || fail "Argumentos inesperados. Consulta -h."
}

validate_inputs() {
    local value label
    local -a labels=()

    for value in \
        "$NAME" "$EMAIL" "$USERNAME" "$PHONE" "$DOMAIN" "$OUTPUT_DIR"
    do
        [[ ! "$value" =~ [[:cntrl:]] ]] \
            || fail "Las entradas contienen caracteres de control."
    done

    [[ -n "$OUTPUT_DIR" ]] \
        || fail "El directorio de salida no puede estar vacío."

    case "$REPORT_FORMAT" in
        json|html|none) ;;
        *) fail "Formato no admitido: utiliza json, html o none." ;;
    esac

    if [[ -z "$NAME$EMAIL$USERNAME$PHONE$DOMAIN" ]]; then
        DOMAIN="example.org"
    fi

    if [[ -n "$EMAIL" ]]; then
        [[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] \
            || fail "Formato de correo electrónico no válido."
    fi

    if [[ -n "$USERNAME" ]]; then
        [[ "$USERNAME" =~ ^[a-zA-Z0-9._-]{1,64}$ ]] \
            || fail "Nombre de usuario no válido."
    fi

    if [[ -n "$PHONE" ]]; then
        [[ "$PHONE" =~ ^\+[1-9][0-9]{6,14}$ ]] \
            || fail "Teléfono no válido. Ejemplo: +34600111222."
    fi

    if [[ -n "$DOMAIN" ]]; then
        DOMAIN="${DOMAIN%.}"

        (( ${#DOMAIN} <= 253 )) \
            || fail "Dominio demasiado largo."

        [[ "$DOMAIN" == *.* && "$DOMAIN" != *. ]] \
            || fail "Formato de dominio no válido."

        [[ ! "$DOMAIN" =~ ^[0-9.]+$ ]] \
            || fail "Introduce un dominio, no una dirección IP."

        IFS='.' read -r -a labels <<< "$DOMAIN"

        for label in "${labels[@]}"; do
            [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
                || fail "Dominio no válido. Utiliza ASCII o punycode."
        done
    fi
}

select_modules() {
    local module
    local -a requested=()
    local -A seen=()

    if [[ "$MODULE_SELECTION" == "auto" ]]; then
        [[ -z "$USERNAME" ]] || SELECTED_MODULES+=("usernames")
        [[ -z "$EMAIL" ]] || SELECTED_MODULES+=("breaches")
        [[ -z "$DOMAIN" ]] || SELECTED_MODULES+=("domain")
    else
        [[ -n "$MODULE_SELECTION" &&
           "$MODULE_SELECTION" != ,* &&
           "$MODULE_SELECTION" != *, &&
           "$MODULE_SELECTION" != *,,* ]] \
            || fail "Lista de módulos no válida."

        IFS=',' read -r -a requested <<< "$MODULE_SELECTION"

        for module in "${requested[@]}"; do
            case "$module" in
                usernames)
                    [[ -n "$USERNAME" ]] \
                        || fail "usernames requiere -u."
                    ;;
                breaches)
                    [[ -n "$EMAIL" ]] \
                        || fail "breaches requiere -e."
                    ;;
                domain|harvester)
                    [[ -n "$DOMAIN" ]] \
                        || fail "$module requiere -d."
                    ;;
                *)
                    fail "Módulo desconocido: $module."
                    ;;
            esac

            if [[ -z "${seen[$module]:-}" ]]; then
                SELECTED_MODULES+=("$module")
                seen["$module"]=1
            fi
        done
    fi

    (( ${#SELECTED_MODULES[@]} > 0 )) \
        || fail "No hay módulos aplicables. Introduce -u, -e o -d."
}

check_dependencies() {
    local module

    command -v jq >/dev/null 2>&1 \
        || fail "Se requiere jq."

    for module in "${SELECTED_MODULES[@]}"; do
        [[ -f "$MODULES_DIR/$module.sh" &&
           -r "$MODULES_DIR/$module.sh" ]] \
            || fail "No se puede leer modules/$module.sh."
    done

    if [[ "$REPORT_FORMAT" != "none" ]]; then
        command -v python3 >/dev/null 2>&1 \
            || fail "Se requiere Python 3 para generar informes."

        [[ -f "$REPORT_GENERATOR" && -r "$REPORT_GENERATOR" ]] \
            || fail "No se puede leer reports/generate_report.py."
    fi
}

prepare_output() {
    mkdir -p -- "$OUTPUT_DIR"
    OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"

    RUN_DIR="$(mktemp -d "$OUTPUT_DIR/run-XXXXXXXX")"
    mkdir -- "$RUN_DIR/raw"

    jq -n \
        --arg created_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        --arg name "$NAME" \
        --arg email "$EMAIL" \
        --arg username "$USERNAME" \
        --arg phone "$PHONE" \
        --arg domain "$DOMAIN" \
        --arg report_format "$REPORT_FORMAT" \
        --argjson modules "$(
            printf '%s\n' "${SELECTED_MODULES[@]}" |
                jq -R . |
                jq -s .
        )" \
        '{
            schema_version: 1,
            created_at: $created_at,
            input: {
                name: $name,
                email: $email,
                username: $username,
                phone: $phone,
                domain: $domain
            },
            modules: $modules,
            report_format: $report_format
        }' > "$RUN_DIR/metadata.json"
}

write_module_error() {
    local module="$1"
    local message="$2"

    jq -n \
        --arg module "$module" \
        --arg message "$message" \
        '{
            module: $module,
            status: "error",
            message: $message,
            data: {}
        }' > "$RUN_DIR/raw/$module.json"
}

run_module() {
    local module="$1"
    local target=""
    local exit_code=0

    local script="$MODULES_DIR/$module.sh"
    local pending="$RUN_DIR/raw/$module.pending"
    local result="$RUN_DIR/raw/$module.json"

    case "$module" in
        usernames) target="$USERNAME" ;;
        breaches) target="$EMAIL" ;;
        domain|harvester) target="$DOMAIN" ;;
    esac

    # stdout se reserva para JSON; no se conservan diagnósticos del módulo.
    bash "$script" --target "$target" \
        > "$pending" 2>/dev/null || exit_code=$?

    if (( exit_code != 0 )); then
        rm -f -- "$pending"
        write_module_error \
            "$module" \
            "El módulo terminó con código $exit_code."

        printf 'Error: fallo de ejecución en %s.\n' "$module" >&2
        HAS_ERRORS=1
        return 0
    fi

    # Se exige un único objeto con la envoltura acordada.
    if ! jq -e -s --arg module "$module" '
        if length != 1 then
            false
        elif (.[0] | type) != "object" then
            false
        else
            .[0] |
            .module == $module and
            (
                .status == "ok" or
                .status == "skipped" or
                .status == "error"
            ) and
            has("data")
        end
    ' "$pending" >/dev/null 2>&1; then
        rm -f -- "$pending"
        write_module_error "$module" "Respuesta JSON no válida."

        printf 'Error: respuesta no válida de %s.\n' "$module" >&2
        HAS_ERRORS=1
        return 0
    fi

    mv -- "$pending" "$result"

    if [[ "$(jq -r '.status' "$result")" == "error" ]]; then
        printf 'Error: %s devolvió un estado de error.\n' "$module" >&2
        HAS_ERRORS=1
    fi
}

generate_report() {
    local report_path="$RUN_DIR/report.$REPORT_FORMAT"

    if [[ "$REPORT_FORMAT" == "none" ]]; then
        printf '%s\n' "$RUN_DIR"
        return 0
    fi

    if ! python3 "$REPORT_GENERATOR" \
        --input "$RUN_DIR" \
        --format "$REPORT_FORMAT" \
        --output "$report_path" \
        >/dev/null 2>&1; then
        printf 'Error: no se pudo generar el informe. Resultados: %s\n' \
            "$RUN_DIR" >&2
        HAS_ERRORS=1
        return 0
    fi

    if [[ ! -s "$report_path" ]]; then
        printf 'Error: informe ausente o vacío. Resultados: %s\n' \
            "$RUN_DIR" >&2
        HAS_ERRORS=1
        return 0
    fi

    printf '%s\n' "$report_path"
}

handle_signal() {
    local exit_code="$1"

    # Elimina salidas incompletas, conservando los resultados terminados.
    if [[ -n "$RUN_DIR" ]]; then
        rm -f -- "$RUN_DIR"/raw/*.pending
        printf 'Ejecución interrumpida. Resultados parciales: %s\n' \
            "$RUN_DIR" >&2
    fi

    exit "$exit_code"
}

main() {
    local module

    parse_arguments "$@"
    validate_inputs
    select_modules
    check_dependencies

    trap 'handle_signal 130' INT
    trap 'handle_signal 143' TERM

    prepare_output

    for module in "${SELECTED_MODULES[@]}"; do
        run_module "$module"
    done

    generate_report

    return "$HAS_ERRORS"
}

main "$@"
