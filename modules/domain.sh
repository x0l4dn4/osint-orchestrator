#!/usr/bin/env bash
#
# Consulta registros DNS e información pública WHOIS.
#
# Uso:
#   bash modules/domain.sh --target example.org
#
# Dependencias:
#   Bash >= 4, jq, dig, whois, timeout y awk.
#
# Salida:
#   Un único objeto JSON por stdout.
#   Sin logs, archivos temporales ni mensajes de progreso.

set -euo pipefail

DOMAIN=""
HAS_ERRORS=0

DNS_RESULTS='[]'
WHOIS_RESULT='{}'

DNS_TIMEOUT=8
WHOIS_TIMEOUT=25

if (( BASH_VERSINFO[0] < 4 )); then
    printf '%s\n' \
        '{"module":"domain","status":"error","message":"Se requiere Bash 4 o superior.","data":{}}'
    exit 1
fi

# Sin jq se devuelve una respuesta estática válida.
if ! command -v jq >/dev/null 2>&1; then
    printf '%s\n' \
        '{"module":"domain","status":"error","message":"Dependencia no disponible: jq.","data":{}}'
    exit 1
fi

fail() {
    jq -n \
        --arg message "$1" \
        '{
            module: "domain",
            status: "error",
            message: $message,
            data: {}
        }'

    exit 1
}

parse_arguments() {
    while (( $# > 0 )); do
        case "$1" in
            --target)
                (( $# >= 2 )) \
                    || fail "La opción --target requiere un dominio."

                [[ -z "$DOMAIN" ]] \
                    || fail "La opción --target no puede repetirse."

                DOMAIN="${2,,}"
                shift 2
                ;;
            *)
                fail "Argumento no admitido."
                ;;
        esac
    done

    [[ -n "$DOMAIN" ]] \
        || fail "Debes proporcionar --target DOMINIO."
}

validate_domain() {
    local label
    local -a labels=()

    [[ ! "$DOMAIN" =~ [[:cntrl:]] ]] \
        || fail "El dominio contiene caracteres de control."

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
}

check_dependencies() {
    local dependency

    for dependency in dig whois timeout awk; do
        command -v "$dependency" >/dev/null 2>&1 \
            || fail "Dependencia no disponible: $dependency."
    done
}

query_dns() {
    local record_type="$1"
    local response=""
    local exit_code=0
    local rcode=""
    local status="ok"
    local message=""
    local answers=""
    local result=""

    # Se conserva la cabecera para interpretar el estado DNS.
    # El punto final evita consultas relativas al dominio de búsqueda local.
    response="$(
        timeout --kill-after=2s "${DNS_TIMEOUT}s" \
            dig "${DOMAIN}." "$record_type" \
                +time=3 \
                +tries=1 \
                +noall \
                +comments \
                +answer \
                2>/dev/null
    )" || exit_code=$?

    if (( exit_code != 0 )); then
        status="error"
        HAS_ERRORS=1

        case "$exit_code" in
            124|137)
                message="La consulta DNS superó el tiempo permitido."
                ;;
            *)
                message="No se pudo completar la consulta DNS."
                ;;
        esac
    elif [[ "$response" =~ status:\ ([A-Z0-9]+), ]]; then
        rcode="${BASH_REMATCH[1]}"

        case "$rcode" in
            NOERROR)
                ;;
            NXDOMAIN)
                message="El nombre consultado no existe según la respuesta DNS."
                ;;
            *)
                status="error"
                HAS_ERRORS=1
                message="El servidor DNS devolvió $rcode."
                ;;
        esac
    else
        status="error"
        HAS_ERRORS=1
        message="No se pudo interpretar el estado de la respuesta DNS."
    fi

    # Mantiene las respuestas en su representación textual DNS:
    # nombre, TTL, clase, tipo y valor.
    answers="$(
        printf '%s\n' "$response" |
            awk 'NF && $0 !~ /^;/ { print }' |
            jq -R . |
            jq -s .
    )"

    result="$(
        jq -n \
            --arg type "$record_type" \
            --arg status "$status" \
            --arg rcode "$rcode" \
            --arg message "$message" \
            --argjson exit_code "$exit_code" \
            --argjson answers "$answers" \
            '{
                type: $type,
                status: $status,
                rcode: (
                    if $rcode == "" then null else $rcode end
                ),
                message: (
                    if $message == "" then null else $message end
                ),
                exit_code: $exit_code,
                answers: $answers
            }'
    )"

    DNS_RESULTS="$(
        jq -c --argjson result "$result" \
            '. + [$result]' <<< "$DNS_RESULTS"
    )"
}

query_whois() {
    local response=""
    local exit_code=0
    local status="ok"
    local message=""

    response="$(
        timeout --kill-after=2s "${WHOIS_TIMEOUT}s" \
            whois "$DOMAIN" 2>/dev/null
    )" || exit_code=$?

    if (( exit_code != 0 )); then
        status="error"
        HAS_ERRORS=1

        case "$exit_code" in
            124|137)
                message="La consulta WHOIS superó el tiempo permitido."
                ;;
            *)
                message="No se pudo completar la consulta WHOIS."
                ;;
        esac
    elif [[ -z "${response//[[:space:]]/}" ]]; then
        status="error"
        HAS_ERRORS=1
        message="El servidor WHOIS no devolvió contenido."
    fi

    # Se conserva el texto original porque el formato depende del registro.
    # Un estado ok indica recepción de contenido, no verificación de identidad.
    WHOIS_RESULT="$(
        jq -n \
            --arg status "$status" \
            --arg message "$message" \
            --arg response "$response" \
            --argjson exit_code "$exit_code" \
            '{
                status: $status,
                message: (
                    if $message == "" then null else $message end
                ),
                exit_code: $exit_code,
                raw: $response
            }'
    )"
}

write_result() {
    local status="ok"

    if (( HAS_ERRORS != 0 )); then
        status="error"
    fi

    jq -n \
        --arg status "$status" \
        --arg domain "$DOMAIN" \
        --argjson dns "$DNS_RESULTS" \
        --argjson whois "$WHOIS_RESULT" \
        '{
            module: "domain",
            status: $status,
            data: {
                domain: $domain,
                dns: {
                    resolver: "system",
                    queries: $dns
                },
                whois: $whois
            }
        }'
}

main() {
    local record_type

    parse_arguments "$@"
    validate_domain
    check_dependencies

    for record_type in A AAAA MX NS TXT SOA CAA CNAME; do
        query_dns "$record_type"
    done

    query_whois
    write_result
}

main "$@"
