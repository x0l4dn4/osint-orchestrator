#!/usr/bin/env bash
#
# visualize.sh - Utilidad de visualizacion del osint-orchestrator
# ---------------------------------------------------------------
# Lee un informe JSON de hallazgos OSINT (ver Testing/sample_report.json)
# y genera un grafo de conexiones en formato Graphviz (DOT). Si la
# herramienta `dot` esta instalada, ademas renderiza una imagen (SVG/PNG).
#
# Es el apartado "Visualizar los resultados con graficos simples o esquemas"
# descrito en los requisitos del proyecto (rol de Miguel: mostrar conexiones
# con Graphviz).
#
# Lo que hace, segun HowItWorks.txt:
#   1. Lee el JSON, normaliza y deduplica entidades -> nodos y aristas.
#   2. Exporta a DOT (y a SVG/PNG si hay `dot`).
#   3. Estilos por tipo de entidad: forma y color distintos + leyenda.
#   4. Estilos por confianza: linea continua si es alta, discontinua si es baja.
#   5. Nodo objetivo (target) destacado.
#   6. Atributo URL en los nodos con enlace (perfiles, dominios) y tooltip
#      con la fuente y la fecha.
#
# Dependencias:
#   - bash 4+
#   - un parser de JSON: `jq` (recomendado) o, en su defecto, `python3`.
#   - `dot` (paquete graphviz) SOLO para renderizar la imagen; sin el se
#     genera igualmente el .dot, que se puede abrir despues en cualquier
#     maquina con graphviz.
#
# Uso:
#   ./visualize.sh informe.json
#   ./visualize.sh -o grafo.svg -f svg informe.json
#   ./visualize.sh -f dot -t 0.75 informe.json
#
# Opciones:
#   -o RUTA   Fichero de salida (por defecto: <informe>.svg o <informe>.dot).
#   -f FMT    Formato: svg | png | dot   (por defecto: svg; dot si no hay graphviz).
#   -t NUM    Umbral de confianza [0-1] para considerar una relacion "alta"
#             (linea continua). Por defecto 0.7.
#   -h        Ayuda.
#
set -euo pipefail

# ----------------------------------------------------------------------------
# Paleta y estilos (colores validados, un color + una FORMA por tipo, de modo
# que el tipo no dependa solo del color -> accesible tambien en escala de grises)
# ----------------------------------------------------------------------------
# Tipo de entidad -> "forma;color_relleno;color_texto"
style_for_type() {
  case "$1" in
    username)      echo "ellipse;#2a78d6;white" ;;
    social_account)echo "box;#1baf7a;white" ;;
    person)        echo "ellipse;#6250d6;white" ;;
    email)         echo "note;#eb6834;white" ;;
    domain)        echo "house;#008300;white" ;;
    ip)            echo "component;#184f95;white" ;;
    phone)         echo "cds;#e87ba4;black" ;;
    breach)        echo "octagon;#d03b3b;white" ;;
    organization)  echo "folder;#eda100;black" ;;
    *)             echo "box;#898781;white" ;;
  esac
}

# Descripcion legible de cada tipo para la leyenda
label_for_type() {
  case "$1" in
    username)       echo "Usuario / alias" ;;
    social_account) echo "Cuenta social / perfil" ;;
    person)         echo "Persona" ;;
    email)          echo "Correo" ;;
    domain)         echo "Dominio / subdominio" ;;
    ip)             echo "Direccion IP" ;;
    phone)          echo "Telefono" ;;
    breach)         echo "Brecha / filtracion" ;;
    organization)   echo "Organizacion" ;;
    *)              echo "$1" ;;
  esac
}

# ----------------------------------------------------------------------------
# Ayuda
# ----------------------------------------------------------------------------
usage() {
  sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# ----------------------------------------------------------------------------
# Parametros
# ----------------------------------------------------------------------------
OUT=""
FMT=""
THRESHOLD="0.7"

while getopts ":o:f:t:h" opt; do
  case "$opt" in
    o) OUT="$OPTARG" ;;
    f) FMT="$OPTARG" ;;
    t) THRESHOLD="$OPTARG" ;;
    h) usage 0 ;;
    \?) echo "Opcion no valida: -$OPTARG" >&2; usage 1 ;;
    :)  echo "La opcion -$OPTARG necesita un valor" >&2; usage 1 ;;
  esac
done
shift $((OPTIND - 1))

if [[ $# -lt 1 ]]; then
  echo "Error: falta el informe JSON de entrada." >&2
  usage 1
fi
INPUT="$1"

if [[ ! -r "$INPUT" ]]; then
  echo "Error: no se puede leer el fichero '$INPUT'." >&2
  exit 1
fi

# ----------------------------------------------------------------------------
# Deteccion de herramientas
# ----------------------------------------------------------------------------
has() { command -v "$1" >/dev/null 2>&1; }

HAVE_DOT=0
if has dot; then HAVE_DOT=1; fi

# Formato por defecto: svg si hay graphviz, si no dot
if [[ -z "$FMT" ]]; then
  if [[ $HAVE_DOT -eq 1 ]]; then FMT="svg"; else FMT="dot"; fi
fi
case "$FMT" in svg|png|dot) ;; *) echo "Formato no soportado: $FMT" >&2; exit 1 ;; esac

if [[ "$FMT" != "dot" && $HAVE_DOT -eq 0 ]]; then
  echo "Aviso: 'dot' (graphviz) no esta instalado; se generara solo el .dot." >&2
  echo "       Instalalo (p.ej. 'sudo apt install graphviz') para renderizar $FMT." >&2
  FMT="dot"
fi

# Salida por defecto: mismo nombre que el informe con la extension del formato
if [[ -z "$OUT" ]]; then
  base="${INPUT##*/}"; base="${base%.*}"
  OUT="${base}.${FMT}"
fi

# Si renderizamos imagen, el .dot es intermedio; si FMT=dot, OUT ya es el .dot
if [[ "$FMT" == "dot" ]]; then
  DOT_FILE="$OUT"
else
  DOT_FILE="$(mktemp -t osint_graph.XXXXXX.dot)"
  trap 'rm -f "$DOT_FILE"' EXIT
fi

# ----------------------------------------------------------------------------
# Extraccion de datos del JSON -> lineas TSV estables
# Campos por hallazgo (10, separados por tabulador):
#   e_type  e_value  r_type  r_value  relation  confidence  source  timestamp  display_name  platform
# El target se obtiene aparte.
# ----------------------------------------------------------------------------
# Los campos se separan con el ASCII Unit Separator (0x1F) en vez de tabulador:
# el tabulador es "espacio en blanco" para IFS y 'read' colapsaria los campos
# vacios consecutivos (p.ej. hallazgos con related_to/relation nulos),
# descuadrando las columnas. 0x1F no es whitespace, asi que preserva los vacios.
SEP=$'\x1f'

extract_findings() {
  if has jq; then
    jq -r '
      .findings[]? |
      [ (.entity.type // ""),
        (.entity.value // ""),
        (.related_to.type // ""),
        (.related_to.value // ""),
        (.relation // ""),
        (.confidence // 0),
        (.source // ""),
        (.timestamp // ""),
        (.entity.attrs.display_name // ""),
        (.entity.attrs.platform // "")
      ] | map(tostring | gsub("[\n\r]"; " ")) | join("\u001f")
    ' "$INPUT"
  elif has python3 || has python; then
    "$(has python3 && echo python3 || echo python)" - "$INPUT" <<'PY'
import json, sys
sys.stdout.reconfigure(encoding="utf-8")   # salida siempre UTF-8 (en Windows la consola puede ser cp1252)
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
def clean(x):
    return str(x).replace("\x1f", " ").replace("\n", " ").replace("\r", " ")
for f in data.get("findings", []):
    e = f.get("entity") or {}
    r = f.get("related_to") or {}
    a = e.get("attrs") or {}
    row = [e.get("type", ""), e.get("value", ""),
           r.get("type", ""), r.get("value", ""),
           f.get("relation") or "", f.get("confidence", 0),
           f.get("source", ""), f.get("timestamp", ""),
           a.get("display_name", ""), a.get("platform", "")]
    print("\x1f".join(clean(v) for v in row))
PY
  else
    echo "Error: necesito 'jq' o 'python3' para leer el JSON." >&2
    exit 1
  fi
}

extract_target() {
  if has jq; then
    jq -r '[ (.target.type // ""), (.target.value // "") ] | @tsv' "$INPUT"
  else
    "$(has python3 && echo python3 || echo python)" - "$INPUT" <<'PY'
import json, sys
sys.stdout.reconfigure(encoding="utf-8")
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
t = data.get("target") or {}
print("%s\t%s" % (t.get("type", ""), t.get("value", "")))
PY
  fi
}

# ----------------------------------------------------------------------------
# Utilidades de texto
# ----------------------------------------------------------------------------
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

# Escapa comillas y barras para una cadena DOT
dot_escape() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }

# Clave de nodo normalizada: "tipo|valor"  (normaliza correos/dominios/perfiles)
norm_key() {
  local type="$1" v; v="$(trim "$2")"
  case "$type" in
    email) v="${v,,}" ;;
    social_account) v="${v,,}"; v="${v%/}" ;;
    domain)
      v="${v,,}"; v="${v#http://}"; v="${v#https://}"; v="${v#www.}"; v="${v%/}" ;;
  esac
  printf '%s|%s' "$type" "$v"
}

# Valor "limpio" para mostrar (quita esquema y www de dominios/urls, recorta largo)
display_value() {
  local type="$1" v; v="$(trim "$2")"
  case "$type" in
    domain) v="${v#http://}"; v="${v#https://}"; v="${v#www.}"; v="${v%/}"; v="${v,,}" ;;
    social_account) v="${v#http://}"; v="${v#https://}"; v="${v%/}" ;;
    email) v="${v,,}" ;;
  esac
  if [[ ${#v} -gt 46 ]]; then v="${v:0:43}..."; fi
  printf '%s' "$v"
}

# URL navegable (solo perfiles y dominios con enlace)
url_for() {
  local type="$1" raw; raw="$(trim "$2")"
  case "$type" in
    social_account)
      [[ "$raw" == http*://* ]] && printf '%s' "$raw" ;;
    domain)
      if [[ "$raw" == http*://* ]]; then printf '%s' "$raw";
      else printf 'https://%s' "${raw#www.}"; fi ;;
  esac
}

# ----------------------------------------------------------------------------
# Construccion del grafo
# ----------------------------------------------------------------------------
declare -A NID            # clave -> id de nodo
declare -A N_TYPE         # id -> tipo
declare -A N_LABEL        # id -> etiqueta a mostrar (ya escapada)
declare -A N_URL          # id -> url (cruda)
declare -A N_TIP          # id -> tooltip (ya escapado)
declare -A N_RICH         # id -> 1 si la definicion viene de una entidad (no de related_to)
declare -A N_TARGET       # id -> 1 si es el objetivo
declare -A TYPES_SEEN     # tipo -> 1 (para la leyenda)
declare -A EDGE_SEEN      # "from>to>rel" -> 1 (dedup de aristas)
EDGE_LINES=()             # lineas DOT de aristas

NODE_SEQ=0                # contador de nodos creados
EDGE_COUNT=0             # contador de aristas
NODE_ID=""                # "valor de retorno" de get_node (evitamos $() = subshell)

# Crea (si hace falta) el nodo para tipo/valor y deja su id en la global NODE_ID.
# IMPORTANTE: NO se puede llamar dentro de $(...) porque modifica arrays globales
# y un subshell perderia esos cambios; por eso devuelve por variable, no por stdout.
# rich=1 cuando los datos proceden de .entity (enlace, tooltip, display_name...).
get_node() {
  local type="$1" value="$2" rich="$3" dname="${4:-}" platform="${5:-}" src="${6:-}" ts="${7:-}" conf="${8:-}"
  NODE_ID=""
  [[ -z "$type" || -z "$value" ]] && return 1

  local key id; key="$(norm_key "$type" "$value")"
  if [[ -n "${NID[$key]:-}" ]]; then
    id="${NID[$key]}"
  else
    NODE_SEQ=$((NODE_SEQ + 1)); id="n${NODE_SEQ}"
    NID[$key]="$id"
    N_TYPE[$id]="$type"
    TYPES_SEEN[$type]=1
  fi

  # Solo (re)escribimos etiqueta/tooltip/url si aun no hay datos ricos y ahora los tenemos,
  # o si nunca se definio la etiqueta.
  if [[ -z "${N_LABEL[$id]:-}" || ( "$rich" == "1" && -z "${N_RICH[$id]:-}" ) ]]; then
    local disp lbl tip url
    disp="$(display_value "$type" "$value")"
    lbl="$(dot_escape "$disp")"
    # Enriquecemos la etiqueta de perfiles con plataforma y nombre mostrado
    if [[ "$type" == "social_account" ]]; then
      [[ -n "$platform" ]] && lbl="$(dot_escape "[${platform^^}]")"'\n'"$lbl"
      [[ -n "$dname" ]] && lbl="$lbl"'\n'"$(dot_escape "$dname")"
    fi
    N_LABEL[$id]="$lbl"

    url="$(url_for "$type" "$value")"
    [[ -n "$url" ]] && N_URL[$id]="$url"

    tip=""
    [[ -n "$src" ]] && tip="fuente: $src"
    [[ -n "$ts" ]]  && tip="${tip:+$tip | }fecha: $ts"
    [[ -n "$conf" ]] && tip="${tip:+$tip | }confianza: $conf"
    [[ -n "$tip" ]] && N_TIP[$id]="$(dot_escape "$tip")"

    [[ "$rich" == "1" ]] && N_RICH[$id]=1
  fi

  NODE_ID="$id"
}

# --- Objetivo ---
TGT_LINE="$(extract_target)"
TGT_TYPE="$(printf '%s' "$TGT_LINE" | cut -f1)"
TGT_VALUE="$(printf '%s' "$TGT_LINE" | cut -f2)"
TGT_KEY=""
[[ -n "$TGT_TYPE" && -n "$TGT_VALUE" ]] && TGT_KEY="$(norm_key "$TGT_TYPE" "$TGT_VALUE")"

# --- Hallazgos ---
N_FINDINGS=0
while IFS="$SEP" read -r e_type e_value r_type r_value relation confidence source timestamp dname platform; do
  [[ -z "$e_type" && -z "$e_value" ]] && continue
  N_FINDINGS=$((N_FINDINGS + 1))

  get_node "$e_type" "$e_value" 1 "$dname" "$platform" "$source" "$timestamp" "$confidence" || continue
  eid="$NODE_ID"

  # El nodo relacionado (origen de la arista) puede no tener datos ricos aun.
  rid=""
  if [[ -n "$r_type" && -n "$r_value" ]]; then
    if get_node "$r_type" "$r_value" 0; then rid="$NODE_ID"; fi
  fi

  # Arista: related_to --(relation)--> entity
  if [[ -n "$rid" && -n "$relation" ]]; then
    ekey="${rid}>${eid}>${relation}"
    if [[ -z "${EDGE_SEEN[$ekey]:-}" ]]; then
      EDGE_SEEN[$ekey]=1
      # Estilo por confianza: continua si alta, discontinua si baja
      if awk -v c="$confidence" -v t="$THRESHOLD" 'BEGIN{exit !(c+0 >= t+0)}'; then
        estyle="solid"; ecolor="#52514e"; epw="1.6"
      else
        estyle="dashed"; ecolor="#898781"; epw="1.0"
      fi
      elabel="$(dot_escape "$relation")"
      etip="$(dot_escape "confianza: ${confidence} | fuente: ${source}")"
      EDGE_LINES+=("  ${rid} -> ${eid} [label=\"${elabel}\", style=${estyle}, color=\"${ecolor}\", fontcolor=\"#52514e\", penwidth=${epw}, labeltooltip=\"${etip}\", edgetooltip=\"${etip}\"];")
      EDGE_COUNT=$((EDGE_COUNT + 1))
    fi
  fi
done < <(extract_findings)

# Marcamos el objetivo
if [[ -n "$TGT_KEY" && -n "${NID[$TGT_KEY]:-}" ]]; then
  N_TARGET["${NID[$TGT_KEY]}"]=1
fi

# ----------------------------------------------------------------------------
# Escritura del DOT
# ----------------------------------------------------------------------------
{
  echo "// Grafo OSINT generado por visualize.sh"
  echo "// Objetivo: ${TGT_TYPE}=${TGT_VALUE}"
  echo "digraph osint {"
  echo "  charset=\"utf-8\";"
  echo "  rankdir=LR;"
  echo "  bgcolor=\"#fcfcfb\";"
  echo "  fontname=\"Segoe UI, Helvetica, Arial, sans-serif\";"
  echo "  node [fontname=\"Segoe UI, Helvetica, Arial, sans-serif\", fontsize=10, style=\"filled\", penwidth=1];"
  echo "  edge [fontname=\"Segoe UI, Helvetica, Arial, sans-serif\", fontsize=8];"
  echo "  labelloc=\"t\";"
  echo "  label=\"Conexiones OSINT - objetivo: $(dot_escape "$TGT_VALUE")\";"
  echo "  fontsize=14; fontcolor=\"#0b0b0b\";"
  echo ""

  # Nodos
  if ((NODE_SEQ > 0)); then
  for id in "${!N_TYPE[@]}"; do
    type="${N_TYPE[$id]}"
    IFS=';' read -r shape fill fontc <<< "$(style_for_type "$type")"
    label="${N_LABEL[$id]:-$id}"
    attrs="label=\"${label}\", shape=${shape}, fillcolor=\"${fill}\", fontcolor=\"${fontc}\", color=\"#0b0b0b22\""

    if [[ -n "${N_TARGET[$id]:-}" ]]; then
      # Nodo objetivo destacado
      attrs="label=\"${label}\", shape=doublecircle, fillcolor=\"#eda100\", fontcolor=\"black\", color=\"#d03b3b\", penwidth=3"
    fi

    [[ -n "${N_URL[$id]:-}" ]] && attrs="${attrs}, URL=\"${N_URL[$id]}\", target=\"_blank\""
    [[ -n "${N_TIP[$id]:-}" ]] && attrs="${attrs}, tooltip=\"${N_TIP[$id]}\""

    echo "  ${id} [${attrs}];"
  done
  fi

  echo ""
  # Aristas
  if ((EDGE_COUNT > 0)); then
  for line in "${EDGE_LINES[@]}"; do
    echo "$line"
  done
  fi

  echo ""
  # Leyenda: una muestra por tipo presente + nota de confianza
  echo "  subgraph cluster_legend {"
  echo "    label=\"Leyenda\"; fontsize=11; color=\"#c3c2b7\"; style=\"rounded\"; bgcolor=\"#f9f9f7\";"
  legseq=0
  if ((NODE_SEQ > 0)); then
  for type in "${!TYPES_SEEN[@]}"; do
    IFS=';' read -r shape fill fontc <<< "$(style_for_type "$type")"
    legseq=$((legseq + 1))
    echo "    leg${legseq} [label=\"$(dot_escape "$(label_for_type "$type")")\", shape=${shape}, fillcolor=\"${fill}\", fontcolor=\"${fontc}\", color=\"#0b0b0b22\"];"
  done
  fi
  echo "    legnote [shape=plaintext, style=\"\", fillcolor=\"none\", label=\"__ linea continua = confianza alta (>= ${THRESHOLD})\\l-- linea discontinua = confianza baja\\l\"];"
  echo "  }"

  echo "}"
} > "$DOT_FILE"

# ----------------------------------------------------------------------------
# Render (si procede) y resumen
# ----------------------------------------------------------------------------
if [[ "$FMT" != "dot" ]]; then
  dot "-T${FMT}" "$DOT_FILE" -o "$OUT"
fi

echo "OK: ${N_FINDINGS} hallazgos -> ${NODE_SEQ} nodos, ${EDGE_COUNT} aristas." >&2
echo "Salida: $OUT" >&2
