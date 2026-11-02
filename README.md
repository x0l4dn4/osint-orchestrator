Herramienta modular para recopilar información pública sobre dominios, nombres de usuario y direcciones de correo electrónico.

## Funcionalidades

| Opción | Módulo | Información |
|---|---|---|
| `-d DOMINIO` | `dns_lookup` | Registros DNS: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA` y `CNAME`. |
| `-w DOMINIO` | `whois_lookup` | Respuesta WHOIS pública del dominio. |
| `-u USERNAME` | `whatsmyname` | Búsqueda de perfiles públicos mediante el catálogo de WhatsMyName. |
| `-e EMAIL` | `breaches` | Brechas registradas para un correo en Have I Been Pwned. |
| `-r` | `report` | Guarda los resultados individuales y un informe JSON. |
| `-o DIRECTORIO` | `main.sh` | Define la carpeta de salida; requiere `-r`. |

Por defecto, los resultados se muestran en la terminal y **no se crean archivos de resultados**.

## Estructura

```text
osint/
├── main.sh
├── modules/
│   ├── dns_lookup.py
│   ├── whois_lookup.py
│   ├── whatsmyname.py
│   └── breaches.py
├── data/
│   └── wmn-data.json
├── report.py
├── requirements.txt
└── .gitignore
```

Cada módulo es una utilidad Python independiente. `main.sh` solo selecciona y ejecuta los módulos solicitados.

## Requisitos

- Python 3.9 o superior.
- `whois` instalado en el sistema.
- Una clave de API de Have I Been Pwned para la opción `-e`.

## Instalación

Crea y activa un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instala las dependencias Python:

```bash
python3 -m pip install -r requirements.txt
```

Descarga el catálogo de WhatsMyName:

```bash
mkdir -p data

curl --fail --silent --show-error \
    --output data/wmn-data.json \
    https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json
```

## Configurar HIBP

La consulta de brechas mediante HIBP requiere una clave de API.

Para introducirla en la sesión actual sin escribirla en el historial de comandos:

```bash
read -rsp "Clave de HIBP: " HIBP_API_KEY
printf '\n'
export HIBP_API_KEY
```

Si ejecutas `-e` sin la variable configurada, la herramienta preguntará si quieres introducirla. La clave se usará solo durante esa ejecución: no se guarda en disco ni aparece en el informe.

## Uso

```bash
./main.sh [entradas] [opciones]
```

### Consultar DNS

```bash
./main.sh -d example.org
```

Muestra los registros DNS disponibles para el dominio.

### Consultar WHOIS

```bash
./main.sh -w example.org
```

Muestra la respuesta WHOIS pública del dominio.

### Buscar un username

```bash
./main.sh -u mi_usuario
```

Consulta el catálogo de WhatsMyName y muestra las coincidencias candidatas a medida que se reciben.

### Consultar brechas

```bash
./main.sh -e usuario@example.org
```

Consulta HIBP. Si no hay clave configurada, preguntará si deseas introducirla.

### Combinar búsquedas

```bash
./main.sh -d example.org -w example.org -u mi_usuario -e usuario@example.org
```

Ejecuta los módulos en este orden:

```text
DNS → WHOIS → WhatsMyName → HIBP
```

### Ejecución sin entradas

```bash
./main.sh
```

Consulta DNS y WHOIS del dominio de ejemplo `example.org`.

## Guardar informes

Añade `-r` para conservar los resultados y generar un informe JSON:

```bash
./main.sh -d example.org -u mi_usuario -r
```

Los archivos se guardarán en:

```text
results/
└── run-XXXXXXXX/
    ├── dns_lookup.json
    ├── whatsmyname.json
    └── report.json
```

Para elegir otra carpeta:

```bash
./main.sh -d example.org -r -o ./informes
```

La opción `-o` requiere `-r`.

## Opciones

```text
-d DOMINIO       Consultar registros DNS.
-w DOMINIO       Consultar información WHOIS.
-u USERNAME      Buscar perfiles con WhatsMyName.
-e EMAIL         Consultar brechas mediante HIBP.
-r               Guardar resultados e informe JSON.
-o DIRECTORIO    Directorio de salida. Requiere -r.
-h               Mostrar ayuda.
```

## Estados de resultado

| Estado | Significado |
|---|---|
| `ok` | La consulta se completó correctamente. |
| `skipped` | El módulo no realizó la consulta; por ejemplo, falta la clave de HIBP. |
| `error` | La consulta falló, fue rechazada o el resultado no pudo interpretarse. |
| `partial` | El informe no contiene errores, pero algún módulo fue omitido. |

Un informe con estado `error` puede contener resultados válidos de otros módulos.

## Interpretación de resultados

- Una coincidencia de username es una **candidata**, no una confirmación de identidad.
- Que no aparezcan brechas no garantiza que un correo nunca haya estado expuesto.
- La respuesta WHOIS puede no incluir datos del titular por políticas de privacidad o restricciones del servidor.
- Los registros DNS reflejan la información publicada en el momento de la consulta.
- Los servicios externos pueden limitar, bloquear o cambiar sus respuestas.

## Limitaciones

La versión actual no incluye:

- Búsquedas por nombre completo o número de teléfono.
- Enumeración de subdominios.
- Consultas RDAP.
- Extracción de metadatos de documentos.
- Correlación automática entre entidades.
- Grafos de relaciones.
- Informes HTML o PDF.
- Reintentos automáticos.
- Interfaz web.

## Seguridad y privacidad

- No introduzcas identificadores de terceros sin autorización.
- Las consultas se envían a servicios externos: HIBP y las plataformas incluidas en el catálogo de WhatsMyName.
- No compartas tu clave de HIBP ni la añadas al repositorio.
- Revisa el contenido de `results/` o de la carpeta elegida con `-o` antes de publicar o compartir archivos.

## Licencias y atribución

- El catálogo de WhatsMyName se distribuye bajo licencia CC BY-SA 4.0 y requiere atribución a Micah Hoffman y colaboradores.
- Have I Been Pwned es un servicio externo con sus propias condiciones de uso y límites de API.
- Revisa las licencias y condiciones de las dependencias antes de publicar o redistribuir el proyecto.
