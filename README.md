Herramienta modular escrita en Bash y modulos en Python para recopilar información pública sobre dominios, nombres de usuario y direcciones de correo electrónico.

## Funcionalidades

| Opción | Módulo | Información |
|---|---|---|
| `-d DOMINIO` | `dns_lookup` | Registros DNS: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA` y `CNAME`. |
| `-w DOMINIO` | `whois_lookup` | Respuesta WHOIS pública del dominio. |
| `-u USERNAME` | `whatsmyname` | Búsqueda de perfiles públicos mediante el catálogo de WhatsMyName. |
| `-e EMAIL` | `breaches` | Brechas registradas para un correo en Have XposedOrNot. |
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
```

Cada módulo es una utilidad Python independiente. `main.sh` solo selecciona y ejecuta los módulos solicitados.

## Requisitos

- Python 3.9 o superior.
- `whois` instalado en el sistema.
- `curl` para descargar automáticamente el catálogo de WhatsMyName.

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

## Configurar WhatsMyName

No es necesario descargar el catálogo manualmente.

Al ejecutar:

```bash
./main.sh -u mi_usuario
```

la herramienta comprueba si existe `data/wmn-data.json`. Si no existe, lo descarga automáticamente desde el repositorio oficial de WhatsMyName.

Requisito: tener `curl` instalado.

Para actualizar el catálogo más adelante, elimina el archivo y vuelve a ejecutar una búsqueda con `-u`:

```bash
rm data/wmn-data.json
./main.sh -u mi_usuario
```

## Uso

```bash
./main.sh [entradas] [opciones]
```

<img width="400" alt="image" src="https://github.com/user-attachments/assets/f274cbd7-28d7-4ea2-8cc1-271d3f230de7" />

### Consultar DNS

```bash
./main.sh -d example.org
```
Muestra los registros DNS disponibles para el dominio.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/98930272-83bd-40f7-8b5e-c08919dfe2d0" />

### Consultar WHOIS

```bash
./main.sh -w example.org
```

Muestra la respuesta WHOIS pública del dominio.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/dba5c373-3942-4803-820f-4c955db3800a" />


### Buscar un username

```bash
./main.sh -u mi_usuario
```

Consulta el catálogo de WhatsMyName y muestra las coincidencias candidatas a medida que se reciben.

<img width="400" alt="image" src="https://github.com/user-attachments/assets/13cf16ac-fb92-4124-9c3d-0a83f43932dc" />

### Consultar brechas

```bash
./main.sh -e usuario@example.org
```

Consulta la API de [XposedOrNot](https://github.com/XposedOrNot/XposedOrNot-API)

<img width="400" alt="image" src="https://github.com/user-attachments/assets/b2d7041a-f44c-4fd9-b54a-b85df61285ea" />

### Combinar búsquedas

```bash
./main.sh -d example.org -w example.org -u mi_usuario -e usuario@example.org
```

Ejecuta los módulos en este orden:

```text
DNS → WHOIS → WhatsMyName → HIBP
```

### Ejecutar sin argumentos

```bash
./main.sh
```

Muestra el manual de uso.

## Guardar informes

Añade `-r` para conservar los resultados y generar un informe JSON:

```bash
./main.sh -d example.org -u mi_usuario -r
```

Los archivos se guardan en una carpeta con el nombre del primer objetivo y la fecha y hora de ejecución:

```text
results/
└── mi_usuario-20261103-230500/
    ├── dns_lookup.json
    ├── whatsmyname.json
    └── report.json
```

Solo se guardan los archivos correspondientes a los módulos ejecutados.

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
-h, --help       Mostrar ayuda.
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
