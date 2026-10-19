# osint-orchestrator

- [x0l4dn4](https://github.com/x0l4dn4) Generation of a structured report in HTML, PDF, and JSON.
- [Miguel](https://github.com/MiguelitoDelito) Display connections using Graphviz.
- [m00nbyt3](https://github.com/m00nbyt3) Extract data from different sources

## Visualizacion del grafo (`visualize.sh`)

Utilidad en bash que lee un informe JSON de hallazgos
(ver `Testing/sample_report.json`) y genera el grafo de conexiones en
formato Graphviz. Cubre el apartado *"Visualizar los resultados con graficos
simples o esquemas"*.

```bash
# Solo DOT (no requiere graphviz):
./visualize.sh -f dot -o grafo.dot Testing/sample_report.json

# Imagen SVG/PNG (requiere el paquete 'graphviz'):
./visualize.sh -o grafo.svg Testing/sample_report.json

# O renderizar un DOT ya generado:
dot -Tsvg grafo.dot -o grafo.svg
```

Qué hace: un color + una **forma** por tipo de entidad (con leyenda), línea
**continua** para confianza alta y **discontinua** para baja (umbral `-t`,
por defecto `0.7`), nodo **objetivo** destacado, y atributo `URL` + `tooltip`
(fuente y fecha) en los nodos con enlace.

Dependencias: `bash` 4+, y `jq` **o** `python3` para leer el JSON; `graphviz`
(`dot`) solo para renderizar la imagen (`sudo apt install graphviz jq`).
