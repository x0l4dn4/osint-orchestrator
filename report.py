#!/usr/bin/env python3

"""Muestra los resultados OSINT y guarda un informe cuando se solicita."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.text import Text


class ReportUtility:
    def run(self, directory, save=False):
        """Muestra los resultados y, opcionalmente, guarda report.json."""

        directory = Path(directory).resolve()

        if not directory.is_dir():
            raise ValueError("El directorio de resultados no existe.")

        report = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "ok",
            "results": {},
        }

        for module in ("domain", "usernames", "breaches"):
            source = directory / f"{module}.json"

            if not source.exists():
                continue

            try:
                with source.open(encoding="utf-8") as file:
                    data = json.load(file)

                if (
                    not isinstance(data, dict)
                    or data.get("module") != module
                    or data.get("status") not in ("ok", "skipped", "error")
                    or not isinstance(data.get("data"), dict)
                ):
                    raise ValueError("Estructura de resultado no válida.")

            except (OSError, ValueError, UnicodeError):
                data = {
                    "module": module,
                    "status": "error",
                    "message": "No se pudo leer un resultado JSON válido.",
                    "data": {},
                }

            report["results"][module] = data

        if not report["results"]:
            raise ValueError("No hay resultados disponibles.")

        statuses = {
            item["status"]
            for item in report["results"].values()
        }

        if "error" in statuses:
            report["status"] = "error"
        elif "skipped" in statuses:
            report["status"] = "partial"

        # Guardar únicamente cuando se ha solicitado.
        output = None

        if save:
            output = directory / "report.json"

            with output.open("w", encoding="utf-8") as file:
                json.dump(report, file, ensure_ascii=False, indent=2)
                file.write("\n")

        # Presentación en pantalla.
        console = Console()
        colors = {
            "ok": "green",
            "skipped": "yellow",
            "error": "red",
            "partial": "yellow",
        }

        console.rule("Resultados OSINT")

        console.print(
            Text(
                f"Estado general: {report['status']}",
                style=colors[report["status"]],
            )
        )

        for module, data in report["results"].items():
            console.print(
                Panel(
                    JSON(
                        json.dumps(data, ensure_ascii=False),
                        indent=2,
                    ),
                    title=module.upper(),
                    border_style=colors[data["status"]],
                )
            )

        if output is not None:
            console.print(Text(f"Informe guardado: {output}"))

        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Muestra resultados OSINT y guarda un informe opcional."
    )
    parser.add_argument(
        "directory",
        help="Directorio con los resultados de los módulos.",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Guardar también report.json.",
    )
    args = parser.parse_args()

    try:
        utility = ReportUtility()
        utility.run(args.directory, save=args.save)

    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
