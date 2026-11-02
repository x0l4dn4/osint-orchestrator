#!/usr/bin/env python3

"""Guarda el informe OSINT y muestra un resumen legible."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


class ReportUtility:
    def run(self, directory, save=False):
        """Guarda el informe y muestra un resumen de los resultados."""

        directory = Path(directory).resolve()

        if not directory.is_dir():
            raise ValueError("El directorio de resultados no existe.")

        report = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "ok",
            "results": {},
        }

        modules = ("dns_lookup", "whois_lookup", "whatsmyname", "breaches")

        for module in modules:
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

        output = None

        if save:
            output = directory / "report.json"

            with output.open("w", encoding="utf-8") as file:
                json.dump(report, file, ensure_ascii=False, indent=2)
                file.write("\n")

        self.show(console=Console(), report=report, output=output)
        return report

    def show(self, console, report, output):
        """Muestra un resumen por módulo."""

        colors = {
            "ok": "green",
            "skipped": "yellow",
            "error": "red",
            "partial": "yellow",
        }

        titles = {
            "dns_lookup": "Dominio · DNS",
            "whois_lookup": "Dominio · WHOIS",
            "whatsmyname": "Username · WhatsMyName",
            "breaches": "Email · HIBP",
        }

        console.rule("Informe OSINT")

        console.print(
            Text(
                f"Estado general: {report['status']}",
                style=colors[report["status"]],
            )
        )

        for module, data in report["results"].items():
            console.print(
                Panel(
                    self.module_summary(module, data),
                    title=titles[module],
                    border_style=colors[data["status"]],
                )
            )

        if output is not None:
            console.print(Text(f"Informe guardado: {output}"))

    def module_summary(self, module, data):
        """Genera una descripción breve para cada módulo."""

        result = data["data"]
        lines = []

        if module == "dns":
            lines.append(f"Dominio: {result.get('domain', '—')}")

            records = result.get("records", {})
            found = [
                record_type
                for record_type, query in records.items()
                if isinstance(query, dict) and query.get("records")
            ]

            lines.append(
                f"Tipos DNS con registros: {', '.join(found) or '—'}"
            )

        elif module == "whois":
            lines.append(f"Dominio: {result.get('domain', '—')}")
            lines.append(f"Estado: {data.get('status', 'desconocido')}")

        elif module == "whatsmyname":
            lines.append(f"Username: {result.get('username', '—')}")

            profiles = result.get("profiles", [])
            lines.append(f"Coincidencias candidatas: {len(profiles)}")

            for profile in profiles[:10]:
                lines.append(
                    f"• {profile.get('platform', '—')}: "
                    f"{profile.get('url', '—')}"
                )

            if len(profiles) > 10:
                lines.append(
                    f"• … y {len(profiles) - 10} coincidencias más."
                )

        elif module == "breaches":
            lines.append(f"Email: {result.get('email', '—')}")

            found = result.get("found")
            breaches = result.get("breaches", [])

            if found is True:
                lines.append(f"Brechas encontradas: {len(breaches)}")

                for breach in breaches[:10]:
                    lines.append(
                        f"• {breach.get('title') or breach.get('name')}: "
                        f"{breach.get('breach_date') or '—'}"
                    )

                if len(breaches) > 10:
                    lines.append(
                        f"• … y {len(breaches) - 10} brechas más."
                    )

            elif found is False:
                lines.append("No se encontraron brechas.")

            else:
                lines.append("No se pudo determinar el resultado.")

        if data.get("message"):
            lines.append(f"Mensaje: {data['message']}")

        return Text("\n".join(lines))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Guarda y muestra un informe OSINT."
    )
    parser.add_argument("directory")
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    try:
        utility = ReportUtility()
        utility.run(args.directory, save=args.save)

    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
