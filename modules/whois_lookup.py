#!/usr/bin/env python3

"""Consulta información WHOIS pública de un dominio."""

import argparse
import json
import re
import subprocess
import sys
from contextlib import redirect_stderr

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


class WhoisUtility:
    def run(self, domain):
        """Consulta WHOIS y devuelve la respuesta pública disponible."""

        domain = domain.strip().lower().removesuffix(".")

        result = {
            "module": "whois_lookup",
            "status": "ok",
            "data": {
                "domain": domain,
                "raw": "",
            },
        }

        labels = domain.split(".")
        valid_label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

        if (
            len(domain) > 253
            or len(labels) < 2
            or re.fullmatch(r"[0-9.]+", domain)
            or not all(re.fullmatch(valid_label, label) for label in labels)
        ):
            result["status"] = "error"
            result["message"] = "Dominio no válido."
            return result

        try:
            response = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )

            content = response.stdout.strip()
            success = response.returncode == 0 and bool(content)

            result["data"]["raw"] = content

            if not success:
                result["status"] = "error"
                result["message"] = (
                    "WHOIS terminó con error o no devolvió contenido."
                )

        except FileNotFoundError:
            result["status"] = "error"
            result["message"] = "No está instalada la utilidad whois."

        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["message"] = "La consulta WHOIS superó los 20 segundos."

        except OSError:
            result["status"] = "error"
            result["message"] = "No se pudo ejecutar la utilidad whois."

        return result

    def show(self, result):
        """Muestra la respuesta WHOIS en un panel."""

        console = Console()
        data = result["data"]

        console.rule(f"WHOIS · {data['domain']}")

        if result["status"] == "ok":
            console.print(
                Panel(
                    data.get("raw") or "Sin contenido.",
                    title="Respuesta WHOIS",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    result.get(
                        "message",
                        "No se pudo obtener información WHOIS.",
                    ),
                    title="Respuesta WHOIS",
                    border_style="red",
                )
            )

        console.print(
            Text(
                "La respuesta WHOIS es información pública del registro; "
                "no confirma la identidad del titular.",
                style="dim",
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Consulta información WHOIS de un dominio."
    )
    parser.add_argument("target")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()

    utility = WhoisUtility()
    result = utility.run(args.target)

    if args.live:
        with redirect_stderr(sys.stdout):
            utility.show(result)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
