#!/usr/bin/env python3

"""Consulta registros DNS de un dominio."""

import argparse
import json
import re
import sys
from contextlib import redirect_stderr

import dns.exception
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.text import Text


class DnsUtility:
    def run(self, domain):
        """Consulta los registros DNS del dominio indicado."""

        domain = domain.strip().lower().removesuffix(".")

        result = {
            "module": "dns_lookup",
            "status": "ok",
            "data": {
                "domain": domain,
                "records": {},
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

        record_types = (
            "A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"
        )

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5

            for record_type in record_types:
                try:
                    answers = resolver.resolve(
                        domain + ".",
                        record_type,
                        search=False,
                    )

                    result["data"]["records"][record_type] = {
                        "status": "ok",
                        "records": [answer.to_text() for answer in answers],
                    }

                except dns.resolver.NoAnswer:
                    result["data"]["records"][record_type] = {
                        "status": "no_records",
                        "records": [],
                    }

                except dns.resolver.NXDOMAIN:
                    result["data"]["records"][record_type] = {
                        "status": "not_found",
                        "records": [],
                        "message": "El nombre consultado no existe en DNS.",
                    }
                    break

                except dns.exception.DNSException:
                    result["status"] = "error"
                    result["data"]["records"][record_type] = {
                        "status": "error",
                        "records": [],
                        "message": "No se pudo completar la consulta DNS.",
                    }

        except dns.exception.DNSException:
            result["status"] = "error"
            result["data"]["records"] = {
                "status": "error",
                "message": "No se pudo configurar el resolver DNS.",
            }

        return result

    def show(self, result):
        """Muestra los registros DNS en una tabla."""

        console = Console()
        data = result["data"]

        console.rule(f"DNS · {data['domain']}")

        table = Table(title="Registros DNS", show_lines=True)
        table.add_column("Tipo")
        table.add_column("Estado")
        table.add_column("Registros")

        records = data["records"]

        # Cuando el resultado es un error global, no hay consultas por tipo.
        if "status" in records:
            console.print(
                Text(
                    records.get(
                        "message",
                        "No se pudieron realizar las consultas DNS.",
                    ),
                    style="red",
                )
            )
            return

        for record_type, query in records.items():
            status = query.get("status", "unknown")
            values = query.get("records", [])

            if status == "ok":
                color = "green"
            elif status == "no_records":
                color = "yellow"
            else:
                color = "red"

            table.add_row(
                record_type,
                Text(status, style=color),
                "\n".join(values) if values else "—",
            )

        console.print(table)

        if result["status"] != "ok":
            console.print(
                Text(
                    result.get(
                        "message",
                        "La consulta DNS terminó con errores.",
                    ),
                    style="yellow",
                )
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Consulta registros DNS de un dominio."
    )
    parser.add_argument("target")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()

    utility = DnsUtility()
    result = utility.run(args.target)

    if args.live:
        with redirect_stderr(sys.stdout):
            utility.show(result)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
