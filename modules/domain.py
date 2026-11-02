#!/usr/bin/env python3

"""Consulta DNS y WHOIS de un dominio y devuelve un resultado JSON."""

import argparse
import json
import re
import subprocess

import dns.exception
import dns.resolver


class DomainUtility:
    def run(self, domain):
        """Recopila información pública del dominio indicado."""

        domain = domain.strip().lower().removesuffix(".")

        result = {
            "module": "domain",
            "status": "ok",
            "data": {
                "domain": domain,
                "dns": {},
                "whois": {},
            },
        }

        # Validar el dominio antes de realizar consultas.
        labels = domain.split(".")
        valid_label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

        if (
            len(domain) > 253
            or len(labels) < 2
            or re.fullmatch(r"[0-9.]+", domain)
            or not all(re.fullmatch(valid_label, label) for label in labels)
        ):
            result["status"] = "error"
            result["message"] = (
                "Dominio no válido. Introduce un dominio ASCII o punycode "
                "sin protocolo, puerto ni rutas."
            )
            return result

        # Consultar los registros utilizando los resolvers del sistema.
        record_types = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME")

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

                    result["data"]["dns"][record_type] = {
                        "status": "ok",
                        "records": [answer.to_text() for answer in answers],
                    }

                except dns.resolver.NoAnswer:
                    result["data"]["dns"][record_type] = {
                        "status": "no_records",
                        "records": [],
                    }

                except dns.resolver.NXDOMAIN:
                    result["data"]["dns"][record_type] = {
                        "status": "not_found",
                        "records": [],
                        "message": "El nombre consultado no existe en DNS.",
                    }
                    # No repetir consultas para un nombre inexistente.
                    break

                except dns.exception.DNSException:
                    result["status"] = "error"
                    result["data"]["dns"][record_type] = {
                        "status": "error",
                        "records": [],
                        "message": "No se pudo completar la consulta DNS.",
                    }

        except dns.exception.DNSException:
            result["status"] = "error"
            result["data"]["dns"] = {
                "status": "error",
                "message": "No se pudo configurar el resolver DNS.",
            }

        # Ejecutar WHOIS sin shell y sin guardar logs.
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

            result["data"]["whois"] = {
                "status": "ok" if success else "error",
                "raw": content,
            }

            if not success:
                result["status"] = "error"
                result["data"]["whois"]["message"] = (
                    "WHOIS terminó con error o no devolvió contenido."
                )

        except FileNotFoundError:
            result["status"] = "error"
            result["data"]["whois"] = {
                "status": "error",
                "message": "No está instalada la utilidad whois.",
            }

        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["data"]["whois"] = {
                "status": "error",
                "message": "La consulta WHOIS superó los 20 segundos.",
            }

        except OSError:
            result["status"] = "error"
            result["data"]["whois"] = {
                "status": "error",
                "message": "No se pudo ejecutar la utilidad whois.",
            }

        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Consulta registros DNS y WHOIS de un dominio."
    )
    parser.add_argument("domain", help="Dominio que se desea consultar.")
    args = parser.parse_args()

    utility = DomainUtility()
    result = utility.run(args.domain)

    print(json.dumps(result, ensure_ascii=False, indent=2))
