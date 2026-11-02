#!/usr/bin/env python3

"""Consulta brechas de un email en Have I Been Pwned."""

import argparse
import json
import os
import re
import sys
from contextlib import redirect_stderr
from urllib.parse import quote

import requests
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel


class BreachesUtility:
    def run(self, email):
        """Consulta HIBP y devuelve un diccionario con los resultados."""

        email = email.strip()

        result = {
            "module": "breaches",
            "status": "ok",
            "data": {
                "email": email,
                "source": "Have I Been Pwned",
                "found": None,
                "breaches": [],
            },
        }

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            result["status"] = "error"
            result["message"] = "Formato de correo electrónico no válido."
            return result

        api_key = os.environ.get("HIBP_API_KEY", "").strip()

        if not api_key:
            result["status"] = "skipped"
            result["message"] = (
                "No se ha configurado la variable HIBP_API_KEY."
            )
            return result

        url = (
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            + quote(email, safe="")
        )

        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "osint-practica/1.0",
            "Accept": "application/json",
        }

        try:
            response = requests.get(
                url,
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=(5, 20),
                allow_redirects=False,
            )

        except requests.Timeout:
            result["status"] = "error"
            result["message"] = "La consulta a HIBP superó el tiempo de espera."
            return result

        except requests.RequestException:
            result["status"] = "error"
            result["message"] = "No se pudo conectar con HIBP."
            return result

        result["data"]["http_status"] = response.status_code

        if response.status_code == 404:
            result["data"]["found"] = False
            return result

        if response.status_code != 200:
            result["status"] = "error"

            messages = {
                400: "HIBP rechazó el formato de la consulta.",
                401: "La clave de HIBP no es válida o no está autorizada.",
                403: "HIBP denegó el acceso a la consulta.",
                429: "Se ha alcanzado el límite de consultas de HIBP.",
            }

            result["message"] = messages.get(
                response.status_code,
                f"HIBP devolvió el código HTTP {response.status_code}.",
            )

            if response.status_code == 429:
                result["data"]["retry_after"] = response.headers.get(
                    "Retry-After"
                )

            return result

        try:
            breaches = response.json()
        except ValueError:
            result["status"] = "error"
            result["message"] = "HIBP no devolvió una respuesta JSON válida."
            return result

        if (
            not isinstance(breaches, list)
            or not all(isinstance(breach, dict) for breach in breaches)
        ):
            result["status"] = "error"
            result["message"] = "El formato de la respuesta no es compatible."
            return result

        result["data"]["found"] = bool(breaches)

        for breach in breaches:
            result["data"]["breaches"].append({
                "name": breach.get("Name"),
                "title": breach.get("Title"),
                "domain": breach.get("Domain"),
                "breach_date": breach.get("BreachDate"),
                "added_date": breach.get("AddedDate"),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified"),
                "is_sensitive": breach.get("IsSensitive"),
                "is_fabricated": breach.get("IsFabricated"),
                "is_retired": breach.get("IsRetired"),
                "is_spam_list": breach.get("IsSpamList"),
            })

        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Consulta la exposición de un email en HIBP."
    )
    parser.add_argument("target")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()

    utility = BreachesUtility()

    if args.live:
        with redirect_stderr(sys.stdout):
            result = utility.run(args.target)

        Console().print(
            Panel(
                JSON(json.dumps(result, ensure_ascii=False)),
                title="EMAIL · HAVE I BEEN PWNED",
            )
        )
    else:
        result = utility.run(args.target)
        print(json.dumps(result, ensure_ascii=False, indent=2))
