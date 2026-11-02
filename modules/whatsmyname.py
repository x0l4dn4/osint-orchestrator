#!/usr/bin/env python3

"""Busca perfiles con WhatsMyName y muestra coincidencias en tiempo real."""

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stderr
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.text import Text


class WhatsMyNameUtility:
    def run(self, username):
        """Consulta sitios en paralelo y devuelve los resultados."""

        username = username.strip().removeprefix("@")
        console = Console(stderr=True)

        result = {
            "module": "whatsmyname",
            "status": "ok",
            "data": {
                "username": username,
                "source": "WhatsMyName",
                "attribution": "Micah Hoffman y colaboradores de WhatsMyName",
                "license": "CC-BY-SA-4.0",
                "identity_verified": False,
                "profiles": [],
                "sites_checked": 0,
                "sites_skipped": 0,
                "not_found": 0,
                "indeterminate_sites": 0,
            },
        }

        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
            result["status"] = "error"
            result["message"] = "Nombre de usuario no válido."
            return result

        catalog = (
            Path(__file__).resolve().parent.parent
            / "data"
            / "wmn-data.json"
        )

        try:
            with catalog.open(encoding="utf-8") as file:
                sites = json.load(file)["sites"]

            if (
                not isinstance(sites, list)
                or not sites
                or not all(isinstance(site, dict) for site in sites)
            ):
                raise ValueError("Catálogo incompatible.")

        except (OSError, ValueError, KeyError, TypeError):
            result["status"] = "error"
            result["message"] = "No se pudo leer data/wmn-data.json."
            return result

        encoded_username = quote(username, safe="")

        def check_site(site):
            """Consulta una regla y devuelve su estado sin compartir estado."""

            template = site.get("uri_check")
            positive = site.get("e_string")
            negative = site.get("m_string")
            headers = site.get("headers") or {}
            payload = site.get("post_body")
            bad_characters = site.get("strip_bad_char") or ""

            if (
                site.get("valid") is False
                or site.get("cat") == "archived"
                or not isinstance(template, str)
                or not isinstance(positive, str)
                or not isinstance(negative, str)
                or not isinstance(headers, dict)
                or not isinstance(bad_characters, str)
                or not isinstance(site.get("e_code"), int)
                or not isinstance(site.get("m_code"), int)
                or (payload is not None and not isinstance(payload, str))
                or any(char in username for char in bad_characters)
            ):
                return "skipped", None

            url = template.replace("{account}", encoded_username)

            try:
                if urlsplit(url).scheme != "https":
                    return "skipped", None
            except ValueError:
                return "skipped", None

            request_headers = {"User-Agent": "osint-practica/1.0"}
            request_headers.update(headers)

            if payload is not None:
                payload = payload.replace(
                    "{account}", username
                ).encode("utf-8")

            try:
                with requests.request(
                    method="POST" if payload is not None else "GET",
                    url=url,
                    headers=request_headers,
                    data=payload,
                    timeout=(3, 5),
                    allow_redirects=False,
                ) as response:
                    text = response.text
                    code = response.status_code

            except (requests.RequestException, ValueError):
                return "unknown", None

            if code in (401, 403, 429):
                return "unknown", None

            exists = (
                code == site["e_code"]
                and (not positive or positive in text)
            )

            missing = (
                code == site["m_code"]
                and (not negative or negative in text)
            )

            if exists and not missing:
                profile_template = site.get("uri_pretty") or template

                if not isinstance(profile_template, str):
                    profile_template = template

                return "found", {
                    "platform": site.get("name"),
                    "category": site.get("cat"),
                    "url": profile_template.replace(
                        "{account}", encoded_username
                    ),
                    "source_url": url,
                    "http_status": code,
                    "result": "candidate",
                    "identity_verified": False,
                }

            if missing and not exists:
                return "not_found", None

            return "unknown", None

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(check_site, site)
                for site in sites
            ]

            for future in as_completed(futures):
                try:
                    state, profile = future.result()
                except Exception:
                    state, profile = "unknown", None

                if state == "skipped":
                    result["data"]["sites_skipped"] += 1
                    continue

                result["data"]["sites_checked"] += 1

                if state == "found":
                    result["data"]["profiles"].append(profile)

                    line = Text("[WhatsMyName] ", style="green")
                    line.append(str(profile["platform"]), style="bold")
                    line.append(f" → {profile['url']}")
                    console.print(line)

                elif state == "not_found":
                    result["data"]["not_found"] += 1

                else:
                    result["data"]["indeterminate_sites"] += 1

        result["data"]["profiles"].sort(
            key=lambda profile: str(profile["platform"]).lower()
        )

        if result["data"]["indeterminate_sites"] > 0:
            result["status"] = "error"
            result["message"] = (
                "Algunas consultas fueron indeterminadas. "
                "Se conservan las coincidencias obtenidas."
            )

        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Busca perfiles mediante WhatsMyName."
    )
    parser.add_argument("target")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()

    utility = WhatsMyNameUtility()

    if args.live:
        with redirect_stderr(sys.stdout):
            result = utility.run(args.target)

        Console().print(
            Panel(
                JSON(json.dumps(result, ensure_ascii=False)),
                title="USERNAME · WHATSMYNAME",
            )
        )
    else:
        result = utility.run(args.target)
        print(json.dumps(result, ensure_ascii=False, indent=2))
