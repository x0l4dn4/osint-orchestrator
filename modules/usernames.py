#!/usr/bin/env python3

"""Busca perfiles públicos mediante Sherlock y devuelve un resultado JSON."""

import argparse
import csv
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


class UsernamesUtility:
    def run(self, username):
        """Ejecuta Sherlock y devuelve las coincidencias encontradas."""

        username = username.strip().removeprefix("@")

        result = {
            "module": "usernames",
            "status": "ok",
            "data": {
                "username": username,
                "source": "sherlock",
                "identity_verified": False,
                "profiles": [],
                "sites_checked": 0,
                "indeterminate_sites": 0,
            },
        }

        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
            result["status"] = "error"
            result["message"] = "Nombre de usuario no válido."
            return result

        executable = shutil.which("sherlock")

        if executable is None:
            result["status"] = "error"
            result["message"] = "No se encuentra el comando sherlock."
            return result

        # Sherlock escribe sus resultados en una carpeta temporal.
        # La carpeta se elimina automáticamente al terminar.
        with tempfile.TemporaryDirectory(prefix="osint-usernames-") as folder:
            command = [
                executable,
                "--csv",
                "--folderoutput", folder,
                "--timeout", "10",
                "--no-color",
                "--",
                username,
            ]

            try:
                process = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=600,
                    check=False,
                )

                if process.returncode != 0:
                    result["status"] = "error"
                    result["message"] = "Sherlock terminó con un error."

            except subprocess.TimeoutExpired:
                result["status"] = "error"
                result["message"] = (
                    "Sherlock superó el límite de 10 minutos."
                )

            except OSError:
                result["status"] = "error"
                result["message"] = "No se pudo ejecutar Sherlock."
                return result

            # Leer también los resultados disponibles si hubo un fallo.
            csv_path = Path(folder) / f"{username}.csv"

            try:
                with csv_path.open(
                    encoding="utf-8-sig",
                    newline="",
                ) as file:
                    reader = csv.DictReader(file)
                    required = {"name", "url_user", "exists"}

                    if not required.issubset(reader.fieldnames or []):
                        result["status"] = "error"
                        result["message"] = (
                            "El CSV de Sherlock tiene un formato incompatible."
                        )
                        return result

                    for row in reader:
                        result["data"]["sites_checked"] += 1

                        state = (
                            (row.get("exists") or "")
                            .strip()
                            .lower()
                            .removeprefix("querystatus.")
                        )

                        if state == "claimed":
                            result["data"]["profiles"].append({
                                "platform": row.get("name"),
                                "url": row.get("url_user"),
                                "result": "candidate",
                                "identity_verified": False,
                            })

                        elif state not in ("available", "illegal"):
                            result["data"]["indeterminate_sites"] += 1

            except (OSError, csv.Error, UnicodeError):
                result["status"] = "error"
                result.setdefault(
                    "message",
                    "No se pudieron leer los resultados de Sherlock.",
                )

        # No presentar una búsqueda incompleta como totalmente satisfactoria.
        if result["data"]["indeterminate_sites"] > 0:
            result["status"] = "error"
            result.setdefault(
                "message",
                "Algunas plataformas no devolvieron un resultado concluyente.",
            )

        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Busca perfiles públicos por nombre de usuario."
    )
    parser.add_argument("username", help="Nombre de usuario que se buscará.")
    args = parser.parse_args()

    utility = UsernamesUtility()
    result = utility.run(args.username)

    print(json.dumps(result, ensure_ascii=False, indent=2))
