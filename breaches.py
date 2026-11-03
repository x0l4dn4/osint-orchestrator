#!/usr/bin/env python3

"""Consulta brechas y datos expuestos de un correo en XposedOrNot."""

import argparse
import json
import re
import sys
from contextlib import redirect_stderr
from urllib.parse import quote

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class BreachesUtility:
    """Consulta la API pública de XposedOrNot para un correo indicado."""

    API_BASE = "https://api.xposedornot.com/v1/check-email/"
    ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"
    TIMEOUT = (5, 20)

    def run(self, email):
        """Devuelve los nombres y detalles de brechas disponibles para email."""
        email = email.strip()
        result = {
            "module": "breaches",
            "status": "ok",
            "data": {
                "email": email,
                "source": "XposedOrNot",
                "found": None,
                "breaches": [],
            },
        }

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            result["status"] = "error"
            result["message"] = "Formato de correo electrónico no válido."
            return result

        return self.query_xposedornot(email, result)

    @staticmethod
    def _request_error(exc, result, endpoint_name):
        if isinstance(exc, requests.Timeout):
            result["status"] = "error"
            result["message"] = f"La consulta a {endpoint_name} superó el tiempo de espera."
        else:
            result["status"] = "error"
            result["message"] = f"No se pudo conectar con {endpoint_name}."
        return result

    def _get_json(self, url, *, params=None):
        """Hace una solicitud acotada; el llamador aplica la gestión de errores."""
        response = requests.get(
            url,
            headers={"User-Agent": "osint-practica/1.0", "Accept": "application/json"},
            params=params,
            timeout=self.TIMEOUT,
            allow_redirects=False,
        )
        return response

    @staticmethod
    def _list_values(value):
        """Convierte categorías expuestas en una lista, sin inventar etiquetas."""
        if isinstance(value, str):
            return [part.strip() for part in re.split(r"[;,]", value) if part.strip()]
        if isinstance(value, list):
            return [item for item in value if isinstance(item, str) and item.strip()]
        return []

    @staticmethod
    def _detail_rows(payload):
        """Extrae filas de detalle en variantes publicadas por XposedOrNot."""
        rows = []
        for key in ("exposedBreaches", "ExposedBreaches"):
            value = payload.get(key)
            if isinstance(value, list):
                rows.extend(row for row in value if isinstance(row, dict))
            elif isinstance(value, dict):
                for subkey in ("breaches_details", "breachesDetails", "breaches", "details"):
                    nested = value.get(subkey)
                    if isinstance(nested, list):
                        rows.extend(row for row in nested if isinstance(row, dict))
        # Algunas respuestas de la consulta detallada pueden exponer los objetos aquí.
        direct = payload.get("breaches")
        if isinstance(direct, list):
            for item in direct:
                if isinstance(item, dict):
                    rows.append(item)
                elif isinstance(item, list):
                    rows.extend(row for row in item if isinstance(row, dict))
        # El formato analytics documentado coloca BreachesSummary y ExposedBreaches
        # junto a campos en snake_case; algunos despliegues anidan detalles en summary.
        summary = payload.get("BreachesSummary") or payload.get("breachesSummary")
        if isinstance(summary, dict):
            for key in ("breaches_details", "breachesDetails", "breaches"):
                nested = summary.get(key)
                if isinstance(nested, list):
                    rows.extend(row for row in nested if isinstance(row, dict))
        return rows

    @staticmethod
    def _first(row, *keys):
        for key in keys:
            value = row.get(key)
            if value is not None and value != "":
                return value
        return None

    @classmethod
    def _canonical_detail(cls, row):
        name = cls._first(row, "breachID", "breachId", "breach", "name", "Name", "title", "Title")
        data_classes = cls._list_values(cls._first(
            row, "exposedData", "exposed_data", "xposed_data", "dataClasses", "data_classes", "DataClasses"
        ))
        return {
            "name": name,
            "title": cls._first(row, "title", "Title") or name,
            "domain": cls._first(row, "domain", "Domain"),
            "breach_date": cls._first(row, "breachedDate", "breached_date", "breachDate", "breach_date", "xposed_date"),
            "added_date": cls._first(row, "addedDate", "added_date", "dateAdded"),
            "data_classes": data_classes,
            "is_verified": cls._first(row, "verified", "isVerified", "IsVerified"),
            "is_sensitive": cls._first(row, "sensitive", "isSensitive", "IsSensitive"),
            "is_fabricated": cls._first(row, "fabricated", "isFabricated", "IsFabricated"),
            "is_retired": cls._first(row, "retired", "isRetired", "IsRetired"),
            "is_spam_list": cls._first(row, "spamList", "isSpamList", "IsSpamList"),
            "description": cls._first(row, "description", "Description"),
            "industry": cls._first(row, "industry", "Industry"),
            "risk": cls._first(row, "risk", "risk_label", "riskLabel"),
            "references": cls._first(row, "references", "reference", "References"),
            "exposed_records": cls._first(row, "exposedRecords", "exposed_records", "records"),
            "breach_type": cls._first(row, "breachType", "breach_type"),
            "password_risk": cls._first(row, "passwordRisk", "password_risk"),
        }

    @staticmethod
    def _name_groups(payload):
        value = payload.get("breaches")
        if not isinstance(value, list):
            return None
        names = []
        for group in value:
            if isinstance(group, list):
                if any(not isinstance(name, str) for name in group):
                    return None
                names.extend(group)
            elif isinstance(group, str):
                names.append(group)
            elif isinstance(group, dict):
                # Los objetos pueden ser una respuesta de detalle (se procesan abajo).
                continue
            else:
                return None
        return names

    @staticmethod
    def _merge_rows(names, detail_rows):
        records = {}
        order = []
        for name in names:
            key = name.casefold()
            if key not in records:
                records[key] = {
                    "name": name, "title": name, "domain": None,
                    "breach_date": None, "added_date": None,
                    "data_classes": [], "is_verified": None,
                    "is_sensitive": None, "is_fabricated": None,
                    "is_retired": None, "is_spam_list": None,
                    "description": None, "industry": None, "risk": None,
                    "references": None, "exposed_records": None,
                    "breach_type": None, "password_risk": None,
                }
                order.append(key)
        for raw in detail_rows:
            detail = BreachesUtility._canonical_detail(raw)
            name = detail.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            key = name.casefold()
            if key not in records:
                records[key] = {
                    "name": name, "title": name, "domain": None,
                    "breach_date": None, "added_date": None,
                    "data_classes": [], "is_verified": None,
                    "is_sensitive": None, "is_fabricated": None,
                    "is_retired": None, "is_spam_list": None,
                    "description": None, "industry": None, "risk": None,
                    "references": None, "exposed_records": None,
                    "breach_type": None, "password_risk": None,
                }
                order.append(key)
            for field, value in detail.items():
                if value is not None and value != []:
                    records[key][field] = value
        return [records[key] for key in order]

    @staticmethod
    def _has_date_and_categories(records):
        return bool(records) and all(
            row.get("breach_date") and row.get("data_classes") for row in records
        )

    def _analytics_fallback(self, email, result):
        """Pide analytics una vez cuando detalles/fechas faltan en check-email."""
        try:
            response = self._get_json(self.ANALYTICS_URL, params={"email": email})
        except requests.RequestException as exc:
            result["data"]["details_warning"] = (
                "No se pudieron completar fechas o categorías con breach-analytics."
            )
            if isinstance(exc, requests.Timeout):
                result["data"]["details_warning"] += " Tiempo de espera agotado."
            return result

        if response.status_code == 429:
            result["data"]["details_warning"] = "XposedOrNot limitó la consulta adicional (HTTP 429); se conservan los datos iniciales."
            result["data"]["analytics_retry_after"] = response.headers.get("Retry-After")
            return result
        if response.status_code != 200:
            result["data"]["details_warning"] = (
                f"breach-analytics no completó los detalles (HTTP {response.status_code}); "
                "se conservan los datos iniciales."
            )
            return result
        try:
            payload = response.json()
        except (ValueError, TypeError):
            result["data"]["details_warning"] = "breach-analytics devolvió JSON no válido; se conservan los datos iniciales."
            return result
        if not isinstance(payload, dict):
            result["data"]["details_warning"] = "Formato de breach-analytics no compatible; se conservan los datos iniciales."
            return result

        more_rows = self._detail_rows(payload)
        current = result["data"]["breaches"]
        merged = self._merge_rows([row["name"] for row in current], more_rows)
        result["data"]["breaches"] = merged
        # Analytics puede incluir xposed_data como resumen agregado, sin mapa
        # fiable por brecha. Se conserva aparte, sin asignarlo a cada entrada.
        for key in ("xposed_data", "xposedData"):
            if key in payload:
                result["data"]["exposed_data_summary"] = payload[key]
                break
        if not more_rows:
            result["data"]["details_warning"] = "La API no devolvió filas detalladas de breach-analytics."
        elif not self._has_date_and_categories(merged):
            result["data"]["details_warning"] = (
                "La respuesta de analytics no aportó fechas y/o categorías para todas las brechas. "
                "Solo se muestran los campos que devolvió la API."
            )
        return result

    def query_xposedornot(self, email, result):
        """Consulta primero detalles y solo amplía analytics si hace falta."""
        url = self.API_BASE + quote(email, safe="")
        try:
            response = self._get_json(url, params={"details": "true"})
        except requests.RequestException as exc:
            return self._request_error(exc, result, "XposedOrNot")

        result["data"]["http_status"] = response.status_code
        if response.status_code != 200:
            result["status"] = "error"
            messages = {
                400: "XposedOrNot rechazó el formato de la consulta.",
                401: "XposedOrNot no autorizó la consulta.",
                403: "XposedOrNot denegó la consulta.",
                404: "El endpoint de XposedOrNot no está disponible.",
                429: "Se ha alcanzado el límite de consultas de XposedOrNot.",
            }
            result["message"] = messages.get(
                response.status_code,
                f"XposedOrNot devolvió el código HTTP {response.status_code}.",
            )
            if response.status_code == 429:
                result["data"]["retry_after"] = response.headers.get("Retry-After")
            return result

        try:
            payload = response.json()
        except (ValueError, TypeError):
            result["status"] = "error"
            result["message"] = "XposedOrNot no devolvió una respuesta JSON válida."
            return result
        if not isinstance(payload, dict):
            result["status"] = "error"
            result["message"] = "El formato de la respuesta de XposedOrNot no es compatible."
            return result
        if payload.get("Error") == "Not found" and payload.get("email") is None:
            result["data"]["found"] = False
            return result
        if payload.get("status") not in (None, "success"):
            result["status"] = "error"
            result["message"] = "XposedOrNot devolvió una respuesta no reconocida."
            return result

        names = self._name_groups(payload)
        detailed = self._detail_rows(payload)
        if names is None and not detailed:
            result["status"] = "error"
            result["message"] = "El formato de brechas de XposedOrNot no es compatible."
            return result
        names = names or []
        result["data"]["breaches"] = self._merge_rows(names, detailed)
        result["data"]["found"] = bool(result["data"]["breaches"])

        # The free endpoint supports details=true. Analytics is a second request
        # only where date/category metadata is still missing, respecting its caps.
        if result["data"]["found"] and not self._has_date_and_categories(result["data"]["breaches"]):
            self._analytics_fallback(email, result)
        # Si persiste el faltante, se reporta como desconocido; no se rellena.
        if result["data"]["found"] and not self._has_date_and_categories(result["data"]["breaches"]):
            result["data"].setdefault(
                "details_warning",
                "La API no aportó fecha y/o categorías expuestas para todas las brechas.",
            )
        return result

    def show(self, result):
        """Muestra las brechas encontradas y los metadatos que devolvió la API."""
        console = Console()
        data = result["data"]
        console.rule(f"EMAIL · {data['email']}")

        if result["status"] == "skipped":
            console.print(Panel(result.get("message", "Consulta omitida."), title="XPOSEDORNOT", border_style="yellow"))
            return
        if result["status"] == "error":
            console.print(Panel(result.get("message", "La consulta falló."), title="XPOSEDORNOT", border_style="red"))
            return
        breaches = data["breaches"]
        if not breaches:
            console.print(Panel("No se han encontrado brechas para este correo.", title="XPOSEDORNOT", border_style="green"))
            return

        table = Table(title=f"{len(breaches)} brechas encontradas", show_lines=True)
        table.add_column("Brecha")
        table.add_column("Fecha de brecha")
        #table.add_column("Fecha añadida")
        table.add_column("Datos expuestos (categorías)")
        for breach in breaches:
            categories = breach.get("data_classes") or []
            table.add_row(
                str(breach.get("title") or breach.get("name") or "—"),
                str(breach.get("breach_date") or "—"),
                #str(breach.get("added_date") or "—"),
                ", ".join(categories) if categories else "—",
            )
        console.print(table)
        summary = data.get("exposed_data_summary")
        if summary:
            console.print(Text(
                "Resumen API de tipos expuestos (xposed_data): "
                + json.dumps(summary, ensure_ascii=False, separators=(",", ":")),
                style="dim",
            ))
        warning = data.get("details_warning")
        if warning:
            console.print(Text(warning, style="yellow"))
        console.print(Text(
            "Las categorías indican tipos de datos que la API asocia a cada brecha; "
            "no son credenciales concretas. Esta herramienta no obtiene contraseñas ni secretos.",
            style="dim",
        ))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Consulta exposición de un email en XposedOrNot (no recupera contraseñas)."
    )
    parser.add_argument("target")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()

    console = Console(stderr=True)
    utility = BreachesUtility()
    result = utility.run(args.target)
    if args.live:
        with redirect_stderr(sys.stdout):
            utility.show(result)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
