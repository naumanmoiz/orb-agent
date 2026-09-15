#!/usr/bin/env python3
"""Create and verify the NetBox custom fields network_discovery writes.

Diode never creates custom field definitions. If an ingested entity references a
custom field that does not exist, the NetBox plugin rejects the plan and the
Diode reconciler reports ERR_OPS_GENERATE_DIFF, dropping the whole batch rather
than the offending field.

Idempotent: an existing field is left alone unless it is missing ipam.ipaddress,
and --dry-run reports what it would change without writing.

Usage:
    export NETBOX_URL=https://netbox.example.net
    export NETBOX_TOKEN=...
    python3 bootstrap_custom_fields.py --config ../../agent.example.yaml --dry-run
    python3 bootstrap_custom_fields.py --config ../../agent.example.yaml

Only the standard library plus requests and PyYAML are needed. pynetbox is not
used, because the object_types/content_types field name differs by NetBox major
version and talking to the REST API directly makes that difference explicit.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.parse
from typing import Any

try:
    import requests
    from requests import exceptions as requests_exceptions
except ImportError:  # pragma: no cover - dependency guidance
    sys.exit("requests is required: pip install requests PyYAML")

try:
    import yaml
except ImportError:  # pragma: no cover - dependency guidance
    sys.exit("PyYAML is required: pip install requests PyYAML")


# The fields the sample policy writes. Any further name found in --config is
# added as text, which is the only type inferable from a name alone.
BASE_CUSTOM_FIELDS: dict[str, str] = {
    "discovery_agent": "text",
    "discovery_policy": "text",
    "discovery_last_seen": "datetime",
    "discovery_source": "text",
}

# network_discovery emits IP addresses only, so this is the single model.
IPAM_OBJECT_TYPES = ["ipam.ipaddress"]


class NetBox:
    """Minimal NetBox REST client scoped to custom fields."""

    def __init__(self, url: str, token: str, dry_run: bool, verify: bool = True) -> None:
        self.url = url.rstrip("/")
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.planned: list[str] = []
        self.problems: list[str] = []
        self._version: str | None = None

    def _fail(self, what: str, err: Exception) -> "SystemExit":
        """Turn a transport failure into one actionable line.

        requests raises through urllib3, so the default traceback is dozens of
        frames of connection-pool internals with the cause on the last line. The
        hints below are the causes actually seen in practice, in order.
        """
        scheme = urllib.parse.urlparse(self.url).scheme
        lines = [f"error: {what} failed: {err}", f"  URL: {self.url}"]

        if isinstance(err, requests_exceptions.SSLError):
            lines += [
                "  TLS failed. If NetBox uses a self-signed or internal CA certificate,",
                "  re-run with --insecure, or point REQUESTS_CA_BUNDLE at your CA file.",
            ]
        elif isinstance(err, requests_exceptions.ConnectionError):
            lines.append("  Could not complete an HTTP conversation with that address. Usually:")
            if scheme == "http":
                lines.append("    - NetBox is serving HTTPS and the URL says http. Try https://")
            else:
                lines.append("    - NetBox is serving plain HTTP and the URL says https. Try http://")
            lines += [
                "    - wrong port (NetBox behind a proxy is often 443 or 8000, not the app port)",
                "    - a proxy or firewall closing the connection",
                f"  Check with:  curl -sS -o /dev/null -w '%{{http_code}}\\n' {self.url}/api/",
            ]
        elif isinstance(err, requests_exceptions.Timeout):
            lines.append("  The request timed out. The host is reachable but did not answer in 30s.")

        return SystemExit("\n".join(lines))

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self.session.request(method, f"{self.url}{path}", timeout=30, **kwargs)
        except requests_exceptions.RequestException as err:
            raise self._fail(f"{method} {path}", err) from None
        if response.status_code in (401, 403):
            # NetBox puts the discriminator in the body: "Invalid token" is a
            # different problem from a valid token without object permissions,
            # and the status code alone cannot tell them apart.
            detail = ""
            try:
                detail = str((response.json() or {}).get("detail", "")).strip()
            except ValueError:
                detail = response.text[:200].strip()

            lines = [f"error: {method} {path} returned {response.status_code}."]
            if detail:
                lines.append(f"  NetBox said: {detail}")

            lowered = detail.lower()
            if "token" in lowered or response.status_code == 401:
                lines += [
                    "  The token is missing, mistyped, expired, or restricted to other source IPs.",
                    "  Check it is set and not truncated:  echo \"${NETBOX_TOKEN:0:8}...\"",
                ]
            else:
                lines += [
                    "  The token authenticated but lacks permission on custom fields.",
                    "  Grant its user extras.view_customfield (plus extras.add_customfield and",
                    "  extras.change_customfield unless you only ever use --dry-run), or use a",
                    "  token belonging to a superuser.",
                ]
            lines.append(
                "  Confirm independently:\n"
                f"    curl -sS -H \"Authorization: Token $NETBOX_TOKEN\" {self.url}/api/extras/custom-fields/ | head -c 300"
            )
            raise SystemExit("\n".join(lines))
        if not response.ok:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                # An HTML error page means the URL is a web server but not a
                # NetBox API root; dumping the page body helps nobody.
                raise SystemExit(
                    f"error: {method} {path} returned {response.status_code} as "
                    f"{content_type or 'an unknown content type'}, not JSON.\n"
                    f"  URL: {self.url}\n"
                    "  That address answers HTTP but does not look like a NetBox API root.\n"
                    "  NETBOX_URL should be the base URL, without /api."
                )
            raise SystemExit(f"error: {method} {path} returned {response.status_code}: {response.text[:500]}")
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            raise SystemExit(
                f"error: {method} {path} did not return JSON.\n"
                f"  Got {response.headers.get('Content-Type', 'no content type')}. "
                "Is this URL really a NetBox API root?"
            ) from None

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        return self._request("GET", f"{path}{query}")

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self._request("POST", path, data=json.dumps(payload))

    def patch(self, path: str, payload: dict[str, Any]) -> Any:
        return self._request("PATCH", path, data=json.dumps(payload))

    @property
    def version(self) -> str:
        """The running NetBox version, from the API root status header."""
        if self._version is None:
            try:
                response = self.session.get(f"{self.url}/api/", timeout=30)
            except requests_exceptions.RequestException as err:
                raise self._fail("GET /api/", err) from None
            self._version = response.headers.get("API-Version") or ""
            if not self._version:
                status = self.get("/api/status/") or {}
                self._version = str(status.get("netbox-version", ""))
        return self._version

    @property
    def object_types_field(self) -> str:
        """The custom field key naming the models a field applies to.

        NetBox renamed content_types to object_types in 4.1. Sending the wrong
        one is accepted as an unknown key and silently produces a custom field
        attached to nothing, so it is resolved from the running version rather
        than guessed.
        """
        major, _, rest = self.version.partition(".")
        minor = rest.partition(".")[0]
        try:
            if (int(major), int(minor or 0)) >= (4, 1):
                return "object_types"
        except ValueError:
            pass
        return "content_types"

    def find(self, path: str, **filters: Any) -> dict[str, Any] | None:
        results = (self.get(path, filters) or {}).get("results") or []
        return results[0] if results else None


def ensure_custom_field(nb: NetBox, name: str, field_type: str) -> None:
    """Create a custom field, or report an existing one that does not match.

    A type mismatch is reported rather than corrected: changing the type of a
    populated custom field is destructive, so that is the operator's call.
    """
    key = nb.object_types_field
    existing = nb.find("/api/extras/custom-fields/", name=name)

    if existing:
        actual_type = (existing.get("type") or {}).get("value", "?")
        current = existing.get(key) or existing.get("content_types") or []
        current = [c if isinstance(c, str) else c.get("value", "") for c in current]
        missing = [t for t in IPAM_OBJECT_TYPES if t not in current]

        if actual_type != field_type:
            # This is the failure that reaches the reconciler as
            # ERR_OPS_GENERATE_DIFF. Either side can be the wrong one, so name
            # both: the type is inferred from the policy value, so a quoted
            # "312" against an integer field is fixed in the YAML, not in NetBox.
            problem = (f"custom field {name}: NetBox has {actual_type}, "
                       f"the policy will send {field_type}")
            nb.problems.append(problem)
            print(f"  ! WRONG   {problem}")
            print(f"             Fix one of the two:")
            print(f"               - change the custom field to {field_type} in NetBox, or")
            print(f"               - change the policy value so it is {actual_type}"
                  f"{_value_hint(actual_type)}")
            return

        if not missing:
            print(f"  ok       custom field {name} ({actual_type}) on {', '.join(current)}")
            return

        label = f"custom field {name}: add {', '.join(missing)}"
        if nb.dry_run:
            nb.planned.append(f"UPDATE {label}")
            print(f"  ~ update {label}")
            return
        nb.patch(f"/api/extras/custom-fields/{existing['id']}/",
                 {key: sorted(set(current) | set(IPAM_OBJECT_TYPES))})
        print(f"  updated  {label}")
        return

    payload = {
        "name": name,
        "label": name.replace("_", " ").title(),
        "type": field_type,
        key: IPAM_OBJECT_TYPES,
        "description": "Populated by orb-agent network_discovery",
        "filter_logic": "loose",
    }
    label = f"custom field {name} ({field_type}) on {', '.join(IPAM_OBJECT_TYPES)}"
    if nb.dry_run:
        nb.planned.append(f"CREATE {label}")
        print(f"  + create {label}")
        return
    created = nb.post("/api/extras/custom-fields/", payload)
    print(f"  created  {label} (id={created['id']})")


# Tokens the agent resolves itself. ${SCAN_TIMESTAMP} becomes a time.Time and
# lands on the datetime variant; the others are strings.
_TOKEN_TYPES = {
    "${SCAN_TIMESTAMP}": "datetime",
    "${AGENT_NAME}": "text",
    "${POLICY_NAME}": "text",
}


def infer_field_type(value: Any) -> str:
    """Map a policy value to the NetBox custom field type the agent will send.

    This mirrors the backend's own detection, which keys off the YAML type, not
    off the field name. Guessing "text" for everything would report an integer
    field such as lab_id as a mismatch, and worse, would let a quoted "312" look
    correct here and then be rejected by an integer field on ingest.
    """
    if isinstance(value, str):
        if value in _TOKEN_TYPES:
            return _TOKEN_TYPES[value]
        # Any other ${VAR} comes from the environment, which is always a string.
        return "text"
    if isinstance(value, bool):
        # Checked before int: bool is a subclass of int in Python.
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "decimal"
    if isinstance(value, (dict, list)):
        return "json"
    if isinstance(value, datetime.datetime):
        return "datetime"
    if isinstance(value, datetime.date):
        return "date"
    return "text"


def _value_hint(netbox_type: str) -> str:
    """A concrete YAML example for the type NetBox actually has."""
    hints = {
        "integer": " (unquoted, e.g. lab_id: 312)",
        "text": ' (quoted, e.g. lab_id: "312")',
        "boolean": " (e.g. true)",
        "decimal": " (e.g. 1.5)",
        "datetime": " (${SCAN_TIMESTAMP}, or an unquoted 2026-09-15T00:00:00Z)",
        "json": " (a YAML mapping or list)",
    }
    return hints.get(netbox_type, "")


def collect_from_config(path: str) -> dict[str, str]:
    """Read the custom field names a config names, with the type each will carry.

    Reads both the agent-level shape (orb.policies.network_discovery.<name>) and
    the backend-level shape (policies.<name>) the backend itself receives, so the
    same script works against either file.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            doc = yaml.safe_load(handle) or {}
    except OSError as err:
        raise SystemExit(f"error: cannot read --config {path}: {err}") from None
    except yaml.YAMLError as err:
        raise SystemExit(f"error: --config {path} is not valid YAML: {err}") from None

    policies = doc.get("policies")
    if policies is None:
        policies = (doc.get("orb") or {}).get("policies", {}).get("network_discovery", {})
    policies = policies or {}

    custom_fields = dict(BASE_CUSTOM_FIELDS)
    conflicts: dict[str, set[str]] = {}
    for policy in policies.values():
        config = (policy or {}).get("config") or {}
        for name, value in (config.get("custom_fields") or {}).items():
            inferred = infer_field_type(value)
            if name in custom_fields and custom_fields[name] != inferred:
                # Two policies sending different types to one field is a real
                # problem: whichever reconciles second is rejected.
                conflicts.setdefault(name, {custom_fields[name]}).add(inferred)
            custom_fields[name] = inferred

    for name, types in conflicts.items():
        print(f"  ! policies disagree on custom field {name}: {', '.join(sorted(types))}. "
              "One NetBox field cannot be both.", file=sys.stderr)
    return custom_fields


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="agent or policy YAML to read extra field names from")
    parser.add_argument("--dry-run", action="store_true", help="print what would change, write nothing")
    parser.add_argument("--url", default=os.environ.get("NETBOX_URL"),
                        help="NetBox base URL (default: $NETBOX_URL)")
    parser.add_argument("--token", default=os.environ.get("NETBOX_TOKEN"),
                        help="NetBox API token (default: $NETBOX_TOKEN)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification (self-signed or internal CA)")
    args = parser.parse_args()

    if not args.url or not args.token:
        parser.error("NETBOX_URL and NETBOX_TOKEN must be set, or passed with --url/--token")

    custom_fields = collect_from_config(args.config) if args.config else dict(BASE_CUSTOM_FIELDS)

    if args.insecure:
        # Only the operator can decide an internal CA is acceptable, so this is
        # opt-in; silence the per-request warning once they have.
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    nb = NetBox(args.url, args.token, args.dry_run, verify=not args.insecure)
    print(f"NetBox {nb.version or 'unknown version'} at {nb.url}")
    print(f"custom field object types key: {nb.object_types_field}")
    if args.dry_run:
        print("dry run: nothing will be written\n")

    print("custom fields:")
    for name in sorted(custom_fields):
        ensure_custom_field(nb, name, custom_fields[name])

    if args.dry_run and nb.planned:
        print(f"\ndry run summary: {len(nb.planned)} change(s) would be made")
        for line in nb.planned:
            print(f"  {line}")

    if nb.problems:
        print(f"\n{len(nb.problems)} field(s) need manual attention:")
        for line in nb.problems:
            print(f"  {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
