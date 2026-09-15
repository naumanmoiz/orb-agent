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
import json
import os
import sys
import urllib.parse
from typing import Any

try:
    import requests
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

    def __init__(self, url: str, token: str, dry_run: bool) -> None:
        self.url = url.rstrip("/")
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.planned: list[str] = []
        self.problems: list[str] = []
        self._version: str | None = None

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.session.request(method, f"{self.url}{path}", timeout=30, **kwargs)
        if not response.ok:
            raise SystemExit(f"{method} {path} failed with {response.status_code}: {response.text[:500]}")
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

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
            response = self.session.get(f"{self.url}/api/", timeout=30)
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
            # ERR_OPS_GENERATE_DIFF: a datetime value sent at a text field.
            problem = (f"custom field {name} is type {actual_type}, expected {field_type}. "
                       f"Change it in NetBox; this script will not retype a populated field.")
            nb.problems.append(problem)
            print(f"  ! WRONG   {problem}")
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


def collect_from_config(path: str) -> dict[str, str]:
    """Read the custom field names a config names.

    Reads both the agent-level shape (orb.policies.network_discovery.<name>) and
    the backend-level shape (policies.<name>) the backend itself receives, so the
    same script works against either file.
    """
    with open(path, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle) or {}

    policies = doc.get("policies")
    if policies is None:
        policies = (doc.get("orb") or {}).get("policies", {}).get("network_discovery", {})
    policies = policies or {}

    custom_fields = dict(BASE_CUSTOM_FIELDS)
    for policy in policies.values():
        config = (policy or {}).get("config") or {}
        for name in (config.get("custom_fields") or {}):
            custom_fields.setdefault(name, "text")
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
    args = parser.parse_args()

    if not args.url or not args.token:
        parser.error("NETBOX_URL and NETBOX_TOKEN must be set, or passed with --url/--token")

    custom_fields = collect_from_config(args.config) if args.config else dict(BASE_CUSTOM_FIELDS)

    nb = NetBox(args.url, args.token, args.dry_run)
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
