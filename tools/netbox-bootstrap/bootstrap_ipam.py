#!/usr/bin/env python3
"""Create the NetBox objects the network_discovery IPAM extension depends on.

Diode never creates custom field definitions. If a changeset references a custom
field that does not exist, the reconciler rejects it with ERR_OPS_GENERATE_DIFF
and the whole batch is lost, so the definitions have to exist first. The same is
true in practice for the ipam.Role and VLANGroup objects a policy names.

Everything here is idempotent: an object that already exists is left alone, and
an existing custom field only has missing object types added to it.

Usage:
    export NETBOX_URL=https://netbox.example.net
    export NETBOX_TOKEN=...
    python3 bootstrap_ipam.py --config ../../agent.example.yaml --dry-run
    python3 bootstrap_ipam.py --config ../../agent.example.yaml

Only the standard library plus requests and PyYAML are needed; pynetbox is not
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


# The custom fields the extension writes on every IPAddress and Prefix. Any
# further name found in the agent config is added to this set as text, which is
# the only type that can be inferred safely from a name alone.
BASE_CUSTOM_FIELDS: dict[str, str] = {
    "discovery_agent": "text",
    "discovery_policy": "text",
    "discovery_last_seen": "datetime",
    "discovery_source": "text",
}

IPAM_OBJECT_TYPES = ["ipam.ipaddress", "ipam.prefix"]


class NetBox:
    """Minimal NetBox REST client scoped to what this script creates."""

    def __init__(self, url: str, token: str, dry_run: bool) -> None:
        self.url = url.rstrip("/")
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self.planned: list[str] = []
        self._version: str | None = None

    # -- transport -----------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self.session.request(method, f"{self.url}{path}", timeout=30, **kwargs)
        if not response.ok:
            raise SystemExit(
                f"{method} {path} failed with {response.status_code}: {response.text[:500]}"
            )
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

    # -- version handling ----------------------------------------------------

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

    # -- idempotent helpers --------------------------------------------------

    def find(self, path: str, **filters: Any) -> dict[str, Any] | None:
        results = (self.get(path, filters) or {}).get("results") or []
        return results[0] if results else None

    def ensure(self, path: str, lookup: dict[str, Any], payload: dict[str, Any], label: str) -> None:
        existing = self.find(path, **lookup)
        if existing:
            print(f"  ok       {label} (exists, id={existing['id']})")
            return
        if self.dry_run:
            self.planned.append(f"CREATE {label}")
            print(f"  + create {label}")
            return
        created = self.post(path, payload)
        print(f"  created  {label} (id={created['id']})")


def slugify(value: str) -> str:
    """Lower-case, replacing each run of non-alphanumerics with one hyphen.

    Matches the slug the agent sends for a VLAN group, so the group this script
    creates is the one the agent then reconciles against rather than a second.
    """
    out: list[str] = []
    for char in value.strip().lower():
        if char.isalnum() and char.isascii():
            out.append(char)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).rstrip("-")


def ensure_custom_field(nb: NetBox, name: str, field_type: str) -> None:
    """Create a custom field, or widen an existing one to cover both models."""
    key = nb.object_types_field
    existing = nb.find("/api/extras/custom-fields/", name=name)
    if existing:
        current = existing.get(key) or existing.get("content_types") or []
        current = [c if isinstance(c, str) else c.get("value", "") for c in current]
        missing = [t for t in IPAM_OBJECT_TYPES if t not in current]
        if not missing:
            print(f"  ok       custom field {name} ({field_type})")
            return
        label = f"custom field {name}: add {', '.join(missing)}"
        if nb.dry_run:
            nb.planned.append(f"UPDATE {label}")
            print(f"  ~ update {label}")
            return
        nb.patch(
            f"/api/extras/custom-fields/{existing['id']}/",
            {key: sorted(set(current) | set(IPAM_OBJECT_TYPES))},
        )
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


def collect_from_config(path: str) -> tuple[dict[str, str], set[str], list[dict[str, str]]]:
    """Read the custom field names, ipam roles and VLAN groups a config names.

    Reads both the agent-level shape (orb.policies.network_discovery.<name>) and
    the backend-level shape (policies.<name>) that the backend itself receives,
    so the same script works against either file.
    """
    with open(path, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle) or {}

    policies = doc.get("policies")
    if policies is None:
        policies = (doc.get("orb") or {}).get("policies", {}).get("network_discovery", {})
    policies = policies or {}

    custom_fields = dict(BASE_CUSTOM_FIELDS)
    roles: set[str] = set()
    groups: list[dict[str, str]] = []
    seen_groups: set[tuple[str, str]] = set()

    def note_group(group: Any, default_site: str) -> None:
        if not group:
            return
        if isinstance(group, str):
            name, site = group, default_site
        else:
            name = group.get("name", "")
            site = group.get("scope_site") or default_site
        if not name:
            return
        key = (name, site)
        if key not in seen_groups:
            seen_groups.add(key)
            groups.append({"name": name, "site": site})

    for policy in policies.values():
        config = (policy or {}).get("config") or {}
        scope = (policy or {}).get("scope") or {}
        defaults = config.get("defaults") or {}
        default_site = defaults.get("site") or ""

        for name in (config.get("custom_fields") or {}):
            custom_fields.setdefault(name, "text")

        # defaults.role is the IPAddress role, which NetBox models as a fixed
        # choice (loopback, secondary, anycast, vip, vrrp, hsrp, glbp, carp)
        # rather than an ipam.Role object, so it is deliberately not collected.
        for role in ((defaults.get("prefix") or {}).get("role"),
                     (defaults.get("vlan") or {}).get("role")):
            if role:
                roles.add(role)
        note_group((defaults.get("vlan") or {}).get("group"), default_site)

        for entry in scope.get("subnet_map") or []:
            if entry.get("role"):
                roles.add(entry["role"])
            for name in (entry.get("custom_fields") or {}):
                custom_fields.setdefault(name, "text")
            vlan = entry.get("vlan") or {}
            if vlan.get("role"):
                roles.add(vlan["role"])
            note_group(vlan.get("group"), default_site)

    return custom_fields, roles, groups


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", help="agent or policy YAML to read extra names from")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be created, change nothing")
    parser.add_argument("--url", default=os.environ.get("NETBOX_URL"),
                        help="NetBox base URL (default: $NETBOX_URL)")
    parser.add_argument("--token", default=os.environ.get("NETBOX_TOKEN"),
                        help="NetBox API token (default: $NETBOX_TOKEN)")
    args = parser.parse_args()

    if not args.url or not args.token:
        parser.error("NETBOX_URL and NETBOX_TOKEN must be set, or passed with --url/--token")

    custom_fields = dict(BASE_CUSTOM_FIELDS)
    roles: set[str] = set()
    groups: list[dict[str, str]] = []
    if args.config:
        custom_fields, roles, groups = collect_from_config(args.config)

    nb = NetBox(args.url, args.token, args.dry_run)
    print(f"NetBox {nb.version or 'unknown version'} at {nb.url}")
    print(f"custom field object types key: {nb.object_types_field}")
    if args.dry_run:
        print("dry run: nothing will be written\n")

    print("custom fields:")
    for name in sorted(custom_fields):
        ensure_custom_field(nb, name, custom_fields[name])

    print("\nipam roles:")
    if not roles:
        print("  (none referenced)")
    for name in sorted(roles):
        nb.ensure("/api/ipam/roles/", {"slug": slugify(name)},
                  {"name": name, "slug": slugify(name)}, f"ipam role {name}")

    print("\nvlan groups:")
    if not groups:
        print("  (none referenced)")
    for group in groups:
        payload: dict[str, Any] = {"name": group["name"], "slug": slugify(group["name"])}
        label = f"vlan group {group['name']}"
        site_name = group["site"]
        if site_name:
            site = nb.find("/api/dcim/sites/", name=site_name)
            if not site:
                print(f"  ! skip   {label}: site {site_name} does not exist, create it first")
                continue
            # VLANGroup scope is a generic relation, so both halves are needed.
            payload["scope_type"] = "dcim.site"
            payload["scope_id"] = site["id"]
            label += f" scoped to site {site_name}"
        nb.ensure("/api/ipam/vlan-groups/", {"slug": payload["slug"]}, payload, label)

    if args.dry_run:
        print(f"\ndry run summary: {len(nb.planned)} change(s) would be made")
        for line in nb.planned:
            print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
