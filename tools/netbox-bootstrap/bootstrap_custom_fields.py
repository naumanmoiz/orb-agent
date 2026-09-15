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

# network_discovery emits IP addresses, and prefixes when a policy declares a
# subnet_map. Custom fields are written to both, so both must be attached.
IPAM_OBJECT_TYPES = ["ipam.ipaddress", "ipam.prefix"]


class NetBox:
    """Minimal NetBox REST client scoped to custom fields."""

    def __init__(self, url: str, token: str, dry_run: bool, verify: bool = True,
                 auth_scheme: str = "Token") -> None:
        self.url = url.rstrip("/")
        self.dry_run = dry_run
        self.auth_scheme = auth_scheme
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({
            "Authorization": f"{auth_scheme} {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.planned: list[str] = []
        self.problems: list[str] = []
        # Literal (non-token) values from the policy, for the select choice check.
        self.expected_values: dict[str, Any] = {}
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
                    f"  This request used the {self.auth_scheme} scheme. If your deployment issues",
                    "  bearer tokens (an nbt_ prefix is a hint), re-run with --auth-scheme Bearer.",
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

        if not types_compatible(actual_type, field_type):
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
            if actual_type == "select":
                _check_choice(nb, name, existing)
            return

        if actual_type == "select":
            _check_choice(nb, name, existing)

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


# NetBox types that hold a string and therefore accept what the backend sends as
# text. A select stores the chosen value verbatim in custom_field_data.
_STRING_TYPES = {"text", "longtext", "url", "select"}


def types_compatible(netbox_type: str, sending: str) -> bool:
    """Whether what the policy will send can land in this NetBox field."""
    if netbox_type == sending:
        return True
    return netbox_type in _STRING_TYPES and sending == "text"


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


def _check_choice(nb: "NetBox", name: str, field: dict[str, Any]) -> None:
    """Warn when a select field's configured value is not one of its choices.

    NetBox validates a select value in full_clean(), which the Diode NetBox
    plugin does not call, so an off-list value is written rather than rejected
    and then reads as invalid in the UI. Checking here is the only place it
    surfaces before the data lands.
    """
    configured = nb.expected_values.get(name)
    if configured is None:
        return
    choice_set = field.get("choice_set") or {}
    set_id = choice_set.get("id")
    if not set_id:
        return
    data = nb.get(f"/api/extras/custom-field-choice-sets/{set_id}/") or {}
    choices = [c[0] if isinstance(c, (list, tuple)) else c
               for c in (data.get("extra_choices") or [])]
    if not choices:
        return
    if str(configured) not in [str(c) for c in choices]:
        problem = (f"custom field {name}: the policy sends {configured!r}, which is not one of "
                   f"the choices in set {choice_set.get('name', set_id)} ({', '.join(map(str, choices))})")
        nb.problems.append(problem)
        print(f"  ! CHOICE  {problem}")
    else:
        print(f"             value {configured!r} is a valid choice")


def check_vrfs(nb: "NetBox", names: set[str]) -> None:
    """Report a VRF the policy names that NetBox does not have.

    Deliberately never creates one. The Diode NetBox plugin matches a VRF on
    name alone, and only while its rd and tenant are both null, so a name that
    does not already exist is silently created by the reconciler as an empty
    VRF. That looks like it worked and quietly splits a lab's address space
    across two VRFs, which is the failure this check exists to prevent.
    """
    if not names:
        return
    print("\nvrfs (verified, never created):")
    for name in sorted(names):
        existing = nb.find("/api/ipam/vrfs/", name=name)
        if not existing:
            problem = (f"VRF {name!r} does not exist. Diode would create an empty one rather than "
                       "match your prebuilt VRF. Create it in NetBox, or fix defaults.vrf.")
            nb.problems.append(problem)
            print(f"  ! MISSING {problem}")
            continue
        rd = existing.get("rd")
        tenant = existing.get("tenant")
        note = ""
        if rd:
            note = f", rd={rd}: the policy must set defaults.rd to exactly this or it will not match"
        elif tenant:
            note = ", which has a tenant: matching is then on (name, tenant)"
        print(f"  ok       VRF {name} (id={existing['id']}){note}")
        if rd:
            nb.problems.append(f"VRF {name} has rd={rd}; set defaults.rd to match, or matching fails")


def check_roles(nb: "NetBox", names: set[str]) -> None:
    """Create the ipam.Role objects a subnet_map names."""
    if not names:
        return
    print("\nipam roles:")
    for name in sorted(names):
        slug = slugify(name)
        existing = nb.find("/api/ipam/roles/", slug=slug)
        if existing:
            print(f"  ok       ipam role {name} (id={existing['id']})")
            continue
        if nb.dry_run:
            nb.planned.append(f"CREATE ipam role {name}")
            print(f"  + create ipam role {name}")
            continue
        created = nb.post("/api/ipam/roles/", {"name": name, "slug": slug})
        print(f"  created  ipam role {name} (id={created['id']})")


def slugify(value: str) -> str:
    """Lower-case, replacing each run of non-alphanumerics with one hyphen.

    Matches the slug the NetBox plugin generates from a Role name, so the role
    this script creates is the one the agent then reconciles against.
    """
    out: list[str] = []
    for char in value.strip().lower():
        if char.isalnum() and char.isascii():
            out.append(char)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).rstrip("-")


def _value_hint(netbox_type: str) -> str:
    """A concrete YAML example for the type NetBox actually has."""
    hints = {
        "integer": " (unquoted, e.g. lab_id: 312)",
        "text": ' (quoted, e.g. lab_id: "312")',
        "boolean": " (e.g. true)",
        "decimal": " (e.g. 1.5)",
        "datetime": " (${SCAN_TIMESTAMP}, or an unquoted 2026-09-15T00:00:00Z)",
        "json": " (a YAML mapping or list)",
        "select": ' (quoted, and one of the choice set values, e.g. lab_id: "312")',
    }
    return hints.get(netbox_type, "")


def collect_from_config(path: str) -> tuple[dict[str, str], dict[str, Any], set[str], set[str]]:
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
    values: dict[str, Any] = {}
    vrfs: set[str] = set()
    roles: set[str] = set()
    conflicts: dict[str, set[str]] = {}
    for policy in policies.values():
        config = (policy or {}).get("config") or {}
        scope = (policy or {}).get("scope") or {}
        defaults = config.get("defaults") or {}
        if defaults.get("vrf"):
            vrfs.add(defaults["vrf"])
        if (defaults.get("prefix") or {}).get("role"):
            roles.add(defaults["prefix"]["role"])
        for entry in scope.get("subnet_map") or []:
            if entry.get("role"):
                roles.add(entry["role"])
            for name, value in (entry.get("custom_fields") or {}).items():
                custom_fields.setdefault(name, infer_field_type(value))
                values.setdefault(name, value)
        for name, value in (config.get("custom_fields") or {}).items():
            inferred = infer_field_type(value)
            if name in custom_fields and custom_fields[name] != inferred:
                # Two policies sending different types to one field is a real
                # problem: whichever reconciles second is rejected.
                conflicts.setdefault(name, {custom_fields[name]}).add(inferred)
            custom_fields[name] = inferred
            # A ${TOKEN} is resolved at scan time, so only a literal can be
            # checked against a choice set here.
            if not (isinstance(value, str) and value.startswith("${")):
                values[name] = value

    for name, types in conflicts.items():
        print(f"  ! policies disagree on custom field {name}: {', '.join(sorted(types))}. "
              "One NetBox field cannot be both.", file=sys.stderr)
    return custom_fields, values, vrfs, roles


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
    parser.add_argument("--auth-scheme", default=os.environ.get("NETBOX_AUTH_SCHEME", "Token"),
                        choices=["Token", "Bearer"],
                        help="Authorization header scheme (default: Token, or $NETBOX_AUTH_SCHEME)")
    args = parser.parse_args()

    if not args.url or not args.token:
        parser.error("NETBOX_URL and NETBOX_TOKEN must be set, or passed with --url/--token")

    expected_values: dict[str, Any] = {}
    vrfs: set[str] = set()
    roles: set[str] = set()
    if args.config:
        custom_fields, expected_values, vrfs, roles = collect_from_config(args.config)
    else:
        custom_fields = dict(BASE_CUSTOM_FIELDS)

    if args.insecure:
        # Only the operator can decide an internal CA is acceptable, so this is
        # opt-in; silence the per-request warning once they have.
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    nb = NetBox(args.url, args.token, args.dry_run, verify=not args.insecure,
                auth_scheme=args.auth_scheme)
    nb.expected_values = expected_values
    print(f"NetBox {nb.version or 'unknown version'} at {nb.url} (auth: {nb.auth_scheme})")
    print(f"custom field object types key: {nb.object_types_field}")
    if args.dry_run:
        print("dry run: nothing will be written\n")

    print("custom fields:")
    for name in sorted(custom_fields):
        ensure_custom_field(nb, name, custom_fields[name])

    check_vrfs(nb, vrfs)
    check_roles(nb, roles)

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
