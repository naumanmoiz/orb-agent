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
    export NETBOX_TOKEN=...              # or "Bearer nbt_..." / "Token ..."
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


# Authorization schemes NetBox issues. Order matters only for the error text.
AUTH_SCHEMES = ("Token", "Bearer")


def split_auth(token: str, scheme: str) -> tuple[str, str, bool]:
    """Return (scheme, bare token, scheme_came_from_token) for the header.

    A token is very often exported with its scheme already attached, because
    that is exactly what the header looks like and what every curl example
    shows:

        export NETBOX_TOKEN="Bearer nbt_1234..."

    Prepending another scheme then produces "Authorization: Token Bearer
    nbt_1234...". NetBox does not report that as a malformed header — it reports
    an invalid token, so it reads like a wrong or expired credential and sends
    you looking in the wrong place. Worse, --auth-scheme Bearer, the obvious
    thing to reach for, makes it "Bearer Bearer ..." and changes nothing.

    So a scheme already on the token wins: the operator wrote the header value
    they wanted. It is echoed at startup rather than applied silently, since
    disagreeing with an explicit --auth-scheme should be visible.

    Also strips surrounding whitespace, which a token read from a file or a
    here-doc usually carries as a trailing newline and which makes the header
    invalid in a way nothing else here would explain.
    """
    token = token.strip()
    head, _, rest = token.partition(" ")
    rest = rest.strip()
    for known in AUTH_SCHEMES:
        if head.lower() == known.lower() and rest:
            return known, rest, True
    return scheme, token, False


class NetBox:
    """Minimal NetBox REST client scoped to custom fields."""

    def __init__(self, url: str, token: str, dry_run: bool, verify: bool = True,
                 auth_scheme: str = "Token") -> None:
        self.url = url.rstrip("/")
        self.dry_run = dry_run
        self.auth_scheme, token, self.scheme_from_token = split_auth(token, auth_scheme)
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({
            "Authorization": f"{self.auth_scheme} {token}",
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
                source = "taken from the token value" if self.scheme_from_token else "the default or --auth-scheme"
                lines += [
                    "  The token is missing, mistyped, expired, or restricted to other source IPs.",
                    "  Check it is set and not truncated:  echo \"${NETBOX_TOKEN:0:8}...\"",
                    f"  This request sent: Authorization: {self.auth_scheme} <token>  ({source}).",
                ]
                others = [s for s in AUTH_SCHEMES if s != self.auth_scheme]
                if others and not self.scheme_from_token:
                    lines.append(
                        f"  If your deployment issues {others[0].lower()} tokens (an nbt_ prefix is a hint), "
                        f"re-run with --auth-scheme {others[0]}."
                    )
            else:
                lines += [
                    "  The token authenticated but lacks permission on custom fields.",
                    "  Grant its user extras.view_customfield (plus extras.add_customfield and",
                    "  extras.change_customfield unless you only ever use --dry-run), or use a",
                    "  token belonging to a superuser.",
                ]
            # $NETBOX_TOKEN may already carry the scheme, in which case repeating
            # it here would reproduce the very double-scheme header this avoids.
            credential = "$NETBOX_TOKEN" if self.scheme_from_token else f"{self.auth_scheme} $NETBOX_TOKEN"
            lines.append(
                "  Confirm independently:\n"
                f"    curl -sS -H \"Authorization: {credential}\" {self.url}/api/extras/custom-fields/ | head -c 300"
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


def check_vrfs(nb: "NetBox", configured: dict[str, dict[str, str]]) -> None:
    """Verify every VRF a policy names, and report the config it needs.

    Deliberately never creates one. The Diode NetBox plugin chooses its VRF
    matcher from the fields the payload carries, and skips any criterion whose
    fields are not all present, so the reference has to mirror the prebuilt
    VRF's own shape:

        reference      -> searches VRFs with
        name              rd IS NULL and tenant IS NULL
        name + tenant     rd IS NULL and tenant set
        name + rd         NetBox's rd unique constraint

    Point a name-only reference at a VRF that has a tenant or an rd and nothing
    matches. Diode then creates a second, empty VRF of the same name, which
    reads as success while splitting the lab's address space in two. This check
    is the only place that mismatch surfaces before the data lands.
    """
    if not configured:
        return
    print("\nvrfs (verified, never created):")
    for name in sorted(configured):
        policy = configured[name]
        existing = nb.find("/api/ipam/vrfs/", name=name)
        if not existing:
            problem = (f"VRF {name!r} does not exist. Diode would create an empty one rather than "
                       "match a prebuilt VRF. Create it in NetBox, or fix defaults.vrf.")
            nb.problems.append(problem)
            print(f"  ! MISSING {problem}")
            continue

        actual_rd = existing.get("rd") or ""
        actual_tenant = (existing.get("tenant") or {}).get("name", "") or ""
        want_rd = policy.get("rd", "")
        want_tenant = policy.get("vrf_tenant", "")

        if actual_rd == want_rd and actual_tenant == want_tenant:
            shape = "name only" if not (actual_rd or actual_tenant) else \
                ", ".join(filter(None, ["name", f"rd={actual_rd}" if actual_rd else "",
                                        f"tenant={actual_tenant}" if actual_tenant else ""]))
            print(f"  ok       VRF {name} (id={existing['id']}), matched on {shape}")
            continue

        lines = [f"VRF {name} exists (id={existing['id']}) but the policy will not match it."]
        lines.append(f"    NetBox has: rd={actual_rd or 'null'}, tenant={actual_tenant or 'null'}")
        lines.append(f"    policy has: rd={want_rd or 'unset'}, vrf_tenant={want_tenant or 'unset'}")
        lines.append("    Diode would create a SECOND VRF with this name. Set in defaults:")
        if actual_rd:
            lines.append(f"      rd: \"{actual_rd}\"")
        if actual_tenant:
            lines.append(f"      vrf_tenant: \"{actual_tenant}\"")
        if not actual_rd and not actual_tenant:
            lines.append("      (remove rd and vrf_tenant; this VRF matches on name alone)")
        problem = lines[0]
        nb.problems.append(problem)
        print(f"  ! MISMATCH {lines[0]}")
        for extra in lines[1:]:
            print(f"        {extra}")


def check_tenants(nb: "NetBox", configured: dict[str, str]) -> None:
    """Verify every tenant a policy names, and report the group it needs.

    NetBox makes Tenant unique on (group, name) with nulls_distinct=False, which
    the plugin turns into a matcher where an absent group means "group IS NULL"
    rather than "any group". A group-less reference cannot find a tenant that
    sits in a group, so Diode creates a second tenant of the same name outside
    it and hangs the objects off that. Same failure as the VRF, one level down,
    and just as silent.
    """
    if not configured:
        return
    print("\ntenants (verified, never created):")
    for name in sorted(configured):
        want_group = configured[name] or ""
        existing = nb.find("/api/tenancy/tenants/", name=name)
        if not existing:
            problem = (f"tenant {name!r} does not exist. Diode would create one rather than match "
                       "a prebuilt tenant. Create it in NetBox, or fix defaults.tenant.")
            nb.problems.append(problem)
            print(f"  ! MISSING {problem}")
            continue
        actual_group = (existing.get("group") or {}).get("name", "") or ""
        if actual_group == want_group:
            shape = f"group {actual_group}" if actual_group else "no group"
            print(f"  ok       tenant {name} (id={existing['id']}), matched on name within {shape}")
            continue
        problem = f"tenant {name} exists (id={existing['id']}) but the policy will not match it."
        nb.problems.append(problem)
        print(f"  ! MISMATCH {problem}")
        print(f"            NetBox has: group={actual_group or 'null'}")
        print(f"            policy has: tenant_group={want_group or 'unset'}")
        print("            Diode would create a SECOND tenant with this name. Set in defaults:")
        if actual_group:
            print(f'              tenant_group: "{actual_group}"')
        else:
            print("              (remove tenant_group; this tenant has none)")


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


def collect_from_config(path: str) -> tuple[dict[str, str], dict[str, Any], dict[str, dict[str, str]], dict[str, str], set[str]]:
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
    vrfs: dict[str, dict[str, str]] = {}
    tenants: dict[str, str] = {}
    roles: set[str] = set()
    prefixes: list[tuple[str, str]] = []
    conflicts: dict[str, set[str]] = {}
    vrf_conflicts: dict[str, set[str]] = {}
    for policy in policies.values():
        config = (policy or {}).get("config") or {}
        scope = (policy or {}).get("scope") or {}
        defaults = config.get("defaults") or {}
        group = defaults.get("tenant_group", "") or ""
        for key in ("tenant", "vrf_tenant"):
            if defaults.get(key):
                tenants[defaults[key]] = group
        if (defaults.get("prefix") or {}).get("tenant"):
            tenants[defaults["prefix"]["tenant"]] = group
        if defaults.get("vrf"):
            add_vrf(vrfs, defaults["vrf"], defaults.get("rd"), defaults.get("vrf_tenant"), vrf_conflicts)
        if (defaults.get("prefix") or {}).get("role"):
            roles.add(defaults["prefix"]["role"])
        for entry in scope.get("subnet_map") or []:
            # An entry's vrf brings its own rd and vrf_tenant; it never inherits
            # the defaults', because the three describe one VRF and a mixed
            # reference matches none. The agent enforces the same rule.
            entry_group = entry.get("tenant_group", "") or group
            if entry.get("vrf"):
                add_vrf(vrfs, entry["vrf"], entry.get("rd"), entry.get("vrf_tenant"), vrf_conflicts)
                if entry.get("vrf_tenant"):
                    tenants[entry["vrf_tenant"]] = entry_group
            if entry.get("tenant"):
                tenants[entry["tenant"]] = entry_group
            if entry.get("role"):
                roles.add(entry["role"])
            if entry.get("prefix"):
                prefixes.append((entry["prefix"], entry.get("vrf") or defaults.get("vrf") or ""))
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

    # str() before sorting, deliberately. These sets are built from values a
    # config supplied, so a YAML type nobody anticipated can land in one, and
    # sorted() on a mixed set raises TypeError. Crashing here would be the worst
    # possible place: this loop exists to report a config problem, so a traceback
    # replaces the diagnosis with a stack trace pointing at the messenger.
    for name, types in conflicts.items():
        print(f"  ! policies disagree on custom field {name}: {_join(types)}. "
              "One NetBox field cannot be both.", file=sys.stderr)
    for name, shapes in vrf_conflicts.items():
        # At most one of the shapes can match the real VRF; the other creates a
        # duplicate of the same name, silently.
        print(f"  ! policies describe {name} two ways: {_join(shapes, '; ')}. "
              "Only one can match the VRF that exists.", file=sys.stderr)
    return custom_fields, values, vrfs, tenants, roles, prefixes


def _join(values: "set[Any]", separator: str = ", ") -> str:
    """Render a set of reported values, whatever types it ended up holding."""
    return separator.join(sorted(str(value) for value in values))


def add_vrf(vrfs: dict[str, dict[str, str]], name: str, rd: Any, vrf_tenant: Any,
            vrf_conflicts: dict[str, set[str]]) -> None:
    """Record one VRF reference, flagging two policies that describe it differently.

    A VRF name reached with two different (rd, vrf_tenant) shapes cannot be
    right for both: at most one shape matches the real VRF, and the other
    creates a duplicate.
    """
    shape = {"rd": rd or "", "vrf_tenant": vrf_tenant or ""}
    existing = vrfs.get(name)
    if existing is not None and existing != shape:
        vrf_conflicts.setdefault(f"VRF {name}", set()).update(
            f"rd={shape_fields['rd'] or 'unset'}, vrf_tenant={shape_fields['vrf_tenant'] or 'unset'}"
            for shape_fields in (existing, shape))
        return
    vrfs[name] = shape


def check_prefixes(nb: "NetBox", declared: list[tuple[str, str]]) -> None:
    """Report which declared prefixes NetBox already holds, and which it does not.

    Not a pass/fail check: creating a prefix that does not exist is the point of
    subnet_map. It is here because "created only when missing" is a claim an
    operator should be able to see rather than take on trust, and because a
    prefix listed as missing that the operator believes exists is the visible
    end of a VRF reference that will not match.

    Matched the way the plugin matches: on (prefix, vrf). A prefix with no VRF
    is matched globally by CIDR, so a VRF-less entry can silently adopt another
    lab's prefix — reported as such.
    """
    if not declared:
        return
    print("\nsubnet_map prefixes (created only when missing):")
    for cidr, vrf in sorted(set(declared)):
        query = {"prefix": cidr}
        if vrf:
            query["vrf"] = vrf
        else:
            query["vrf_id"] = "null"
        existing = nb.find("/api/ipam/prefixes/", **query)
        where = f"in VRF {vrf}" if vrf else "with no VRF (matched globally by CIDR)"
        if existing:
            print(f"  ok       prefix {cidr} exists {where} (id={existing['id']}); it will be updated, not created")
        else:
            print(f"  + create prefix {cidr} does not exist {where}; Diode will create it")
            if not vrf:
                nb.problems.append(
                    f"prefix {cidr} is declared with no VRF. It is matched globally by CIDR, so two "
                    "labs sharing address space collapse onto one NetBox prefix. Set defaults.vrf, "
                    "or the entry's own vrf.")


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
    vrfs: dict[str, dict[str, str]] = {}
    tenants: dict[str, str] = {}
    roles: set[str] = set()
    prefixes: list[tuple[str, str]] = []
    if args.config:
        custom_fields, expected_values, vrfs, tenants, roles, prefixes = collect_from_config(args.config)
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
    scheme_note = f"{nb.auth_scheme}, from the token value" if nb.scheme_from_token else nb.auth_scheme
    print(f"NetBox {nb.version or 'unknown version'} at {nb.url} (auth: {scheme_note})")
    print(f"custom field object types key: {nb.object_types_field}")
    if args.dry_run:
        print("dry run: nothing will be written\n")

    print("custom fields:")
    for name in sorted(custom_fields):
        ensure_custom_field(nb, name, custom_fields[name])

    check_vrfs(nb, vrfs)
    check_tenants(nb, tenants)
    check_roles(nb, roles)
    check_prefixes(nb, prefixes)

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
