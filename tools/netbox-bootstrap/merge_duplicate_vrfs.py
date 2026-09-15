#!/usr/bin/env python3
"""Merge a VRF Diode created by mistake back into the prebuilt one.

When the agent's VRF reference does not match a prebuilt VRF, Diode creates a
second VRF with the same name and reconciles into it. The addresses and prefixes
land in the duplicate while the real VRF stays empty. Nothing errors, so this is
usually noticed only when NetBox shows two VRFs of the same name.

This moves the objects back and deletes the empty duplicate. It does not fix the
cause: set defaults.vrf_tenant (or defaults.rd) so the reference matches, or the
next scan recreates the duplicate. bootstrap_custom_fields.py --dry-run prints
what to set.

Dry run by default. Nothing is written without --apply.

    export NETBOX_URL=... NETBOX_TOKEN=...
    python3 merge_duplicate_vrfs.py --name VRF-Lab-312
    python3 merge_duplicate_vrfs.py --name VRF-Lab-312 --apply
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
    from requests import exceptions as requests_exceptions
except ImportError:  # pragma: no cover
    sys.exit("requests is required: pip install requests")

MOVABLE = [
    ("prefixes", "/api/ipam/prefixes/", "prefix"),
    ("ip addresses", "/api/ipam/ip-addresses/", "address"),
    ("ip ranges", "/api/ipam/ip-ranges/", "display"),
]


class NetBox:
    def __init__(self, url: str, token: str, verify: bool, scheme: str) -> None:
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({
            "Authorization": f"{scheme} {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def _call(self, method: str, path: str, **kw: Any) -> Any:
        try:
            r = self.session.request(method, f"{self.url}{path}", timeout=30, **kw)
        except requests_exceptions.RequestException as err:
            raise SystemExit(f"error: {method} {path} failed: {err}\n  URL: {self.url}") from None
        if r.status_code in (401, 403):
            detail = ""
            try:
                detail = str((r.json() or {}).get("detail", ""))
            except ValueError:
                pass
            raise SystemExit(f"error: {method} {path} returned {r.status_code}. {detail}")
        if not r.ok:
            raise SystemExit(f"error: {method} {path} returned {r.status_code}: {r.text[:400]}")
        return r.json() if r.content else None

    def list_all(self, path: str, **filters: Any) -> list[dict]:
        """Every page, so a partial move cannot leave the duplicate half empty."""
        out: list[dict] = []
        query = urllib.parse.urlencode({**filters, "limit": 200})
        nxt = f"{path}?{query}"
        while nxt:
            page = self._call("GET", nxt if nxt.startswith("/") else nxt.replace(self.url, ""))
            out.extend(page.get("results") or [])
            nxt = page.get("next")
        return out

    def patch(self, path: str, payload: dict) -> Any:
        return self._call("PATCH", path, data=json.dumps(payload))

    def delete(self, path: str) -> Any:
        return self._call("DELETE", path)


def describe(vrf: dict) -> str:
    tenant = (vrf.get("tenant") or {}).get("name")
    return (f"id={vrf['id']} rd={vrf.get('rd') or 'null'} tenant={tenant or 'null'} "
            f"created={vrf.get('created', '?')[:19]} "
            f"ips={vrf.get('ipaddress_count', '?')} prefixes={vrf.get('prefix_count', '?')}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="the duplicated VRF name")
    ap.add_argument("--keep", type=int, help="id of the VRF to keep (default: the oldest)")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    ap.add_argument("--url", default=os.environ.get("NETBOX_URL"))
    ap.add_argument("--token", default=os.environ.get("NETBOX_TOKEN"))
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--auth-scheme", default=os.environ.get("NETBOX_AUTH_SCHEME", "Token"),
                    choices=["Token", "Bearer"])
    args = ap.parse_args()
    if not args.url or not args.token:
        ap.error("NETBOX_URL and NETBOX_TOKEN must be set, or passed with --url/--token")

    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    nb = NetBox(args.url, args.token, not args.insecure, args.auth_scheme)
    vrfs = nb.list_all("/api/ipam/vrfs/", name=args.name)
    if len(vrfs) < 2:
        print(f"{len(vrfs)} VRF named {args.name!r}; nothing to merge.")
        return 0

    print(f"{len(vrfs)} VRFs named {args.name!r}:")
    for v in vrfs:
        print(f"  {describe(v)}")

    # The prebuilt one is the oldest. A newer one with no tenant and no rd is the
    # shape Diode creates from a name-only reference.
    vrfs.sort(key=lambda v: v.get("created") or "")
    keeper = next((v for v in vrfs if v["id"] == args.keep), vrfs[0]) if args.keep else vrfs[0]
    dupes = [v for v in vrfs if v["id"] != keeper["id"]]
    print(f"\nkeeping   {describe(keeper)}")
    for d in dupes:
        print(f"merging   {describe(d)}")
    if not args.apply:
        print("\ndry run: nothing will be written (pass --apply)\n")

    moved = collisions = 0
    for dupe in dupes:
        for label, path, display_key in MOVABLE:
            objects = nb.list_all(path, vrf_id=dupe["id"])
            if not objects:
                continue
            print(f"\n{label} in VRF {dupe['id']}: {len(objects)}")
            for obj in objects:
                shown = obj.get(display_key) or obj.get("display") or obj["id"]
                # An identical object already in the keeper blocks the move;
                # NetBox would either reject it or create a second row.
                existing = nb.list_all(path, vrf_id=keeper["id"],
                                       **({display_key: obj[display_key]} if display_key in obj else {}))
                if existing:
                    collisions += 1
                    print(f"  ! {shown}: already present in VRF {keeper['id']}, left in place. "
                          "Resolve by hand, then re-run.")
                    continue
                if args.apply:
                    nb.patch(f"{path}{obj['id']}/", {"vrf": keeper["id"]})
                    print(f"  moved {shown}")
                else:
                    print(f"  would move {shown}")
                moved += 1

    print(f"\n{moved} object(s) {'moved' if args.apply else 'would move'}, {collisions} collision(s)")
    if collisions:
        print("Duplicate VRFs left in place: resolve the collisions above first.")
        return 1

    for dupe in dupes:
        if args.apply:
            # Re-read rather than trust the counters from the initial listing.
            fresh = nb.list_all("/api/ipam/vrfs/", id=dupe["id"])
            remaining = (fresh[0].get("ipaddress_count", 0) + fresh[0].get("prefix_count", 0)) if fresh else 0
            if remaining:
                print(f"VRF {dupe['id']} still holds {remaining} object(s); not deleting.")
                return 1
            nb.delete(f"/api/ipam/vrfs/{dupe['id']}/")
            print(f"deleted duplicate VRF {dupe['id']}")
        else:
            print(f"would delete duplicate VRF {dupe['id']}")

    print("\nFix the cause before the next scan, or the duplicate comes back:")
    tenant = (keeper.get("tenant") or {}).get("name")
    if tenant:
        print(f'  defaults.vrf_tenant: "{tenant}"')
    if keeper.get("rd"):
        print(f'  defaults.rd: "{keeper["rd"]}"')
    if not tenant and not keeper.get("rd"):
        print("  (this VRF matches on name alone; remove rd and vrf_tenant)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
