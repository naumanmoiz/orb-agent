# network_discovery prefixes

Declares subnets as NetBox prefixes alongside the IP addresses a scan discovers,
so IPAM is complete after a run: the prefix exists, it nests under whatever
parent already exists, and every discovered address sits inside it.

Additive. A policy with no `subnet_map` emits IP addresses alone, as before.

Builds on [CUSTOM_FIELDS.md](CUSTOM_FIELDS.md); custom fields apply to prefixes
as well as addresses.

## How nesting works

NetBox derives prefix hierarchy from **containment within a VRF**. Nothing sets
a parent. A `192.0.2.0/25` emitted into VRF `LAB-A` nests under any
`192.0.2.0/24` already in `LAB-A`, whether that parent came from this agent or
was created by hand years ago.

The same mechanism files addresses. A discovered address takes the mask of the
most specific `subnet_map` entry containing it, so `192.0.2.10` under a
`192.0.2.0/25` entry is emitted as `192.0.2.10/25` and NetBox places it in that
prefix. An address matching no entry keeps the previous behaviour: the mask of
the most specific scan target, then `defaults.network_mask`, then `/32`.

So the VRF is the only thing tying the three together, which is why the next
section matters more than anything else here.

## VRFs are matched, never created

The Diode NetBox plugin picks its VRF matcher from the fields the **payload**
carries, and skips any criterion whose fields are not all present. So the
reference has to mirror the shape of the VRF you already have:

| Reference carries | Searches VRFs where |
|---|---|
| `name` | `rd IS NULL` and `tenant IS NULL` |
| `name` + `tenant` | `rd IS NULL` and `tenant` set |
| `name` + `rd` | NetBox's own `rd` unique constraint |

Point a name-only reference at a VRF that has a tenant or an RD and **nothing
matches**. Diode then creates a second, empty VRF of the same name and
reconciles into it. That reads as success while splitting the lab's address
space across two VRFs.

### What is and is not part of VRF identity

Only some of a VRF's fields take part in matching. The rest are untouched.

| VRF field | Part of matching? | What the agent sends |
|---|---|---|
| `name` | yes, always | `defaults.vrf` |
| `tenant` | yes, its presence selects the criterion | `defaults.vrf_tenant` |
| `rd` | yes, switches to NetBox's rd constraint | `defaults.rd` |
| `tags` | **no** | nothing |
| `description`, `comments`, `enforce_unique`, route targets | **no** | nothing |

A tagged VRF is safe. Tags are not in any VRF matcher, so they neither help nor
hinder the match, and the agent never sends them. The plugin's `_partially_merge`
only processes keys present in the payload, and `tags` specifically is merged
with the existing list rather than replacing it, so a prebuilt VRF keeps its tags
whether or not anything sends them.

`defaults.tags` deliberately reaches the prefix and the address, never the VRF.
Putting agent tags on an object an operator owns is not the agent's business,
and it would not help matching anyway.

### The same trap applies to tenants

NetBox makes `Tenant` unique on `(group, name)` with `nulls_distinct=False`. The
plugin turns that into a matcher where an **absent group means `group IS NULL`**,
not "any group". So a group-less tenant reference cannot find a tenant that sits
in a tenant group, and Diode creates a second tenant of the same name outside it.

`defaults.tenant_group` sets the group on every tenant reference the agent emits:
the prefix's, the address's, and the one inside the VRF reference. The preflight
checks it the same way:

```
tenants (verified, never created):
  ! MISMATCH tenant 312 exists (id=3) but the policy will not match it.
            NetBox has: group=Labs
            policy has: tenant_group=unset
            Diode would create a SECOND tenant with this name. Set in defaults:
              tenant_group: "Labs"
```

Setting it when the tenant has no group is equally wrong, and is reported too.

Four keys control the references:

```yaml
defaults:
  vrf: VRF-Lab-312      # the name
  rd: "65000:9"         # only if the prebuilt VRF has an RD
  vrf_tenant: "312"     # only if the prebuilt VRF has a tenant
  tenant: "312"         # the prefix's and address's tenant
  tenant_group: "Labs"  # only if those tenants sit in a group
```

`vrf_tenant` and `tenant` are deliberately separate. `tenant` describes the
prefix and the address. `vrf_tenant` exists only to make the VRF reference
match, and setting `tenant` alone will not do it.

There is no "match only, do not create" flag in the Diode protocol, so the guard
is the preflight, which verifies and **never creates**. It reads the real VRF
and prints the config it needs:

```
vrfs (verified, never created):
  ok       VRF VRF-Plain (id=1), matched on name only
  ! MISMATCH VRF VRF-Lab-312 exists (id=2) but the policy will not match it.
            NetBox has: rd=null, tenant=312
            policy has: rd=unset, vrf_tenant=unset
            Diode would create a SECOND VRF with this name. Set in defaults:
              vrf_tenant: "312"
  ! MISSING VRF 'VRF-Nope' does not exist. Diode would create an empty one...
```

It exits non-zero, so it can gate a deploy. Run it before every rollout: this is
the failure that looks like success.

### If duplicates already exist

The duplicate is recognisable by shape: same name, newer `created`, no tenant
and no rd, and it holds the objects while the prebuilt one is empty.

```bash
python3 tools/netbox-bootstrap/merge_duplicate_vrfs.py --name VRF-Lab-312
python3 tools/netbox-bootstrap/merge_duplicate_vrfs.py --name VRF-Lab-312 --apply
```

Dry run by default. It keeps the oldest VRF (override with `--keep <id>`), moves
prefixes, addresses and IP ranges onto it, and deletes the duplicate only once it
is empty. An object that already exists in the keeper is reported as a collision
and left alone rather than merged blindly.

It prints the `defaults` change needed at the end. **Fix that before the next
scan** or the duplicate is recreated.

## Config

```yaml
config:
  defaults:
    vrf: LAB-A            # must already exist in NetBox
    tenant: LAB-A
    prefix:               # defaults for the emitted prefixes
      status: active
      role: lab-data
scope:
  targets: [192.0.2.0/24]   # what nmap scans
  subnet_map:               # what becomes a prefix
    - prefix: 192.0.2.0/24
      status: container
      role: lab-aggregate
    - prefix: 192.0.2.0/25
      role: lab-servers
      custom_fields:
        lab_id: "312"
```

### `scope.subnet_map`

A list. Unknown keys are a hard error, not a warning: `WarnUnknownPolicyKeys`
deliberately skips `scope`, so a typo would otherwise decode cleanly and drop the
attribute silently.

| Key | Type | Required | Notes |
|---|---|---|---|
| `prefix` | string | yes | CIDR. Host bits are normalized onto the network address, with a warning |
| `status` | string | no | `container`, `active`, `reserved`, `deprecated` |
| `role` | string | no | An `ipam.Role` by name. Overrides `defaults.prefix.role` |
| `tenant` | string | no | Overrides `defaults.prefix.tenant`, then `defaults.tenant`. Not the VRF's tenant; see `vrf_tenant` |
| `description` | string | no | |
| `is_pool` | bool | no | Tri-state: an explicit `false` is sent, an absent key is not |
| `mark_utilized` | bool | no | Same |
| `tags` | list | no | Added to `defaults.tags` and `defaults.prefix.tags` |
| `custom_fields` | map | no | Extends, does not replace, `config.custom_fields` |

### `config.defaults.prefix`

| Key | Type | Default |
|---|---|---|
| `status` | string | unset |
| `role` | string | unset |
| `tenant` | string | `defaults.tenant` |
| `is_pool` | bool | unset |
| `mark_utilized` | bool | unset |
| `tags` | list | unset |
| `description` | string | unset |

An unset field is **left off the emitted entity** rather than defaulted, so
Diode omits it from the changeset and NetBox keeps what it already holds.
Defaulting `status` to `active` would make every scan re-assert it over a prefix
you had marked `reserved`.

## `targets` and `subnet_map` are independent

`targets` is the only thing nmap scans. `subnet_map` is metadata and costs no
scan time.

That separation is useful: declare a `/16` container without ever probing 65,536
addresses.

```yaml
targets:                  # nmap scans 128 addresses
  - 192.0.2.0/25
subnet_map:
  - prefix: 192.0.2.0/24  # container in NetBox, never scanned
    status: container
  - prefix: 192.0.2.0/25
```

The reverse is the expensive mistake: putting the container in `targets` makes
nmap probe all of it. An entry that overlaps no target is logged as a warning,
since that is more often a typo than an intent, but it is still emitted.

## Validation at policy load

A bad `subnet_map` fails that policy alone and is logged; the agent and every
other policy keep running.

| Rejected | Why |
|---|---|
| Missing or invalid CIDR | |
| Two entries resolving to the same network | The second would silently win the longest-prefix match |
| An unknown key in an entry | Would otherwise drop an attribute silently |

Overlapping parent and child entries are valid and expected: that is how the
hierarchy is declared.

A `subnet_map` with no `defaults.vrf` is warned about rather than rejected: the
prefixes are then matched globally by CIDR, so two labs sharing address space
collapse onto one NetBox prefix.

## Verifying

```bash
python3 tools/netbox-bootstrap/bootstrap_custom_fields.py \
  --config /opt/orb-agent/agent.yaml --dry-run
```

Checks the custom fields exist on **both** `ipam.ipaddress` and `ipam.prefix`,
that every `defaults.vrf` exists, and that the `ipam.Role` objects named by the
map exist. Then dry-run the agent and confirm the payload:

```json
{"prefix": {"prefix": "192.0.2.0/24", "vrf": {"name": "LAB-A"}, "status": "container"}}
{"prefix": {"prefix": "192.0.2.0/25", "vrf": {"name": "LAB-A"}, "role": {"name": "lab-servers"}}}
{"ip_address": {"address": "192.0.2.10/25", "vrf": {"name": "LAB-A"}}}
```

Three things to check: all three carry the **same** `vrf.name`; the `vrf` object
has **no** `rd` or `tenant` key; and the address mask is the child's, not `/32`.

In NetBox, IPAM > Prefixes filtered by the VRF should show the child indented
under the parent, and the child's IP Addresses tab should list the address.

## Known limitations

- **A rejected field costs every entity carrying it.** The reconciler plans one
  ingestion log per entity, so a failure is scoped to the entities naming the bad
  field rather than the whole ingest. A field set in the policy block is on every
  prefix and address, so in practice that is the whole scan.

- **One VRF per policy.** Containment only nests within a VRF, so use one policy
  per lab. One agent runs many policies.
- **No NetBox lookup.** `subnet_map` is static. A prefix in NetBox but absent
  from the map contributes nothing, and addresses inside it fall back to the
  target mask.
- **Removing an entry does not delete the prefix.** Discovery only adds and
  updates. Delete it in NetBox.
- **Unset means untouched.** Removing `role` from an entry stops the agent
  sending it, but NetBox keeps the old value, since an absent field is omitted
  from the changeset rather than sent as null.
- **A typo'd CIDR creates a real, empty prefix.** The coverage warning is the
  only signal, and it fires only when the entry overlaps nothing at all.
