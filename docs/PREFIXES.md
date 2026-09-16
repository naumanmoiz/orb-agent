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

A `subnet_map` entry outranks `use_target_masks: false` as well. That switch
turns off *inferring* a mask from what was scanned; an entry is a declaration of
what the prefix is, and suppressing it would leave a loose `/32` beside the
prefix the same policy just created. Outside the map, `use_target_masks: false`
still means the default mask.

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

## Placing subnets in different VRFs and tenants

`defaults.vrf` and `defaults.tenant` are the policy's fallback, not its limit.
An entry that names its own `vrf` or `tenant` places **its prefix and every
address discovered inside it** there instead, so one policy can scan address
space spread across several prebuilt VRFs:

```yaml
config:
  defaults:
    vrf: LAB-A                  # used by entries that name none
    tenant: LAB-A
    tenant_group: Labs
scope:
  targets: [10.1.0.0/16, 10.2.0.0/16]
  subnet_map:
    - prefix: 10.1.0.0/16
      vrf: CORP                 # this subnet lives in CORP, not LAB-A
      vrf_tenant: Corp          # because the prebuilt CORP VRF has a tenant
      tenant: Corp              # owns the prefix and the addresses in it
    - prefix: 10.2.0.0/16       # no vrf: falls back to defaults.vrf
      tenant: Lab-A
```

`10.1.0.5` is emitted as `10.1.0.5/16` in VRF `CORP` under tenant `Corp`;
`10.2.0.5` as `10.2.0.5/16` in `LAB-A` under `Lab-A`. Each address reaches
NetBox in the same VRF as the prefix declared for its subnet, which is what
lets NetBox file one under the other.

### The VRF's three fields travel together

An entry's `vrf` brings its own `rd` and `vrf_tenant`. It never inherits the
defaults' — the three describe **one** VRF, and a reference pairing this entry's
name with the defaults' `rd` describes a VRF that does not exist, which Diode
answers by creating one. An entry with no `vrf` inherits all three unchanged.

`rd` or `vrf_tenant` on an entry with no `vrf` is a hard error at policy load,
because they would otherwise be silently dropped.

`tenant_group` is the exception: it is inherited from `defaults.tenant_group`,
since a deployment's tenants almost always share one group. An entry whose
tenant lives in a different group names that group itself.

### One CIDR, one entry

Two entries for the same network are rejected even when they name different
VRFs. The same CIDR really can exist in two VRFs, but a scan cannot tell which
one answered — the reply is just a packet — so the second entry would only ever
win the longest-prefix match. Give each VRF its own policy; one agent runs many.

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
| `vrf` | string | no | Places this prefix **and the addresses in it** in this VRF instead of `defaults.vrf`. Must already exist |
| `rd` | string | no | Only with `vrf`, and only if that prebuilt VRF has an RD. Rejected without `vrf` |
| `vrf_tenant` | string | no | Only with `vrf`, and only if that prebuilt VRF has a tenant. Rejected without `vrf` |
| `tenant` | string | no | Owns the prefix **and the addresses in it**. Overrides `defaults.prefix.tenant`, then `defaults.tenant`. Not the VRF's tenant; see `vrf_tenant` |
| `tenant_group` | string | no | Overrides `defaults.tenant_group` for this entry's tenant references |
| `status` | string | no | `container`, `active`, `reserved`, `deprecated` |
| `role` | string | no | An `ipam.Role` by name. Overrides `defaults.prefix.role` |
| `description` | string | no | |
| `is_pool` | bool | no | Tri-state: an explicit `false` is sent, an absent key is not |
| `mark_utilized` | bool | no | Same |
| `tags` | list | no | Added to `defaults.tags` and `defaults.prefix.tags` |
| `custom_fields` | map | no | Extends, does not replace, `config.custom_fields`. Applied to the prefix **and the addresses in it** |

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
| Two entries resolving to the same network | The second would silently win the longest-prefix match, even in another VRF |
| `rd` or `vrf_tenant` without `vrf` | They describe the entry's own VRF and would otherwise be dropped silently |
| An unknown key in an entry | Would otherwise drop an attribute silently |

Overlapping parent and child entries are valid and expected: that is how the
hierarchy is declared.

An entry left with no VRF at all — no `vrf` of its own and no `defaults.vrf` —
is warned about rather than rejected, by prefix. Its prefix is then matched
globally by CIDR, so two labs sharing address space collapse onto one NetBox
prefix.

## Verifying

```bash
python3 tools/netbox-bootstrap/bootstrap_custom_fields.py \
  --config /opt/orb-agent/agent.yaml --dry-run
```

Checks the custom fields exist on **both** `ipam.ipaddress` and `ipam.prefix`;
that every VRF named — `defaults.vrf` and each entry's own — exists and will be
matched rather than duplicated; that every tenant will be found in the group the
config gives it; and that the `ipam.Role` objects named by the map exist. It also
lists every declared prefix, saying which NetBox already holds:

```
subnet_map prefixes (created only when missing):
  ok       prefix 10.1.0.0/16 exists in VRF CORP (id=44); it will be updated, not created
  + create prefix 10.2.0.0/16 does not exist in VRF LAB-A; Diode will create it
```

That listing is how "created only when missing" stops being a claim you have to
take on trust. A prefix reported missing that you know exists is the visible end
of a VRF reference that will not match.

It also reports two policies describing one VRF name with different `rd` or
`vrf_tenant`. At most one of those shapes can match the VRF that exists; the
other creates a duplicate.

Then dry-run the agent and confirm the payload:

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

- **One VRF per CIDR.** A policy can span many VRFs, but not the same network in
  two of them: a scan reply carries no VRF, so the agent could not tell them
  apart. Overlapping VRFs need one policy each. One agent runs many policies.
- **No NetBox lookup.** `subnet_map` is static. A prefix in NetBox but absent
  from the map contributes nothing, and addresses inside it fall back to the
  target mask. Nothing is read back from NetBox at scan time, which is why the
  preflight exists.
- **Nothing refuses to create.** The Diode protocol has no match-only flag, so
  "created only when missing" is a property of the reference matching what is
  already there, not of a switch the agent can set. The preflight is the guard,
  and it is worth gating a rollout on: it exits non-zero.
- **Removing an entry does not delete the prefix.** Discovery only adds and
  updates. Delete it in NetBox.
- **Unset means untouched.** Removing `role` from an entry stops the agent
  sending it, but NetBox keeps the old value, since an absent field is omitted
  from the changeset rather than sent as null.
- **A typo'd CIDR creates a real, empty prefix.** The coverage warning is the
  only signal, and it fires only when the entry overlaps nothing at all.
