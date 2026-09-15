# network_discovery IPAM extension

Extends the `network_discovery` backend so a scan policy can populate NetBox
IPAM completely: the prefixes exist, the VLANs exist, roles are set, and every
discovered address sits inside the right prefix in the right VRF, with custom
fields identifying the agent and the scan that produced it.

Everything here is additive. A policy that sets none of the new keys behaves
exactly as it did before, and emits `IPAddress` entities alone.

For build and deploy steps, see
[IPAM_BUILD_RUNBOOK.md](IPAM_BUILD_RUNBOOK.md).

## Contents

- [What changed](#what-changed)
- [How it works](#how-it-works)
- [Config reference](#config-reference)
- [NetBox prerequisites](#netbox-prerequisites)
- [Runbook](#runbook)
- [Docker](#docker)
- [Copy-over inventory](#copy-over-inventory)
- [Known limitations](#known-limitations)

## What changed

| File | Reason |
|---|---|
| `orb-discovery/network-discovery/config/config.go` | Adds `defaults.site`, `defaults.prefix`, `defaults.vlan`, `config.custom_fields` and `scope.subnet_map` to the existing structs. No existing field changed. |
| `orb-discovery/network-discovery/config/subnet_map.go` | New. `SubnetMapEntry`, `SubnetVlan` and `VlanGroupParameters`, their strict unknown-key decoders, and the validation and coverage warning run at policy load. |
| `orb-discovery/network-discovery/config/customfields.go` | New. YAML value to `CustomFieldValue` type detection, and `${AGENT_NAME}` / `${POLICY_NAME}` / `${SCAN_TIMESTAMP}` substitution. |
| `orb-discovery/network-discovery/policy/subnetmap.go` | New. Longest-prefix matcher resolving a discovered address to its most specific entry. |
| `orb-discovery/network-discovery/policy/entities.go` | New. Builds and dedupes the `Prefix`, `VLAN` and `VLANGroup` entities. |
| `orb-discovery/network-discovery/policy/customfields_run.go` | New. Resolves the custom field values once per scan run. |
| `orb-discovery/network-discovery/policy/runner.go` | Mask now comes from the matched entry; custom fields land on `IPAddress`; IPAM entities are emitted ahead of the addresses. |
| `orb-discovery/network-discovery/policy/manager.go` | Validates `subnet_map` at policy load and adds `WithAgentName`. |
| `orb-discovery/network-discovery/policy/entity_run_metadata.go` | `run_id` now also reaches `Prefix` and `VLAN`. |
| `orb-discovery/network-discovery/cmd/main.go` | Passes the agent name into the policy manager so `${AGENT_NAME}` can resolve. |
| `orb-discovery/network-discovery/config/subnet_map_test.go` | New. Parsing with and without the new keys, validation, coverage warning. |
| `orb-discovery/network-discovery/config/customfields_test.go` | New. Type detection, token substitution, merge precedence. |
| `orb-discovery/network-discovery/policy/ipam_internal_test.go` | New. Longest-prefix matching, mask assignment, entity shape, dedupe, unmatched fallback. |
| `orb-discovery/network-discovery/policy/manager_subnetmap_test.go` | New. An invalid `subnet_map` fails one policy, not the agent. |
| `orb-discovery/network-discovery/policy/dryrun_test.go` | New. Walks the sample policy through the real dry-run client. |
| `orb-discovery/network-discovery/policy/entity_internal_test.go` | Updated for the new `ipAddressEntity` parameter. |
| `agent.example.yaml` | New. Sample config exercising every new key. |
| `tools/netbox-bootstrap/bootstrap_ipam.py` | New. Creates the custom fields, ipam roles and VLAN groups a policy needs. |
| `agent/docker/Dockerfile.overlay` | New. Rebuilds only network-discovery and lays it over an existing image. |
| `Makefile` | Adds `make test-network-discovery`. |
| `docs/IPAM_EXTENSION.md` | This document. |
| `docs/IPAM_BUILD_RUNBOOK.md` | Build and deploy runbook: image build paths, bootstrap, dry run, go live, rollback. |

Not touched: `device_discovery`, `snmp_discovery`, `gnmi_discovery`, the worker,
and every other part of the agent.

## How it works

`scope.subnet_map` is the only source of prefix and VLAN mapping. Nothing is
looked up in NetBox and nothing is inferred.

1. At policy load, each entry is parsed and validated. A bad entry fails that
   policy alone and is logged; the agent and every other policy keep running.
2. On each scan run, one `Prefix` is emitted per entry, plus one `VLAN` per
   distinct vid-in-group where `vlan` is declared. Both are sent ahead of the
   addresses, deduped so each is sent once per run.
3. Each discovered address is matched against the entries, longest prefix
   winning, and takes its mask from the matched entry. `10.10.20.200` matches
   `10.10.20.128/25` rather than the `/24` or `/16` that also contain it, and is
   emitted as `10.10.20.200/25`.
4. An address matching no entry is emitted exactly as it was before this feature
   existed: the mask comes from the most specific scan target containing it, or
   from `defaults.network_mask`, or `/32`. No prefix or VLAN is generated for it.

Every prefix goes into the same VRF and **no parent reference is set**. NetBox
derives the hierarchy itself from containment within a VRF, so parent, child and
grandchild entries nest themselves. Nothing is inherited from a parent entry;
each address takes its role, VLAN and custom fields from its matched entry alone,
on top of whatever `defaults` provides.

A `subnet_map` entry that is not a scan target, or is wider than the targets, is
still emitted. The map defines IPAM while the targets define what nmap scans. An
entry overlapping no target at all is logged as a warning, because that is far
more often a typo than an intent.

### Where site and tenant go

A `Prefix` in the Diode schema has no plain site field, only a scope oneof. This
extension deliberately does not use it: a prefix carries its site through its
tenant. `defaults.site` reaches `VLAN.site` and becomes the default scope of the
VLAN group, and nothing else.

## Config reference

All keys below are optional. An unset field is **left off the emitted entity**
rather than defaulted, so Diode omits it from the changeset and NetBox keeps
whatever the object already holds. That is deliberate: defaulting `status` to
`active` would make every scan re-assert it over a prefix you had marked
`reserved` or `deprecated`.

### `config.defaults`

| Key | Type | Default | Applies to |
|---|---|---|---|
| `site` | string | unset | `VLAN.site`, and the VLAN group scope when the group sets no `scope_*`. Never the prefix. |
| `prefix` | block | unset | The prefixes declared in `subnet_map` |
| `vlan` | block | unset | The VLANs declared in `subnet_map` |

Existing keys (`vrf`, `rd`, `tenant`, `role`, `description`, `comments`, `tags`,
`network_mask`) are unchanged. `tags` applies to prefixes and VLANs as well as
addresses.

`defaults.role` is the **IPAddress** role, which NetBox models as a fixed choice,
not as an `ipam.Role` object. Valid values are `loopback`, `secondary`,
`anycast`, `vip`, `vrrp`, `hsrp`, `glbp`, `carp`. Any other value is rejected on
ingest.

### `config.defaults.prefix`

| Key | Type | Default | Notes |
|---|---|---|---|
| `status` | string | unset | `container`, `active`, `reserved`, `deprecated` |
| `role` | string | unset | An `ipam.Role` by name. Must exist in NetBox. |
| `tenant` | string | `defaults.tenant` | |
| `is_pool` | bool | unset | Tri-state: an explicit `false` is sent, an absent key is not |
| `mark_utilized` | bool | unset | Same |
| `tags` | list | unset | Added to `defaults.tags` |
| `description` | string | unset | |

### `config.defaults.vlan`

| Key | Type | Default | Notes |
|---|---|---|---|
| `group` | string or block | unset | Bare string is the group name. Block form takes `name` plus at most one of `scope_site`, `scope_site_group`, `scope_region`, `scope_location`. With no scope it falls back to `defaults.site`. |
| `status` | string | unset | `active`, `reserved`, `deprecated` |
| `role` | string | unset | An `ipam.Role` by name |
| `tenant` | string | `defaults.tenant` | |
| `tags` | list | unset | Added to `defaults.tags` |
| `description` | string | unset | |

### `config.custom_fields`

`map[string]any`, unset by default. Applied to every `IPAddress` and `Prefix` the
policy emits. Keys must be NetBox custom field **names** (snake_case), not
labels, and the definitions must already exist.

Value types map from YAML:

| YAML | NetBox custom field type |
|---|---|
| string | text |
| integer | integer |
| boolean | boolean |
| float | decimal |
| timestamp (`2026-09-14T10:30:00Z`, unquoted) | datetime |
| mapping or sequence | json |
| null | dropped, not sent |

A value that is **exactly** `${NAME}` is substituted. `"lab-${NAME}"` is left as
literal text, matching the whole-value convention the backend already uses for
its flags.

| Token | Resolves to |
|---|---|
| `${AGENT_NAME}` | `common.diode.agent_name`, which reaches the backend as `--diode-app-name-prefix`. An empty agent name is an error, not a blank field. |
| `${POLICY_NAME}` | The policy key |
| `${SCAN_TIMESTAMP}` | The start of the scan run, as a **datetime**, not a string. Identical across every entity in one run. |
| any other `${VAR}` | The environment variable. Unset or empty is an error. |

### `scope.subnet_map`

A list. Unknown keys are a hard error, not a warning: `WarnUnknownPolicyKeys`
deliberately skips `scope`, so a typo would otherwise decode cleanly and drop the
attribute silently.

| Key | Type | Required | Notes |
|---|---|---|---|
| `prefix` | string | yes | CIDR. Host bits are normalized onto the network address, with a warning. |
| `status` | string | no | Overrides `defaults.prefix.status` |
| `role` | string | no | Overrides `defaults.prefix.role` |
| `tenant` | string | no | Overrides `defaults.prefix.tenant`, then `defaults.tenant` |
| `description` | string | no | |
| `is_pool` | bool | no | |
| `mark_utilized` | bool | no | |
| `tags` | list | no | Added to `defaults.tags` and `defaults.prefix.tags` |
| `vlan` | block | no | No block means no VLAN for this prefix, which is normal for a container |
| `custom_fields` | map | no | Extends, does not replace, `config.custom_fields` |

`subnet_map[].vlan`:

| Key | Type | Required | Notes |
|---|---|---|---|
| `vid` | int | yes | 1 to 4094 |
| `name` | string | no | Defaults to `VLAN<vid>`; NetBox requires a name |
| `status` | string | no | Overrides `defaults.vlan.status` |
| `role` | string | no | Overrides `defaults.vlan.role` |
| `tenant` | string | no | |
| `group` | string or block | no | Overrides `defaults.vlan.group` |
| `description` | string | no | |

Validation failures at policy load: missing or invalid CIDR, `vid` outside
1-4094, `vlan` without `vid`, an unknown key, or two entries resolving to the
identical network. Overlapping parent and child entries are valid and expected.

## NetBox prerequisites

Diode **never creates custom field definitions**. A changeset naming a custom
field that does not exist is rejected with `ERR_OPS_GENERATE_DIFF` and the whole
batch is lost. The `ipam.Role` and `VLANGroup` objects a policy names must exist
too, as must the site and tenant.

`tools/netbox-bootstrap/bootstrap_ipam.py` creates them idempotently.

```bash
pip install requests PyYAML

export NETBOX_URL=https://netbox.example.net
export NETBOX_TOKEN=...          # never put this in a file

# See what it would do
python3 tools/netbox-bootstrap/bootstrap_ipam.py --config agent.example.yaml --dry-run

# Apply
python3 tools/netbox-bootstrap/bootstrap_ipam.py --config agent.example.yaml
```

It creates:

- `discovery_agent` (text), `discovery_policy` (text), `discovery_last_seen`
  (datetime) and `discovery_source` (text) on `ipam.ipaddress` and `ipam.prefix`,
  plus any further custom field name found in `--config`, as text.
- Every `ipam.Role` named by `defaults.prefix.role`, `defaults.vlan.role` or a
  `subnet_map` entry's `role`. `defaults.role` is not collected, because the
  IPAddress role is a choice rather than an object.
- Every `VLANGroup` named by `defaults.vlan.group` or an entry's `vlan.group`,
  scoped to the site. The slug matches what the agent sends, so the group the
  script creates is the one the agent reconciles against rather than a second.

A custom field that already exists is left alone except to add any missing object
type. The script reads the running NetBox version and picks `object_types` or
`content_types` accordingly: NetBox renamed the field in 4.1, and sending the
wrong one is accepted as an unknown key, silently producing a custom field
attached to nothing.

Sites and tenants are **not** created. A VLAN group whose site does not exist is
skipped with a message rather than created unscoped.

## Runbook

### a. Bootstrap NetBox

```bash
export NETBOX_URL=https://netbox.example.net NETBOX_TOKEN=...
python3 tools/netbox-bootstrap/bootstrap_ipam.py --config agent.example.yaml --dry-run
python3 tools/netbox-bootstrap/bootstrap_ipam.py --config agent.example.yaml
```

Create the site, tenant and VRF by hand first if they do not exist.

### b. Dry run and inspect the JSON

Set `dry_run: true` and `dry_run_output_dir` under `backends.common.diode`, then:

```bash
mkdir -p /tmp/orb-dry/out
cp agent.example.yaml /tmp/orb-dry/agent.yaml
docker run --rm -u root -v /tmp/orb-dry:/opt/orb \
  orb-agent:ipam-<gitsha> run -c /opt/orb/agent.yaml
```

No Diode and no credentials are needed. Inspect the result:

```bash
python3 - <<'EOF'
import json, glob
from collections import Counter
d = json.load(open(glob.glob('/tmp/orb-dry/out/*.json')[0]))
print(Counter(k for e in d['entities'] for k in e if k != 'timestamp'))
EOF
```

You should see `prefix`, `vlan` and `ip_address` counts matching the policy. A
prefix looks like this, with the VLAN nested and the custom fields present:

```json
{
  "prefix": "10.10.20.128/25",
  "vrf": {"name": "LAB-AUS-01"},
  "tenant": {"name": "LAB-AUS-01"},
  "vlan": {
    "site": {"name": "LAB-AUS-01"},
    "group": {"name": "LAB-AUS-01-VLANS", "slug": "lab-aus-01-vlans",
              "scope_site": {"name": "LAB-AUS-01"}},
    "vid": "21", "name": "SERVERS-GPU", "status": "active"
  },
  "status": "active",
  "role": {"name": "lab-servers-gpu"},
  "is_pool": false,
  "custom_fields": {
    "discovery_agent":     {"text": "lab-agent-01"},
    "discovery_policy":    {"text": "lab_scan"},
    "discovery_source":    {"text": "network_discovery"},
    "discovery_last_seen": {"datetime": "2026-09-14T10:30:00Z"}
  },
  "metadata": {"run_id": "..."}
}
```

Check specifically that:

- `discovery_last_seen` is under `"datetime"`, not `"text"`. Under `"text"` it
  will be rejected by a datetime custom field.
- A discovered address carries the mask of its matched entry, for example
  `"address": "10.10.20.200/25"` and not `/24`, `/16` or `/32`.
- `vid` is a quoted string. That is protojson rendering an int64 and is correct.

The same walkthrough runs as a Go test, which needs no Docker and no nmap:

```bash
cd orb-discovery/network-discovery
NETWORK_DISCOVERY_DRYRUN_DIR=/tmp/nd-dry GOWORK=off go test -run TestDryRunGolden -v ./policy/...
```

### c. Switch to live Diode

Remove `dry_run` and `dry_run_output_dir`, and set:

```yaml
target: grpc://<DIODE_HOST>:8080/diode
client_id: ${DIODE_CLIENT_ID}
client_secret: ${DIODE_CLIENT_SECRET}
```

with the credentials in the environment, never in the file.

### d. Verify in NetBox

| Check | Where |
|---|---|
| Prefixes exist in the right VRF | IPAM > Prefixes, filter by VRF |
| Parent/child nesting | The prefix list shows the hierarchy. `10.10.20.128/25` should be indented under `10.10.20.0/24`, which sits under `10.10.0.0/16`. NetBox derives this itself; the agent sends no parent reference. |
| Each address under its most specific prefix | Open `10.10.20.128/25` and its IP Addresses tab. `10.10.20.200` belongs here, not on the `/24`. |
| Roles | The Role column on each prefix |
| VLANs and group | IPAM > VLANs, and IPAM > VLAN Groups for the site scope |
| Tenant | The Tenant column. The prefix carries its site through the tenant. |
| Custom fields | Any prefix or address detail page. `discovery_last_seen` should render as a date and time. |

If prefixes are nesting wrongly, the usual cause is two entries in different
VRFs. Containment only nests within one VRF.

### e. Read the Diode reconciler log

```bash
docker compose logs -f diode-reconciler | grep -i ERR_OPS_GENERATE_DIFF
```

`ERR_OPS_GENERATE_DIFF` means the reconciler could not turn the ingested
entities into a NetBox changeset, and **the whole batch is dropped**, not just
the offending entity. With custom fields the causes are, in order of likelihood:

1. **The custom field does not exist.** Re-run the bootstrap script. This is the
   common one after adding a new key to `custom_fields`.
2. **It exists but is not attached to the model.** A field created for
   `ipam.ipaddress` only will fail on prefixes. The bootstrap script widens an
   existing field rather than creating a second one.
3. **Type mismatch.** A datetime field receiving `{"text": ...}`, most often
   because `${SCAN_TIMESTAMP}` was replaced with a literal quoted string.
4. **Name versus label.** The key must be the NetBox `name` (snake_case). A label
   like `Discovery Agent` will not resolve.
5. **A choice field receiving a value outside its choice set.**

The log line names the entity and the field. Fix NetBox, then wait for the next
scheduled run or restart the agent.

## Docker

### Full build

```bash
SHA=$(git rev-parse --short HEAD)
docker build -f agent/docker/Dockerfile \
  --platform linux/amd64 \
  --build-arg NETWORK_DISCOVERY_VERSION=$(cat orb-discovery/network-discovery/version/BUILD_VERSION.txt) \
  --build-arg BUILD_COMMIT=$SHA \
  -t orb-agent:ipam-$SHA .
```

Multi-arch is not required, hence the single `--platform linux/amd64`.

### Overlay build

Rebuilds only the network-discovery backend and lays it over an existing image.

```bash
SHA=$(git rev-parse --short HEAD)
docker build -f agent/docker/Dockerfile.overlay \
  --platform linux/amd64 \
  --build-arg BASE_IMAGE=netboxlabs/orb-agent:latest \
  --build-arg NETWORK_DISCOVERY_VERSION=$(cat orb-discovery/network-discovery/version/BUILD_VERSION.txt) \
  --build-arg BUILD_COMMIT=$SHA \
  -t orb-agent:ipam-overlay-$SHA .
```

Pin `BASE_IMAGE` to what your container actually runs:

```bash
docker inspect --format '{{.Config.Image}}' <container>
docker inspect --format '{{index .RepoDigests 0}}' netboxlabs/orb-agent:<tag>
```

A digest pin (`netboxlabs/orb-agent@sha256:...`) is better than a moving tag, so
the overlay cannot silently rebase onto a different agent.

**Runtime compatibility.** The final stage of the agent image is
`python:3.14-alpine`, which is musl. The backend is built `CGO_ENABLED=0`, so the
binary is fully static ELF with no libc dependency and drops onto that base
unchanged. No glibc/musl matching is needed, and no static-build flags beyond
what the repo already uses.

### No-rebuild alternative

The image sets `ENV PATH=/opt/orb/files:$PATH` and the entrypoint recreates
`/opt/orb/files` on start, so a binary there shadows `/usr/local/bin`. The agent
execs the bare name `network-discovery`, which resolves through `PATH`. To test a
rebuilt backend against a stock image with no image build at all:

```bash
cd orb-discovery/network-discovery && GOWORK=off make build
docker run --rm -u root \
  -v ${PWD}/build/network-discovery:/opt/orb/files/network-discovery:ro \
  -v /tmp/orb-dry:/opt/orb/conf \
  netboxlabs/orb-agent:latest run -c /opt/orb/conf/agent.yaml
```

Mount the binary somewhere other than the config directory if you bind-mount over
`/opt/orb` itself.

## Copy-over inventory

**Only one binary changed.** The IPAM extension is contained entirely within
`orb-discovery/network-discovery`, which compiles to its own binary. The
`orb-agent` binary is unchanged, as are `device-discovery`, `snmp-discovery`,
`gnmi-discovery`, the telemetry binaries, pktvisor and the Python packages. Do
not rebuild or copy any of those.

| Source in repo | Destination in image | Why |
|---|---|---|
| Built from `orb-discovery/network-discovery/` | `/usr/local/bin/network-discovery` | The only changed artifact. Contains the config parsing, matching and entity building. Static, `CGO_ENABLED=0`. |

Nothing else needs copying. Specifically:

| Not copied | Why |
|---|---|
| `/usr/local/bin/orb-agent` | Unchanged. The agent passes the policy through verbatim and already forwards `agent_name` as `--diode-app-name-prefix`. |
| Lookup or data files | The extension adds none. Everything it needs comes from the policy YAML, and the version strings are `go:embed`ed into the binary at build time. |
| `agent.example.yaml` | A sample for your host, not something the image needs. Bind-mount your own config. |
| `tools/netbox-bootstrap/bootstrap_ipam.py` | Runs against the NetBox API from wherever you like, not inside the agent. |
| `docs/IPAM_EXTENSION.md` | Documentation. |

## Known limitations

- **A rejected changeset takes the whole batch.** `ERR_OPS_GENERATE_DIFF` from
  one missing custom field drops every entity in that ingest, prefixes and
  addresses alike. Run the bootstrap script before adding a custom field key.
- **JSON custom fields in diode-netbox-plugin.** A mapping or sequence is sent as
  a serialized string on the `json` variant. Plugin versions differ in whether
  they re-parse it, so a `json` custom field can end up holding an escaped string
  rather than an object. Prefer flat scalars for anything you intend to filter on.
- **Reconciler PATCH semantics do not clear stale links.** Removing a `vlan` from
  a `subnet_map` entry stops the agent sending the link, but an absent field is
  omitted from the changeset rather than sent as null, so NetBox keeps the old
  VLAN association. The same applies to role, tenant and description. Clear these
  in the NetBox UI or API. This is the direct cost of the "unset means untouched"
  rule, which is what stops every scan overwriting operator edits.
- **No NetBox lookup.** `subnet_map` is static by design. A prefix that exists in
  NetBox but is absent from the map contributes nothing; addresses inside it fall
  back to the target mask.
- **One VRF per policy.** All prefixes go into `defaults.vrf`. Containment only
  nests within a VRF, so per-entry VRFs would break the hierarchy. Use one policy
  per VRF.
- **Deleted addresses are not reaped.** Discovery only adds and updates. An
  address that stops responding keeps its last `discovery_last_seen`; use that
  field to find stale records.
- **`is_pool` and `mark_utilized` are write-once in practice.** Because unset
  means untouched, flipping one back to its default requires setting it
  explicitly to `false`, not removing the key.
