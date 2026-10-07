# NetBox prefix sync

The `netbox` config manager reads IPAM prefixes from NetBox and generates
`network_discovery` (and optionally `snmp_discovery`) policies from them. NetBox
stays the source of truth for what is scanned and where results are filed:
every discovered IP address is sent with exactly the VRF (name, RD, tenant) and
tenant of the NetBox prefix it was found in, so the Diode matcher finds the
existing objects instead of creating duplicates.

- [How it works](#how-it-works)
- [Configuration reference](#configuration-reference)
- [Generated policies](#generated-policies)
- [Reviewing before running: `netbox-render`](#reviewing-before-running-netbox-render)
- [Scale, batching and name stability](#scale-batching-and-name-stability)
- [Resilience](#resilience)
- [Automation template](#automation-template)
- [Limitations](#limitations)

A complete example is in [`agent.netbox-sync.example.yaml`](../agent.netbox-sync.example.yaml),
and a fully commented template for automation in
[`agent.netbox-sync.template.yaml`](../agent.netbox-sync.template.yaml).

## How it works

On startup and then on `schedule`, the agent:

1. Reads all prefixes (`/api/ipam/prefixes/`, plus `filters`), all VRFs and all
   tenants, with paginated list calls only: three endpoints per refresh, never
   one request per prefix. VRF and tenant lists give each prefix its VRF's RD
   and tenant, and the groups of both tenants.
2. Builds the prefix tree locally, **per VRF**: a prefix's children are the
   prefixes nested in it in the same VRF; the global table (no VRF) is its own
   tree. The same network in two VRFs is never treated as parent and child.
   A duplicate of a network in the same VRF nests under the first one.
3. **Pass 1** scans every *leaf* prefix (no children), at any depth, whose
   status is in `statuses`.
4. **Pass 2 ("stragglers")** scans, for every *parent* prefix (one with
   children, or any prefix whose status is `container`) whose status is in
   `statuses`, the address space none of its direct children covers. Children
   of every status count as covering. Each leftover block is filed under that
   parent's attributes, so addresses found there take the parent's mask, VRF,
   tenant and tags.
5. Renders the policies, writes them to `generated_config_path`, diffs them
   against the set it applied last time and adds, updates or removes policies.

Example tree in `VRF-A`:

```
198.51.100.0/24   container          <- parent: pass 2 scans .128/25 (uncovered)
  198.51.100.0/25   active           <- parent: pass 2 scans .96/27
    198.51.100.0/26   active         <- leaf: pass 1
    198.51.100.64/27  reserved       <- not scanned (status), but covers its space
```

Prefixes are sent with `emit_prefix: false`: they already exist in NetBox, so
the agent never re-asserts them. Descriptions and comments of existing objects
are never written by the generated policies (network_discovery no longer
writes scan JSON to comments; SNMP policies turn off
`device_description_from_sysdescr` and `interface_description_from_ifalias`
unless the template turns them back on).

**Branches.** The agent does not choose a NetBox branch. When the Diode NetBox
plugin is configured with a default branch, everything this agent sends lands
in that branch for review.

## Configuration reference

```yaml
orb:
  config_manager:
    active: netbox
    sources:
      netbox:
        url: ${NETBOX_URL}
        token: ${NETBOX_TOKEN}
        ...
```

### `sources.netbox`

| Key | Type | Default | Description |
|---|---|---|---|
| `url` | string | required | NetBox base URL, e.g. `https://netbox.example.com`. `${VAR}` is resolved from the environment. |
| `token` | string | required | API token. `Token <t>` and `Bearer <t>` are sent as is; a bare token is sent as `Bearer` when it starts with `nbt_` (NetBox v2 tokens) and as `Token` otherwise. `${VAR}` is resolved from the environment. The token needs read access to prefixes, VRFs and tenants. |
| `skip_tls_verify` | bool | `false` | Skip TLS verification. |
| `branch` | string | unset | Read from a netbox-branching branch (name or schema ID) instead of main, e.g. the branch Diode writes to, so subnets discovered there are scanned before the branch is merged. Resolved on every refresh; a missing branch, or one that is not `ready` (merged, archived), fails the refresh and the running policies are kept. The token also needs read access to branches. |
| `schedule` | cron | unset | When NetBox is re-read. Unset: the policies are generated once at startup, and a NetBox error at startup fails the agent. Set: a startup error is retried on the schedule. |
| `timeout` | int (s) | `30` | Per-request HTTP timeout. |
| `retries` | int | `3` | Retries for network errors, HTTP 429 and 5xx, with exponential backoff from 1 s. Other 4xx fail at once. |
| `page_size` | int | `1000` | API page size (capped at 1000). Paging is by `limit`/`offset`; the `next` URL is not followed, as proxies often rewrite it wrongly. |
| `statuses` | list | `[container, active]` | Prefix statuses that are scanned. All statuses are read, since all of them cover space. |
| `filters` | map | `{}` | Extra query parameters for `/api/ipam/prefixes/`; a list becomes a repeated parameter (`tag: [a, b]` is `tag=a&tag=b`). `limit` and `offset` are reserved. See [Limitations](#limitations). |
| `generated_config_path` | path | unset | The rendered policies are written here atomically on every refresh, before they are applied. |
| `allow_empty` | bool | `false` | When NetBox returns no prefixes at all, keep the running policies unless this is `true`. |
| `network_discovery` | map | | See below. |
| `snmp_discovery` | map | | See below. |

### `sources.netbox.network_discovery`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Generate network_discovery policies. |
| `schedule` | cron | `0 */6 * * *` | Pass-1 schedule. |
| `straggler_delay_minutes` | int | `30` | Pass 2 runs this many minutes after pass 1. The shift works when the minute field is a single number and the hour field is numbers, ranges, steps or lists; a shift past midnight additionally needs `*` day fields. |
| `straggler_schedule` | cron | unset | Explicit pass-2 schedule, replacing the shifted one. Required when `schedule` cannot be shifted (startup fails with a message saying so). |
| `stagger_minutes` | int | `0` | Spread the generated policies' start times evenly over this window. With 4 policies and 60 minutes they start at +0, +15, +30, +45. Pass 1 and pass 2 are staggered separately. Ignored, with a warning, for an unshiftable schedule. |
| `timeout` | int (min) | `30` | Policy timeout (nmap run time per policy). |
| `max_targets_per_policy` | int | `256` | At most this many prefixes per policy. |
| `max_hosts_per_policy` | int | `65536` | At most this many addresses per policy. Whichever limit is hit first closes the batch; a single prefix larger than the host limit gets a policy of its own. |
| `max_block_prefix_len_v4` | int | `16` | Pass-1 leaves shorter than this mask (larger) are skipped and logged. |
| `max_block_prefix_len_v6` | int | `112` | Same, IPv6. |
| `config` | map | `{}` | Merged into every generated policy's `config` (e.g. `defaults.tags`, `defaults.description`, `custom_fields`, `timestamp_precision`, `scan_details_in_comments`). `defaults.vrf`, `rd`, `vrf_tenant`, `vrf_tenant_group`, `tenant` and `tenant_group` are removed with a warning: they come from each prefix, and a template value would leak onto global-table prefixes. |
| `scope` | map | `{}` | Merged into every generated policy's `scope` (`top_ports`, `ports`, `timing`, `scan_types`, `max_retries`, `ping_scan`, ...). `targets` and `subnet_map` are generated. |
| `straggler.enabled` | bool | `true` | Generate pass-2 policies. |
| `straggler.max_block_prefix_len_v4` | int | `20` | Leftover blocks shorter than this mask are skipped and logged. |
| `straggler.max_block_prefix_len_v6` | int | `116` | Same, IPv6. |
| `straggler.max_hosts_per_parent` | int | `16384` | Total leftover addresses scanned per parent; blocks past the cap are skipped and logged. |
| `straggler.ping_only` | bool | `true` | Pass 2 does host discovery only: `ping_scan: true`, and `ports`, `exclude_ports`, `top_ports`, `scan_types`, `os_detection` and `fast_mode` are removed. |
| `straggler.max_targets_per_policy` / `max_hosts_per_policy` | int | pass-1 values | Batching limits for pass 2. |
| `straggler.scope` | map | `{}` | Extra scope merged into pass-2 policies only. |

### `sources.netbox.snmp_discovery`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Generate snmp_discovery policies, one target per pass-1 prefix. |
| `schedule` | cron | `15 */6 * * *` | SNMP schedule. |
| `stagger_minutes` | int | `0` | As for network_discovery. |
| `include_stragglers` | bool | `false` | Also poll the pass-2 leftover blocks, with their parent's attributes. |
| `max_targets_per_policy` / `max_hosts_per_policy` | int | `256` / `65536` | Batching limits. |
| `authentication` | map | `{}` | Copied into every policy's `scope.authentication`. Keep secrets as `${VAR}` (e.g. `community: ${SNMP_COMMUNITY}`); snmp-discovery resolves them from its environment, so they never reach the generated file. |
| `config` | map | `{}` | Merged into every policy's `config`. `defaults.tenant` and `defaults.ip_address`/`defaults.prefix` `vrf`, `vrf_ipv4`, `vrf_ipv6` and `tenant` are removed with a warning: they come from each prefix. `options.device_description_from_sysdescr` and `options.interface_description_from_ifalias` default to `false` here. `timeout` is the per-device walk budget in seconds and must exceed `snmp_timeout` (default 5); `netbox-render` rejects anything else. |

Switch-side setup (Cisco IOS-XE, Dell OS10, SONiC) and the SNMPv3 settings
to use are in [SNMP_DEVICE_SETUP.md](SNMP_DEVICE_SETUP.md).

Each SNMP target carries `override_defaults` built from its prefix: `site`
(the prefix scope's site name when `scope_type` is `dcim.site`, or the legacy
`site` field), `tenant` as `{name, group}`, and under both `ip_address` and
`prefix`: `vrf` as `{name, rd, tenant, tenant_group}`, `tenant`, and the
prefix's `tags`.

## Generated policies

Names are deterministic: `<kind>-<vrf>-<NNN>`.

| Kind | Name | Content |
|---|---|---|
| Pass 1 | `nb-nd-<vrf>-001` | Leaf prefixes as `targets`, one `subnet_map` entry each. |
| Pass 2 | `nb-nd-straggler-<vrf>-001` | Leftover blocks as `targets`, one `subnet_map` entry per parent. |
| SNMP | `nb-snmp-<vrf>-001` | Prefixes (and optionally blocks) as targets with `override_defaults`. |

`<vrf>` is the VRF name slugified (`VRF-A` is `vrf-a`), `global` for prefixes
without a VRF; if two VRF names slugify alike, both get `-v<id>`. The
config manager only ever manages or removes policies whose names start with
`nb-`.

A pass-1 policy for one prefix in `VRF-A`:

```yaml
network_discovery:
  nb-nd-vrf-a-001:
    config:
      schedule: 0 */6 * * *
      timeout: 30
      defaults:
        tags: [discovered]
    scope:
      top_ports: 100
      targets: [198.51.100.0/26]
      subnet_map:
        - prefix: 198.51.100.0/26
          emit_prefix: false
          vrf: VRF-A
          rd: "65000:1"
          vrf_tenant: Tenant A
          vrf_tenant_group: Group A
          tenant: Tenant B
          tenant_group: Group A
          status: active
          role: servers
          tags: [servers]
          address_tags: [servers]
```

Every subnet_map entry carries the prefix's VRF name, RD and VRF tenant (with
its group), its tenant (with its group), status, role, tags, `is_pool`,
`mark_utilized` and description. Only the VRF, tenant, mask and
`address_tags` affect what is sent, since the prefix itself is not emitted:
each discovered address takes the mask of the most specific entry containing
it, that entry's VRF and tenant, and its `address_tags` on top of
`config.defaults.tags`.

## Reviewing before running: `netbox-render`

```bash
orb-agent netbox-render -c agent.yaml                 # print to stdout
orb-agent netbox-render -c agent.yaml -o review.yaml  # write a file
```

It reads NetBox with the same settings, prints the policies in the same shape
as `orb.policies` with a header giving the counts and listing every skipped
block (up to 1000) with its reason, logs the counts and one warning per skip
reason to stderr (`-d` lists every skip), and exits. The file written to
`generated_config_path` has the same header. Nothing is scanned and nothing is applied. With the
docker image:

```bash
docker run --rm -e NETBOX_URL -e NETBOX_TOKEN -v "$PWD:/opt/orb" \
  orb-agent:netbox-sync netbox-render -c /opt/orb/agent.yaml
```

## Scale, batching and name stability

Prefixes are grouped by VRF, sorted by network, and cut into batches of at
most `max_targets_per_policy` prefixes and `max_hosts_per_policy` addresses. A
few thousand prefixes therefore become tens of policies, not thousands, and
each policy runs one nmap process. Generating policies for 5000 prefixes takes
well under a second.

Names are stable across refreshes, and a change in one VRF never touches
another VRF's policies. Within a VRF, batches are positional: a prefix added
or removed in the middle shifts the boundaries of the batches after it, which
then get updated (re-applied at a new version) on the next refresh. Adding
prefixes at the end of a VRF's address space only changes its last batch.
Updated policies restart their schedule; nothing is lost but the churn is
visible in the agent log.

The network_discovery backend runs every policy on its own schedule. Use
`stagger_minutes` to spread the start times so not every batch fires at once,
and size `timeout` for the largest batch.

## Resilience

- Every request has a timeout and is retried on network errors, 429 and 5xx.
- Any error while reading NetBox leaves the running policies untouched; the
  error is logged and the next scheduled refresh tries again.
- An empty result (no prefixes) is refused unless `allow_empty: true`.
- The generated file is written atomically (temporary file and rename).
- A policy is re-applied only when its rendered content changes (compared by
  hash), so an unchanged NetBox causes no restarts.

## Automation template

[`agent.netbox-sync.template.yaml`](../agent.netbox-sync.template.yaml) has every
site-specific value as a placeholder. Render-time placeholders (schedules,
limits, filters, statuses, agent name, output path) are meant to be filled by
your automation, for example with `envsubst` and an explicit variable list.
Runtime placeholders stay in the deployed file and are resolved by the agent
and backends from their environment: `NETBOX_URL`, `NETBOX_TOKEN`,
`DIODE_TARGET`, `DIODE_CLIENT_ID`, `DIODE_CLIENT_SECRET`, `SNMP_COMMUNITY`.
The scan tokens `${AGENT_NAME}`, `${POLICY_NAME}`, `${SCAN_TIMESTAMP}` and
`${SCAN_DETAILS}` in `custom_fields` are resolved by network_discovery and must
not be substituted, which is why the template names the agent
`${ORB_AGENT_NAME}` at render time. The variable list and typical values are
at the top of the template.

## Limitations

- `filters` narrow the single prefix read. A child hidden by a filter does not
  count as covering its parent, so pass 2 scans its space. Filter by whole
  subtrees (`vrf_id`, `tenant_id`, a tag on every level) rather than by
  attributes that differ between parents and children.
- A parent whose status is not in `statuses` has no pass-2 policy, although its
  eligible children are still scanned.
- Very large blocks are skipped rather than split, per the size limits. Lower
  the limits' masks to scan them, and raise `timeout` accordingly.
- `stagger_minutes` and `straggler_delay_minutes` need a shiftable schedule
  (see above); otherwise set `straggler_schedule` and leave staggering off.
- Only policies generated by this source are managed. `orb.policies` is not
  applied when `active: netbox`.
