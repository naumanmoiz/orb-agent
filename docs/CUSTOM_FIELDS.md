# network_discovery custom fields

Attaches NetBox custom field values to every IP address the `network_discovery`
backend emits, identifying the agent, the policy and the scan that produced the
record.

Purely additive. A policy that sets no `custom_fields` behaves exactly as before.

For build and deploy steps, see
[CUSTOM_FIELDS_RUNBOOK.md](CUSTOM_FIELDS_RUNBOOK.md).

## Config

```yaml
policies:
  lab_scan:
    config:
      defaults:
        vrf: LAB-AUS-01
        tenant: LAB-AUS-01
      custom_fields:
        discovery_agent: "${AGENT_NAME}"
        discovery_policy: "${POLICY_NAME}"
        discovery_last_seen: "${SCAN_TIMESTAMP}"
        discovery_source: network_discovery
      timestamp_precision: day
    scope:
      targets: [192.0.2.0/24]
```

### `config.custom_fields`

`map[string]any`, optional. Applied to every emitted `IPAddress`. Keys must be
NetBox custom field **names** (snake_case), not labels, and the definitions must
already exist on `ipam.ipaddress`.

Value types map from YAML:

| YAML | NetBox custom field type |
|---|---|
| string | text |
| integer | integer |
| boolean | boolean |
| float | decimal |
| timestamp (`2026-09-15T10:30:00Z`, unquoted) | datetime |
| mapping or sequence | json |
| null | dropped, not sent |

A value that is **exactly** `${NAME}` is substituted. `"lab-${NAME}"` is left as
literal text, matching the whole-value convention the backend already uses for
its flags.

| Token | Resolves to |
|---|---|
| `${AGENT_NAME}` | `common.diode.agent_name`, which reaches the backend as `--diode-app-name-prefix`. An empty agent name is an error, not a blank field. |
| `${POLICY_NAME}` | The policy key |
| `${SCAN_TIMESTAMP}` | The start of the scan run, truncated to `timestamp_precision`, as a **datetime** rather than a string. Identical across every address in one run. |
| any other `${VAR}` | The environment variable. Unset or empty is an error. |

A value that cannot be resolved is logged and the whole block is skipped for that
run. The addresses are still ingested, without custom fields.

### `config.timestamp_precision`

String, optional, default `day`. One of `nanosecond`, `second`, `minute`,
`hour`, `day`. An unrecognized value fails that policy at load with a clear log
line, leaving the agent and other policies running.

**This is a load control, not cosmetics.** Diode's reconciler writes to NetBox
only when an entity differs from what NetBox holds. At `nanosecond` precision
every address carries a value NetBox has never seen, so every address is
rewritten on every scan and NetBox records an `ObjectChange` for each. At `day`,
an otherwise unchanged address reconciles to a no-op.

At 600k addresses scanned every four hours, that is the difference between about
3.6M NetBox writes per day and close to zero. Choose a finer setting only if you
need sub-day last-seen resolution and have measured the write volume.

## NetBox prerequisites

Diode **never creates custom field definitions**. If an entity references one
that does not exist, the NetBox plugin rejects the plan and the reconciler
reports `ERR_OPS_GENERATE_DIFF`, dropping the **whole batch** rather than the
offending field.

```bash
pip install requests PyYAML
export NETBOX_URL=https://netbox.example.net NETBOX_TOKEN=...

# Check
python3 tools/netbox-bootstrap/bootstrap_custom_fields.py --config agent.example.yaml --dry-run

# Apply
python3 tools/netbox-bootstrap/bootstrap_custom_fields.py --config agent.example.yaml
```

Read the output as a checklist:

| Line | Meaning |
|---|---|
| `ok` | Exists, right type, attached to `ipam.ipaddress` |
| `+ create` | Does not exist |
| `~ update` | Exists but not attached to `ipam.ipaddress` |
| `! WRONG` | Exists with the **wrong type**, for example `discovery_last_seen` as `text` when a datetime is sent |

A type mismatch is reported, never corrected: retyping a populated custom field
is destructive, so that is your call. The script exits non-zero when any field
needs manual attention, so it can gate a deploy.

`NETBOX_URL` is the base URL without `/api`. A connection failure is reported in
one line with the likely cause; a `Connection reset by peer` is usually `http`
against an HTTPS listener. Use `--insecure` for a self-signed or internal CA
certificate.

It resolves `object_types` versus `content_types` from the running NetBox
version. NetBox renamed the field in 4.1, and sending the wrong one is accepted
as an unknown key, silently producing a custom field attached to nothing.

## Verifying

Set `dry_run: true` and `dry_run_output_dir`, run one scan, then:

```bash
docker exec <container> sh -c 'cat /opt/orb/out/*.json' | python3 -m json.tool | head -40
```

An emitted address should look like:

```json
{
  "address": "192.0.2.200/24",
  "vrf": {"name": "LAB-AUS-01"},
  "custom_fields": {
    "discovery_agent":     {"text": "lab-agent-01"},
    "discovery_policy":    {"text": "lab_scan"},
    "discovery_source":    {"text": "network_discovery"},
    "discovery_last_seen": {"datetime": "2026-09-15T00:00:00Z"}
  }
}
```

Check that `discovery_last_seen` sits under `"datetime"` and not `"text"`, and
that it is truncated to your configured precision.

The same walkthrough runs as a Go test, needing no Docker and no nmap:

```bash
cd orb-discovery/network-discovery
GOWORK=off go test -run TestDryRunGolden -v ./policy/...
```

## When it does not appear in NetBox

The agent logs `entities ingested successfully` as soon as Diode's **ingester**
accepts the batch. Everything after that (Redis, reconciler, the NetBox plugin)
is invisible to the agent, so a rejected changeset still logs success.

Look in Diode's Postgres:

```sql
SELECT state, COUNT(*) FROM ingestion_logs GROUP BY state;

SELECT ingestion_ts, object_type, state, error
FROM ingestion_logs
WHERE state <> 'reconciled'
ORDER BY id DESC LIMIT 20;
```

The `error` column carries the NetBox plugin's response and names the field.
`ERR_OPS_GENERATE_DIFF` on a custom field is almost always one of:

1. The field does not exist. Run the bootstrap script.
2. It exists but is not on `ipam.ipaddress`.
3. Type mismatch, usually `discovery_last_seen` as text.
4. The key is the label rather than the snake_case name.

## Known limitations

- **A rejected changeset takes the whole batch**, not just the offending entity.
- **Removing a key does not clear the value in NetBox.** An absent field is
  omitted from the changeset rather than sent as null, so the old value stays.
  Clear it in NetBox directly.
- **Discovery never deletes.** An address that stops responding keeps its last
  `discovery_last_seen`; use that field to find stale records, and note that
  `timestamp_precision` bounds how precise it can be.
