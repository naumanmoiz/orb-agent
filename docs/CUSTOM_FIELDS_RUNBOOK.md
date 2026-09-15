# Build and deploy runbook: network_discovery custom fields

From a clean checkout to a running agent writing custom fields into NetBox.

For what the keys mean, see [CUSTOM_FIELDS.md](CUSTOM_FIELDS.md). This document
is about building the image and running it.

## 0. Prerequisites

On the build host: Docker with buildx. Nothing else. Go, nmap and Python all
live inside the build stages.

In NetBox, before the first **live** run: the custom field definitions must
exist on `ipam.ipaddress`. Step 4 handles that. The tenant and VRF named in your
policy must also exist.

## 1. Get the code

```bash
git clone https://github.com/netboxlabs/orb-agent.git
cd orb-agent
git checkout feat/network-discovery-custom-fields
export SHA=$(git rev-parse --short HEAD)
```

## 2. Choose a build path

Only one artifact changes: `/usr/local/bin/network-discovery`. The `orb-agent`
binary, the other discovery backends, pktvisor and the Python packages are
untouched, so a full rebuild is rarely needed.

| Path | Time | Use when |
|---|---|---|
| **A. Bind-mount** | seconds | Trying it out. No image build at all. |
| **B. Overlay image** | under a minute | Normal. Rebuilds one backend over your existing image. |
| **C. Full image** | several minutes | You want a self-contained image. |

### A. Bind-mount, no image build

The image sets `ENV PATH=/opt/orb/files:$PATH` and the entrypoint recreates
`/opt/orb/files` on start, so a binary there shadows the stock one. The agent
execs the bare name `network-discovery`, resolved through `PATH`.

```bash
cd orb-discovery/network-discovery && GOWORK=off make build && cd ../..

docker run --rm --net=host -u root \
  -v $(pwd)/orb-discovery/network-discovery/build/network-discovery:/opt/orb/files/network-discovery:ro \
  -v /opt/orb-agent:/opt/orb \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

Needs a local Go toolchain matching `go.mod` (1.26.6).

### B. Overlay image

Find the tag your container runs first, so the overlay rebases onto the same
agent rather than a newer one:

```bash
docker inspect --format '{{.Config.Image}}' <your-orb-agent-container>
docker inspect --format '{{index .RepoDigests 0}}' netboxlabs/orb-agent:<tag>
```

```bash
docker build -f agent/docker/Dockerfile.overlay \
  --platform linux/amd64 \
  --build-arg BASE_IMAGE=netboxlabs/orb-agent@sha256:<digest> \
  --build-arg NETWORK_DISCOVERY_VERSION=$(cat orb-discovery/network-discovery/version/BUILD_VERSION.txt) \
  --build-arg BUILD_COMMIT=$SHA \
  -t orb-agent:cf-$SHA .
```

Pin the digest rather than a moving tag so the overlay cannot silently rebase.
With no container to inspect, `BASE_IMAGE=netboxlabs/orb-agent:latest` is fine.

### C. Full image

```bash
docker build -f agent/docker/Dockerfile \
  --platform linux/amd64 \
  --build-arg NETWORK_DISCOVERY_VERSION=$(cat orb-discovery/network-discovery/version/BUILD_VERSION.txt) \
  --build-arg BUILD_COMMIT=$SHA \
  -t orb-agent:cf-$SHA .
```

The Python stage installs from PyPI. If your Docker daemon cannot resolve DNS in
the build sandbox, add `--network=host`.

No static-build flags are needed: the backend already builds `CGO_ENABLED=0`, so
it is static ELF with no libc dependency and drops onto the image's
`python:3.14-alpine` base unchanged.

### Verify the image

```bash
docker run --rm --entrypoint sh orb-agent:cf-$SHA -c '
  /usr/local/bin/network-discovery -help 2>&1 | head -2
  echo "nmap: $(command -v nmap)"
  ls -l /usr/local/bin/network-discovery'
```

Expect the usage banner, `nmap: /usr/bin/nmap`, and a binary newer than the rest
of the image.

## 3. Write the config

Put `agent.yaml` in a directory you will mount, e.g. `/opt/orb-agent`. A full
sample is at [`agent.example.yaml`](../agent.example.yaml) and in
[section 8](#8-sample-agentyaml).

| Placeholder | Meaning |
|---|---|
| `<DIODE_HOST>` | Your Diode server address |
| `LAB-AUS-01` | Your real tenant / VRF identifier |
| `lab-agent-01` | Identifies this agent; this is what `${AGENT_NAME}` becomes |
| `192.0.2.0/24` | What nmap actually scans |

Credentials come from the environment, never the file.

## 4. Create or verify the custom fields

Diode never creates custom field definitions. An entity naming one that does not
exist makes the NetBox plugin reject the plan, and the reconciler reports
`ERR_OPS_GENERATE_DIFF` after dropping the **whole batch**.

```bash
pip install requests PyYAML
export NETBOX_URL=https://netbox.example.net NETBOX_TOKEN=...

python3 tools/netbox-bootstrap/bootstrap_custom_fields.py \
  --config /opt/orb-agent/agent.yaml --dry-run
```

Read it as a checklist:

| Line | Meaning |
|---|---|
| `ok` | Exists, right type, on `ipam.ipaddress` |
| `+ create` | Does not exist |
| `~ update` | Exists but not attached to `ipam.ipaddress` |
| `! WRONG` | Exists with the **wrong type** |

**If you created the fields by hand, run this anyway.** The common mistake is
`discovery_last_seen` created as `text`; it receives a datetime and fails
exactly as `ERR_OPS_GENERATE_DIFF`. The script exits non-zero when anything
needs attention, so it can gate a deploy.

Drop `--dry-run` to create what is missing. A type mismatch is reported, never
corrected: retyping a populated custom field is destructive, so that is your
call.

## 5. Dry run

Uncomment both dry-run keys under `backends.common.diode`:

```yaml
dry_run: true
dry_run_output_dir: /opt/orb/out
```

```bash
mkdir -p /opt/orb-agent/out
docker run --rm --net=host -u root \
  -v /opt/orb-agent:/opt/orb \
  orb-agent:cf-$SHA run -c /opt/orb/agent.yaml
```

No Diode and no credentials are needed. The agent runs until stopped; wait for
one scan, Ctrl-C, then inspect:

```bash
python3 - <<'EOF'
import json, glob
path = sorted(glob.glob('/opt/orb-agent/out/*.json'))[-1]
doc = json.load(open(path))
print(path, len(doc['entities']), 'entities')
for e in doc['entities']:
    if 'ip_address' in e:
        print(json.dumps(e['ip_address'], indent=2)); break
EOF
```

Check two things:

1. `discovery_last_seen` sits under `"datetime"`, not `"text"`. Under `"text"` a
   NetBox datetime custom field rejects it.
2. It is truncated to your `timestamp_precision`, e.g. `2026-09-15T00:00:00Z`
   for `day`.

> **The startup log is the authority on dry-run mode.** Look for `--dry-run` in
> the `network-discovery startup` arguments. The agent logs
> `entities ingested successfully` in dry-run mode too, because the same line
> covers both clients; in dry run it means "wrote a file".

The same walkthrough runs as a Go test, no Docker and no nmap:

```bash
cd orb-discovery/network-discovery
GOWORK=off go test -run TestDryRunGolden -v ./policy/...
```

## 6. Go live

**Remove** both dry-run keys. Do not set `dry_run: false` and leave the output
directory; remove the lines.

```bash
export DIODE_CLIENT_ID=... DIODE_CLIENT_SECRET=...

docker run -d --name orb-agent --restart unless-stopped \
  --net=host -u root \
  -e DIODE_CLIENT_ID -e DIODE_CLIENT_SECRET \
  -v /opt/orb-agent:/opt/orb \
  orb-agent:cf-$SHA run -c /opt/orb/agent.yaml

docker logs -f orb-agent
```

Confirm from the `network-discovery startup` line that `--dry-run` is gone and
`--diode-target` is present.

`--net=host` lets nmap reach your subnets directly. `-u root` is needed for
raw-socket scan types and to write into the mounted directory.

Compose form:

```yaml
services:
  orb-agent:
    image: orb-agent:cf-<sha>
    container_name: orb-agent
    restart: unless-stopped
    network_mode: host
    user: root
    environment:
      DIODE_CLIENT_ID: ${DIODE_CLIENT_ID}
      DIODE_CLIENT_SECRET: ${DIODE_CLIENT_SECRET}
    volumes:
      - /opt/orb-agent:/opt/orb
    command: ["run", "-c", "/opt/orb/agent.yaml"]
```

## 7. Verify in NetBox

IPAM > IP Addresses, filter by your VRF. Open one and check the custom fields
are populated and `discovery_last_seen` renders as a date and time.

### When the agent says success but NetBox is empty

This is the one that wastes time. `entities ingested successfully` means only
that **Diode's ingester** accepted the batch. Everything after that (Redis, the
reconciler, the NetBox plugin) is invisible to the agent, so a changeset the
plugin later rejects still looks like a clean run.

On the Diode host:

```bash
docker compose exec postgres psql -U <user> -d <diode_db> \
  -c "SELECT state, COUNT(*) FROM ingestion_logs GROUP BY state;"

docker compose exec postgres psql -U <user> -d <diode_db> -c \
  "SELECT ingestion_ts, object_type, state, error FROM ingestion_logs
   WHERE state <> 'reconciled' ORDER BY id DESC LIMIT 20;"
```

The `error` column carries the NetBox plugin's response and names the field. If
every row is `reconciled`, the data is in NetBox and you are filtering on the
wrong VRF.

Also useful:

```bash
docker compose logs --tail=200 diode-reconciler | grep -iE "error|ERR_"
docker compose exec redis redis-cli KEYS '*'   # then LLEN/XLEN: is the queue draining?
```

## 8. Sample agent.yaml

Identical to [`agent.example.yaml`](../agent.example.yaml).

```yaml
orb:
  config_manager:
    active: local
  backends:
    common:
      diode:
        target: grpc://<DIODE_HOST>:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: lab-agent-01
        # Uncomment both for a dry run. REMOVE them to go live.
        # dry_run: true
        # dry_run_output_dir: /opt/orb/out
    network_discovery: {}
  policies:
    network_discovery:
      lab_scan:
        config:
          schedule: "0 */4 * * *"
          timeout: 10
          defaults:
            vrf: LAB-AUS-01
            tenant: LAB-AUS-01
            description: "Discovered by orb network_discovery"
            tags: [orb, network-discovery]
          custom_fields:
            discovery_agent: "${AGENT_NAME}"
            discovery_policy: "${POLICY_NAME}"
            discovery_last_seen: "${SCAN_TIMESTAMP}"
            discovery_source: network_discovery
          timestamp_precision: day
        scope:
          targets:
            - 192.0.2.0/24
```

### Many labs on one agent

One agent runs many policies, each with its own VRF. Overlapping subnets stay
separate because each policy is its own runner and prefixes are matched by
`(prefix, vrf)`:

```yaml
  policies:
    network_discovery:
      lab_a_scan:
        config:
          defaults: {vrf: LAB-A, tenant: LAB-A}
          custom_fields:
            discovery_agent: "${AGENT_NAME}"
            discovery_policy: "${POLICY_NAME}"
            discovery_last_seen: "${SCAN_TIMESTAMP}"
            discovery_source: network_discovery
          timestamp_precision: day
        scope:
          targets: ["192.0.2.0/24"]
      lab_b_scan:
        config:
          defaults: {vrf: LAB-B, tenant: LAB-B}
          custom_fields:
            discovery_agent: "${AGENT_NAME}"
            discovery_policy: "${POLICY_NAME}"
            discovery_last_seen: "${SCAN_TIMESTAMP}"
            discovery_source: network_discovery
          timestamp_precision: day
        scope:
          targets: ["198.51.100.0/24"]
```

`${POLICY_NAME}` distinguishes them in NetBox, so one agent's records stay
attributable per lab.

## 9. Rollback

Nothing in NetBox needs undoing; this change only adds field values.

```bash
docker stop orb-agent && docker rm orb-agent
docker run -d --name orb-agent --restart unless-stopped \
  --net=host -u root -v /opt/orb-agent:/opt/orb \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

The stock backend ignores `custom_fields` and `timestamp_precision`, so the same
config file keeps working. Verified against `netboxlabs/orb-agent:latest` with
the sample config: it starts, scans, and emits the address with no
`custom_fields`, no error and, worth knowing, **no warning either**. The keys are
dropped silently, so the only way to tell a rolled-back agent from a current one
is that the fields stop being populated. Existing values stay in NetBox until
something clears them.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ERR_OPS_GENERATE_DIFF` in the reconciler log | A custom field is missing, not on `ipam.ipaddress`, or the wrong type. Re-run step 4. |
| No `custom_fields` in the dry-run output | The policy has no `custom_fields`, or a `${VAR}` failed to resolve. Check the agent log for `skipping custom fields`. |
| `discovery_agent` missing, log says `${AGENT_NAME} is empty` | `common.diode.agent_name` is unset. |
| Agent exits immediately | Bad YAML, or a `${VAR}` with no value in the environment. |
| Policy rejected at startup | `timestamp_precision` is not one of nanosecond, second, minute, hour, day. |
| Data written to a file, nothing in NetBox | Still in dry-run mode. Check the startup arguments for `--dry-run`. |
| NetBox changelog growing fast | `timestamp_precision` is too fine. See [CUSTOM_FIELDS.md](CUSTOM_FIELDS.md#configtimestamp_precision). |
