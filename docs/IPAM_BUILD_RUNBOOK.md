# Build and deploy runbook: network_discovery IPAM extension

End to end, from a clean checkout to a running agent writing prefixes, VLANs and
custom fields into NetBox.

For what the new config keys mean, see [IPAM_EXTENSION.md](IPAM_EXTENSION.md).
This document is only about building the image and running it.

## 0. Prerequisites

On the build host:

- Docker with buildx (any recent Docker Engine). Nothing else is required: Go,
  nmap and Python all live inside the build stages.
- The repo, on the branch carrying the extension.

On the NetBox side, before the first **live** run:

- The site, tenant and VRF named in your policy must already exist.
- The custom fields, `ipam.Role` objects and VLAN group must exist. Step 5
  creates them.

Nothing here needs Docker on the NetBox host, and nothing needs the bootstrap
script on the agent host.

## 1. Get the code

```bash
git clone https://github.com/netboxlabs/orb-agent.git
cd orb-agent
git checkout feat/network-discovery-ipam
export SHA=$(git rev-parse --short HEAD)
echo "building from $SHA"
```

## 2. Choose a build path

Only one artifact changes: `/usr/local/bin/network-discovery`. The `orb-agent`
binary, the other discovery backends, pktvisor and the Python packages are all
untouched, so you do not have to rebuild them.

| Path | Build time | Use when |
|---|---|---|
| **A. Bind-mount** | seconds | Trying the extension out. No image build at all. |
| **B. Overlay image** | under a minute | Normal. Rebuilds one backend over your existing image. |
| **C. Full image** | several minutes | You want a self-contained image, or you are also changing the agent. |

### A. Bind-mount, no image build

The image sets `ENV PATH=/opt/orb/files:$PATH` and the entrypoint recreates
`/opt/orb/files` on start, so a binary dropped there shadows the stock one. The
agent execs the bare name `network-discovery`, resolved through `PATH`.

```bash
cd orb-discovery/network-discovery
GOWORK=off make build          # produces build/network-discovery
cd ../..

docker run --rm --net=host -u root \
  -v $(pwd)/orb-discovery/network-discovery/build/network-discovery:/opt/orb/files/network-discovery:ro \
  -v /opt/orb-agent:/opt/orb \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

Requires a local Go toolchain matching `go.mod` (1.26.6). Mount your config
somewhere other than `/opt/orb` if you would rather not bind-mount over it.

### B. Overlay image

First find the tag your current container runs, so the overlay rebases onto the
same agent and not a newer one:

```bash
docker inspect --format '{{.Config.Image}}' <your-orb-agent-container>
docker inspect --format '{{index .RepoDigests 0}}' netboxlabs/orb-agent:<tag>
```

Pin the digest rather than a moving tag:

```bash
docker build -f agent/docker/Dockerfile.overlay \
  --platform linux/amd64 \
  --build-arg BASE_IMAGE=netboxlabs/orb-agent@sha256:<digest> \
  --build-arg NETWORK_DISCOVERY_VERSION=$(cat orb-discovery/network-discovery/version/BUILD_VERSION.txt) \
  --build-arg BUILD_COMMIT=$SHA \
  -t orb-agent:ipam-overlay-$SHA .
```

If you have no running container to inspect, `BASE_IMAGE=netboxlabs/orb-agent:latest`
is a reasonable default.

### C. Full image

```bash
docker build -f agent/docker/Dockerfile \
  --platform linux/amd64 \
  --build-arg NETWORK_DISCOVERY_VERSION=$(cat orb-discovery/network-discovery/version/BUILD_VERSION.txt) \
  --build-arg BUILD_COMMIT=$SHA \
  -t orb-agent:ipam-$SHA .
```

The Python stage installs from PyPI. On a host whose Docker daemon cannot
resolve DNS in the build sandbox, add `--network=host`.

Multi-arch is not needed; `--platform linux/amd64` is deliberate.

### Why no static-build flags are needed

The backend already builds `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`, so it is
static ELF with no libc dependency. The agent image's final stage is
`python:3.14-alpine` (musl). The binary drops in unchanged, which is what makes
the overlay and the bind-mount safe.

## 3. Verify the image before deploying

```bash
docker run --rm --entrypoint sh orb-agent:ipam-$SHA -c '
  /usr/local/bin/network-discovery -help 2>&1 | head -2
  echo "nmap: $(command -v nmap)"
  ls -l /usr/local/bin/network-discovery'
```

Expected: the usage banner, `nmap: /usr/bin/nmap`, and a binary newer than the
rest of the image.

## 4. Write the config

Put `agent.yaml` in a directory you will mount, for example `/opt/orb-agent`.
A full sample is in [`agent.example.yaml`](../agent.example.yaml) at the repo
root, and reproduced in [section 8](#8-sample-agentyaml) below.

Replace before running:

| Placeholder | Meaning |
|---|---|
| `<DIODE_HOST>` | Your Diode server address |
| `LAB-AUS-01` | Your real site / tenant / VRF identifier |
| `10.10.x.x` | Your real lab subnets |
| `lab-agent-01` | A name identifying this agent, used by `${AGENT_NAME}` |

Credentials come from the environment, never from the file.

## 5. Bootstrap NetBox

Run this from anywhere that can reach the NetBox API. Diode does not create
custom field definitions, and a changeset naming one that does not exist is
rejected with `ERR_OPS_GENERATE_DIFF`, dropping the whole batch.

```bash
pip install requests PyYAML
export NETBOX_URL=https://netbox.example.net
export NETBOX_TOKEN=...

python3 tools/netbox-bootstrap/bootstrap_ipam.py --config /opt/orb-agent/agent.yaml --dry-run
python3 tools/netbox-bootstrap/bootstrap_ipam.py --config /opt/orb-agent/agent.yaml
```

The script is idempotent: re-running it reports everything as `ok`. It skips a
VLAN group whose site does not exist rather than creating it unscoped, so create
the site first if you see that message.

## 6. Dry run

Keep `dry_run: true` for the first run. No Diode and no credentials are needed.

```bash
mkdir -p /opt/orb-agent/out
docker run --rm --net=host -u root \
  -v /opt/orb-agent:/opt/orb \
  orb-agent:ipam-$SHA run -c /opt/orb/agent.yaml
```

The agent runs until stopped. Wait for one scan, then Ctrl-C and inspect:

```bash
python3 - <<'EOF'
import json, glob
from collections import Counter
path = sorted(glob.glob('/opt/orb-agent/out/*.json'))[-1]
doc = json.load(open(path))
print(path)
print(Counter(k for e in doc['entities'] for k in e if k != 'timestamp'))
for e in doc['entities']:
    if 'ip_address' in e:
        print(json.dumps(e['ip_address'], indent=2)); break
EOF
```

Check three things:

1. The counts include `prefix` and `vlan`, not just `ip_address`.
2. A discovered address carries the mask of its matched `subnet_map` entry, e.g.
   `"address": "10.10.20.200/25"` and not `/24`, `/16` or `/32`.
3. `discovery_last_seen` sits under `"datetime"`, not `"text"`. Under `"text"` a
   NetBox datetime custom field will reject it.

`"vid": "20"` being a quoted string is correct; that is protojson rendering an
int64.

## 7. Go live

Edit `agent.yaml`: remove `dry_run` and `dry_run_output_dir`, keep `target`,
`client_id` and `client_secret`. Then:

```bash
export DIODE_CLIENT_ID=...
export DIODE_CLIENT_SECRET=...

docker run -d --name orb-agent --restart unless-stopped \
  --net=host -u root \
  -e DIODE_CLIENT_ID -e DIODE_CLIENT_SECRET \
  -v /opt/orb-agent:/opt/orb \
  orb-agent:ipam-$SHA run -c /opt/orb/agent.yaml

docker logs -f orb-agent
```

`--net=host` lets nmap reach your lab subnets directly. `-u root` is needed for
raw-socket scan types and to write into the mounted directory.

Compose form:

```yaml
services:
  orb-agent:
    image: orb-agent:ipam-<sha>
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

Then verify in NetBox: prefixes nest under one another in the policy VRF, each
address sits under its most specific prefix, VLANs carry their group, and the
custom fields are populated. The detailed checklist is in
[IPAM_EXTENSION.md](IPAM_EXTENSION.md#d-verify-in-netbox).

## 8. Sample agent.yaml

Identical to [`agent.example.yaml`](../agent.example.yaml) at the repo root.

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
        # Remove both dry_run lines to ingest for real.
        dry_run: true
        dry_run_output_dir: /opt/orb/out
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
            site: LAB-AUS-01
            prefix:
              status: active
              role: lab-data
              is_pool: false
              mark_utilized: false
            vlan:
              status: active
              group: LAB-AUS-01-VLANS
          custom_fields:
            discovery_agent: "${AGENT_NAME}"
            discovery_policy: "${POLICY_NAME}"
            discovery_last_seen: "${SCAN_TIMESTAMP}"
            discovery_source: network_discovery
        scope:
          targets:
            - 10.10.0.0/16
          subnet_map:
            - prefix: 10.10.0.0/16
              status: container
              role: lab-aggregate
              description: "LAB-AUS-01 lab space"
            - prefix: 10.10.20.0/24
              description: "Lab server VLAN"
              role: lab-servers
              vlan: {vid: 20, name: SERVERS}
            - prefix: 10.10.20.128/25
              role: lab-servers-gpu
              vlan: {vid: 21, name: SERVERS-GPU}
            - prefix: 10.10.30.0/24
              role: lab-mgmt
              vlan: {vid: 30, name: MGMT}
              custom_fields:
                discovery_zone: management
```

`defaults.role` is deliberately absent. NetBox models the IPAddress role as a
fixed choice (`loopback`, `secondary`, `anycast`, `vip`, `vrrp`, `hsrp`, `glbp`,
`carp`), not as an `ipam.Role` object, so a value like `host` is rejected on
ingest. Use a tag or a custom field for arbitrary labels.

## 9. Rollback

Nothing in NetBox needs undoing; the extension only adds objects.

```bash
docker stop orb-agent && docker rm orb-agent
# restart on the stock image with your previous config
docker run -d --name orb-agent --restart unless-stopped \
  --net=host -u root -v /opt/orb-agent:/opt/orb \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

The stock backend ignores `subnet_map`, `custom_fields` and the new `defaults`
blocks, so the same config file keeps working unchanged. Verified against
`netboxlabs/orb-agent:latest` with the sample config: it starts, scans, and emits
`ip_address` entities only, with no `custom_fields` and the address back on the
target mask. No crash and no config error.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ERR_OPS_GENERATE_DIFF` in the reconciler log | A custom field is missing, or attached to only one of the two models. Re-run step 5. See [IPAM_EXTENSION.md](IPAM_EXTENSION.md#e-read-the-diode-reconciler-log). |
| No `prefix` entities in the dry-run output | The policy has no `subnet_map`, or it failed validation. Check the agent log for `policy rejected: invalid subnet_map`. |
| Addresses still `/32` | No `subnet_map` entry contains them. The fallback is the target mask, then `defaults.network_mask`, then `/32`. |
| `subnet_map entry overlaps no scan target` warning | An entry covers nothing in `targets`. Its prefix is still created; usually a typo. |
| Prefixes not nesting in NetBox | Entries landed in different VRFs. Containment only nests within one VRF; use one policy per VRF. |
| `nmap binary was not found` | Only possible outside the image. The image ships nmap at `/usr/bin/nmap`. |
| Agent exits immediately | Bad YAML, or a `${VAR}` with no value in the environment. |
