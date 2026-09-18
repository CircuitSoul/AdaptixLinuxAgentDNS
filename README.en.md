**Read this in:** [Português](README.md) · [English](README.en.md)

# AdaptixC2 — DNS Listener + Linux Agent

Repository containing two extenders that are meant to be used together:

- **`beacon_listener_dns/`** — DNS listener registered as `BeaconDNS`.
- **`agent_linux/`** — Linux agent registered as `linux`, rewritten in C++20 and compatible with the `BeaconHTTP`, `GopherTCP`, and `BeaconDNS` listeners.

The agent includes fixes for correctly populating AdaptixClient metadata (internal IP, domain, computer, user, OS, process, and architecture) and supports the DNS transport with fragmentation, reassembly, RC4, base32, and zlib.

---

## 1. Repository layout

```text
.
├── README.md
├── README.en.md
├── .gitignore
├── beacon_listener_dns/
│   ├── Makefile
│   ├── ax_config.axs
│   ├── config.yaml
│   ├── go.mod
│   ├── go.sum
│   ├── pl_main.go
│   └── pl_transport.go
└── agent_linux/
    ├── Makefile
    ├── ax_config.axs
    ├── config.yaml
    ├── go.mod
    ├── go.sum
    ├── pl_main.go
    └── src_cpp/
        ├── Makefile
        ├── README.md
        ├── config.h.example
        ├── agent.cpp
        ├── agent.hpp
        ├── crypto.cpp
        ├── miniz.cpp
        ├── miniz.h
        ├── msgpack.cpp
        ├── tasks.cpp
        └── transports.cpp
```

Generated artifacts (`dist/`, `*.so`, `agent_linux_*`, `config.h`, and `build/`) are ignored by `.gitignore`.

---

## 2. Requirements

- AdaptixC2 v1.2 installed or cloned.
- Linux x86_64 to build the `.so` plugins (`-buildmode=plugin`).
- Go 1.25 or newer with `buildmode=plugin` support.
- `make`, `gcc`, and `g++` with C++20 support.
- To generate an ARM64 agent: `g++-aarch64-linux-gnu` (the `aarch64-linux-gnu-g++` command).
- To use DNS: access to `53/UDP` (ideally also `53/TCP`) and a configured DNS delegation.

---

## 3. Local plugin build

Both directories build independently:

```bash
cd beacon_listener_dns
make

cd ../agent_linux
make
```

Each `make` produces a `dist/` directory containing:

- The `.so` plugin.
- The `config.yaml` file.
- The `ax_config.axs` file.
- For the agent, a clean copy of `src_cpp/`.

If your environment requires `github.com/Adaptix-Framework/axc2` to be treated as private, use:

```bash
GOWORK=off GOSUMDB=off GOPRIVATE=github.com/Adaptix-Framework/axc2 make
```

---

## 4. Installing on a fresh AdaptixC2 installation

### 4.1 Standalone installation (copying `dist/`)

Adjust the paths to match your installation:

```bash
ADAPTIX_DIST="/opt/AdaptixC2/dist"

mkdir -p "$ADAPTIX_DIST/extenders/beacon_listener_dns"
mkdir -p "$ADAPTIX_DIST/extenders/agent_linux"

cp -r beacon_listener_dns/dist/. "$ADAPTIX_DIST/extenders/beacon_listener_dns/"
cp -r agent_linux/dist/.        "$ADAPTIX_DIST/extenders/agent_linux/"
```

Then edit `"$ADAPTIX_DIST/profile.yaml"` and make sure both extenders are listed:

```yaml
Teamserver:
  extenders:
    - "extenders/beacon_listener_dns/config.yaml"
    - "extenders/agent_linux/config.yaml"
```

Restart the server:

```bash
cd "$ADAPTIX_DIST"
pkill -f adaptixserver || true
nohup ./adaptixserver -profile profile.yaml > /tmp/adaptixserver.log 2>&1 &
```

### 4.2 Integrating into the official build (`make server-ext`)

If you prefer to build everything together with AdaptixC2:

```bash
ADAPTIX_ROOT="/opt/AdaptixC2"

cp -r beacon_listener_dns "$ADAPTIX_ROOT/AdaptixServer/extenders/"
cp -r agent_linux          "$ADAPTIX_ROOT/AdaptixServer/extenders/"

cd "$ADAPTIX_ROOT/AdaptixServer"
go work use ./extenders/beacon_listener_dns ./extenders/agent_linux
go work sync
```

Edit `"$ADAPTIX_ROOT/AdaptixServer/profile.yaml"` and add:

```yaml
Teamserver:
  extenders:
    - "extenders/beacon_listener_dns/config.yaml"
    - "extenders/agent_linux/config.yaml"
```

Build the server and extenders:

```bash
cd "$ADAPTIX_ROOT"
make server-ext
```

The result is placed in `"$ADAPTIX_ROOT/dist"`. Start it with:

```bash
cd "$ADAPTIX_ROOT/dist"
./adaptixserver -profile profile.yaml
```

---

## 5. DNS delegation (generic example)

Use placeholder names and replace them with your own domain and public server IP:

| Type | Name | Value |
|------|------|-------|
| `A`  | `ns1.example.com` | `198.51.100.10` |
| `NS` | `c2.example.com`  | `ns1.example.com` |

In Cloudflare or your DNS provider, create the records in the `example.com` zone without removing the other existing records. The listener and the agent must use **exactly** the same authoritative domain (`c2.example.com` in this example).

Validate the delegation:

```bash
dig @198.51.100.10 c2.example.com NS
dig @198.51.100.10 c2.example.com TXT
```

---

## 6. Creating the DNS listener

### 6.1 Through the AdaptixClient interface

- Listener type: `BeaconDNS`.
- Listener name: `dns_local` (example).
- Host & Port (Bind): `0.0.0.0` / `53`.
- Authoritative Domain(s): `c2.example.com`.
- Max Payload: `4096` (lower it to `512` if the network limits large DNS packets).
- DNS TTL: `5`.
- Encryption Key: 32 hexadecimal characters, for example:

```text
00112233445566778899aabbccddeeff
```

### 6.2 Through the API

```bash
SERVER="https://<c2-host>:<port>"
ENDPOINT="/endpoint"

TOKEN="$(curl -sk -X POST "$SERVER$ENDPOINT/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"<operator>","password":"<password>","version":"1.2"}' \
  | jq -r .access_token)"

curl -sk -X POST "$SERVER$ENDPOINT/listener/create" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "dns_local",
    "type": "BeaconDNS",
    "config": "{\"host_bind\":\"0.0.0.0\",\"port_bind\":53,\"domain\":\"c2.example.com\",\"pkt_size\":4096,\"ttl\":5,\"encrypt_key\":\"00112233445566778899aabbccddeeff\",\"protocol\":\"dns\",\"burst_enabled\":false,\"burst_sleep\":50,\"burst_jitter\":0}"
  }'
```

---

## 7. Generating the Linux agent

### 7.1 Through the AdaptixClient interface

- Agent: `linux`.
- Listener: `dns_local`.
- Arch: `amd64` (or `arm64`).
- Format: `Binary ELF`.
- Reconnect timeout / base sleep: `5` (example).
- Jitter: `10` (example, `0` to disable it).

The agent build invokes `agent_linux/src_cpp/Makefile` and generates the ELF.

### 7.2 Through the API

```bash
RESPONSE="$(curl -sk -X POST "$SERVER$ENDPOINT/agent/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "agent": "linux",
    "listener_name": ["dns_local"],
    "config": "{\"arch\":\"amd64\",\"format\":\"Binary ELF\",\"reconnect_timeout\":\"5\",\"reconnect_count\":0,\"jitter\":10,\"kill_date\":\"\",\"working_time\":\"\"}"
  }' | jq -r .message)"

FILEPART="${RESPONSE%%:*}"
DATAPART="${RESPONSE#*:}"
FILENAME="$(printf '%s' "$FILEPART" | base64 -d)"
printf '%s' "$DATAPART" | base64 -d > "$FILENAME"
chmod +x "$FILENAME"
```

The command above writes the ELF to the current directory. For `arm64`, use `"arch":"arm64"` and install the toolchain first:

```bash
sudo apt-get update
sudo apt-get install -y g++-aarch64-linux-gnu
```

---

## 8. Manual C++ implant build

You can also build the agent directly without going through the API:

```bash
cd agent_linux/src_cpp
make clean

# DNS amd64
make \
  TRANSPORT=dns \
  DNS_DOMAIN=c2.example.com \
  DNS_ENC_KEY=00112233445566778899aabbccddeeff \
  DNS_PKT_SIZE=4096 \
  RECONN=5 \
  JITTER=10 \
  TARGET=agent_linux_dns

# DNS arm64
make \
  CXX=aarch64-linux-gnu-g++ \
  TRANSPORT=dns \
  DNS_DOMAIN=c2.example.com \
  DNS_ENC_KEY=00112233445566778899aabbccddeeff \
  DNS_PKT_SIZE=4096 \
  RECONN=5 \
  JITTER=10 \
  TARGET=agent_linux_arm64
```

The Makefile generates `config.h` automatically. A generic example is available at `agent_linux/src_cpp/config.h.example`.

For static musl builds, see `agent_linux/src_cpp/README.md`.

---

## 9. Modifications included in the agent

- AdaptixClient metadata is populated correctly:
  - `os_desc` defaults to `Linux` when empty.
  - `domain` defaults to `(none)` when empty.
  - `process` defaults to `linux_agent` when empty.
  - `amd64` architecture is reported as `x64`.
- The DNS heartbeat sends the fields required to create the session correctly (`process`, `user`, `host`, `ipaddr`, `elevated`, `encrypt_key`, `arch`, among others).
- The `src_cpp` Makefile was adjusted to generate `config.h` correctly even for standalone builds (`SKIP_CONFIG=0`) and to keep `dist/src_cpp` clean, without generated binaries or headers.

---

## 10. OPSEC notes

- Replace every example value (`example.com`, `198.51.100.10`, `001122...`) with the real values for your authorized environment.
- Do not commit real keys inside `config.h` or compiled binaries to the repository.
- The DNS listener usually requires `root` or `CAP_NET_BIND_SERVICE` to listen on port 53.
- Test in a lab first; validate with `dig` and a test agent before using it in a real operation.
