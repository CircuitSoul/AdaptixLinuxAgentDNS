**Read this in:** [Português](README.md) · [English](README.en.md)

# AdaptixC2 — Listener DNS + Agente Linux

Repositório com dois extenders usados em conjunto:

- **`beacon_listener_dns/`** — listener DNS registrado como `BeaconDNS`.
- **`agent_linux/`** — agente Linux registrado como `linux`, reescrito em C++20 e compatível com os listeners `BeaconHTTP`, `GopherTCP` e `BeaconDNS`.

O agente inclui correções para preenchimento correto dos metadados no AdaptixClient (IP interno, domínio, computador, usuário, OS, processo e arquitetura) e suporte ao transporte DNS com fragmentação, remontagem, RC4, base32 e zlib.

---

## 1. Estrutura do repositório

```text
.
├── README.md
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

Os artefatos gerados (`dist/`, `*.so`, `agent_linux_*`, `config.h` e `build/`) são ignorados pelo `.gitignore`.

---

## 2. Pré-requisitos

- AdaptixC2 v1.2 instalado ou clonado.
- Linux x86_64 para compilar os plugins `.so` (`-buildmode=plugin`).
- Go 1.25 ou superior com suporte a `buildmode=plugin`.
- `make`, `gcc` e `g++` com suporte a C++20.
- Para gerar agente ARM64: `g++-aarch64-linux-gnu` (comando `aarch64-linux-gnu-g++`).
- Para usar DNS: acesso à porta `53/UDP` (idealmente também `53/TCP`) e delegação DNS configurada.

---

## 3. Build local dos plugins

Os dois diretórios compilam de forma independente:

```bash
cd beacon_listener_dns
make

cd ../agent_linux
make
```

Cada `make` gera uma pasta `dist/` com:

- O plugin `.so`.
- O `config.yaml`.
- O `ax_config.axs`.
- No caso do agente, também uma cópia limpa de `src_cpp/`.

Se a sua rede exigir que o módulo `github.com/Adaptix-Framework/axc2` seja tratado como privado, use:

```bash
GOWORK=off GOSUMDB=off GOPRIVATE=github.com/Adaptix-Framework/axc2 make
```

---

## 4. Instalação em uma instalação nova do AdaptixC2

### 4.1 Instalação independente (copiando o `dist/`)

Ajuste os caminhos conforme a sua instalação:

```bash
ADAPTIX_DIST="/opt/AdaptixC2/dist"

mkdir -p "$ADAPTIX_DIST/extenders/beacon_listener_dns"
mkdir -p "$ADAPTIX_DIST/extenders/agent_linux"

cp -r beacon_listener_dns/dist/. "$ADAPTIX_DIST/extenders/beacon_listener_dns/"
cp -r agent_linux/dist/.        "$ADAPTIX_DIST/extenders/agent_linux/"
```

Depois edite `"$ADAPTIX_DIST/profile.yaml"` e garanta que os dois extenders estejam listados:

```yaml
Teamserver:
  extenders:
    - "extenders/beacon_listener_dns/config.yaml"
    - "extenders/agent_linux/config.yaml"
```

Reinicie o servidor:

```bash
cd "$ADAPTIX_DIST"
pkill -f adaptixserver || true
nohup ./adaptixserver -profile profile.yaml > /tmp/adaptixserver.log 2>&1 &
```

### 4.2 Integração no build oficial (`make server-ext`)

Se preferir compilar tudo junto com o AdaptixC2:

```bash
ADAPTIX_ROOT="/opt/AdaptixC2"

cp -r beacon_listener_dns "$ADAPTIX_ROOT/AdaptixServer/extenders/"
cp -r agent_linux          "$ADAPTIX_ROOT/AdaptixServer/extenders/"

cd "$ADAPTIX_ROOT/AdaptixServer"
go work use ./extenders/beacon_listener_dns ./extenders/agent_linux
go work sync
```

Edite `"$ADAPTIX_ROOT/AdaptixServer/profile.yaml"` e adicione:

```yaml
Teamserver:
  extenders:
    - "extenders/beacon_listener_dns/config.yaml"
    - "extenders/agent_linux/config.yaml"
```

Compile servidor e extenders:

```bash
cd "$ADAPTIX_ROOT"
make server-ext
```

O resultado fica em `"$ADAPTIX_ROOT/dist"`. Inicie com:

```bash
cd "$ADAPTIX_ROOT/dist"
./adaptixserver -profile profile.yaml
```

---

## 5. Delegação DNS (exemplo genérico)

Use nomes fictícios e substitua pelo seu próprio domínio e IP público do servidor:

| Tipo | Nome | Valor |
|------|------|-------|
| `A`  | `ns1.example.com` | `198.51.100.10` |
| `NS` | `c2.example.com`  | `ns1.example.com` |

Na Cloudflare ou no seu provedor de DNS, crie os registros na zona `example.com` sem remover os demais registros existentes. O listener e o agente devem usar **exatamente** o mesmo domínio autoritativo (`c2.example.com` no exemplo).

Valide a delegação:

```bash
dig @198.51.100.10 c2.example.com NS
dig @198.51.100.10 c2.example.com TXT
```

---

## 6. Criando o listener DNS

### 6.1 Pela interface do AdaptixClient

- Listener type: `BeaconDNS`.
- Nome do listener: `dns_local` (exemplo).
- Host & Port (Bind): `0.0.0.0` / `53`.
- Authoritative Domain(s): `c2.example.com`.
- Max Payload: `4096` (reduza para `512` se a rede limitar pacotes DNS grandes).
- DNS TTL: `5`.
- Encryption Key: 32 caracteres hexadecimais, por exemplo:

```text
00112233445566778899aabbccddeeff
```

### 6.2 Pela API

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

## 7. Gerando o agente Linux

### 7.1 Pela interface do AdaptixClient

- Agente: `linux`.
- Listener: `dns_local`.
- Arch: `amd64` (ou `arm64`).
- Format: `Binary ELF`.
- Reconnect timeout / sleep base: `5` (exemplo).
- Jitter: `10` (exemplo, `0` para desativar).

O build do agente invoca `agent_linux/src_cpp/Makefile` e gera o ELF.

### 7.2 Pela API

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

O comando acima grava o ELF no diretório atual. Para `arm64`, use `"arch":"arm64"` e instale antes:

```bash
sudo apt-get update
sudo apt-get install -y g++-aarch64-linux-gnu
```

---

## 8. Build manual do implante C++

Também é possível compilar o agente diretamente, sem passar pela API:

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

O Makefile gera automaticamente `config.h`. Um exemplo genérico está em `agent_linux/src_cpp/config.h.example`.

Para builds estáticos com musl, consulte `agent_linux/src_cpp/README.md`.

---

## 9. Modificações incluídas no agente

- Preenchimento dos metadados no AdaptixClient:
  - `os_desc` usa `Linux` quando vazio.
  - `domain` usa `(none)` quando vazio.
  - `process` usa `linux_agent` quando vazio.
  - Arquitetura `amd64` é apresentada como `x64`.
- O heartbeat DNS envia os campos necessários para criar a sessão corretamente (`process`, `user`, `host`, `ipaddr`, `elevated`, `encrypt_key`, `arch`, entre outros).
- O Makefile do `src_cpp` foi ajustado para gerar `config.h` corretamente também no build independente (`SKIP_CONFIG=0`) e para manter o `dist/src_cpp` limpo, sem binários ou headers gerados.

---

## 10. Observações de OPSEC

- Substitua todos os valores de exemplo (`example.com`, `198.51.100.10`, chaves `001122...`) pelos valores reais do seu ambiente autorizado.
- Não coloque em produção `config.h` com chaves reais nem binários compilados dentro do repositório.
- O listener DNS normalmente precisa de `root` ou `CAP_NET_BIND_SERVICE` para escutar na porta 53.
- Teste primeiro em laboratório; valide com `dig` e com um agente de teste antes de usar em uma operação real.
