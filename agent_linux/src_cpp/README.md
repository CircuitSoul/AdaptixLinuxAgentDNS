# Linux Agent C++ (AdaptixC2)

Agente Linux reescrito em **C++20** para substituir o `src_linux` Go original.

## Transportes suportados

| `TRANSPORT` | Listener Adaptix | Protocolo | Status |
|-------------|------------------|-----------|--------|
| `http`      | `BeaconHTTP`     | HTTP(S), heartbeat RC4/base64 em header custom, payload AES-GCM no corpo | validado localmente |
| `tcp`       | `GopherTCP`      | TCP/mTLS, framing length-prefix (4 bytes BE), msgpack + AES-GCM | validado localmente |
| `dns`       | `BeaconDNS`      | DNS TXT/A, fragmentação/reassembly, base32, RC4, zlib | implementado (exige validação contra listener real) |
| `icmp`      | listener customizado | ICMP echo com payload (raw socket) | implementado no agente; falta listener no servidor |

## Features implementadas

### Núcleo
- Heartbeat com `watermark + agent_id + session_info` (MsgPack) e RC4/base64.
- Criptografia de sessão AES-GCM com nonce de 12 bytes.
- Sleep/jitter, kill date e working time.
- `exit` e troca dinâmica de sleep/jitter.

### Arquivos e shell
- `pwd`, `cd`, `ls`, `cat`, `cp`, `mv`, `mkdir`, `rm`, `zip`
- `upload`, `download` com chunks de 1 MiB
- `shell`, `run` com timeout de 30s
- `ps`, `kill`

### Coleta Linux
- `sysinfo`, `env`, `network`, `users`, `cron`, `sshkeys`, `history`
- `docker`, `services`, `privesc`, `mounts`
- `getuid`, `filesearch`, `sshagent`, `kubeconfig`, `cloudmeta`
- `whoami`, `hostname`, `lsof`, `iptables`, `last`, `shadow`

### Persistência
- `persist_cron`
- `persist_ssh`

### Canais interativos
- Túnel TCP / SOCKS (`CMD_TUNNEL_*`)
- Reverse port forwarding (`CMD_TUNNEL_REVERSE` / `CMD_TUNNEL_ACCEPT`)
- Terminal PTY (`CMD_TERMINAL_*`)

## Build

```bash
cd src_cpp
make                       # HTTP amd64 por padrão
make TRANSPORT=tcp HOST=10.0.0.5 PORT=4444 ENC_KEY=<32 hex> TCP_BANNER='' TARGET=agent_linux_tcp
make TRANSPORT=dns DNS_DOMAIN=ns1.c2.com DNS_ENC_KEY=<32 hex> TARGET=agent_linux_dns
```

O plugin servidor (`agent_linux/pl_main.go`) gera `config.h` e chama este Makefile durante a geração do payload.

Quando o toolchain musl está instalado, o Makefile o usa automaticamente e
gera binário **estático** (sem dependência de glibc):

```bash
# no servidor de build (Ubuntu 24.04 usado como builder):
cd /opt
curl -fsSL https://musl.cc/x86_64-linux-musl-cross.tgz | tar xz
make                       # já produz static-pie com musl
ldd agent_linux_amd64      # esperado: statically linked
```

Para TLS (`USE_SSL=true` ou `TCP_USE_SSL=true`) o Makefile espera OpenSSL
estático compilado para musl em `/opt/openssl-musl`:

```bash
cd /opt
curl -fsSLO https://www.openssl.org/source/openssl-3.0.13.tar.gz
tar xzf openssl-3.0.13.tar.gz
cd openssl-3.0.13
./Configure linux-x86_64 no-shared no-async no-dso no-tests no-engine no-comp \
  --prefix=/opt/openssl-musl --openssldir=/opt/openssl-musl/ssl \
  CC=/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc \
  CXX=/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-g++ \
  AR=/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-ar \
  RANLIB=/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-ranlib
make -j2 && make install_sw
```

O caminho detectado automaticamente é:

- toolchain: `/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-g++`
- OpenSSL musl: `/opt/openssl-musl/include` e `/opt/openssl-musl/lib64`

## Observações
- Para binários ARM64 é necessário `aarch64-linux-gnu-g++`.
- O transporte ICMP usa `SOCK_RAW`/`IPPROTO_ICMP` e normalmente exige `root`/`CAP_NET_RAW`; o listener ICMP correspondente ainda precisa ser criado no lado do AdaptixC2.
