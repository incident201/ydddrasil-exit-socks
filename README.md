# ygg-exit-socks

Minimal Windows-friendly console client for ExitVPN-over-Yggdrasil.

It does not create Windows network interfaces, does not require administrator rights and does not route all system traffic. It starts an embedded Yggdrasil node, opens a UDP-over-Yggdrasil tunnel to `yggdrasil-exitd`, creates an in-process IPv4 TCP stack and exposes a local SOCKS5 proxy.

Only TCP CONNECT is implemented. Domain names are resolved through DNS-over-TCP via the exit tunnel, not through the local system resolver.

## Server side

`/etc/ygg-exitd.conf` must contain the Windows client's Yggdrasil IPv6 and the same inner IPv4:

```text
200:client:yggdrasil:ipv6:address:here 10.66.0.10
```

## Build

Clone your fork next to this project:

```bash
git clone https://github.com/incident201/yggdrasil-go ../yggdrasil-go
cd ../yggdrasil-go
git checkout develop
```

Then build:

```bash
cd ../ygg-exit-socks
go mod tidy
go build -o ygg-exit-socks.exe .
```

## Run

Copy `config.example.json` to `config.json`, edit it, put a normal Yggdrasil config into `yggdrasil.conf`, then:

```powershell
.\ygg-exit-socks.exe -config config.json
```

Configure applications to use SOCKS5 proxy:

```text
127.0.0.1:1080
```
