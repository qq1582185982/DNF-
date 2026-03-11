# Linux Tunnel Client

This is a minimal Linux peer client for the current virtual LAN path:

- lease via LEASE_IP
- TUN interface on /dev/net/tun
- packet tunnel over TCP
- lease renew and release

Build:

```bash
./build.sh
```

Run:

```bash
sudo ./dnf-linux-client \
  --api-url 61.sviplk.com \
  --api-port 35333 \
  --server-key 1 \
  --client-id vm-95 \
  --if-name dnfcli95
```

Optional:

```bash
  --preferred-ip 10.0.11.50
  --tunnel-host 61.sviplk.com
  --tunnel-port 33335
```