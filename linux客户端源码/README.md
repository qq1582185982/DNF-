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

Quick start:

```bash
cp dnf-linux-client.conf.example dnf-linux-client.conf
vi dnf-linux-client.conf
chmod +x run.sh
./run.sh
```

Direct run:

```bash
sudo ./dnf-linux-client --config ./dnf-linux-client.conf
```

Optional:

```bash
  --config ./dnf-linux-client.conf
  --api-url 61.sviplk.com
  --api-port 35333
  --server-key 1
  --client-id vm-95
  --if-name dnfcli95
  --preferred-ip 10.0.11.50
  --tunnel-host 61.sviplk.com
  --tunnel-port 33335
```

Defaults:

- config search order:
  - `./dnf-linux-client.conf`
  - `./client.conf`
  - `/etc/dnf-linux-client.conf`
  - `/etc/dnf-linux-client/client.conf`
- `server_key` can be omitted when the API returns only one server
- `client_id` defaults to current hostname
- `if_name` defaults to `dnfcli0`

systemd:

```bash
chmod +x install.sh
sudo ./install.sh vm95
vi /etc/dnf-linux-client/vm95.conf
systemctl enable --now dnf-linux-client@vm95
```
