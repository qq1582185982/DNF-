package com.dnf.tunnel.android;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

public final class DnfVpnService extends VpnService {
    static final String ACTION_START = "com.dnf.tunnel.android.START";
    static final String ACTION_STOP = "com.dnf.tunnel.android.STOP";
    static final String EXTRA_API_HOST = "api_host";
    static final String EXTRA_API_PORT = "api_port";
    static final String EXTRA_SERVER_KEY = "server_key";
    static final String EXTRA_CLIENT_ID = "client_id";

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread workerThread;
    private PacketTunnelClient packetTunnelClient;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }
        if (intent != null && ACTION_START.equals(intent.getAction())) {
            startVpn(intent);
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private synchronized void startVpn(final Intent intent) {
        if (running.get()) {
            return;
        }
        running.set(true);
        workerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                runVpnLoop(intent);
            }
        }, "dnf-android-vpn");
        workerThread.start();
    }

    private void runVpnLoop(Intent intent) {
        String apiHost = intent.getStringExtra(EXTRA_API_HOST);
        int apiPort = intent.getIntExtra(EXTRA_API_PORT, 0);
        String requestedServerKey = intent.getStringExtra(EXTRA_SERVER_KEY);
        String clientId = intent.getStringExtra(EXTRA_CLIENT_ID);
        String preferredIp = "";

        while (running.get()) {
            String sessionUuid = UUID.randomUUID().toString();
            String activeServerKey = null;
            ControlClient controlClient = null;
            try {
                controlClient = new ControlClient(apiHost, apiPort);
                List<ServerInfo> servers = controlClient.getServers();
                ServerInfo server = selectServer(servers, requestedServerKey);
                activeServerKey = server.serverKey();
                LeaseGrant lease = controlClient.requestLease(activeServerKey,
                                                              sessionUuid,
                                                              clientId,
                                                              preferredIp);
                preferredIp = lease.virtualIp;
                ParcelFileDescriptor vpnInterface = buildVpnInterface(server, lease);
                packetTunnelClient = new PacketTunnelClient(this,
                                                            vpnInterface,
                                                            server,
                                                            lease,
                                                            sessionUuid,
                                                            clientId);
                Thread renewThread = startRenewThread(controlClient,
                                                      activeServerKey,
                                                      sessionUuid,
                                                      lease.leaseSeconds);
                try {
                    packetTunnelClient.run();
                } finally {
                    renewThread.interrupt();
                }
            } catch (Exception ignored) {
                sleepQuietly(2000);
            } finally {
                if (packetTunnelClient != null) {
                    packetTunnelClient.stop();
                    packetTunnelClient = null;
                }
                if (controlClient != null && activeServerKey != null) {
                    controlClient.releaseLease(activeServerKey, sessionUuid);
                }
            }
        }
    }

    private Thread startRenewThread(final ControlClient controlClient,
                                    final String serverKey,
                                    final String sessionUuid,
                                    int leaseSeconds) {
        final long waitMs = Math.max(15, leaseSeconds / 2) * 1000L;
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (running.get() && !Thread.currentThread().isInterrupted()) {
                    sleepQuietly(waitMs);
                    if (!running.get() || Thread.currentThread().isInterrupted()) {
                        break;
                    }
                    try {
                        controlClient.renewLease(serverKey, sessionUuid);
                    } catch (Exception ignored) {
                        if (packetTunnelClient != null) {
                            packetTunnelClient.stop();
                        }
                        break;
                    }
                }
            }
        }, "dnf-android-lease-renew");
        thread.start();
        return thread;
    }

    private ParcelFileDescriptor buildVpnInterface(ServerInfo server, LeaseGrant lease) throws Exception {
        Builder builder = new Builder();
        builder.setSession("DNF Android Client");
        builder.setMtu(lease.mtu > 0 ? lease.mtu : 1400);
        builder.addAddress(lease.virtualIp, subnetMaskToPrefix(lease.subnetMask));
        if (!lease.routes.isEmpty()) {
            for (String route : lease.routes) {
                addRoute(builder, route);
            }
        } else if (server.virtualSubnet != null && !server.virtualSubnet.isEmpty()) {
            addRoute(builder, server.virtualSubnet);
        } else if (lease.serverVirtualIp != null && !lease.serverVirtualIp.isEmpty()) {
            builder.addRoute(lease.serverVirtualIp, 32);
        }
        ParcelFileDescriptor fd = builder.establish();
        if (fd == null) {
            throw new IllegalStateException("VPN permission not granted");
        }
        return fd;
    }

    private static void addRoute(Builder builder, String cidr) {
        if (cidr == null) {
            return;
        }
        int slash = cidr.indexOf('/');
        if (slash <= 0 || slash + 1 >= cidr.length()) {
            return;
        }
        builder.addRoute(cidr.substring(0, slash), Integer.parseInt(cidr.substring(slash + 1)));
    }

    private static ServerInfo selectServer(List<ServerInfo> servers, String serverKey) {
        if (servers == null || servers.isEmpty()) {
            throw new IllegalStateException("server list is empty");
        }
        if (serverKey != null && !serverKey.trim().isEmpty()) {
            String key = serverKey.trim();
            for (ServerInfo server : servers) {
                if (key.equals(server.serverKey())) {
                    return server;
                }
            }
        }
        return servers.get(0);
    }

    private synchronized void stopVpn() {
        running.set(false);
        if (packetTunnelClient != null) {
            packetTunnelClient.stop();
            packetTunnelClient = null;
        }
        if (workerThread != null) {
            workerThread.interrupt();
            workerThread = null;
        }
        stopSelf();
    }

    private static int subnetMaskToPrefix(String subnetMask) throws Exception {
        String[] parts = subnetMask.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("invalid subnet mask: " + subnetMask);
        }
        int prefix = 0;
        for (String part : parts) {
            int value = Integer.parseInt(part);
            for (int bit = 7; bit >= 0; --bit) {
                if ((value & (1 << bit)) != 0) {
                    ++prefix;
                }
            }
        }
        return prefix;
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
