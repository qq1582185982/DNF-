package com.dnf.tunnel.android;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class ControlClient {
    private static final int TIMEOUT_MS = 15000;

    private final String host;
    private final int port;

    ControlClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    List<ServerInfo> getServers() throws Exception {
        String response = sendCommand("GET_SERVERS\n", false);
        JSONObject root = new JSONObject(response);
        JSONArray array = root.getJSONArray("servers");
        List<ServerInfo> servers = new ArrayList<>();
        for (int i = 0; i < array.length(); ++i) {
            JSONObject item = array.getJSONObject(i);
            ServerInfo server = new ServerInfo();
            server.id = item.optInt("id", i + 1);
            server.name = item.optString("name", "node-" + server.id);
            server.serverVirtualIp = item.optString("server_virtual_ip", "");
            server.tunnelServerIp = item.optString("tunnel_server_ip", host);
            server.tunnelPort = item.optInt("tunnel_port", 0);
            server.virtualSubnet = item.optString("virtual_subnet", "");
            server.virtualGateway = item.optString("virtual_gateway", "");
            server.leaseSeconds = item.optInt("lease_seconds", 120);
            servers.add(server);
        }
        return servers;
    }

    LeaseGrant requestLease(String serverKey,
                            String sessionUuid,
                            String clientId,
                            String preferredIp) throws Exception {
        StringBuilder command = new StringBuilder();
        command.append("LEASE_IP ")
                .append(serverKey).append(' ')
                .append(sessionUuid).append(' ')
                .append(sanitizeToken(clientId));
        if (preferredIp != null && !preferredIp.trim().isEmpty()) {
            command.append(' ').append(preferredIp.trim());
        }
        command.append('\n');
        return parseLease(sendCommand(command.toString(), false));
    }

    LeaseGrant renewLease(String serverKey, String sessionUuid) throws Exception {
        return parseLease(sendCommand("RENEW_LEASE " + serverKey + " " + sessionUuid + "\n", false));
    }

    void releaseLease(String serverKey, String sessionUuid) {
        try {
            sendCommand("RELEASE_LEASE " + serverKey + " " + sessionUuid + "\n", true);
        } catch (Exception ignored) {
        }
    }

    private LeaseGrant parseLease(String response) throws Exception {
        JSONObject root = new JSONObject(response);
        LeaseGrant lease = new LeaseGrant();
        lease.status = root.optInt("status", 1);
        lease.message = root.optString("message", "");
        lease.virtualIp = root.optString("virtual_ip", "");
        lease.subnetMask = root.optString("subnet_mask", "");
        lease.gatewayIp = root.optString("gateway_ip", "");
        lease.serverVirtualIp = root.optString("server_virtual_ip", "");
        lease.mtu = root.optInt("mtu", 1400);
        lease.leaseSeconds = root.optInt("lease_seconds", 120);
        JSONArray routes = root.optJSONArray("routes");
        if (routes != null) {
            for (int i = 0; i < routes.length(); ++i) {
                lease.routes.add(routes.optString(i, ""));
            }
        }
        if (lease.status != 0) {
            throw new IllegalStateException("lease failed: " + lease.message);
        }
        if (lease.virtualIp.isEmpty() || lease.subnetMask.isEmpty() || lease.gatewayIp.isEmpty()) {
            throw new IllegalStateException("lease response missing network fields");
        }
        return lease;
    }

    private String sendCommand(String command, boolean allowEmptyResponse) throws Exception {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
        socket.setSoTimeout(TIMEOUT_MS);
        try {
            OutputStream out = socket.getOutputStream();
            out.write(command.getBytes(StandardCharsets.UTF_8));
            out.flush();
            socket.shutdownOutput();

            ByteArrayOutputStream body = new ByteArrayOutputStream();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[4096];
            while (true) {
                int n = in.read(buffer);
                if (n < 0) {
                    break;
                }
                if (n > 0) {
                    body.write(buffer, 0, n);
                }
            }
            String response = new String(body.toByteArray(), StandardCharsets.UTF_8);
            if (!allowEmptyResponse && response.trim().isEmpty()) {
                throw new IllegalStateException("empty server response");
            }
            return response;
        } finally {
            socket.close();
        }
    }

    private static String sanitizeToken(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().replaceAll("\\s+", "_");
    }
}
