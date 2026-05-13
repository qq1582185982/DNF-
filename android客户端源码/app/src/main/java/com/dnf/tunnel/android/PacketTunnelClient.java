package com.dnf.tunnel.android;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

final class PacketTunnelClient {
    interface StatusListener {
        void onStatus(String message);
    }

    private static final int HEARTBEAT_INTERVAL_MS = 3000;
    private static final int PEER_KEEPALIVE_INTERVAL_MS = 3000;
    private static final int PEER_ROUTE_TIMEOUT_MS = 30000;
    private static final int SERVER_RECEIVE_TIMEOUT_MS = 60000;
    private static final int SOCKET_TIMEOUT_MS = 1000;
    private static final int MAX_PACKET_SIZE = 65535;

    private final VpnService vpnService;
    private final ParcelFileDescriptor vpnInterface;
    private final ServerInfo server;
    private final LeaseGrant lease;
    private final String sessionUuid;
    private final String clientId;
    private final boolean peerDirectEnabled;
    private final StatusListener statusListener;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Map<String, PeerRoute> peerRoutes = new ConcurrentHashMap<>();

    private DatagramSocket socket;
    private InetSocketAddress serverEndpoint;
    private Thread tunReadThread;
    private volatile long lastReceiveMs;
    private int nextPeerNonce = 1;

    PacketTunnelClient(VpnService vpnService,
                       ParcelFileDescriptor vpnInterface,
                       ServerInfo server,
                       LeaseGrant lease,
                       String sessionUuid,
                       String clientId,
                       boolean peerDirectEnabled,
                       StatusListener statusListener) {
        this.vpnService = vpnService;
        this.vpnInterface = vpnInterface;
        this.server = server;
        this.lease = lease;
        this.sessionUuid = sessionUuid;
        this.clientId = clientId;
        this.peerDirectEnabled = peerDirectEnabled;
        this.statusListener = statusListener;
    }

    void run() throws Exception {
        running.set(true);
        socket = new DatagramSocket();
        vpnService.protect(socket);
        serverEndpoint = new InetSocketAddress(InetAddress.getByName(server.tunnelServerIp),
                                               server.tunnelPort);
        socket.setSoTimeout(SOCKET_TIMEOUT_MS);

        sendHandshake();
        receiveHandshakeAck();
        startTunReadThread();
        receiveLoop();
    }

    void stop() {
        running.set(false);
        if (socket != null) {
            socket.close();
        }
        try {
            vpnInterface.close();
        } catch (IOException ignored) {
        }
        if (tunReadThread != null) {
            tunReadThread.interrupt();
        }
    }

    private void startTunReadThread() {
        tunReadThread = new Thread(new Runnable() {
            @Override
            public void run() {
                byte[] buffer = new byte[MAX_PACKET_SIZE];
                try {
                    FileInputStream input = new FileInputStream(vpnInterface.getFileDescriptor());
                    while (running.get()) {
                        int n = input.read(buffer);
                        if (n < 0) {
                            break;
                        }
                        if (n == 0 || !isIpv4Unicast(buffer, n)) {
                            continue;
                        }
                        String dstVirtualIp = ipv4String(buffer, 16);
                        if (isUdpIpv4(buffer, n) && trySendDirect(dstVirtualIp, buffer, n)) {
                            continue;
                        }
                        sendFrameToServer(PacketTunnelProtocol.FRAME_IPV4_PACKET, buffer, n);
                    }
                } catch (IOException ignored) {
                } finally {
                    running.set(false);
                }
            }
        }, "dnf-android-tun-read");
        tunReadThread.start();
    }

    private void receiveLoop() throws Exception {
        byte[] buffer = new byte[MAX_PACKET_SIZE];
        long lastHeartbeatMs = 0;
        long lastPeerMaintenanceMs = 0;
        FileOutputStream output = new FileOutputStream(vpnInterface.getFileDescriptor());
        while (running.get()) {
            long now = System.currentTimeMillis();
            if (now - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
                sendFrameToServer(PacketTunnelProtocol.FRAME_HEARTBEAT, null, 0);
                lastHeartbeatMs = now;
            }
            if (peerDirectEnabled && now - lastPeerMaintenanceMs >= PEER_KEEPALIVE_INTERVAL_MS) {
                maintainPeerRoutes(now);
                lastPeerMaintenanceMs = now;
            }
            if (lastReceiveMs != 0 && now - lastReceiveMs > SERVER_RECEIVE_TIMEOUT_MS) {
                throw new IOException("server receive timeout: " + (now - lastReceiveMs) + "ms");
            }

            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
            } catch (java.net.SocketTimeoutException ignored) {
                continue;
            }
            boolean fromServer = isFromServer(packet);
            if (fromServer) {
                lastReceiveMs = System.currentTimeMillis();
            } else if (!markDirectPeerSource(packet)) {
                continue;
            }
            consumeFrames(packet.getData(),
                          packet.getLength(),
                          output,
                          fromServer,
                          new InetSocketAddress(packet.getAddress(), packet.getPort()));
        }
    }

    private void consumeFrames(byte[] data,
                               int length,
                               FileOutputStream output,
                               boolean fromServer,
                               InetSocketAddress source) throws IOException {
        int offset = 0;
        while (offset + PacketTunnelProtocol.FRAME_HEADER_SIZE <= length) {
            int frameType = data[offset] & 0xFF;
            int payloadLength = PacketTunnelProtocol.readU16(data, offset + 1);
            int payloadOffset = offset + PacketTunnelProtocol.FRAME_HEADER_SIZE;
            int nextOffset = payloadOffset + payloadLength;
            if (nextOffset > length) {
                break;
            }

            if (frameType == PacketTunnelProtocol.FRAME_HEARTBEAT) {
                if (!fromServer) {
                    try {
                        sendFrameToEndpoint(source, PacketTunnelProtocol.FRAME_HEARTBEAT_ACK, null, 0);
                    } catch (IOException ignored) {
                    }
                }
            } else if (frameType == PacketTunnelProtocol.FRAME_HEARTBEAT_ACK) {
                // Keepalive acknowledgement.
            } else if (fromServer && handlePeerControlFrame(frameType, data, payloadOffset, payloadLength)) {
                // Peer control handled.
            } else if (frameType == PacketTunnelProtocol.FRAME_IPV4_PACKET && payloadLength > 0) {
                output.write(data, payloadOffset, payloadLength);
                output.flush();
            }
            offset = nextOffset;
        }
    }

    private boolean handlePeerControlFrame(int frameType, byte[] data, int offset, int length) {
        if (frameType == PacketTunnelProtocol.FRAME_PEER_OFFER) {
            PeerOffer offer = parsePeerOffer(data, offset, length);
            if (offer == null) {
                return true;
            }
            if (!peerDirectEnabled) {
                sendPeerDisableFrame(offer.peerVirtualIp, offer.endpointVersion);
                return true;
            }
            PeerRoute route = peerRoutes.get(offer.peerVirtualIp);
            if (route == null) {
                route = new PeerRoute();
                route.peerVirtualIp = offer.peerVirtualIp;
                peerRoutes.put(offer.peerVirtualIp, route);
            }
            if (route.endpointVersion != offer.endpointVersion) {
                route.active = false;
            }
            route.endpointVersion = offer.endpointVersion;
            route.endpoint = offer.endpoint;
            route.lastSeenMs = System.currentTimeMillis();
            emitStatus("收到 UDP 直连候选：" + offer.peerVirtualIp + " -> " +
                       offer.endpoint.getAddress().getHostAddress() + ":" + offer.endpoint.getPort());
            int nonce = nextPeerNonce();
            route.pendingNonce = nonce;
            sendPeerSignalFrame(PacketTunnelProtocol.FRAME_PEER_HELLO,
                                offer.peerVirtualIp,
                                offer.endpointVersion,
                                nonce);
            return true;
        }

        if (frameType == PacketTunnelProtocol.FRAME_PEER_HELLO ||
            frameType == PacketTunnelProtocol.FRAME_PEER_ACK ||
            frameType == PacketTunnelProtocol.FRAME_PEER_KEEPALIVE) {
            PeerSignal signal = parsePeerSignal(data, offset, length);
            if (signal == null) {
                return true;
            }
            if (!peerDirectEnabled) {
                if (frameType != PacketTunnelProtocol.FRAME_PEER_ACK) {
                    sendPeerDisableFrame(signal.peerVirtualIp, signal.endpointVersion);
                }
                return true;
            }
            PeerRoute route = peerRoutes.get(signal.peerVirtualIp);
            if (route != null && route.endpointVersion <= signal.endpointVersion) {
                boolean wasActive = route.active;
                route.endpointVersion = signal.endpointVersion;
                route.lastSeenMs = System.currentTimeMillis();
                if (frameType == PacketTunnelProtocol.FRAME_PEER_HELLO ||
                    frameType == PacketTunnelProtocol.FRAME_PEER_KEEPALIVE ||
                    route.pendingNonce == 0 ||
                    route.pendingNonce == signal.nonce) {
                    route.active = true;
                }
                if (!wasActive && route.active) {
                    emitStatus("UDP 直连已就绪：" + signal.peerVirtualIp);
                }
            }
            if (frameType == PacketTunnelProtocol.FRAME_PEER_HELLO) {
                sendPeerSignalFrame(PacketTunnelProtocol.FRAME_PEER_ACK,
                                    signal.peerVirtualIp,
                                    signal.endpointVersion,
                                    signal.nonce);
            }
            return true;
        }

        if (frameType == PacketTunnelProtocol.FRAME_PEER_DISABLE) {
            PeerDisable disable = parsePeerDisable(data, offset, length);
            if (disable != null) {
                peerRoutes.remove(disable.peerVirtualIp);
            }
            return true;
        }

        return false;
    }

    private boolean trySendDirect(String dstVirtualIp, byte[] payload, int payloadLength) throws IOException {
        if (!peerDirectEnabled || dstVirtualIp == null || dstVirtualIp.isEmpty()) {
            return false;
        }
        PeerRoute route = peerRoutes.get(dstVirtualIp);
        long now = System.currentTimeMillis();
        if (route == null || route.endpoint == null || !route.active ||
            now - route.lastSeenMs > PEER_ROUTE_TIMEOUT_MS) {
            return false;
        }
        try {
            sendFrameToEndpoint(route.endpoint,
                                PacketTunnelProtocol.FRAME_IPV4_PACKET,
                                payload,
                                payloadLength);
            if (route.lastDirectMs == 0) {
                emitStatus("UDP 直连已开始发送：" + dstVirtualIp);
            }
            route.lastDirectMs = now;
            return true;
        } catch (IOException e) {
            route.active = false;
            emitStatus("UDP 直连发送失败，已回退中转：" + dstVirtualIp);
            return false;
        }
    }

    private void maintainPeerRoutes(long now) {
        for (PeerRoute route : peerRoutes.values()) {
            if (route.endpoint == null || now - route.lastSeenMs > PEER_ROUTE_TIMEOUT_MS) {
                peerRoutes.remove(route.peerVirtualIp);
                continue;
            }
            if (route.active) {
                sendPeerSignalFrame(PacketTunnelProtocol.FRAME_PEER_KEEPALIVE,
                                    route.peerVirtualIp,
                                    route.endpointVersion,
                                    0);
                try {
                    sendFrameToEndpoint(route.endpoint, PacketTunnelProtocol.FRAME_HEARTBEAT, null, 0);
                } catch (IOException ignored) {
                    route.active = false;
                }
            }
        }
    }

    private boolean markDirectPeerSource(DatagramPacket packet) {
        InetSocketAddress source = new InetSocketAddress(packet.getAddress(), packet.getPort());
        long now = System.currentTimeMillis();
        for (PeerRoute route : peerRoutes.values()) {
            if (route.endpoint != null && sameEndpoint(route.endpoint, source)) {
                route.active = true;
                route.lastSeenMs = now;
                route.lastDirectMs = now;
                return true;
            }
        }
        return false;
    }

    private void sendHandshake() throws Exception {
        byte[] sessionBytes = sessionUuid.getBytes(StandardCharsets.UTF_8);
        byte[] clientBytes = clientId.getBytes(StandardCharsets.UTF_8);
        if (sessionBytes.length > 255 || clientBytes.length == 0 || clientBytes.length > 255) {
            throw new IllegalArgumentException("invalid session/client id length");
        }

        byte[] virtualIp = InetAddress.getByName(lease.virtualIp).getAddress();
        byte[] payload = new byte[7 + sessionBytes.length + 1 + clientBytes.length + 8];
        PacketTunnelProtocol.writeU32(payload, 0, PacketTunnelProtocol.HANDSHAKE_CONN_ID);
        PacketTunnelProtocol.writeU16(payload, 4, PacketTunnelProtocol.HANDSHAKE_PORT_MARKER);
        payload[6] = (byte) sessionBytes.length;
        System.arraycopy(sessionBytes, 0, payload, 7, sessionBytes.length);
        int clientOffset = 7 + sessionBytes.length;
        payload[clientOffset] = (byte) clientBytes.length;
        System.arraycopy(clientBytes, 0, payload, clientOffset + 1, clientBytes.length);
        int tail = clientOffset + 1 + clientBytes.length;
        payload[tail] = (byte) PacketTunnelProtocol.PROTOCOL_VERSION;
        payload[tail + 1] = (byte) (peerDirectEnabled
                ? PacketTunnelProtocol.HANDSHAKE_FLAG_NONE
                : PacketTunnelProtocol.HANDSHAKE_FLAG_RELAY_ONLY);
        PacketTunnelProtocol.writeU16(payload, tail + 2, lease.mtu);
        System.arraycopy(virtualIp, 0, payload, tail + 4, 4);
        sendDatagram(payload, payload.length, serverEndpoint);
    }

    private void receiveHandshakeAck() throws Exception {
        byte[] ack = new byte[PacketTunnelProtocol.HANDSHAKE_ACK_SIZE];
        DatagramPacket packet = new DatagramPacket(ack, ack.length);
        long deadlineMs = System.currentTimeMillis() + 10000;
        while (true) {
            try {
                packet.setLength(ack.length);
                socket.receive(packet);
                if (isFromServer(packet)) {
                    break;
                }
            } catch (java.net.SocketTimeoutException e) {
                if (System.currentTimeMillis() >= deadlineMs) {
                    throw e;
                }
            }
        }
        if (packet.getLength() != PacketTunnelProtocol.HANDSHAKE_ACK_SIZE) {
            throw new IOException("invalid handshake ack length");
        }
        if ((ack[0] & 0xFF) != PacketTunnelProtocol.PROTOCOL_VERSION) {
            throw new IOException("unsupported tunnel protocol version");
        }
        int status = ack[1] & 0xFF;
        if (status != PacketTunnelProtocol.STATUS_OK) {
            throw new IOException("handshake rejected: status=" + status);
        }
        lastReceiveMs = System.currentTimeMillis();
    }

    private boolean sendPeerSignalFrame(int frameType,
                                        String peerVirtualIp,
                                        long endpointVersion,
                                        int nonce) {
        try {
            byte[] payload = new byte[PacketTunnelProtocol.PEER_SIGNAL_PAYLOAD_SIZE];
            writeIpv4(payload, 0, peerVirtualIp);
            PacketTunnelProtocol.writeU64(payload, 4, endpointVersion);
            PacketTunnelProtocol.writeU32(payload, 12, nonce);
            sendFrameToServer(frameType, payload, payload.length);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean sendPeerDisableFrame(String peerVirtualIp, long endpointVersion) {
        try {
            byte[] payload = new byte[PacketTunnelProtocol.PEER_DISABLE_PAYLOAD_SIZE];
            writeIpv4(payload, 0, peerVirtualIp);
            PacketTunnelProtocol.writeU64(payload, 4, endpointVersion);
            payload[12] = (byte) PacketTunnelProtocol.PEER_DISABLE_REASON_COOLDOWN;
            sendFrameToServer(PacketTunnelProtocol.FRAME_PEER_DISABLE, payload, payload.length);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private PeerOffer parsePeerOffer(byte[] payload, int offset, int length) {
        if (length != PacketTunnelProtocol.PEER_OFFER_PAYLOAD_SIZE) {
            return null;
        }
        int family = payload[offset + 12] & 0xFF;
        int port = PacketTunnelProtocol.readU16(payload, offset + 14);
        if (port <= 0 ||
            (family != PacketTunnelProtocol.PEER_ENDPOINT_FAMILY_IPV4 &&
             family != PacketTunnelProtocol.PEER_ENDPOINT_FAMILY_IPV6)) {
            return null;
        }
        try {
            int addressLength = family == PacketTunnelProtocol.PEER_ENDPOINT_FAMILY_IPV4 ? 4 : 16;
            byte[] addressBytes = Arrays.copyOfRange(payload,
                                                     offset + 16,
                                                     offset + 16 + addressLength);
            PeerOffer offer = new PeerOffer();
            offer.peerVirtualIp = ipv4String(payload, offset);
            offer.endpointVersion = PacketTunnelProtocol.readU64(payload, offset + 4);
            offer.endpoint = new InetSocketAddress(InetAddress.getByAddress(addressBytes), port);
            return offer;
        } catch (Exception ignored) {
            return null;
        }
    }

    private PeerSignal parsePeerSignal(byte[] payload, int offset, int length) {
        if (length != PacketTunnelProtocol.PEER_SIGNAL_PAYLOAD_SIZE) {
            return null;
        }
        PeerSignal signal = new PeerSignal();
        signal.peerVirtualIp = ipv4String(payload, offset);
        signal.endpointVersion = PacketTunnelProtocol.readU64(payload, offset + 4);
        signal.nonce = PacketTunnelProtocol.readU32(payload, offset + 12);
        return signal;
    }

    private PeerDisable parsePeerDisable(byte[] payload, int offset, int length) {
        if (length != PacketTunnelProtocol.PEER_DISABLE_PAYLOAD_SIZE) {
            return null;
        }
        PeerDisable disable = new PeerDisable();
        disable.peerVirtualIp = ipv4String(payload, offset);
        return disable;
    }

    private void sendFrameToServer(int frameType, byte[] payload, int payloadLength) throws IOException {
        sendFrameToEndpoint(serverEndpoint, frameType, payload, payloadLength);
    }

    private void sendFrameToEndpoint(SocketAddress endpoint,
                                     int frameType,
                                     byte[] payload,
                                     int payloadLength) throws IOException {
        byte[] datagram = new byte[PacketTunnelProtocol.FRAME_HEADER_SIZE + payloadLength];
        datagram[0] = (byte) frameType;
        PacketTunnelProtocol.writeU16(datagram, 1, payloadLength);
        if (payload != null && payloadLength > 0) {
            System.arraycopy(payload, 0, datagram, PacketTunnelProtocol.FRAME_HEADER_SIZE, payloadLength);
        }
        sendDatagram(datagram, datagram.length, endpoint);
    }

    private synchronized void sendDatagram(byte[] data, int length, SocketAddress endpoint) throws IOException {
        if (socket == null || socket.isClosed()) {
            throw new IOException("packet tunnel socket is closed");
        }
        byte[] out = length == data.length ? data : Arrays.copyOf(data, length);
        socket.send(new DatagramPacket(out, out.length, endpoint));
    }

    private boolean isFromServer(DatagramPacket packet) {
        return serverEndpoint != null &&
               packet.getPort() == serverEndpoint.getPort() &&
               packet.getAddress().equals(serverEndpoint.getAddress());
    }

    private synchronized int nextPeerNonce() {
        int nonce = nextPeerNonce++;
        if (nextPeerNonce == 0) {
            nextPeerNonce = 1;
        }
        return nonce;
    }

    private void emitStatus(String message) {
        if (statusListener != null) {
            statusListener.onStatus(message);
        }
    }

    private static boolean sameEndpoint(InetSocketAddress left, InetSocketAddress right) {
        return left.getPort() == right.getPort() && left.getAddress().equals(right.getAddress());
    }

    private static void writeIpv4(byte[] data, int offset, String ipv4) throws Exception {
        byte[] address = InetAddress.getByName(ipv4).getAddress();
        if (address.length != 4) {
            throw new IllegalArgumentException("not an IPv4 address: " + ipv4);
        }
        System.arraycopy(address, 0, data, offset, 4);
    }

    private static String ipv4String(byte[] packet, int offset) {
        return (packet[offset] & 0xFF) + "." +
               (packet[offset + 1] & 0xFF) + "." +
               (packet[offset + 2] & 0xFF) + "." +
               (packet[offset + 3] & 0xFF);
    }

    private static boolean isIpv4Unicast(byte[] packet, int length) {
        if (length < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
            return false;
        }
        int dst0 = packet[16] & 0xFF;
        return dst0 < 224 && dst0 != 255;
    }

    private static boolean isUdpIpv4(byte[] packet, int length) {
        if (length < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
            return false;
        }
        int headerLength = (packet[0] & 0x0F) * 4;
        return headerLength >= 20 && length >= headerLength + 8 && (packet[9] & 0xFF) == 17;
    }

    private static final class PeerRoute {
        String peerVirtualIp;
        InetSocketAddress endpoint;
        long endpointVersion;
        int pendingNonce;
        boolean active;
        long lastSeenMs;
        long lastDirectMs;
    }

    private static final class PeerOffer {
        String peerVirtualIp;
        InetSocketAddress endpoint;
        long endpointVersion;
    }

    private static final class PeerSignal {
        String peerVirtualIp;
        long endpointVersion;
        int nonce;
    }

    private static final class PeerDisable {
        String peerVirtualIp;
    }
}
