package com.dnf.tunnel.android;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
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
    private static final int LOCAL_CANDIDATE_ADVERTISE_INTERVAL_MS = 30000;
    private static final int SERVER_RECEIVE_TIMEOUT_MS = 60000;
    private static final int SOCKET_TIMEOUT_MS = 1000;
    private static final int TCP_DIRECT_CONNECT_TIMEOUT_MS = 1200;
    private static final int TCP_DIRECT_RETRY_COOLDOWN_MS = 5000;
    private static final int TCP_DIRECT_HEARTBEAT_INTERVAL_MS = 3000;
    private static final int TCP_DIRECT_IDLE_TIMEOUT_MS = 15000;
    private static final int TCP_DIRECT_LISTEN_BACKLOG = 32;
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
    private final Map<String, TcpDirectOffer> tcpDirectOffers = new ConcurrentHashMap<>();
    private final Map<String, TcpDirectConnection> tcpDirectConnections = new ConcurrentHashMap<>();
    private final Object tcpDirectLock = new Object();
    private final Object tcpRelaySendLock = new Object();
    private final Object tunWriteLock = new Object();

    private DatagramSocket socket;
    private Socket tcpRelaySocket;
    private InetSocketAddress serverEndpoint;
    private Thread tunReadThread;
    private Thread tcpRelayReadThread;
    private ServerSocket tcpDirectServerSocket;
    private Thread tcpDirectAcceptThread;
    private volatile FileOutputStream tunOutput;
    private volatile long lastReceiveMs;
    private volatile boolean tcpRelayConnected;
    private volatile int tcpDirectListenPort;
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

        if (peerDirectEnabled) {
            startTcpDirectListener();
        }

        sendHandshake();
        receiveHandshakeAck();
        if (peerDirectEnabled) {
            sendUdpDirectCandidateAdvertises();
        }
        connectTcpRelaySocket();
        if (peerDirectEnabled && tcpRelayConnected) {
            sendTcpDirectCandidateAdvertises();
        }
        startTunReadThread();
        receiveLoop();
    }

    void stop() {
        running.set(false);
        if (socket != null) {
            socket.close();
        }
        closeTcpRelaySocket();
        stopTcpDirectSockets();
        try {
            vpnInterface.close();
        } catch (IOException ignored) {
        }
        if (tunReadThread != null) {
            tunReadThread.interrupt();
        }
        if (tcpRelayReadThread != null) {
            tcpRelayReadThread.interrupt();
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
                        if (isUdpIpv4(buffer, n) && trySendUdpDirect(dstVirtualIp, buffer, n)) {
                            continue;
                        }
                        if (isTcpIpv4(buffer, n) && trySendTcpDirectPacket(dstVirtualIp, buffer, n)) {
                            continue;
                        }
                        if (isTcpIpv4(buffer, n) && trySendTcpRelayPacket(buffer, n)) {
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
        long lastLocalCandidateAdvertiseMs = peerDirectEnabled ? System.currentTimeMillis() : 0;
        tunOutput = new FileOutputStream(vpnInterface.getFileDescriptor());
        while (running.get()) {
            long now = System.currentTimeMillis();
            if (now - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
                sendFrameToServer(PacketTunnelProtocol.FRAME_HEARTBEAT, null, 0);
                sendTcpRelayHeartbeat();
                lastHeartbeatMs = now;
            }
            if (peerDirectEnabled && now - lastPeerMaintenanceMs >= PEER_KEEPALIVE_INTERVAL_MS) {
                maintainPeerRoutes(now);
                maintainTcpDirectConnections(now);
                lastPeerMaintenanceMs = now;
            }
            if (peerDirectEnabled &&
                now - lastLocalCandidateAdvertiseMs >= LOCAL_CANDIDATE_ADVERTISE_INTERVAL_MS) {
                sendLocalDirectCandidateAdvertises();
                lastLocalCandidateAdvertiseMs = now;
            }
            if (lastReceiveMs != 0 && now - lastReceiveMs > SERVER_RECEIVE_TIMEOUT_MS) {
                throw new IOException("server receive timeout: " + (now - lastReceiveMs) + "ms");
            }

            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
            } catch (SocketTimeoutException ignored) {
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
                          fromServer,
                          new InetSocketAddress(packet.getAddress(), packet.getPort()));
        }
    }

    private void consumeFrames(byte[] data,
                               int length,
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
                writeToTun(data, payloadOffset, payloadLength);
            }
            offset = nextOffset;
        }
    }

    private boolean handlePeerControlFrame(int frameType, byte[] data, int offset, int length) {
        if (frameType == PacketTunnelProtocol.FRAME_TCP_PEER_OFFER) {
            return handleTcpPeerOffer(data, offset, length);
        }

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
                removeTcpDirectConnection(disable.peerVirtualIp, null, true);
            }
            return true;
        }

        return false;
    }

    private boolean handleTcpPeerOffer(byte[] data, int offset, int length) {
        PeerOffer offer = parsePeerOffer(data, offset, length);
        if (offer == null) {
            return true;
        }
        if (!peerDirectEnabled) {
            sendPeerDisableFrame(offer.peerVirtualIp, offer.endpointVersion);
            return true;
        }
        if (offer.peerVirtualIp == null ||
            offer.peerVirtualIp.length() == 0 ||
            offer.peerVirtualIp.equals(lease.virtualIp) ||
            offer.endpoint == null ||
            offer.endpoint.getPort() <= 0) {
            return true;
        }

        TcpDirectCandidate candidate = new TcpDirectCandidate();
        candidate.endpoint = offer.endpoint;
        candidate.endpointFamily = offer.endpointFamily;
        boolean changed = false;
        synchronized (tcpDirectLock) {
            TcpDirectOffer stored = tcpDirectOffers.get(offer.peerVirtualIp);
            if (stored == null) {
                stored = new TcpDirectOffer();
                stored.peerVirtualIp = offer.peerVirtualIp;
                tcpDirectOffers.put(offer.peerVirtualIp, stored);
            }
            if (stored.endpointVersion != 0 && offer.endpointVersion < stored.endpointVersion) {
                return true;
            }
            List<TcpDirectCandidate> previous = new ArrayList<>(stored.candidates);
            if (stored.endpointVersion != offer.endpointVersion) {
                stored.candidates.clear();
                changed = true;
            }
            copyCandidateStats(previous, candidate);
            if (!containsTcpCandidate(stored.candidates, candidate)) {
                stored.candidates.add(candidate);
                changed = true;
            }
            stored.endpointVersion = offer.endpointVersion;
            stored.lastOfferMs = System.currentTimeMillis();
            if (changed) {
                stored.connecting = false;
                stored.cooldownUntilMs = 0;
            }
        }

        if (changed) {
            emitStatus("收到 TCP 直连候选：" + offer.peerVirtualIp + " -> " +
                       offer.endpoint.getAddress().getHostAddress() + ":" + offer.endpoint.getPort());
        }
        maybeStartTcpDirectConnect(offer.peerVirtualIp);
        return true;
    }

    private boolean trySendUdpDirect(String dstVirtualIp, byte[] payload, int payloadLength) throws IOException {
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

    private boolean trySendTcpDirectPacket(String dstVirtualIp, byte[] payload, int payloadLength) {
        if (!peerDirectEnabled || dstVirtualIp == null || dstVirtualIp.isEmpty()) {
            return false;
        }
        if (payloadLength <= 0 || payloadLength > 0xFFFF) {
            return false;
        }

        TcpDirectConnection connection;
        synchronized (tcpDirectLock) {
            connection = tcpDirectConnections.get(dstVirtualIp);
            if (connection != null &&
                (!connection.active.get() || connection.socket == null || connection.socket.isClosed())) {
                tcpDirectConnections.remove(dstVirtualIp);
                connection = null;
            }
        }

        if (connection == null) {
            maybeStartTcpDirectConnect(dstVirtualIp);
            return false;
        }

        try {
            sendFrameOverTcpDirect(connection,
                                   PacketTunnelProtocol.FRAME_IPV4_PACKET,
                                   payload,
                                   payloadLength);
            long now = System.currentTimeMillis();
            if (connection.firstPacketSentMs == 0) {
                emitStatus("TCP 直连已开始发送：" + dstVirtualIp);
                connection.firstPacketSentMs = now;
            }
            connection.lastTxMs = now;
            return true;
        } catch (IOException e) {
            emitStatus("TCP 直连发送失败，已回退中转：" + dstVirtualIp);
            recordTcpDirectCandidateResult(dstVirtualIp, connection.candidate, false, 0);
            removeTcpDirectConnection(dstVirtualIp, connection, true);
            maybeStartTcpDirectConnect(dstVirtualIp);
            return false;
        }
    }

    private boolean trySendTcpRelayPacket(byte[] payload, int payloadLength) {
        if (!tcpRelayConnected || payloadLength <= 0 || payloadLength > 0xFFFF) {
            return false;
        }
        try {
            sendFrameToTcpRelay(PacketTunnelProtocol.FRAME_IPV4_PACKET, payload, payloadLength);
            return true;
        } catch (IOException e) {
            closeTcpRelaySocket();
            emitStatus("TCP 中转载体发送失败，已回退 UDP 中转");
            return false;
        }
    }

    private void sendTcpRelayHeartbeat() {
        if (!tcpRelayConnected) {
            return;
        }
        try {
            sendFrameToTcpRelay(PacketTunnelProtocol.FRAME_HEARTBEAT, null, 0);
        } catch (IOException e) {
            closeTcpRelaySocket();
            emitStatus("TCP 中转载体心跳失败，已回退 UDP 中转");
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

    private void maintainTcpDirectConnections(long now) {
        List<TcpDirectConnection> heartbeatConnections = new ArrayList<>();
        List<TcpDirectConnection> staleConnections = new ArrayList<>();
        synchronized (tcpDirectLock) {
            for (TcpDirectConnection connection : tcpDirectConnections.values()) {
                if (connection == null ||
                    !connection.active.get() ||
                    connection.socket == null ||
                    connection.socket.isClosed()) {
                    staleConnections.add(connection);
                    continue;
                }
                if (connection.lastRxMs != 0 && now - connection.lastRxMs > TCP_DIRECT_IDLE_TIMEOUT_MS) {
                    staleConnections.add(connection);
                    continue;
                }
                if (connection.lastTxMs == 0 ||
                    now - connection.lastTxMs >= TCP_DIRECT_HEARTBEAT_INTERVAL_MS) {
                    heartbeatConnections.add(connection);
                }
            }
        }

        for (TcpDirectConnection connection : staleConnections) {
            if (connection != null) {
                removeTcpDirectConnection(connection.peerVirtualIp, connection, true);
            }
        }
        for (TcpDirectConnection connection : heartbeatConnections) {
            try {
                sendFrameOverTcpDirect(connection, PacketTunnelProtocol.FRAME_HEARTBEAT, null, 0);
                connection.lastTxMs = now;
            } catch (IOException e) {
                removeTcpDirectConnection(connection.peerVirtualIp, connection, true);
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

    private void connectTcpRelaySocket() {
        Socket relaySocket = new Socket();
        try {
            vpnService.protect(relaySocket);
            configureTcpDirectSocket(relaySocket);
            relaySocket.connect(serverEndpoint, TCP_DIRECT_CONNECT_TIMEOUT_MS);
            tcpRelaySocket = relaySocket;
            tcpRelayConnected = true;
            emitStatus("TCP 中转载体已连接");

            byte[] handshake = buildHandshakePayload(true);
            sendRawTcpRelay(handshake, 0, handshake.length);
            receiveTcpRelayHandshakeAck();
            emitStatus("TCP 中转载体握手已确认");
            startTcpRelayReadThread();
        } catch (Exception e) {
            tcpRelayConnected = false;
            tcpRelaySocket = null;
            closeQuietly(relaySocket);
            emitStatus("TCP 中转载体不可用，回退 UDP 中转：" + safeMessage(e));
        }
    }

    private void receiveTcpRelayHandshakeAck() throws IOException {
        Socket relaySocket = tcpRelaySocket;
        if (relaySocket == null || relaySocket.isClosed()) {
            throw new IOException("tcp relay socket is closed");
        }
        byte[] ack = new byte[PacketTunnelProtocol.HANDSHAKE_ACK_SIZE];
        readExact(relaySocket.getInputStream(), ack, 0, ack.length, 10000);
        if ((ack[0] & 0xFF) != PacketTunnelProtocol.PROTOCOL_VERSION) {
            throw new IOException("unsupported tcp relay protocol version");
        }
        int status = ack[1] & 0xFF;
        if (status != PacketTunnelProtocol.STATUS_OK) {
            throw new IOException("tcp relay handshake rejected: status=" + status);
        }
        lastReceiveMs = System.currentTimeMillis();
    }

    private void startTcpRelayReadThread() {
        tcpRelayReadThread = new Thread(new Runnable() {
            @Override
            public void run() {
                tcpRelayReadLoop();
            }
        }, "dnf-android-tcp-relay-read");
        tcpRelayReadThread.start();
    }

    private void tcpRelayReadLoop() {
        while (running.get() && tcpRelayConnected) {
            Socket relaySocket = tcpRelaySocket;
            if (relaySocket == null || relaySocket.isClosed()) {
                break;
            }
            try {
                TcpFrame frame = readFrameFromSocket(relaySocket);
                lastReceiveMs = System.currentTimeMillis();
                if (frame.frameType == PacketTunnelProtocol.FRAME_HEARTBEAT &&
                    frame.payload.length == 0) {
                    sendFrameToTcpRelay(PacketTunnelProtocol.FRAME_HEARTBEAT_ACK, null, 0);
                    continue;
                }
                if (frame.frameType == PacketTunnelProtocol.FRAME_HEARTBEAT_ACK &&
                    frame.payload.length == 0) {
                    continue;
                }
                if (handlePeerControlFrame(frame.frameType, frame.payload, 0, frame.payload.length)) {
                    continue;
                }
                if (frame.frameType == PacketTunnelProtocol.FRAME_IPV4_PACKET &&
                    frame.payload.length > 0) {
                    writeToTun(frame.payload, 0, frame.payload.length);
                }
            } catch (IOException e) {
                if (running.get()) {
                    emitStatus("TCP 中转载体读取停止：" + safeMessage(e));
                }
                break;
            }
        }
        closeTcpRelaySocket();
    }

    private void closeTcpRelaySocket() {
        tcpRelayConnected = false;
        Socket relaySocket = tcpRelaySocket;
        tcpRelaySocket = null;
        closeQuietly(relaySocket);
    }

    private void startTcpDirectListener() {
        try {
            ServerSocket serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(0), TCP_DIRECT_LISTEN_BACKLOG);
            tcpDirectServerSocket = serverSocket;
            tcpDirectListenPort = serverSocket.getLocalPort();
            tcpDirectAcceptThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    tcpDirectAcceptLoop();
                }
            }, "dnf-android-tcp-direct-accept");
            tcpDirectAcceptThread.start();
            emitStatus("TCP 直连监听已就绪，端口=" + tcpDirectListenPort);
        } catch (IOException e) {
            tcpDirectListenPort = 0;
            emitStatus("TCP 直连监听不可用，继续保留中转路径：" + e.getMessage());
        }
    }

    private void tcpDirectAcceptLoop() {
        while (running.get()) {
            ServerSocket serverSocket = tcpDirectServerSocket;
            if (serverSocket == null || serverSocket.isClosed()) {
                break;
            }
            try {
                Socket accepted = serverSocket.accept();
                vpnService.protect(accepted);
                configureTcpDirectSocket(accepted);
                TcpDirectConnection connection = new TcpDirectConnection();
                connection.socket = accepted;
                connection.incoming = true;
                connection.active.set(true);
                startTcpDirectReadThread(connection, true);
            } catch (SocketException e) {
                if (running.get()) {
                    emitStatus("TCP 直连接入失败：" + e.getMessage());
                }
            } catch (IOException e) {
                if (running.get()) {
                    emitStatus("TCP 直连接入失败：" + e.getMessage());
                }
            }
        }
    }

    private void maybeStartTcpDirectConnect(final String peerVirtualIp) {
        if (!peerDirectEnabled ||
            !running.get() ||
            peerVirtualIp == null ||
            peerVirtualIp.length() == 0 ||
            peerVirtualIp.equals(lease.virtualIp)) {
            return;
        }

        long now = System.currentTimeMillis();
        synchronized (tcpDirectLock) {
            TcpDirectOffer offer = tcpDirectOffers.get(peerVirtualIp);
            if (offer == null ||
                offer.candidates.isEmpty() ||
                offer.connecting ||
                (offer.cooldownUntilMs != 0 && now < offer.cooldownUntilMs)) {
                return;
            }
            TcpDirectConnection existing = tcpDirectConnections.get(peerVirtualIp);
            if (existing != null &&
                existing.active.get() &&
                existing.socket != null &&
                !existing.socket.isClosed()) {
                return;
            }
            offer.connecting = true;
        }

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                tcpDirectConnectWorker(peerVirtualIp);
            }
        }, "dnf-android-tcp-direct-connect");
        thread.start();
    }

    private void tcpDirectConnectWorker(String peerVirtualIp) {
        List<TcpDirectCandidate> candidates;
        synchronized (tcpDirectLock) {
            TcpDirectOffer offer = tcpDirectOffers.get(peerVirtualIp);
            if (offer == null) {
                finishTcpDirectConnectAttempt(peerVirtualIp, false);
                return;
            }
            candidates = buildOrderedTcpDirectCandidates(offer);
        }
        if (candidates.isEmpty()) {
            finishTcpDirectConnectAttempt(peerVirtualIp, true);
            return;
        }

        for (int i = 0; i < candidates.size() && running.get(); ++i) {
            TcpDirectCandidate candidate = candidates.get(i);
            Socket directSocket = new Socket();
            long connectStartMs = System.currentTimeMillis();
            try {
                vpnService.protect(directSocket);
                configureTcpDirectSocket(directSocket);
                directSocket.connect(candidate.endpoint, TCP_DIRECT_CONNECT_TIMEOUT_MS);

                TcpDirectConnection connection = new TcpDirectConnection();
                connection.socket = directSocket;
                connection.peerVirtualIp = peerVirtualIp;
                connection.candidate = candidate;
                connection.incoming = false;
                connection.active.set(true);

                byte[] openPayload = new byte[PacketTunnelProtocol.TCP_DIRECT_OPEN_PAYLOAD_SIZE];
                writeIpv4(openPayload, 0, lease.virtualIp);
                writeIpv4(openPayload, 4, peerVirtualIp);
                sendFrameOverTcpDirect(connection,
                                       PacketTunnelProtocol.FRAME_TCP_DIRECT_OPEN,
                                       openPayload,
                                       openPayload.length);

                long connectMs = Math.max(0, System.currentTimeMillis() - connectStartMs);
                recordTcpDirectCandidateResult(peerVirtualIp, candidate, true, connectMs);
                registerTcpDirectConnection(peerVirtualIp, connection, false);
                startTcpDirectReadThread(connection, false);
                emitStatus("TCP 直连已连接：" + peerVirtualIp);
                return;
            } catch (Exception e) {
                closeQuietly(directSocket);
                recordTcpDirectCandidateResult(peerVirtualIp, candidate, false, 0);
            }
        }
        finishTcpDirectConnectAttempt(peerVirtualIp, running.get());
    }

    private void finishTcpDirectConnectAttempt(String peerVirtualIp, boolean cooldown) {
        synchronized (tcpDirectLock) {
            TcpDirectOffer offer = tcpDirectOffers.get(peerVirtualIp);
            if (offer != null) {
                offer.connecting = false;
                if (cooldown) {
                    offer.cooldownUntilMs = System.currentTimeMillis() + TCP_DIRECT_RETRY_COOLDOWN_MS;
                }
            }
        }
    }

    private void startTcpDirectReadThread(final TcpDirectConnection connection,
                                          final boolean expectOpenFrame) {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                tcpDirectReadLoop(connection, expectOpenFrame);
            }
        }, "dnf-android-tcp-direct-read");
        connection.readThread = thread;
        thread.start();
    }

    private void tcpDirectReadLoop(TcpDirectConnection connection, boolean expectOpenFrame) {
        if (connection == null || connection.socket == null) {
            return;
        }

        try {
            if (expectOpenFrame) {
                TcpFrame openFrame = readFrameFromSocket(connection.socket);
                if (openFrame.frameType != PacketTunnelProtocol.FRAME_TCP_DIRECT_OPEN ||
                    openFrame.payload.length != PacketTunnelProtocol.TCP_DIRECT_OPEN_PAYLOAD_SIZE) {
                    return;
                }

                String srcVirtualIp = ipv4String(openFrame.payload, 0);
                String dstVirtualIp = ipv4String(openFrame.payload, 4);
                if (srcVirtualIp.length() == 0 ||
                    srcVirtualIp.equals(lease.virtualIp) ||
                    !lease.virtualIp.equals(dstVirtualIp)) {
                    return;
                }
                connection.peerVirtualIp = srcVirtualIp;
                registerTcpDirectConnection(srcVirtualIp, connection, true);
            }

            while (running.get() && connection.active.get() && !connection.socket.isClosed()) {
                TcpFrame frame = readFrameFromSocket(connection.socket);
                long now = System.currentTimeMillis();
                connection.lastRxMs = now;
                if (frame.frameType == PacketTunnelProtocol.FRAME_HEARTBEAT &&
                    frame.payload.length == 0) {
                    sendFrameOverTcpDirect(connection, PacketTunnelProtocol.FRAME_HEARTBEAT_ACK, null, 0);
                    connection.lastTxMs = now;
                    continue;
                }
                if (frame.frameType == PacketTunnelProtocol.FRAME_HEARTBEAT_ACK &&
                    frame.payload.length == 0) {
                    continue;
                }
                if (frame.frameType != PacketTunnelProtocol.FRAME_IPV4_PACKET ||
                    frame.payload.length <= 0 ||
                    !isIpv4Unicast(frame.payload, frame.payload.length)) {
                    continue;
                }
                String innerSrcVirtualIp = ipv4String(frame.payload, 12);
                if (connection.peerVirtualIp != null &&
                    connection.peerVirtualIp.length() > 0 &&
                    !connection.peerVirtualIp.equals(innerSrcVirtualIp)) {
                    continue;
                }
                writeToTun(frame.payload, 0, frame.payload.length);
            }
        } catch (IOException ignored) {
        } finally {
            removeTcpDirectConnection(connection.peerVirtualIp, connection, true);
            connection.active.set(false);
            closeQuietly(connection.socket);
        }
    }

    private void registerTcpDirectConnection(String peerVirtualIp,
                                             TcpDirectConnection connection,
                                             boolean incoming) {
        if (peerVirtualIp == null || peerVirtualIp.length() == 0 || connection == null) {
            return;
        }

        TcpDirectConnection oldConnection = null;
        long now = System.currentTimeMillis();
        synchronized (tcpDirectLock) {
            oldConnection = tcpDirectConnections.get(peerVirtualIp);
            if (oldConnection != null && oldConnection != connection) {
                oldConnection.active.set(false);
            }
            tcpDirectConnections.put(peerVirtualIp, connection);
            connection.peerVirtualIp = peerVirtualIp;
            connection.lastRxMs = now;
            connection.lastTxMs = now;

            TcpDirectOffer offer = tcpDirectOffers.get(peerVirtualIp);
            if (offer == null) {
                offer = new TcpDirectOffer();
                offer.peerVirtualIp = peerVirtualIp;
                tcpDirectOffers.put(peerVirtualIp, offer);
            }
            offer.connecting = false;
            offer.cooldownUntilMs = 0;
        }

        if (oldConnection != null && oldConnection != connection) {
            closeQuietly(oldConnection.socket);
        }
        emitStatus("TCP 直连" + (incoming ? "入站" : "出站") + "已激活：" + peerVirtualIp);
    }

    private void removeTcpDirectConnection(String peerVirtualIp,
                                           TcpDirectConnection connection,
                                           boolean enterCooldown) {
        if (peerVirtualIp == null || peerVirtualIp.length() == 0) {
            return;
        }

        TcpDirectConnection removed = null;
        synchronized (tcpDirectLock) {
            TcpDirectConnection current = tcpDirectConnections.get(peerVirtualIp);
            if (current == null || (connection != null && current != connection)) {
                return;
            }
            removed = current;
            tcpDirectConnections.remove(peerVirtualIp);
            TcpDirectOffer offer = tcpDirectOffers.get(peerVirtualIp);
            if (offer != null) {
                offer.connecting = false;
                if (enterCooldown) {
                    offer.cooldownUntilMs = System.currentTimeMillis() + TCP_DIRECT_RETRY_COOLDOWN_MS;
                }
            }
        }

        if (removed != null) {
            removed.active.set(false);
            closeQuietly(removed.socket);
        }
    }

    private TcpFrame readFrameFromSocket(Socket frameSocket) throws IOException {
        InputStream input = frameSocket.getInputStream();
        byte[] header = new byte[PacketTunnelProtocol.FRAME_HEADER_SIZE];
        readExact(input, header, 0, header.length);
        int payloadLength = PacketTunnelProtocol.readU16(header, 1);
        byte[] payload = new byte[payloadLength];
        if (payloadLength > 0) {
            readExact(input, payload, 0, payloadLength);
        }
        TcpFrame frame = new TcpFrame();
        frame.frameType = header[0] & 0xFF;
        frame.payload = payload;
        return frame;
    }

    private void readExact(InputStream input, byte[] data, int offset, int length) throws IOException {
        readExact(input, data, offset, length, 0);
    }

    private void readExact(InputStream input,
                           byte[] data,
                           int offset,
                           int length,
                           long timeoutMs) throws IOException {
        int received = 0;
        long deadlineMs = timeoutMs > 0 ? System.currentTimeMillis() + timeoutMs : 0;
        while (received < length && running.get()) {
            if (deadlineMs != 0 && System.currentTimeMillis() >= deadlineMs) {
                throw new SocketTimeoutException("tcp read timeout");
            }
            try {
                int n = input.read(data, offset + received, length - received);
                if (n < 0) {
                    throw new EOFException("tcp direct peer closed");
                }
                received += n;
            } catch (SocketTimeoutException ignored) {
                if (deadlineMs != 0 && System.currentTimeMillis() >= deadlineMs) {
                    throw ignored;
                }
            }
        }
        if (received != length) {
            throw new EOFException("tcp direct read interrupted");
        }
    }

    private void sendFrameOverTcpDirect(TcpDirectConnection connection,
                                        int frameType,
                                        byte[] payload,
                                        int payloadLength) throws IOException {
        if (connection == null ||
            connection.socket == null ||
            connection.socket.isClosed() ||
            payloadLength < 0 ||
            payloadLength > 0xFFFF) {
            throw new IOException("invalid tcp direct frame");
        }

        byte[] header = new byte[PacketTunnelProtocol.FRAME_HEADER_SIZE];
        header[0] = (byte) frameType;
        PacketTunnelProtocol.writeU16(header, 1, payloadLength);
        synchronized (connection.sendLock) {
            OutputStream output = connection.socket.getOutputStream();
            output.write(header);
            if (payload != null && payloadLength > 0) {
                output.write(payload, 0, payloadLength);
            }
            output.flush();
        }
    }

    private void sendLocalDirectCandidateAdvertises() {
        if (!peerDirectEnabled) {
            return;
        }

        int udpCount = sendUdpDirectCandidateAdvertises();
        int tcpCount = sendTcpDirectCandidateAdvertises();
        if (udpCount > 0 || tcpCount > 0) {
            emitStatus("直连本地候选已上报：UDP=" + udpCount + " TCP=" + tcpCount);
        }
    }

    private int sendUdpDirectCandidateAdvertises() {
        int udpCount = 0;
        int udpPort = socket == null ? 0 : socket.getLocalPort();
        if (udpPort > 0) {
            List<DirectCandidate> udpCandidates = collectLocalCandidates(udpPort);
            for (DirectCandidate candidate : udpCandidates) {
                if (sendDirectCandidateAdvertise(PacketTunnelProtocol.FRAME_UDP_DIRECT_CANDIDATE_ADVERTISE,
                                                 candidate)) {
                    ++udpCount;
                }
            }
        }
        if (udpCount > 0) {
            emitStatus("UDP 直连本地候选已上报，数量=" + udpCount);
        }
        return udpCount;
    }

    private int sendTcpDirectCandidateAdvertises() {
        int tcpCount = 0;
        if (tcpDirectListenPort > 0 && tcpRelayConnected && sendTcpDirectAdvertise()) {
            List<DirectCandidate> tcpCandidates = collectLocalCandidates(tcpDirectListenPort);
            for (DirectCandidate candidate : tcpCandidates) {
                if (sendDirectCandidateAdvertise(
                        PacketTunnelProtocol.FRAME_TCP_DIRECT_CANDIDATE_ADVERTISE,
                        candidate)) {
                    ++tcpCount;
                }
            }
        }
        if (tcpCount > 0) {
            emitStatus("TCP 直连本地候选已上报，数量=" + tcpCount);
        }
        return tcpCount;
    }

    private boolean sendTcpDirectAdvertise() {
        if (tcpDirectListenPort <= 0 || !tcpRelayConnected) {
            return false;
        }
        try {
            byte[] payload = new byte[PacketTunnelProtocol.TCP_DIRECT_ADVERTISE_PAYLOAD_SIZE];
            PacketTunnelProtocol.writeU16(payload, 0, tcpDirectListenPort);
            sendFrameToTcpRelay(PacketTunnelProtocol.FRAME_TCP_DIRECT_ADVERTISE, payload, payload.length);
            return true;
        } catch (IOException ignored) {
            return false;
        }
    }

    private boolean sendDirectCandidateAdvertise(int frameType, DirectCandidate candidate) {
        if (candidate == null || candidate.port <= 0 || candidate.address == null) {
            return false;
        }
        try {
            byte[] payload = new byte[PacketTunnelProtocol.DIRECT_CANDIDATE_ADVERTISE_PAYLOAD_SIZE];
            payload[0] = (byte) candidate.endpointFamily;
            PacketTunnelProtocol.writeU16(payload, 2, candidate.port);
            byte[] addressBytes = candidate.address.getAddress();
            System.arraycopy(addressBytes, 0, payload, 4, Math.min(addressBytes.length, 16));
            if (frameType == PacketTunnelProtocol.FRAME_TCP_DIRECT_CANDIDATE_ADVERTISE) {
                sendFrameToTcpRelay(frameType, payload, payload.length);
            } else {
                sendFrameToServer(frameType, payload, payload.length);
            }
            return true;
        } catch (IOException ignored) {
            return false;
        }
    }

    private List<DirectCandidate> collectLocalCandidates(int port) {
        List<DirectCandidate> candidates = new ArrayList<>();
        List<String> seen = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!isUsableNetworkInterface(networkInterface)) {
                    continue;
                }
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    if (!isUsableLocalAddress(address)) {
                        continue;
                    }
                    int endpointFamily = endpointFamily(address);
                    if (endpointFamily == 0) {
                        continue;
                    }
                    String key = endpointFamily + "|" + address.getHostAddress() + "|" + port;
                    if (seen.contains(key)) {
                        continue;
                    }
                    seen.add(key);
                    DirectCandidate candidate = new DirectCandidate();
                    candidate.endpointFamily = endpointFamily;
                    candidate.address = address;
                    candidate.port = port;
                    candidates.add(candidate);
                }
            }
        } catch (SocketException ignored) {
        }
        return candidates;
    }

    private boolean isUsableNetworkInterface(NetworkInterface networkInterface) throws SocketException {
        return networkInterface != null &&
               networkInterface.isUp() &&
               !networkInterface.isLoopback() &&
               !networkInterface.isVirtual();
    }

    private boolean isUsableLocalAddress(InetAddress address) {
        if (address == null ||
            address.isAnyLocalAddress() ||
            address.isLoopbackAddress() ||
            address.isLinkLocalAddress() ||
            address.isMulticastAddress()) {
            return false;
        }
        if (address instanceof Inet4Address) {
            byte[] raw = address.getAddress();
            int first = raw[0] & 0xFF;
            int second = raw[1] & 0xFF;
            if (first == 0 ||
                first == 127 ||
                (first == 169 && second == 254) ||
                first >= 224) {
                return false;
            }
            String ip = address.getHostAddress();
            return !ip.equals(lease.virtualIp) &&
                   (lease.serverVirtualIp == null || !ip.equals(lease.serverVirtualIp));
        }
        return address instanceof Inet6Address;
    }

    private void configureTcpDirectSocket(Socket tcpSocket) throws SocketException {
        tcpSocket.setTcpNoDelay(true);
        tcpSocket.setKeepAlive(true);
        tcpSocket.setSoTimeout(SOCKET_TIMEOUT_MS);
    }

    private void stopTcpDirectSockets() {
        ServerSocket serverSocket = tcpDirectServerSocket;
        tcpDirectServerSocket = null;
        tcpDirectListenPort = 0;
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
        }

        List<TcpDirectConnection> connections = new ArrayList<>();
        synchronized (tcpDirectLock) {
            connections.addAll(tcpDirectConnections.values());
            tcpDirectConnections.clear();
            tcpDirectOffers.clear();
        }
        for (TcpDirectConnection connection : connections) {
            if (connection != null) {
                connection.active.set(false);
                closeQuietly(connection.socket);
            }
        }

        if (tcpDirectAcceptThread != null) {
            tcpDirectAcceptThread.interrupt();
            tcpDirectAcceptThread = null;
        }
    }

    private byte[] buildHandshakePayload(boolean relayOnly) throws Exception {
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
        payload[tail + 1] = (byte) (peerDirectEnabled && !relayOnly
                ? PacketTunnelProtocol.HANDSHAKE_FLAG_NONE
                : PacketTunnelProtocol.HANDSHAKE_FLAG_RELAY_ONLY);
        PacketTunnelProtocol.writeU16(payload, tail + 2, lease.mtu);
        System.arraycopy(virtualIp, 0, payload, tail + 4, 4);
        return payload;
    }

    private void sendHandshake() throws Exception {
        byte[] payload = buildHandshakePayload(false);
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
            } catch (SocketTimeoutException e) {
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
            offer.endpointFamily = family;
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

    private void sendFrameToTcpRelay(int frameType, byte[] payload, int payloadLength) throws IOException {
        Socket relaySocket = tcpRelaySocket;
        if (!tcpRelayConnected || relaySocket == null || relaySocket.isClosed()) {
            throw new IOException("tcp relay socket is closed");
        }
        if (payloadLength < 0 || payloadLength > 0xFFFF) {
            throw new IOException("invalid tcp relay frame");
        }
        byte[] header = new byte[PacketTunnelProtocol.FRAME_HEADER_SIZE];
        header[0] = (byte) frameType;
        PacketTunnelProtocol.writeU16(header, 1, payloadLength);
        synchronized (tcpRelaySendLock) {
            OutputStream output = relaySocket.getOutputStream();
            output.write(header);
            if (payload != null && payloadLength > 0) {
                output.write(payload, 0, payloadLength);
            }
            output.flush();
        }
    }

    private void sendRawTcpRelay(byte[] payload, int offset, int length) throws IOException {
        Socket relaySocket = tcpRelaySocket;
        if (!tcpRelayConnected || relaySocket == null || relaySocket.isClosed()) {
            throw new IOException("tcp relay socket is closed");
        }
        synchronized (tcpRelaySendLock) {
            OutputStream output = relaySocket.getOutputStream();
            output.write(payload, offset, length);
            output.flush();
        }
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

    private void writeToTun(byte[] data, int offset, int length) throws IOException {
        FileOutputStream output = tunOutput;
        if (output == null) {
            return;
        }
        synchronized (tunWriteLock) {
            output.write(data, offset, length);
            output.flush();
        }
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

    private static boolean isTcpIpv4(byte[] packet, int length) {
        if (length < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
            return false;
        }
        int headerLength = (packet[0] & 0x0F) * 4;
        return headerLength >= 20 && length >= headerLength + 20 && (packet[9] & 0xFF) == 6;
    }

    private static int endpointFamily(InetAddress address) {
        if (address instanceof Inet4Address) {
            return PacketTunnelProtocol.PEER_ENDPOINT_FAMILY_IPV4;
        }
        if (address instanceof Inet6Address) {
            return PacketTunnelProtocol.PEER_ENDPOINT_FAMILY_IPV6;
        }
        return 0;
    }

    private static boolean containsTcpCandidate(List<TcpDirectCandidate> candidates,
                                                TcpDirectCandidate candidate) {
        for (TcpDirectCandidate existing : candidates) {
            if (sameTcpCandidate(existing, candidate)) {
                return true;
            }
        }
        return false;
    }

    private static void copyCandidateStats(List<TcpDirectCandidate> previous,
                                           TcpDirectCandidate candidate) {
        for (TcpDirectCandidate existing : previous) {
            if (sameTcpCandidate(existing, candidate)) {
                candidate.successCount = existing.successCount;
                candidate.failureCount = existing.failureCount;
                candidate.lastSuccessMs = existing.lastSuccessMs;
                candidate.lastFailureMs = existing.lastFailureMs;
                candidate.lastConnectMs = existing.lastConnectMs;
                return;
            }
        }
    }

    private static boolean sameTcpCandidate(TcpDirectCandidate left, TcpDirectCandidate right) {
        return left != null &&
               right != null &&
               left.endpointFamily == right.endpointFamily &&
               left.endpoint != null &&
               right.endpoint != null &&
               left.endpoint.getPort() == right.endpoint.getPort() &&
               left.endpoint.getAddress().equals(right.endpoint.getAddress());
    }

    private static List<TcpDirectCandidate> buildOrderedTcpDirectCandidates(TcpDirectOffer offer) {
        List<TcpDirectCandidate> ordered = new ArrayList<>(offer.candidates);
        final long now = System.currentTimeMillis();
        Collections.sort(ordered, new Comparator<TcpDirectCandidate>() {
            @Override
            public int compare(TcpDirectCandidate left, TcpDirectCandidate right) {
                boolean leftRecentFail = left.lastFailureMs != 0 &&
                                         now - left.lastFailureMs < TCP_DIRECT_RETRY_COOLDOWN_MS;
                boolean rightRecentFail = right.lastFailureMs != 0 &&
                                          now - right.lastFailureMs < TCP_DIRECT_RETRY_COOLDOWN_MS;
                if (leftRecentFail != rightRecentFail) {
                    return leftRecentFail ? 1 : -1;
                }
                if ((left.successCount > 0) != (right.successCount > 0)) {
                    return left.successCount > 0 ? -1 : 1;
                }
                if (left.successCount != right.successCount) {
                    return right.successCount - left.successCount;
                }
                long leftConnect = left.lastConnectMs == 0 ? Long.MAX_VALUE : left.lastConnectMs;
                long rightConnect = right.lastConnectMs == 0 ? Long.MAX_VALUE : right.lastConnectMs;
                if (leftConnect != rightConnect) {
                    return leftConnect < rightConnect ? -1 : 1;
                }
                return left.failureCount - right.failureCount;
            }
        });
        return ordered;
    }

    private void recordTcpDirectCandidateResult(String peerVirtualIp,
                                                TcpDirectCandidate candidate,
                                                boolean success,
                                                long connectMs) {
        if (peerVirtualIp == null || candidate == null) {
            return;
        }
        long now = System.currentTimeMillis();
        synchronized (tcpDirectLock) {
            TcpDirectOffer offer = tcpDirectOffers.get(peerVirtualIp);
            if (offer == null) {
                return;
            }
            for (TcpDirectCandidate existing : offer.candidates) {
                if (!sameTcpCandidate(existing, candidate)) {
                    continue;
                }
                if (success) {
                    ++existing.successCount;
                    existing.lastSuccessMs = now;
                    existing.lastConnectMs = connectMs;
                } else {
                    ++existing.failureCount;
                    existing.lastFailureMs = now;
                }
                return;
            }
        }
    }

    private static void closeQuietly(Socket tcpSocket) {
        if (tcpSocket == null) {
            return;
        }
        try {
            tcpSocket.close();
        } catch (IOException ignored) {
        }
    }

    private static String safeMessage(Exception e) {
        if (e == null) {
            return "unknown";
        }
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return e.getClass().getSimpleName();
        }
        return message.trim();
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
        int endpointFamily;
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

    private static final class DirectCandidate {
        int endpointFamily;
        InetAddress address;
        int port;
    }

    private static final class TcpDirectCandidate {
        InetSocketAddress endpoint;
        int endpointFamily;
        int successCount;
        int failureCount;
        long lastSuccessMs;
        long lastFailureMs;
        long lastConnectMs;
    }

    private static final class TcpDirectOffer {
        String peerVirtualIp;
        long endpointVersion;
        long lastOfferMs;
        boolean connecting;
        long cooldownUntilMs;
        final List<TcpDirectCandidate> candidates = new ArrayList<>();
    }

    private static final class TcpDirectConnection {
        final AtomicBoolean active = new AtomicBoolean(false);
        final Object sendLock = new Object();
        Socket socket;
        String peerVirtualIp;
        TcpDirectCandidate candidate;
        Thread readThread;
        boolean incoming;
        long lastRxMs;
        long lastTxMs;
        long firstPacketSentMs;
    }

    private static final class TcpFrame {
        int frameType;
        byte[] payload;
    }
}
