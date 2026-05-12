package com.dnf.tunnel.android;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

final class PacketTunnelClient {
    private static final int HEARTBEAT_INTERVAL_MS = 3000;
    private static final int SERVER_RECEIVE_TIMEOUT_MS = 60000;
    private static final int SOCKET_TIMEOUT_MS = 1000;
    private static final int MAX_PACKET_SIZE = 65535;

    private final VpnService vpnService;
    private final ParcelFileDescriptor vpnInterface;
    private final ServerInfo server;
    private final LeaseGrant lease;
    private final String sessionUuid;
    private final String clientId;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private DatagramSocket socket;
    private Thread tunReadThread;
    private volatile long lastReceiveMs;

    PacketTunnelClient(VpnService vpnService,
                       ParcelFileDescriptor vpnInterface,
                       ServerInfo server,
                       LeaseGrant lease,
                       String sessionUuid,
                       String clientId) {
        this.vpnService = vpnService;
        this.vpnInterface = vpnInterface;
        this.server = server;
        this.lease = lease;
        this.sessionUuid = sessionUuid;
        this.clientId = clientId;
    }

    void run() throws Exception {
        running.set(true);
        socket = new DatagramSocket();
        vpnService.protect(socket);
        socket.connect(InetAddress.getByName(server.tunnelServerIp), server.tunnelPort);
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
                        sendFrame(PacketTunnelProtocol.FRAME_IPV4_PACKET, buffer, n);
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
        FileOutputStream output = new FileOutputStream(vpnInterface.getFileDescriptor());
        while (running.get()) {
            long now = System.currentTimeMillis();
            if (now - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
                sendFrame(PacketTunnelProtocol.FRAME_HEARTBEAT, null, 0);
                lastHeartbeatMs = now;
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
            lastReceiveMs = System.currentTimeMillis();
            consumeFrames(packet.getData(), packet.getLength(), output);
        }
    }

    private void consumeFrames(byte[] data, int length, FileOutputStream output) throws IOException {
        int offset = 0;
        while (offset + PacketTunnelProtocol.FRAME_HEADER_SIZE <= length) {
            int frameType = data[offset] & 0xFF;
            int payloadLength = PacketTunnelProtocol.readU16(data, offset + 1);
            int payloadOffset = offset + PacketTunnelProtocol.FRAME_HEADER_SIZE;
            int nextOffset = payloadOffset + payloadLength;
            if (nextOffset > length) {
                break;
            }
            if (frameType == PacketTunnelProtocol.FRAME_IPV4_PACKET && payloadLength > 0) {
                output.write(data, payloadOffset, payloadLength);
                output.flush();
            }
            offset = nextOffset;
        }
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
        payload[tail + 1] = (byte) PacketTunnelProtocol.HANDSHAKE_FLAG_RELAY_ONLY;
        PacketTunnelProtocol.writeU16(payload, tail + 2, lease.mtu);
        System.arraycopy(virtualIp, 0, payload, tail + 4, 4);
        sendDatagram(payload, payload.length);
    }

    private void receiveHandshakeAck() throws Exception {
        byte[] ack = new byte[PacketTunnelProtocol.HANDSHAKE_ACK_SIZE];
        DatagramPacket packet = new DatagramPacket(ack, ack.length);
        long deadlineMs = System.currentTimeMillis() + 10000;
        while (true) {
            try {
                socket.receive(packet);
                break;
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

    private void sendFrame(int frameType, byte[] payload, int payloadLength) throws IOException {
        byte[] datagram = new byte[PacketTunnelProtocol.FRAME_HEADER_SIZE + payloadLength];
        datagram[0] = (byte) frameType;
        PacketTunnelProtocol.writeU16(datagram, 1, payloadLength);
        if (payload != null && payloadLength > 0) {
            System.arraycopy(payload, 0, datagram, PacketTunnelProtocol.FRAME_HEADER_SIZE, payloadLength);
        }
        sendDatagram(datagram, datagram.length);
    }

    private synchronized void sendDatagram(byte[] data, int length) throws IOException {
        if (socket == null || socket.isClosed()) {
            throw new IOException("packet tunnel socket is closed");
        }
        byte[] out = length == data.length ? data : Arrays.copyOf(data, length);
        socket.send(new DatagramPacket(out, out.length, socket.getInetAddress(), socket.getPort()));
    }

    private static boolean isIpv4Unicast(byte[] packet, int length) {
        if (length < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
            return false;
        }
        int dst0 = packet[16] & 0xFF;
        return dst0 < 224 && dst0 != 255;
    }
}
