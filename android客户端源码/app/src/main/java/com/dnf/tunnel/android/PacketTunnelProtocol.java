package com.dnf.tunnel.android;

final class PacketTunnelProtocol {
    static final int HANDSHAKE_CONN_ID = 0xFFFFFFFE;
    static final int HANDSHAKE_PORT_MARKER = 0;
    static final int PROTOCOL_VERSION = 1;
    static final int STATUS_OK = 0;
    static final int HANDSHAKE_FLAG_RELAY_ONLY = 1;
    static final int FRAME_HEARTBEAT = 0x20;
    static final int FRAME_HEARTBEAT_ACK = 0x21;
    static final int FRAME_IPV4_PACKET = 0x22;
    static final int HANDSHAKE_ACK_SIZE = 8;
    static final int FRAME_HEADER_SIZE = 3;

    private PacketTunnelProtocol() {
    }

    static void writeU16(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }

    static void writeU32(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >> 24) & 0xFF);
        data[offset + 1] = (byte) ((value >> 16) & 0xFF);
        data[offset + 2] = (byte) ((value >> 8) & 0xFF);
        data[offset + 3] = (byte) (value & 0xFF);
    }

    static int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
