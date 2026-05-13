package com.dnf.tunnel.android;

final class PacketTunnelProtocol {
    static final int HANDSHAKE_CONN_ID = 0xFFFFFFFE;
    static final int HANDSHAKE_PORT_MARKER = 0;
    static final int PROTOCOL_VERSION = 1;
    static final int STATUS_OK = 0;
    static final int HANDSHAKE_FLAG_NONE = 0;
    static final int HANDSHAKE_FLAG_RELAY_ONLY = 1;
    static final int FRAME_HEARTBEAT = 0x20;
    static final int FRAME_HEARTBEAT_ACK = 0x21;
    static final int FRAME_IPV4_PACKET = 0x22;
    static final int FRAME_PEER_OFFER = 0x23;
    static final int FRAME_PEER_HELLO = 0x24;
    static final int FRAME_PEER_ACK = 0x25;
    static final int FRAME_PEER_KEEPALIVE = 0x26;
    static final int FRAME_PEER_DISABLE = 0x27;
    static final int HANDSHAKE_ACK_SIZE = 8;
    static final int FRAME_HEADER_SIZE = 3;
    static final int PEER_ENDPOINT_FAMILY_IPV4 = 4;
    static final int PEER_ENDPOINT_FAMILY_IPV6 = 6;
    static final int PEER_DISABLE_REASON_COOLDOWN = 2;
    static final int PEER_OFFER_PAYLOAD_SIZE = 32;
    static final int PEER_SIGNAL_PAYLOAD_SIZE = 16;
    static final int PEER_DISABLE_PAYLOAD_SIZE = 16;

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

    static int readU32(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) |
               ((data[offset + 1] & 0xFF) << 16) |
               ((data[offset + 2] & 0xFF) << 8) |
               (data[offset + 3] & 0xFF);
    }

    static long readU64(byte[] data, int offset) {
        long value = 0;
        for (int i = 0; i < 8; ++i) {
            value = (value << 8) | (long) (data[offset + i] & 0xFF);
        }
        return value;
    }

    static void writeU64(byte[] data, int offset, long value) {
        for (int i = 7; i >= 0; --i) {
            data[offset + i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
    }
}
