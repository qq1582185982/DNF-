#pragma once

#include <stddef.h>
#include <stdint.h>

namespace packet_tunnel {

static const uint32_t kHandshakeConnId = 0xFFFFFFFEu;
static const uint16_t kHandshakePortMarker = 0;
static const uint8_t kProtocolVersion = 1;

enum HandshakeFlags : uint8_t {
    kHandshakeFlagNone = 0,
    kHandshakeFlagRelayOnly = 1 << 0
};

enum StatusCode : uint8_t {
    kStatusOk = 0,
    kStatusInvalidRequest = 1,
    kStatusUnsupportedVersion = 2
};

enum FrameType : uint8_t {
    kFrameHeartbeat = 0x20,
    kFrameHeartbeatAck = 0x21,
    kFrameIpv4Packet = 0x22,
    kFramePeerOffer = 0x23,
    kFramePeerHello = 0x24,
    kFramePeerAck = 0x25,
    kFramePeerKeepalive = 0x26,
    kFramePeerDisable = 0x27,
    kFrameTcpPeerOffer = 0x28,
    kFrameTcpDirectAdvertise = 0x29,
    kFrameTcpDirectOpen = 0x2A,
    kFrameTcpDirectCandidateAdvertise = 0x2B
};

enum PeerEndpointFamily : uint8_t {
    kPeerEndpointFamilyUnknown = 0,
    kPeerEndpointFamilyIpv4 = 4,
    kPeerEndpointFamilyIpv6 = 6
};

enum PeerDisableReason : uint8_t {
    kPeerDisableReasonUnknown = 0,
    kPeerDisableReasonEndpointChanged = 1,
    kPeerDisableReasonCooldown = 2
};

static const size_t kHandshakeTailSize = 8;
static const size_t kHandshakeAckSize = 8;
static const size_t kFrameHeaderSize = 3;
static const size_t kPeerEndpointAddrSize = 16;
static const size_t kPeerOfferPayloadSize = 32;
static const size_t kPeerSignalPayloadSize = 16;
static const size_t kPeerDisablePayloadSize = 16;
static const size_t kTcpDirectAdvertisePayloadSize = 4;
static const size_t kTcpDirectOpenPayloadSize = 8;
static const size_t kTcpDirectCandidateAdvertisePayloadSize = 20;

inline uint16_t read_u16_be(const uint8_t* data) {
    return static_cast<uint16_t>(data[0] << 8) |
           static_cast<uint16_t>(data[1]);
}

inline uint32_t read_u32_be(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

inline uint64_t read_u64_be(const uint8_t* data) {
    return (static_cast<uint64_t>(data[0]) << 56) |
           (static_cast<uint64_t>(data[1]) << 48) |
           (static_cast<uint64_t>(data[2]) << 40) |
           (static_cast<uint64_t>(data[3]) << 32) |
           (static_cast<uint64_t>(data[4]) << 24) |
           (static_cast<uint64_t>(data[5]) << 16) |
           (static_cast<uint64_t>(data[6]) << 8) |
           static_cast<uint64_t>(data[7]);
}

inline void write_u16_be(uint8_t* data, uint16_t value) {
    data[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[1] = static_cast<uint8_t>(value & 0xFF);
}

inline void write_u32_be(uint8_t* data, uint32_t value) {
    data[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    data[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    data[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[3] = static_cast<uint8_t>(value & 0xFF);
}

inline void write_u64_be(uint8_t* data, uint64_t value) {
    data[0] = static_cast<uint8_t>((value >> 56) & 0xFF);
    data[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
    data[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
    data[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
    data[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
    data[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
    data[6] = static_cast<uint8_t>((value >> 8) & 0xFF);
    data[7] = static_cast<uint8_t>(value & 0xFF);
}

}  // namespace packet_tunnel
