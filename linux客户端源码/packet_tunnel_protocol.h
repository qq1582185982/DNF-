#pragma once

#include <stddef.h>
#include <stdint.h>

namespace packet_tunnel {

static const uint32_t kHandshakeConnId = 0xFFFFFFFEu;
static const uint16_t kHandshakePortMarker = 0;
static const uint8_t kProtocolVersion = 1;

enum StatusCode : uint8_t {
    kStatusOk = 0,
    kStatusInvalidRequest = 1,
    kStatusUnsupportedVersion = 2
};

enum FrameType : uint8_t {
    kFrameHeartbeat = 0x20,
    kFrameHeartbeatAck = 0x21,
    kFrameIpv4Packet = 0x22
};

static const size_t kHandshakeTailSize = 8;
static const size_t kHandshakeAckSize = 8;
static const size_t kFrameHeaderSize = 3;

}  // namespace packet_tunnel