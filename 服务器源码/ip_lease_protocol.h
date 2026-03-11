#pragma once

#include <stdint.h>
#include <string>
#include <vector>

namespace ip_tunnel {

static const uint16_t kProtocolVersion = 1;
static const uint32_t kDefaultLeaseSeconds = 120;
static const uint16_t kDefaultMtu = 1400;

enum MessageType : uint8_t {
    kLoginRequest = 0x10,
    kLoginResponse = 0x11,
    kLeaseRequest = 0x20,
    kLeaseResponse = 0x21,
    kLeaseRenew = 0x22,
    kLeaseRelease = 0x23,
    kHeartbeat = 0x30,
    kPacketIPv4 = 0x40,
    kPacketIPv6 = 0x41
};

enum StatusCode : uint8_t {
    kStatusOk = 0,
    kStatusInvalidRequest = 1,
    kStatusAuthFailed = 2,
    kStatusPoolExhausted = 3,
    kStatusLeaseNotFound = 4,
    kStatusServerNotFound = 5
};

struct RouteEntry {
    std::string cidr;

    RouteEntry() {}
    explicit RouteEntry(const std::string& value) : cidr(value) {}
};

struct LeaseRequest {
    std::string session_uuid;
    std::string client_id;
    std::string server_key;
    std::string preferred_ip;

    LeaseRequest() {}
};

struct LeaseGrant {
    StatusCode status;
    std::string message;
    std::string virtual_ip;
    std::string subnet_mask;
    std::string gateway_ip;
    uint16_t mtu;
    uint32_t lease_seconds;
    std::vector<RouteEntry> routes;
    bool reused_previous_ip;

    LeaseGrant()
        : status(kStatusOk),
          mtu(kDefaultMtu),
          lease_seconds(kDefaultLeaseSeconds),
          reused_previous_ip(false) {}
};

struct SessionIdentity {
    std::string session_uuid;
    std::string client_id;
    std::string server_key;

    SessionIdentity() {}
};

}  // namespace ip_tunnel
