#include "linux_packet_tunnel_client.h"

#include "linux_client_common.h"
#include "linux_peer_link_manager.h"
#include "packet_tunnel_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <sstream>
#include <vector>

namespace {

const int kHeartbeatIntervalMs = 3000;
const int kHeartbeatTimeoutMs = 12000;
const int kPeerOfferTimeoutMs = 9000;
const int kPeerDirectReadyTimeoutMs = 15000;
const int kPeerCooldownTimeoutMs = 30000;
const int kPeerDirectProbeGraceMs = 3000;
const int kPeerDirectDataTimeoutMs = 5000;
const int kPeerSnapshotLogIntervalMs = 15000;
const int kPeerRouteDebugLogIntervalMs = 2000;
const int kPeerDirectProbeIntervalMs = 500;
const int kSocketReadTimeoutMs = 1000;
const int kTunReadWaitMs = 500;
const int kSocketBufferBytes = 256 * 1024;
const uint16_t kPeerDirectProbeSrcPort = 65401;
const uint16_t kPeerDirectProbeDstPort = 65402;
const uint8_t kPeerDirectProbeMagic[4] = {'P', 'T', 'D', 'P'};
const uint8_t kPeerDirectProbeVersion = 1;
const uint8_t kPeerDirectProbeRequest = 1;
const uint8_t kPeerDirectProbeResponse = 2;

uint16_t ComputeLinuxIpv4HeaderChecksum(const uint8_t* header, size_t header_len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < header_len; i += 2) {
        sum += static_cast<uint16_t>((header[i] << 8) | header[i + 1]);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

bool BuildLinuxPeerDirectProbePacket(uint32_t src_ip_be,
                                     uint32_t dst_ip_be,
                                     uint8_t probe_type,
                                     std::vector<uint8_t>* out_packet) {
    if (out_packet == NULL ||
        (probe_type != kPeerDirectProbeRequest &&
         probe_type != kPeerDirectProbeResponse)) {
        return false;
    }

    const size_t packet_len = 20 + 8 + 8;
    out_packet->assign(packet_len, 0);
    uint8_t* packet = out_packet->data();
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = IPPROTO_UDP;
    packet_tunnel::write_u16_be(packet + 2, static_cast<uint16_t>(packet_len));
    memcpy(packet + 12, &src_ip_be, sizeof(src_ip_be));
    memcpy(packet + 16, &dst_ip_be, sizeof(dst_ip_be));

    const size_t udp_offset = 20;
    packet_tunnel::write_u16_be(packet + udp_offset,
                                probe_type == kPeerDirectProbeRequest
                                    ? kPeerDirectProbeSrcPort
                                    : kPeerDirectProbeDstPort);
    packet_tunnel::write_u16_be(packet + udp_offset + 2,
                                probe_type == kPeerDirectProbeRequest
                                    ? kPeerDirectProbeDstPort
                                    : kPeerDirectProbeSrcPort);
    packet_tunnel::write_u16_be(packet + udp_offset + 4, 16);

    uint8_t* payload = packet + udp_offset + 8;
    memcpy(payload, kPeerDirectProbeMagic, sizeof(kPeerDirectProbeMagic));
    payload[4] = kPeerDirectProbeVersion;
    payload[5] = probe_type;

    packet_tunnel::write_u16_be(packet + 10, ComputeLinuxIpv4HeaderChecksum(packet, 20));
    return true;
}

bool ParseLinuxPeerDirectProbePacket(const uint8_t* packet,
                                     size_t packet_len,
                                     uint8_t* out_probe_type) {
    if (packet == NULL || packet_len < 36 || ((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len != 20 || packet_len < ip_header_len + 16) {
        return false;
    }

    const uint16_t udp_len = ntohs(*(const uint16_t*)(packet + ip_header_len + 4));
    if (udp_len < 16 || packet_len < ip_header_len + udp_len) {
        return false;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    const uint8_t* payload = packet + ip_header_len + 8;
    if (!((src_port == kPeerDirectProbeSrcPort && dst_port == kPeerDirectProbeDstPort) ||
          (src_port == kPeerDirectProbeDstPort && dst_port == kPeerDirectProbeSrcPort))) {
        return false;
    }
    if (memcmp(payload, kPeerDirectProbeMagic, sizeof(kPeerDirectProbeMagic)) != 0 ||
        payload[4] != kPeerDirectProbeVersion) {
        return false;
    }
    if (payload[5] != kPeerDirectProbeRequest && payload[5] != kPeerDirectProbeResponse) {
        return false;
    }
    if (out_probe_type != NULL) {
        *out_probe_type = payload[5];
    }
    return true;
}

bool IsDirectPathFresh(const LinuxPeerRouteStatus& route, unsigned long long now_tick) {
    if (!route.active_direct) {
        return false;
    }

    return
        route.last_direct_data_ms != 0 &&
        now_tick >= route.last_direct_data_ms &&
        (now_tick - route.last_direct_data_ms) <= kPeerDirectDataTimeoutMs;
}

unsigned long long now_ms() {
    return static_cast<unsigned long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct ParsedLinuxPeerOffer {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t endpoint_family;
    uint16_t endpoint_port;
    uint8_t endpoint_addr[16];
    std::string endpoint;
};

struct ParsedLinuxPeerSignal {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint32_t nonce;
};

struct ParsedLinuxPeerDisable {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t reason;
};

std::string LinuxFrameName(uint8_t frame_type) {
    switch (frame_type) {
    case packet_tunnel::kFrameHeartbeat:
        return "heartbeat";
    case packet_tunnel::kFrameHeartbeatAck:
        return "heartbeat_ack";
    case packet_tunnel::kFrameIpv4Packet:
        return "ipv4_packet";
    case packet_tunnel::kFramePeerOffer:
        return "peer_offer";
    case packet_tunnel::kFramePeerHello:
        return "peer_hello";
    case packet_tunnel::kFramePeerAck:
        return "peer_ack";
    case packet_tunnel::kFramePeerKeepalive:
        return "peer_keepalive";
    case packet_tunnel::kFramePeerDisable:
        return "peer_disable";
    default:
        return "unknown";
    }
}

const char* LinuxPeerRouteStateName(LinuxPeerRouteState state) {
    switch (state) {
    case LinuxPeerRouteState::RelayOnly:
        return "relay_only";
    case LinuxPeerRouteState::OfferReceived:
        return "offer_received";
    case LinuxPeerRouteState::Probing:
        return "probing";
    case LinuxPeerRouteState::DirectActive:
        return "direct_active";
    case LinuxPeerRouteState::Cooldown:
        return "cooldown";
    default:
        return "unknown";
    }
}

std::string BuildLinuxPeerRouteSnapshotSummary(const std::vector<LinuxPeerRouteStatus>& peers,
                                               unsigned long long now_ms_value) {
    if (peers.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < peers.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_ms_value > peers[i].last_observed_ms)
                ? (now_ms_value - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_ms_value > peers[i].last_state_change_ms)
                ? (now_ms_value - peers[i].last_state_change_ms)
                : 0;
        ss << peers[i].peer_virtual_ip
           << "[" << LinuxPeerRouteStateName(peers[i].state)
           << " v=" << peers[i].endpoint_version
           << " ready=" << (peers[i].direct_ready ? "y" : "n")
           << " eligible=" << (peers[i].direct_eligible ? "y" : "n")
           << " active=" << (peers[i].active_direct ? "y" : "n")
           << " obs=" << observed_age << "ms"
           << " direct=" << ((peers[i].last_direct_data_ms != 0 && now_ms_value > peers[i].last_direct_data_ms)
                                ? (now_ms_value - peers[i].last_direct_data_ms)
                                : 0) << "ms"
           << " sample=" << peers[i].direct_sample_count
           << " fail=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " state=" << state_age << "ms]";
    }
    return ss.str();
}

std::string DescribeSingleLinuxPeerRoute(const std::vector<LinuxPeerRouteStatus>& peers,
                                         const std::string& peer_virtual_ip,
                                         unsigned long long now_ms_value) {
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip != peer_virtual_ip) {
            continue;
        }

        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_ms_value > peers[i].last_observed_ms)
                ? (now_ms_value - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_ms_value > peers[i].last_state_change_ms)
                ? (now_ms_value - peers[i].last_state_change_ms)
                : 0;

        std::ostringstream ss;
        ss << peers[i].peer_virtual_ip
           << "[" << LinuxPeerRouteStateName(peers[i].state)
           << " v=" << peers[i].endpoint_version
           << " family=" << static_cast<int>(peers[i].endpoint_family)
           << " port=" << peers[i].endpoint_port
           << " ready=" << (peers[i].direct_ready ? "y" : "n")
           << " eligible=" << (peers[i].direct_eligible ? "y" : "n")
           << " active=" << (peers[i].active_direct ? "y" : "n")
           << " obs=" << observed_age << "ms"
           << " direct=" << ((peers[i].last_direct_data_ms != 0 && now_ms_value > peers[i].last_direct_data_ms)
                                ? (now_ms_value - peers[i].last_direct_data_ms)
                                : 0) << "ms"
           << " sample=" << peers[i].direct_sample_count
           << " fail=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " state=" << state_age << "ms]";
        return ss.str();
    }

    return std::string();
}

std::string LinuxIpv4ToString(const uint8_t* addr) {
    char buffer[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, addr, buffer, sizeof(buffer)) == NULL) {
        return "?";
    }
    return std::string(buffer);
}

bool IsLinuxNoisyUdpPacket(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 20) {
        return true;
    }
    if (((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return true;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return true;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    const uint8_t* dst_ip = packet + 16;

    const bool is_multicast = (dst_ip[0] >= 224 && dst_ip[0] <= 239);
    const bool is_limited_broadcast =
        (dst_ip[0] == 255 && dst_ip[1] == 255 && dst_ip[2] == 255 && dst_ip[3] == 255);
    const bool is_likely_subnet_broadcast = (dst_ip[3] == 255);
    const bool is_common_noise_port =
        (src_port == 137 || dst_port == 137 ||
         src_port == 138 || dst_port == 138 ||
         src_port == 1900 || dst_port == 1900 ||
         src_port == 5355 || dst_port == 5355);

    return is_multicast || is_limited_broadcast || is_likely_subnet_broadcast || is_common_noise_port;
}

bool TryDescribeLinuxUdpPacket(const uint8_t* packet, size_t packet_len, std::string* out_desc) {
    if (out_desc == NULL || packet == NULL || packet_len < 20) {
        return false;
    }
    if (((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return false;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    std::ostringstream ss;
    ss << "src=" << LinuxIpv4ToString(packet + 12) << ":" << src_port
       << " dst=" << LinuxIpv4ToString(packet + 16) << ":" << dst_port
       << " len=" << packet_len;
    *out_desc = ss.str();
    return true;
}

bool IsFocusedLinuxGameUdpPort(uint16_t port) {
    return port == 5063 || port == 2311 || port == 2312 || port == 2313;
}

bool IsFocusedLinuxGameUdpPacket(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 20) {
        return false;
    }
    if (((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return false;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    return IsFocusedLinuxGameUdpPort(src_port) || IsFocusedLinuxGameUdpPort(dst_port);
}

bool ParseLinuxIpv4StringToBe(const std::string& value, uint32_t* out_ip_be) {
    if (out_ip_be == NULL || value.empty()) {
        return false;
    }

    in_addr addr = {};
    if (inet_pton(AF_INET, value.c_str(), &addr) != 1) {
        return false;
    }

    *out_ip_be = addr.s_addr;
    return true;
}

bool TryExtractLinuxPeerEndpointFromSockaddr(const sockaddr_storage& source_addr,
                                             uint8_t* endpoint_family,
                                             uint8_t* endpoint_addr,
                                             uint16_t* endpoint_port) {
    if (endpoint_family == NULL || endpoint_addr == NULL || endpoint_port == NULL) {
        return false;
    }

    *endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
    *endpoint_port = 0;
    memset(endpoint_addr, 0, 16);

    if (source_addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&source_addr);
        *endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
        *endpoint_port = ntohs(addr4->sin_port);
        memcpy(endpoint_addr, &addr4->sin_addr, 4);
        return true;
    }

    if (source_addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&source_addr);
        *endpoint_port = ntohs(addr6->sin6_port);
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&addr6->sin6_addr);
        static const uint8_t kV4MappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (memcmp(bytes, kV4MappedPrefix, sizeof(kV4MappedPrefix)) == 0) {
            *endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
            memcpy(endpoint_addr, bytes + 12, 4);
        } else {
            *endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv6;
            memcpy(endpoint_addr, bytes, 16);
        }
        return true;
    }

    return false;
}

std::string LinuxPeerEndpointToString(uint8_t family, const uint8_t* addr, uint16_t port) {
    char buffer[INET6_ADDRSTRLEN] = {};
    if (family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        if (inet_ntop(AF_INET, addr, buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(port);
        }
    } else if (family == packet_tunnel::kPeerEndpointFamilyIpv6) {
        if (inet_ntop(AF_INET6, addr, buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(port);
        }
    }
    return "unknown";
}

void NormalizeLinuxPeerEndpointFamily(uint8_t* family, uint8_t* addr) {
    if (family == NULL || addr == NULL ||
        *family != packet_tunnel::kPeerEndpointFamilyIpv6) {
        return;
    }

    static const uint8_t kV4MappedPrefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
    };
    if (memcmp(addr, kV4MappedPrefix, sizeof(kV4MappedPrefix)) != 0) {
        return;
    }

    uint8_t ipv4_addr[4] = {};
    memcpy(ipv4_addr, addr + 12, sizeof(ipv4_addr));
    memset(addr, 0, packet_tunnel::kPeerEndpointAddrSize);
    memcpy(addr, ipv4_addr, sizeof(ipv4_addr));
    *family = packet_tunnel::kPeerEndpointFamilyIpv4;
}

std::string LinuxSockaddrToString(const sockaddr_storage& addr, socklen_t addr_len) {
    (void)addr_len;
    char buffer[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&addr);
        if (inet_ntop(AF_INET, &addr4->sin_addr, buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(ntohs(addr4->sin_port));
        }
    } else if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(ntohs(addr6->sin6_port));
        }
    }
    return "unknown";
}

void LinuxClearSockaddrPort(sockaddr_storage* addr) {
    if (addr == NULL) {
        return;
    }

    if (addr->ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(addr)->sin_port = 0;
    } else if (addr->ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = 0;
    }
}

bool LinuxIsPublicInternetAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        const uint32_t ip = ntohl(addr4->sin_addr.s_addr);
        if (ip == 0 ||
            (ip & 0xff000000u) == 0x0a000000u ||
            (ip & 0xfff00000u) == 0xac100000u ||
            (ip & 0xffff0000u) == 0xc0a80000u ||
            (ip & 0xff000000u) == 0x7f000000u ||
            (ip & 0xffff0000u) == 0xa9fe0000u ||
            (ip & 0xffc00000u) == 0x64400000u ||
            (ip & 0xfffe0000u) == 0xc6120000u) {
            return false;
        }
        return true;
    }

    if (addr->sa_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr) ||
            IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
            return false;
        }
        if ((addr6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
            return false;
        }
        return (addr6->sin6_addr.s6_addr[0] & 0xe0) == 0x20;
    }

    return false;
}

bool LinuxSockaddrEquals(const sockaddr_storage& left,
                         socklen_t left_len,
                         const sockaddr_storage& right,
                         socklen_t right_len);

bool BuildEndpointForSocketFamily(const sockaddr* source_addr,
                                  socklen_t source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  socklen_t* endpoint_addr_len);

struct LinuxRelayEndpointCandidate {
    sockaddr_storage endpoint_addr;
    socklen_t endpoint_addr_len;
    int socket_family;
    bool public_internet;
    size_t original_order;
};

int LinuxRelayEndpointPriority(const LinuxRelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? 0 : 1;
    }
    return (candidate.socket_family == AF_INET6) ? 2 : 3;
}

const char* LinuxRelayEndpointScopeName(const LinuxRelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? "public_ipv6" : "public_ipv4";
    }
    return (candidate.socket_family == AF_INET6) ? "non_public_ipv6" : "non_public_ipv4";
}

std::string BuildLinuxRelayEndpointCandidateSummary(
    const std::vector<LinuxRelayEndpointCandidate>& candidates) {
    if (candidates.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        ss << LinuxRelayEndpointScopeName(candidates[i]) << "="
           << LinuxSockaddrToString(candidates[i].endpoint_addr, candidates[i].endpoint_addr_len);
    }
    return ss.str();
}

void BuildLinuxRelayEndpointCandidates(addrinfo* result,
                                       std::vector<LinuxRelayEndpointCandidate>* out_candidates) {
    if (out_candidates == NULL) {
        return;
    }

    out_candidates->clear();
    size_t order = 0;
    for (addrinfo* rp = result; rp != NULL; rp = rp->ai_next, ++order) {
        if (rp->ai_addr == NULL) {
            continue;
        }

        const int family = rp->ai_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }

        LinuxRelayEndpointCandidate candidate = {};
        if (!BuildEndpointForSocketFamily(rp->ai_addr,
                                          static_cast<socklen_t>(rp->ai_addrlen),
                                          family,
                                          &candidate.endpoint_addr,
                                          &candidate.endpoint_addr_len)) {
            continue;
        }

        candidate.socket_family = family;
        candidate.public_internet =
            LinuxIsPublicInternetAddress(reinterpret_cast<const sockaddr*>(&candidate.endpoint_addr));
        candidate.original_order = order;

        bool duplicate = false;
        for (size_t i = 0; i < out_candidates->size(); ++i) {
            if (LinuxSockaddrEquals((*out_candidates)[i].endpoint_addr,
                                    (*out_candidates)[i].endpoint_addr_len,
                                    candidate.endpoint_addr,
                                    candidate.endpoint_addr_len)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            out_candidates->push_back(candidate);
        }
    }

    std::stable_sort(out_candidates->begin(),
                     out_candidates->end(),
                     [](const LinuxRelayEndpointCandidate& left,
                        const LinuxRelayEndpointCandidate& right) {
                         const int left_priority = LinuxRelayEndpointPriority(left);
                         const int right_priority = LinuxRelayEndpointPriority(right);
                         if (left_priority != right_priority) {
                             return left_priority < right_priority;
                         }
                         return left.original_order < right.original_order;
                     });
}

bool ParseLinuxPeerOfferPayload(const uint8_t* payload, size_t length, ParsedLinuxPeerOffer* out_offer) {
    if (payload == NULL || out_offer == NULL || length != packet_tunnel::kPeerOfferPayloadSize) {
        return false;
    }

    out_offer->peer_virtual_ip = LinuxIpv4ToString(payload);
    out_offer->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_offer->endpoint_family = payload[12];
    out_offer->endpoint_port = packet_tunnel::read_u16_be(payload + 14);
    memset(out_offer->endpoint_addr, 0, sizeof(out_offer->endpoint_addr));
    memcpy(out_offer->endpoint_addr, payload + 16, sizeof(out_offer->endpoint_addr));
    NormalizeLinuxPeerEndpointFamily(&out_offer->endpoint_family, out_offer->endpoint_addr);
    out_offer->endpoint = LinuxPeerEndpointToString(out_offer->endpoint_family,
                                                    out_offer->endpoint_addr,
                                                    out_offer->endpoint_port);
    return true;
}

bool ParseLinuxPeerSignalPayload(const uint8_t* payload, size_t length, ParsedLinuxPeerSignal* out_signal) {
    if (payload == NULL || out_signal == NULL || length != packet_tunnel::kPeerSignalPayloadSize) {
        return false;
    }

    out_signal->peer_virtual_ip = LinuxIpv4ToString(payload);
    out_signal->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_signal->nonce = packet_tunnel::read_u32_be(payload + 12);
    return true;
}

bool ParseLinuxPeerDisablePayload(const uint8_t* payload, size_t length, ParsedLinuxPeerDisable* out_disable) {
    if (payload == NULL || out_disable == NULL || length != packet_tunnel::kPeerDisablePayloadSize) {
        return false;
    }

    out_disable->peer_virtual_ip = LinuxIpv4ToString(payload);
    out_disable->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_disable->reason = payload[12];
    return true;
}

bool LinuxSockaddrEquals(const sockaddr_storage& left,
                         socklen_t left_len,
                         const sockaddr_storage& right,
                         socklen_t right_len) {
    (void)left_len;
    (void)right_len;
    if (left.ss_family != right.ss_family) {
        return false;
    }

    if (left.ss_family == AF_INET) {
        const sockaddr_in* left4 = reinterpret_cast<const sockaddr_in*>(&left);
        const sockaddr_in* right4 = reinterpret_cast<const sockaddr_in*>(&right);
        return left4->sin_port == right4->sin_port &&
               left4->sin_addr.s_addr == right4->sin_addr.s_addr;
    }

    if (left.ss_family == AF_INET6) {
        const sockaddr_in6* left6 = reinterpret_cast<const sockaddr_in6*>(&left);
        const sockaddr_in6* right6 = reinterpret_cast<const sockaddr_in6*>(&right);
        return left6->sin6_port == right6->sin6_port &&
               memcmp(&left6->sin6_addr, &right6->sin6_addr, sizeof(left6->sin6_addr)) == 0;
    }

    return false;
}

bool BuildEndpointForSocketFamily(const sockaddr* source_addr,
                                  socklen_t source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  socklen_t* endpoint_addr_len) {
    (void)source_addr_len;
    if (source_addr == NULL || endpoint_addr == NULL || endpoint_addr_len == NULL) {
        return false;
    }

    sockaddr_storage out_addr = {};
    socklen_t out_len = 0;
    if (socket_family == AF_INET6) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&out_addr);
        memset(addr6, 0, sizeof(*addr6));
        addr6->sin6_family = AF_INET6;

        if (source_addr->sa_family == AF_INET6) {
            const sockaddr_in6* source6 = reinterpret_cast<const sockaddr_in6*>(source_addr);
            memcpy(addr6, source6, sizeof(*source6));
            out_len = sizeof(sockaddr_in6);
        } else if (source_addr->sa_family == AF_INET) {
            const sockaddr_in* source4 = reinterpret_cast<const sockaddr_in*>(source_addr);
            addr6->sin6_port = source4->sin_port;
            addr6->sin6_addr.s6_addr[10] = 0xff;
            addr6->sin6_addr.s6_addr[11] = 0xff;
            memcpy(&addr6->sin6_addr.s6_addr[12], &source4->sin_addr, sizeof(source4->sin_addr));
            out_len = sizeof(sockaddr_in6);
        }
    } else if (socket_family == AF_INET && source_addr->sa_family == AF_INET) {
        memcpy(&out_addr, source_addr, sizeof(sockaddr_in));
        out_len = sizeof(sockaddr_in);
    }

    if (out_len == 0) {
        return false;
    }

    *endpoint_addr = out_addr;
    *endpoint_addr_len = out_len;
    return true;
}

}  // namespace

LinuxPacketTunnelClient::LinuxPacketTunnelClient(const std::string& tunnel_host,
                                                 uint16_t tunnel_port,
                                                 const std::string& session_uuid,
                                                 const std::string& client_id,
                                                 const std::string& virtual_ip,
                                                 uint16_t mtu,
                                                 LinuxTunManager* tun_manager)
    : tunnel_host_(tunnel_host),
      tunnel_port_(tunnel_port),
      session_uuid_(session_uuid),
      client_id_(client_id),
      virtual_ip_(virtual_ip),
      mtu_(mtu),
      tun_manager_(tun_manager),
      sock_(-1),
      socket_family_(AF_UNSPEC),
      connected_(false),
      stop_requested_(false),
      last_receive_ms_(0),
      last_network_activity_ms_(0),
      peer_link_manager_(new LinuxPeerLinkManager()),
      peer_signal_nonce_(1) {}

LinuxPacketTunnelClient::~LinuxPacketTunnelClient() {
    Stop();
    delete peer_link_manager_;
    peer_link_manager_ = NULL;
}

void LinuxPacketTunnelClient::MarkNetworkActivity() {
    last_network_activity_ms_ = now_ms();
}

bool LinuxPacketTunnelClient::Start(std::string* error) {
    Stop();
    stop_requested_ = false;
    if (peer_link_manager_ != NULL) {
        peer_link_manager_->SetLocalVirtualIp(virtual_ip_);
    }

    if (!ConnectSocket(error)) {
        return false;
    }
    if (!SendHandshake(error)) {
        Stop();
        return false;
    }
    if (!ReceiveHandshakeAck(error)) {
        Stop();
        return false;
    }
    if (!StartThreads(error)) {
        Stop();
        return false;
    }

    connected_ = true;
    return true;
}

void LinuxPacketTunnelClient::Stop() {
    stop_requested_ = true;
    connected_ = false;
    if (sock_ >= 0 && peer_link_manager_ != NULL) {
        std::vector<LinuxPeerRouteStatus> peers = peer_link_manager_->Snapshot();
        for (size_t i = 0; i < peers.size(); ++i) {
            if (peers[i].endpoint_version == 0) {
                continue;
            }
            SendPeerDisableFrame(peers[i].peer_virtual_ip,
                                 peers[i].endpoint_version,
                                 packet_tunnel::kPeerDisableReasonCooldown);
        }
    }
    if (peer_link_manager_ != NULL) {
        peer_link_manager_->ResetAll();
    }

    if (sock_ >= 0) {
        close(sock_);
        sock_ = -1;
    }

    if (socket_thread_.joinable()) {
        socket_thread_.join();
    }
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
}

bool LinuxPacketTunnelClient::ConnectSocket(std::string* error) {
    server_endpoint_ = UdpEndpoint();
    socket_family_ = AF_UNSPEC;

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = NULL;
    const std::string port_str = std::to_string(tunnel_port_);
    int ret = getaddrinfo(tunnel_host_.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        if (error != NULL) {
            *error = "packet tunnel DNS resolve failed: " + tunnel_host_;
        }
        return false;
    }

    std::vector<LinuxRelayEndpointCandidate> relay_candidates;
    BuildLinuxRelayEndpointCandidates(result, &relay_candidates);
    freeaddrinfo(result);
    result = NULL;

    if (relay_candidates.empty()) {
        if (error != NULL) {
            *error = "packet tunnel resolve returned no usable endpoint: " + tunnel_host_;
        }
        return false;
    }

    LogInfo("packet tunnel relay endpoint candidates: " +
            BuildLinuxRelayEndpointCandidateSummary(relay_candidates));

    auto configure_socket = [&](int sock, int family) {
        if (family == AF_INET6) {
            int dual_stack = 0;
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &dual_stack, sizeof(dual_stack));
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));

        timeval send_timeout = {};
        send_timeout.tv_sec = 5;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));

        timeval recv_timeout = {};
        recv_timeout.tv_sec = kSocketReadTimeoutMs / 1000;
        recv_timeout.tv_usec = (kSocketReadTimeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
    };

    auto try_connect_candidate = [&](const LinuxRelayEndpointCandidate& candidate) -> bool {
        const sockaddr_storage endpoint_addr = candidate.endpoint_addr;
        const socklen_t endpoint_addr_len = candidate.endpoint_addr_len;
        const int preferred_family = candidate.socket_family;

        sockaddr_storage local_bind_addr = {};
        socklen_t local_bind_addr_len = 0;
        bool has_local_bind = false;

        int probe_sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (probe_sock >= 0) {
            configure_socket(probe_sock, preferred_family);
            if (connect(probe_sock,
                        reinterpret_cast<const sockaddr*>(&endpoint_addr),
                        endpoint_addr_len) == 0) {
                local_bind_addr_len = sizeof(local_bind_addr);
                if (getsockname(probe_sock,
                                reinterpret_cast<sockaddr*>(&local_bind_addr),
                                &local_bind_addr_len) == 0) {
                    LinuxClearSockaddrPort(&local_bind_addr);
                    has_local_bind = true;
                }
            }
            close(probe_sock);
        }

        int sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            return false;
        }

        configure_socket(sock, preferred_family);

        if (has_local_bind &&
            bind(sock,
                 reinterpret_cast<const sockaddr*>(&local_bind_addr),
                 local_bind_addr_len) != 0) {
            LogWarn("packet tunnel local bind fallback: " + std::string(strerror(errno)));
            has_local_bind = false;
        }

        sock_ = sock;
        socket_family_ = preferred_family;
        server_endpoint_.addr = endpoint_addr;
        server_endpoint_.addr_len = endpoint_addr_len;
        server_endpoint_.valid = true;
        LogInfo("packet tunnel udp socket ready for relay server " + tunnel_host_ +
                ":" + std::to_string(tunnel_port_) +
                " scope=" + LinuxRelayEndpointScopeName(candidate) +
                " family=" + std::to_string(socket_family_) +
                (has_local_bind
                     ? (" local=" + LinuxSockaddrToString(local_bind_addr, local_bind_addr_len))
                     : std::string("")));
        return true;
    };

    bool connected = false;
    for (size_t i = 0; i < relay_candidates.size(); ++i) {
        if (try_connect_candidate(relay_candidates[i])) {
            connected = true;
            break;
        }
    }

    if (!connected) {
        if (error != NULL) {
            *error = "packet tunnel connect failed: " + tunnel_host_ + ":" + port_str;
        }
        return false;
    }
    return true;
}

bool LinuxPacketTunnelClient::SendHandshake(std::string* error) {
    const uint8_t session_uuid_len = static_cast<uint8_t>(session_uuid_.size());
    if (client_id_.empty()) {
        if (error != NULL) {
            *error = "packet tunnel client_id is empty";
        }
        return false;
    }
    if (client_id_.size() > 255) {
        if (error != NULL) {
            *error = "packet tunnel client_id is too long";
        }
        return false;
    }

    const uint8_t client_id_len = static_cast<uint8_t>(client_id_.size());
    std::vector<uint8_t> handshake(7 + session_uuid_len + 1 + client_id_len + packet_tunnel::kHandshakeTailSize, 0);

    uint32_t conn_id_be = htonl(packet_tunnel::kHandshakeConnId);
    uint16_t port_be = htons(packet_tunnel::kHandshakePortMarker);
    memcpy(&handshake[0], &conn_id_be, sizeof(conn_id_be));
    memcpy(&handshake[4], &port_be, sizeof(port_be));
    handshake[6] = session_uuid_len;
    if (session_uuid_len > 0) {
        memcpy(&handshake[7], session_uuid_.data(), session_uuid_len);
    }
    const size_t client_id_offset = 7 + session_uuid_len;
    handshake[client_id_offset] = client_id_len;
    memcpy(&handshake[client_id_offset + 1], client_id_.data(), client_id_len);

    uint32_t virtual_ip_be = ParseVirtualIp(error);
    if (virtual_ip_be == 0) {
        return false;
    }

    const size_t tail = client_id_offset + 1 + client_id_len;
    handshake[tail + 0] = packet_tunnel::kProtocolVersion;
    handshake[tail + 1] = 0;
    uint16_t mtu_be = htons(mtu_);
    memcpy(&handshake[tail + 2], &mtu_be, sizeof(mtu_be));
    memcpy(&handshake[tail + 4], &virtual_ip_be, sizeof(virtual_ip_be));

    return SendDatagramToEndpoint(server_endpoint_, handshake.data(), handshake.size(), error);
}

bool LinuxPacketTunnelClient::ReceiveHandshakeAck(std::string* error) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    while (!stop_requested_) {
        sockaddr_storage source_addr = {};
        socklen_t source_addr_len = sizeof(source_addr);
        int received = RecvDatagramFrom(ack, sizeof(ack), &source_addr, &source_addr_len, error);
        if (received < 0) {
            return false;
        }
        if (received == 0) {
            continue;
        }
        if (!IsServerEndpoint(source_addr, source_addr_len)) {
            continue;
        }
        if (received != static_cast<int>(sizeof(ack))) {
            if (error != NULL) {
                *error = "packet tunnel ack size mismatch";
            }
            return false;
        }

        if (ack[0] != packet_tunnel::kProtocolVersion) {
            if (error != NULL) {
                *error = "packet tunnel ack version mismatch";
            }
            return false;
        }
        if (ack[1] != packet_tunnel::kStatusOk) {
            if (error != NULL) {
                *error = "packet tunnel ack rejected";
            }
            return false;
        }

        last_receive_ms_ = now_ms();
        MarkNetworkActivity();
        return true;
    }
    if (error != NULL) {
        *error = "packet tunnel handshake interrupted";
    }
    return false;
}

bool LinuxPacketTunnelClient::StartThreads(std::string* error) {
    if (tun_manager_ == NULL) {
        if (error != NULL) {
            *error = "tun manager is null";
        }
        return false;
    }

    socket_thread_ = std::thread(&LinuxPacketTunnelClient::SocketReadLoop, this);
    tun_thread_ = std::thread(&LinuxPacketTunnelClient::TunReadLoop, this);
    heartbeat_thread_ = std::thread(&LinuxPacketTunnelClient::HeartbeatLoop, this);
    return true;
}

void LinuxPacketTunnelClient::SocketReadLoop() {
    std::vector<uint8_t> buffer(65535);
    while (!stop_requested_) {
        std::string error;
        sockaddr_storage source_addr = {};
        socklen_t source_addr_len = sizeof(source_addr);
        int received = RecvDatagramFrom(buffer.data(),
                                        buffer.size(),
                                        &source_addr,
                                        &source_addr_len,
                                        &error);
        if (received < 0) {
            break;
        }
        if (received == 0) {
            continue;
        }

        if (received < static_cast<int>(packet_tunnel::kFrameHeaderSize)) {
            continue;
        }

        const uint8_t frame_type = buffer[0];
        const uint16_t payload_len = ntohs(*(uint16_t*)(&buffer[1]));
        if (received != static_cast<int>(packet_tunnel::kFrameHeaderSize + payload_len)) {
            continue;
        }

        const bool from_server = IsServerEndpoint(source_addr, source_addr_len);
        std::string peer_virtual_ip;
        bool from_known_peer = !from_server &&
                               TryResolvePeerBySource(source_addr, source_addr_len, &peer_virtual_ip);
        bool learned_direct_probe = false;
        bool learned_direct_endpoint_changed = false;
        auto has_fresh_direct_route = [this](const std::string& candidate_peer_virtual_ip) -> bool {
            if (candidate_peer_virtual_ip.empty() || peer_link_manager_ == NULL) {
                return false;
            }

            LinuxPeerRouteStatus route = {};
            const unsigned long long current_ms = now_ms();
            if (!peer_link_manager_->TryGetDirectRoute(candidate_peer_virtual_ip,
                                                       current_ms,
                                                       kPeerDirectDataTimeoutMs,
                                                       kPeerDirectProbeGraceMs,
                                                       &route)) {
                return false;
            }
            return route.active_direct && IsDirectPathFresh(route, current_ms);
        };

        if (from_server) {
            last_receive_ms_ = now_ms();
            MarkNetworkActivity();

            if (frame_type == packet_tunnel::kFrameHeartbeatAck) {
                continue;
            }

            if (HandlePeerControlFrame(frame_type,
                                       buffer.data() + packet_tunnel::kFrameHeaderSize,
                                       payload_len)) {
                continue;
            }
        }

        if (frame_type == packet_tunnel::kFrameIpv4Packet && tun_manager_ != NULL) {
            const uint8_t* payload = buffer.data() + packet_tunnel::kFrameHeaderSize;
            uint8_t probe_type = 0;
            const bool is_direct_probe =
                ParseLinuxPeerDirectProbePacket(payload, payload_len, &probe_type);
            if (!from_server && !from_known_peer && is_direct_probe && peer_link_manager_ != NULL &&
                payload_len >= 20) {
                const std::string inferred_peer_virtual_ip = LinuxIpv4ToString(payload + 12);
                const std::string inferred_local_virtual_ip = LinuxIpv4ToString(payload + 16);
                uint8_t endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
                uint16_t endpoint_port = 0;
                uint8_t endpoint_addr[16] = {};
                if (!inferred_peer_virtual_ip.empty() &&
                    inferred_peer_virtual_ip != virtual_ip_ &&
                    inferred_local_virtual_ip == virtual_ip_ &&
                    TryExtractLinuxPeerEndpointFromSockaddr(source_addr,
                                                           &endpoint_family,
                                                           endpoint_addr,
                                                           &endpoint_port) &&
                    peer_link_manager_->ObserveDirectEndpoint(inferred_peer_virtual_ip,
                                                              endpoint_family,
                                                              endpoint_addr,
                                                              endpoint_port,
                                                              &learned_direct_endpoint_changed,
                                                              NULL)) {
                    peer_virtual_ip = inferred_peer_virtual_ip;
                    from_known_peer = true;
                    learned_direct_probe = true;
                    LogInfo("learn direct probe endpoint peer=" + peer_virtual_ip +
                            " source=" + LinuxSockaddrToString(source_addr, source_addr_len) +
                            (learned_direct_endpoint_changed ? " changed=yes" : " changed=no"));
                }
            }
            if (!from_server && !from_known_peer) {
                LogWarn("ignore ipv4 packet from unknown endpoint source=" +
                        LinuxSockaddrToString(source_addr, source_addr_len));
                continue;
            }
            if (from_known_peer &&
                (payload_len < 20 ||
                 LinuxIpv4ToString(payload + 12) != peer_virtual_ip)) {
                LogWarn("ignore peer ipv4 packet with mismatched inner src peer=" + peer_virtual_ip);
                continue;
            }
            if (from_known_peer) {
                MarkNetworkActivity();
                if (peer_link_manager_ != NULL) {
                    peer_link_manager_->TouchPeerDirectData(peer_virtual_ip, 0);
                }
                if (is_direct_probe) {
                    if (probe_type == kPeerDirectProbeRequest) {
                        uint32_t peer_virtual_ip_be = 0;
                        uint32_t local_virtual_ip_be = ParseVirtualIp(NULL);
                        if (local_virtual_ip_be != 0 &&
                            ParseLinuxIpv4StringToBe(peer_virtual_ip, &peer_virtual_ip_be)) {
                            std::vector<uint8_t> probe_response;
                            if (BuildLinuxPeerDirectProbePacket(local_virtual_ip_be,
                                                                peer_virtual_ip_be,
                                                                kPeerDirectProbeResponse,
                                                                &probe_response)) {
                                UdpEndpoint reply_endpoint;
                                reply_endpoint.addr = source_addr;
                                reply_endpoint.addr_len = source_addr_len;
                                reply_endpoint.valid = true;
                                SendFrameToEndpoint(reply_endpoint,
                                                    packet_tunnel::kFrameIpv4Packet,
                                                    probe_response.data(),
                                                    probe_response.size(),
                                                    NULL);
                            }
                        }
                    }
                    if (learned_direct_probe) {
                        MaybeLogDirectRouteFallback(peer_virtual_ip,
                                                    learned_direct_endpoint_changed
                                                        ? "probe_endpoint_updated"
                                                        : "probe_endpoint_confirmed");
                    }
                    continue;
                }
                if (!has_fresh_direct_route(peer_virtual_ip)) {
                    continue;
                }
            } else if (payload_len >= 20 && has_fresh_direct_route(LinuxIpv4ToString(payload + 12))) {
                continue;
            }
            const bool should_log_focused_udp = IsFocusedLinuxGameUdpPacket(payload, payload_len);
            std::string udp_desc;
            if (should_log_focused_udp) {
                TryDescribeLinuxUdpPacket(payload, payload_len, &udp_desc);
            }

            std::string tun_error;
            if (!tun_manager_->WritePacket(payload, payload_len, &tun_error)) {
                if (should_log_focused_udp && !udp_desc.empty()) {
                    LogWarn(std::string(from_known_peer ? "udp peer->tun write failed " :
                                                           "udp tunnel->tun write failed ") +
                            udp_desc + " error=" + tun_error);
                } else {
                    LogWarn("write packet to TUN failed: " + tun_error);
                }
                continue;
            }

            if (should_log_focused_udp && !udp_desc.empty()) {
                LogInfo(std::string(from_known_peer ? "udp peer->tun " : "udp tunnel->tun ") +
                        udp_desc);
            }
            continue;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

bool LinuxPacketTunnelClient::HandlePeerControlFrame(uint8_t frame_type,
                                                     const uint8_t* payload,
                                                     size_t length) {
    if (frame_type == packet_tunnel::kFramePeerOffer) {
        ParsedLinuxPeerOffer offer = {};
        if (!ParseLinuxPeerOfferPayload(payload, length, &offer)) {
            LogWarn("ignore invalid peer_offer frame len=" + std::to_string(length));
            return true;
        }
        bool should_send_hello = true;
        if (peer_link_manager_ != NULL) {
            should_send_hello = peer_link_manager_->UpdatePeerOffer(offer.peer_virtual_ip,
                                                                    offer.endpoint_version,
                                                                    offer.endpoint_family,
                                                                    offer.endpoint_addr,
                                                                    offer.endpoint_port);
        }
        LogInfo("peer control peer_offer: peer=" + offer.peer_virtual_ip +
                " version=" + std::to_string(offer.endpoint_version) +
                " endpoint=" + offer.endpoint);
        if (!should_send_hello) {
            LogInfo("peer control ignore stable peer_offer: peer=" + offer.peer_virtual_ip +
                    " version=" + std::to_string(offer.endpoint_version));
            return true;
        }
        const uint32_t nonce = peer_signal_nonce_.fetch_add(1);
        if (SendPeerSignalFrame(packet_tunnel::kFramePeerHello,
                                offer.peer_virtual_ip,
                                offer.endpoint_version,
                                nonce)) {
            if (peer_link_manager_ != NULL) {
                peer_link_manager_->RecordPeerHelloSent(offer.peer_virtual_ip,
                                                        offer.endpoint_version,
                                                        nonce);
            }
            LogInfo("peer control send peer_hello: peer=" + offer.peer_virtual_ip +
                    " version=" + std::to_string(offer.endpoint_version) +
                    " nonce=" + std::to_string(nonce));
        } else {
            LogWarn("peer control send peer_hello failed: peer=" + offer.peer_virtual_ip +
                    " version=" + std::to_string(offer.endpoint_version) +
                    " nonce=" + std::to_string(nonce));
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerHello ||
        frame_type == packet_tunnel::kFramePeerAck ||
        frame_type == packet_tunnel::kFramePeerKeepalive) {
        ParsedLinuxPeerSignal signal = {};
        if (!ParseLinuxPeerSignalPayload(payload, length, &signal)) {
            LogWarn("ignore invalid " + LinuxFrameName(frame_type) +
                    " frame len=" + std::to_string(length));
            return true;
        }

        if (peer_link_manager_ != NULL) {
            if (frame_type == packet_tunnel::kFramePeerHello) {
                peer_link_manager_->MarkPeerProbing(signal.peer_virtual_ip, signal.endpoint_version);
            } else if (frame_type == packet_tunnel::kFramePeerAck) {
                if (!peer_link_manager_->TryPromotePeerDirectReady(signal.peer_virtual_ip,
                                                                   signal.endpoint_version,
                                                                   signal.nonce)) {
                    LogInfo("peer control ignore unexpected peer_ack: peer=" + signal.peer_virtual_ip +
                            " version=" + std::to_string(signal.endpoint_version) +
                            " nonce=" + std::to_string(signal.nonce));
                    return true;
                }
            } else {
                peer_link_manager_->TouchPeer(signal.peer_virtual_ip, signal.endpoint_version);
            }
        }

        LogInfo("peer control " + LinuxFrameName(frame_type) +
                ": peer=" + signal.peer_virtual_ip +
                " version=" + std::to_string(signal.endpoint_version) +
                " nonce=" + std::to_string(signal.nonce));
        if (frame_type == packet_tunnel::kFramePeerHello) {
            if (SendPeerSignalFrame(packet_tunnel::kFramePeerAck,
                                    signal.peer_virtual_ip,
                                    signal.endpoint_version,
                                    signal.nonce)) {
                LogInfo("peer control send peer_ack: peer=" + signal.peer_virtual_ip +
                        " version=" + std::to_string(signal.endpoint_version) +
                        " nonce=" + std::to_string(signal.nonce));
            } else {
                LogWarn("peer control send peer_ack failed: peer=" + signal.peer_virtual_ip +
                        " version=" + std::to_string(signal.endpoint_version) +
                        " nonce=" + std::to_string(signal.nonce));
            }
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerDisable) {
        ParsedLinuxPeerDisable disable = {};
        if (!ParseLinuxPeerDisablePayload(payload, length, &disable)) {
            LogWarn("ignore invalid peer_disable frame len=" + std::to_string(length));
            return true;
        }
        if (peer_link_manager_ != NULL) {
            peer_link_manager_->MarkPeerCooldown(disable.peer_virtual_ip,
                                                 disable.endpoint_version);
        }
        LogInfo("peer control peer_disable: peer=" + disable.peer_virtual_ip +
                " version=" + std::to_string(disable.endpoint_version) +
                " reason=" + std::to_string(disable.reason));
        return true;
    }

    return false;
}

bool LinuxPacketTunnelClient::SendPeerSignalFrame(uint8_t frame_type,
                                                  const std::string& target_peer_virtual_ip,
                                                  uint64_t endpoint_version,
                                                  uint32_t nonce) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseLinuxIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerSignalPayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    packet_tunnel::write_u32_be(payload.data() + 12, nonce);
    return SendFrame(frame_type, payload.data(), payload.size(), NULL);
}

bool LinuxPacketTunnelClient::SendPeerDisableFrame(const std::string& target_peer_virtual_ip,
                                                   uint64_t endpoint_version,
                                                   uint8_t reason) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseLinuxIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerDisablePayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    payload[12] = reason;
    return SendFrame(packet_tunnel::kFramePeerDisable, payload.data(), payload.size(), NULL);
}

bool LinuxPacketTunnelClient::TryBuildPeerEndpoint(const std::string& peer_virtual_ip,
                                                   UdpEndpoint* endpoint,
                                                   bool* direct_path_fresh,
                                                   bool* active_direct) const {
    if (endpoint == NULL || peer_link_manager_ == NULL) {
        return false;
    }

    LinuxPeerRouteStatus route = {};
    if (!peer_link_manager_->TryGetDirectRoute(peer_virtual_ip,
                                               now_ms(),
                                               kPeerDirectDataTimeoutMs,
                                               kPeerDirectProbeGraceMs,
                                               &route)) {
        return false;
    }
    if (direct_path_fresh != NULL) {
        *direct_path_fresh = IsDirectPathFresh(route, now_ms());
    }
    if (active_direct != NULL) {
        *active_direct = route.active_direct;
    }

    memset(&endpoint->addr, 0, sizeof(endpoint->addr));
    endpoint->addr_len = 0;
    endpoint->valid = false;

    if (socket_family_ == AF_INET && route.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&endpoint->addr);
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(route.endpoint_port);
        memcpy(&addr4->sin_addr, route.endpoint_addr, 4);
        endpoint->addr_len = sizeof(sockaddr_in);
        endpoint->valid = true;
        return true;
    }

    if (socket_family_ == AF_INET6) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&endpoint->addr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(route.endpoint_port);
        if (route.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv6) {
            memcpy(&addr6->sin6_addr, route.endpoint_addr, 16);
            endpoint->addr_len = sizeof(sockaddr_in6);
            endpoint->valid = true;
            return true;
        }
        if (route.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4) {
            memset(&addr6->sin6_addr, 0, sizeof(addr6->sin6_addr));
            addr6->sin6_addr.s6_addr[10] = 0xFF;
            addr6->sin6_addr.s6_addr[11] = 0xFF;
            memcpy(&addr6->sin6_addr.s6_addr[12], route.endpoint_addr, 4);
            endpoint->addr_len = sizeof(sockaddr_in6);
            endpoint->valid = true;
            return true;
        }
    }

    return false;
}

bool LinuxPacketTunnelClient::TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                                     socklen_t source_addr_len,
                                                     std::string* peer_virtual_ip) const {
    (void)source_addr_len;
    if (peer_link_manager_ == NULL) {
        return false;
    }

    uint8_t endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
    uint16_t endpoint_port = 0;
    uint8_t endpoint_addr[16] = {};
    if (!TryExtractLinuxPeerEndpointFromSockaddr(source_addr,
                                                 &endpoint_family,
                                                 endpoint_addr,
                                                 &endpoint_port)) {
        return false;
    }

    LinuxPeerRouteStatus route = {};
    if (!peer_link_manager_->TryResolveByEndpoint(endpoint_family,
                                                  endpoint_addr,
                                                  endpoint_port,
                                                  &route)) {
        return false;
    }

    if (peer_virtual_ip != NULL) {
        *peer_virtual_ip = route.peer_virtual_ip;
    }
    return true;
}

bool LinuxPacketTunnelClient::IsServerEndpoint(const sockaddr_storage& source_addr,
                                               socklen_t source_addr_len) const {
    if (!server_endpoint_.valid) {
        return false;
    }
    return LinuxSockaddrEquals(source_addr,
                               source_addr_len,
                               server_endpoint_.addr,
                               server_endpoint_.addr_len);
}

bool LinuxPacketTunnelClient::SendFrameToEndpoint(const UdpEndpoint& endpoint,
                                                  uint8_t frame_type,
                                                  const uint8_t* data,
                                                  size_t length,
                                                  std::string* error) {
    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons(static_cast<uint16_t>(length));
    if (length > 0 && data != NULL) {
        memcpy(&frame[packet_tunnel::kFrameHeaderSize], data, length);
    }

    std::lock_guard<std::mutex> lock(send_mutex_);
    return SendDatagramToEndpoint(endpoint, frame.data(), frame.size(), error);
}

bool LinuxPacketTunnelClient::SendDatagramToEndpoint(const UdpEndpoint& endpoint,
                                                     const uint8_t* data,
                                                     size_t length,
                                                     std::string* error) {
    if (!endpoint.valid) {
        if (error != NULL) {
            *error = "packet tunnel send target is invalid";
        }
        return false;
    }

    ssize_t n = sendto(sock_,
                       data,
                       length,
                       0,
                       reinterpret_cast<const sockaddr*>(&endpoint.addr),
                       endpoint.addr_len);
    if (n != static_cast<ssize_t>(length)) {
        if (error != NULL) {
            *error = std::string("packet tunnel send failed: ") + strerror(errno);
        }
        return false;
    }
    MarkNetworkActivity();
    return true;
}

int LinuxPacketTunnelClient::RecvDatagramFrom(uint8_t* data,
                                              size_t length,
                                              sockaddr_storage* source_addr,
                                              socklen_t* source_addr_len,
                                              std::string* error) {
    socklen_t addr_len = static_cast<socklen_t>(sizeof(sockaddr_storage));
    if (source_addr_len != NULL && *source_addr_len > 0) {
        addr_len = *source_addr_len;
    }
    ssize_t n = recvfrom(sock_,
                         data,
                         length,
                         0,
                         (source_addr != NULL) ? reinterpret_cast<sockaddr*>(source_addr) : NULL,
                         (source_addr_len != NULL) ? &addr_len : NULL);
    if (source_addr_len != NULL) {
        *source_addr_len = addr_len;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ECONNREFUSED || errno == ECONNRESET) {
            return 0;
        }
        if (error != NULL) {
            *error = std::string("packet tunnel recv failed: ") + strerror(errno);
        }
        return -1;
    }
    if (n == 0) {
        if (error != NULL) {
            *error = "packet tunnel peer closed";
        }
        return -1;
    }
    return static_cast<int>(n);
}

void LinuxPacketTunnelClient::TunReadLoop() {
    uint32_t local_virtual_ip_be = 0;
    ParseLinuxIpv4StringToBe(virtual_ip_, &local_virtual_ip_be);
    while (!stop_requested_) {
        std::vector<uint8_t> packet;
        std::string error;
        if (!tun_manager_ || !tun_manager_->ReadPacket(&packet, kTunReadWaitMs, &error)) {
            continue;
        }
        if (packet.empty()) {
            continue;
        }

        const uint8_t version = (packet[0] >> 4) & 0x0F;
        if (version != 4) {
            continue;
        }

        if (packet.size() >= 20) {
            const uint8_t dst_octet0 = packet[16];
            if ((dst_octet0 >= 224 && dst_octet0 <= 239) ||
                (packet[16] == 255 && packet[17] == 255 && packet[18] == 255 && packet[19] == 255)) {
                continue;
            }
        }

        std::string desc;
        const bool has_desc =
            !IsLinuxNoisyUdpPacket(packet.data(), packet.size()) &&
            TryDescribeLinuxUdpPacket(packet.data(), packet.size(), &desc);
        const bool is_udp = packet.size() >= 20 && packet[9] == IPPROTO_UDP;
        if (is_udp) {
            const std::string dst_virtual_ip = LinuxIpv4ToString(packet.data() + 16);
            const std::string route_desc =
                has_desc ? desc : ("dst=" + dst_virtual_ip + " len=" + std::to_string(packet.size()));
            UdpEndpoint peer_endpoint;
            bool direct_path_fresh = false;
            bool active_direct = false;
            if (TryBuildPeerEndpoint(dst_virtual_ip,
                                     &peer_endpoint,
                                     &direct_path_fresh,
                                     &active_direct)) {
                if (direct_path_fresh) {
                    if (SendFrameToEndpoint(peer_endpoint,
                                            packet_tunnel::kFrameIpv4Packet,
                                            packet.data(),
                                            packet.size(),
                                            NULL)) {
                        LogInfo("udp tun->peer " + route_desc);
                        continue;
                    }
                    LinuxPeerRouteStatus failed_status = {};
                    const bool state_changed =
                        peer_link_manager_ != NULL &&
                        peer_link_manager_->RecordDirectSendFailure(dst_virtual_ip,
                                                                    0,
                                                                    true,
                                                                    &failed_status);
                    LogWarn("udp active direct send failed, fallback to relay " + route_desc);
                    if (state_changed && failed_status.state == LinuxPeerRouteState::Cooldown) {
                        LogInfo("udp direct route entered cooldown peer=" +
                                failed_status.peer_virtual_ip);
                    }
                } else {
                    const unsigned long long tick = now_ms();
                    std::map<std::string, unsigned long long>::iterator probe_it =
                        peer_probe_send_tick_.find(dst_virtual_ip);
                    const bool should_send_probe =
                        probe_it == peer_probe_send_tick_.end() ||
                        tick < probe_it->second ||
                        (tick - probe_it->second) >= static_cast<unsigned long long>(kPeerDirectProbeIntervalMs);
                    if (should_send_probe) {
                        uint32_t dst_virtual_ip_be = 0;
                        std::vector<uint8_t> probe_packet;
                        if (ParseLinuxIpv4StringToBe(virtual_ip_, &local_virtual_ip_be) &&
                            ParseLinuxIpv4StringToBe(dst_virtual_ip, &dst_virtual_ip_be) &&
                            BuildLinuxPeerDirectProbePacket(local_virtual_ip_be,
                                                            dst_virtual_ip_be,
                                                            kPeerDirectProbeRequest,
                                                            &probe_packet) &&
                            SendFrameToEndpoint(peer_endpoint,
                                                packet_tunnel::kFrameIpv4Packet,
                                                probe_packet.data(),
                                                probe_packet.size(),
                                                NULL)) {
                            peer_probe_send_tick_[dst_virtual_ip] = tick;
                            LogInfo("udp direct probe request " + route_desc);
                        } else {
                            LinuxPeerRouteStatus failed_status = {};
                            const bool state_changed =
                                peer_link_manager_ != NULL &&
                                peer_link_manager_->RecordDirectSendFailure(dst_virtual_ip,
                                                                            0,
                                                                            active_direct,
                                                                            &failed_status);
                            if (active_direct) {
                                LogWarn("udp active direct probe failed, fallback to relay " + route_desc);
                            } else {
                                LogInfo("udp direct probe send failed, keep relay primary " + route_desc);
                            }
                            if (state_changed && failed_status.state == LinuxPeerRouteState::Cooldown) {
                                LogInfo("udp direct route entered cooldown peer=" +
                                        failed_status.peer_virtual_ip);
                            }
                        }
                    }
                }
            } else {
                MaybeLogDirectRouteFallback(dst_virtual_ip, "route_unavailable");
            }
        }

        if (!SendFrame(packet_tunnel::kFrameIpv4Packet, packet.data(), packet.size(), NULL)) {
            break;
        }

        if (has_desc) {
            LogInfo("udp tun->tunnel " + desc);
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void LinuxPacketTunnelClient::MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip,
                                                          const std::string& reason) {
    if (peer_link_manager_ == NULL || peer_virtual_ip.empty()) {
        return;
    }

    const unsigned long long tick = now_ms();
    std::map<std::string, unsigned long long>::iterator it = peer_route_debug_log_tick_.find(peer_virtual_ip);
    if (it != peer_route_debug_log_tick_.end() &&
        tick >= it->second &&
        (tick - it->second) < static_cast<unsigned long long>(kPeerRouteDebugLogIntervalMs)) {
        return;
    }

    const std::vector<LinuxPeerRouteStatus> peers = peer_link_manager_->Snapshot();
    const std::string detail = DescribeSingleLinuxPeerRoute(peers, peer_virtual_ip, tick);
    if (detail.empty()) {
        return;
    }

    peer_route_debug_log_tick_[peer_virtual_ip] = tick;
    LogInfo("udp direct route fallback: reason=" + reason + " peer=" + detail);
}

void LinuxPacketTunnelClient::HeartbeatLoop() {
    unsigned long long last_peer_snapshot_log_ms = 0;
    while (!stop_requested_) {
        for (int waited = 0; waited < kHeartbeatIntervalMs && !stop_requested_; waited += 200) {
            usleep(200 * 1000);
        }
        if (stop_requested_) {
            break;
        }

        if (!SendFrame(packet_tunnel::kFrameHeartbeat, NULL, 0, NULL)) {
            break;
        }

        const unsigned long long current_ms = now_ms();

        if (peer_link_manager_ != NULL) {
            std::vector<LinuxPeerRouteStatus> expired = peer_link_manager_->ExpireStalePeers(
                current_ms,
                kPeerOfferTimeoutMs,
                kPeerDirectReadyTimeoutMs,
                kPeerCooldownTimeoutMs);
            for (size_t i = 0; i < expired.size(); ++i) {
                LogInfo("peer control state transition: peer=" + expired[i].peer_virtual_ip +
                        " state=" + LinuxPeerRouteStateName(expired[i].state) +
                        " version=" + std::to_string(expired[i].endpoint_version));
            }

            std::vector<LinuxPeerRouteStatus> peers = peer_link_manager_->Snapshot();
            if (!peers.empty() &&
                (last_peer_snapshot_log_ms == 0 ||
                 current_ms < last_peer_snapshot_log_ms ||
                 (current_ms - last_peer_snapshot_log_ms) >= kPeerSnapshotLogIntervalMs)) {
                LogInfo("peer control snapshot: " +
                        BuildLinuxPeerRouteSnapshotSummary(peers, current_ms));
                last_peer_snapshot_log_ms = current_ms;
            }
            for (size_t i = 0; i < peers.size(); ++i) {
                if (!peers[i].direct_ready || peers[i].endpoint_version == 0) {
                    continue;
                }
                const uint32_t nonce = peer_signal_nonce_.fetch_add(1);
                if (SendPeerSignalFrame(packet_tunnel::kFramePeerKeepalive,
                                        peers[i].peer_virtual_ip,
                                        peers[i].endpoint_version,
                                        nonce)) {
                    LogInfo("peer control send peer_keepalive: peer=" + peers[i].peer_virtual_ip +
                            " version=" + std::to_string(peers[i].endpoint_version) +
                            " nonce=" + std::to_string(nonce));
                }
            }
        }

        const unsigned long long last_ms = last_network_activity_ms_.load();
        if (last_ms != 0 && current_ms > last_ms && (current_ms - last_ms) > kHeartbeatTimeoutMs) {
            break;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

bool LinuxPacketTunnelClient::SendFrame(uint8_t frame_type,
                                        const uint8_t* data,
                                        size_t length,
                                        std::string* error) {
    return SendFrameToEndpoint(server_endpoint_, frame_type, data, length, error);
}

bool LinuxPacketTunnelClient::SendDatagram(const uint8_t* data, size_t length, std::string* error) {
    return SendDatagramToEndpoint(server_endpoint_, data, length, error);
}

int LinuxPacketTunnelClient::RecvDatagram(uint8_t* data, size_t length, std::string* error) {
    sockaddr_storage source_addr = {};
    socklen_t source_addr_len = sizeof(source_addr);
    return RecvDatagramFrom(data, length, &source_addr, &source_addr_len, error);
}

uint32_t LinuxPacketTunnelClient::ParseVirtualIp(std::string* error) const {
    in_addr addr = {};
    if (inet_pton(AF_INET, virtual_ip_.c_str(), &addr) != 1) {
        if (error != NULL) {
            *error = "invalid virtual ip: " + virtual_ip_;
        }
        return 0;
    }
    return addr.s_addr;
}
