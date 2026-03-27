#include "packet_tunnel_client.h"

#include "packet_tunnel_protocol.h"
#include "peer_link_manager.h"
#include "wintun_manager.h"

#include <windows.h>
#include <windns.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <netioapi.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <vector>

#pragma comment(lib, "dnsapi.lib")

void PacketTunnelDebugLog(const std::string& msg);

namespace {

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

const DWORD kHeartbeatIntervalMs = 3000;
const DWORD kHeartbeatTimeoutMs = 12000;
const DWORD kPeerOfferTimeoutMs = 9000;
const DWORD kPeerDirectReadyTimeoutMs = 15000;
const DWORD kPeerCooldownTimeoutMs = 30000;
const DWORD kPeerDirectProbeGraceMs = 3000;
const DWORD kPeerDirectDataTimeoutMs = 5000;
const DWORD kPeerSnapshotLogIntervalMs = 15000;
const DWORD kPeerRouteDebugLogIntervalMs = 2000;
const DWORD kSocketReadTimeoutMs = 1000;
const DWORD kPhysicalDnsQueryTimeoutMs = 1500;
const DWORD kWintunReadWaitMs = 500;
const int kSocketBufferBytes = 256 * 1024;

bool IsDirectPathFresh(const PeerRouteStatus& route, unsigned long long now_tick) {
    if (!route.active_direct) {
        return false;
    }

    return
        route.last_direct_data_ms != 0 &&
        now_tick >= route.last_direct_data_ms &&
        (now_tick - route.last_direct_data_ms) <= kPeerDirectDataTimeoutMs;
}

std::wstring BuildSocketError(const wchar_t* prefix, int error_code) {
    std::wstringstream stream;
    stream << prefix << L" (WSA=" << error_code << L")";
    return stream.str();
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
    if (required <= 1) {
        return std::string();
    }

    std::string utf8(required - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &utf8[0], required, NULL, NULL);
    return utf8;
}

std::wstring Utf8ToWideString(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (required <= 1) {
        return std::wstring();
    }

    std::wstring wide(required - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &wide[0], required);
    return wide;
}

std::string Ipv4ToString(const uint8_t* addr) {
    IN_ADDR in_addr = {};
    memcpy(&in_addr, addr, sizeof(in_addr));
    char ip_buf[INET_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET, &in_addr, ip_buf, sizeof(ip_buf)) == NULL) {
        return std::string("?");
    }
    return std::string(ip_buf);
}

bool ParseIpv4StringToBe(const std::string& value, uint32_t* out_ip_be) {
    if (out_ip_be == NULL || value.empty()) {
        return false;
    }

    IN_ADDR addr = {};
    if (InetPtonA(AF_INET, value.c_str(), &addr) != 1) {
        return false;
    }

    *out_ip_be = addr.S_un.S_addr;
    return true;
}

const char* PeerRouteStateName(PeerRouteState state) {
    switch (state) {
    case PeerRouteState::RelayOnly:
        return "relay_only";
    case PeerRouteState::OfferReceived:
        return "offer_received";
    case PeerRouteState::Probing:
        return "probing";
    case PeerRouteState::DirectActive:
        return "direct_active";
    case PeerRouteState::Cooldown:
        return "cooldown";
    default:
        return "unknown";
    }
}

std::string BuildPeerRouteSnapshotSummary(const std::vector<PeerRouteStatus>& peers,
                                          unsigned long long now_tick) {
    if (peers.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < peers.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_tick > peers[i].last_observed_ms)
                ? (now_tick - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_tick > peers[i].last_state_change_ms)
                ? (now_tick - peers[i].last_state_change_ms)
                : 0;
        ss << peers[i].peer_virtual_ip
           << "[" << PeerRouteStateName(peers[i].state)
           << " v=" << peers[i].endpoint_version
           << " ready=" << (peers[i].direct_ready ? "y" : "n")
           << " eligible=" << (peers[i].direct_eligible ? "y" : "n")
           << " active=" << (peers[i].active_direct ? "y" : "n")
           << " obs=" << observed_age << "ms"
           << " direct=" << ((peers[i].last_direct_data_ms != 0 && now_tick > peers[i].last_direct_data_ms)
                                ? (now_tick - peers[i].last_direct_data_ms)
                                : 0) << "ms"
           << " sample=" << peers[i].direct_sample_count
           << " fail=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " state=" << state_age << "ms]";
    }
    return ss.str();
}

std::string DescribeSinglePeerRoute(const std::vector<PeerRouteStatus>& peers,
                                    const std::string& peer_virtual_ip,
                                    unsigned long long now_tick) {
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip != peer_virtual_ip) {
            continue;
        }

        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_tick > peers[i].last_observed_ms)
                ? (now_tick - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_tick > peers[i].last_state_change_ms)
                ? (now_tick - peers[i].last_state_change_ms)
                : 0;

        std::ostringstream ss;
        ss << peers[i].peer_virtual_ip
           << "[" << PeerRouteStateName(peers[i].state)
           << " v=" << peers[i].endpoint_version
           << " family=" << static_cast<int>(peers[i].endpoint_family)
           << " port=" << peers[i].endpoint_port
           << " ready=" << (peers[i].direct_ready ? "y" : "n")
           << " eligible=" << (peers[i].direct_eligible ? "y" : "n")
           << " active=" << (peers[i].active_direct ? "y" : "n")
           << " obs=" << observed_age << "ms"
           << " direct=" << ((peers[i].last_direct_data_ms != 0 && now_tick > peers[i].last_direct_data_ms)
                                ? (now_tick - peers[i].last_direct_data_ms)
                                : 0) << "ms"
           << " sample=" << peers[i].direct_sample_count
           << " fail=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " state=" << state_age << "ms]";
        return ss.str();
    }

    return std::string();
}

bool IsNoisyUdpForLogging(const uint8_t* packet, size_t packet_len) {
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

bool TryDescribeUdpPacket(const uint8_t* packet, size_t packet_len, std::string* out_desc) {
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

    uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    std::ostringstream ss;
    ss << "src=" << Ipv4ToString(packet + 12) << ":" << src_port
       << " dst=" << Ipv4ToString(packet + 16) << ":" << dst_port
       << " len=" << packet_len;
    *out_desc = ss.str();
    return true;
}

struct ParsedPeerOffer {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t endpoint_family;
    uint16_t endpoint_port;
    uint8_t endpoint_addr[16];
    std::string endpoint;
};

struct ParsedPeerSignal {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint32_t nonce;
};

struct ParsedPeerDisable {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t reason;
};

std::string PacketTunnelFrameName(uint8_t frame_type) {
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

std::string PeerEndpointToString(uint8_t family, const uint8_t* addr, uint16_t port) {
    char buffer[INET6_ADDRSTRLEN] = {};
    if (family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        if (InetNtopA(AF_INET, const_cast<uint8_t*>(addr), buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(port);
        }
    } else if (family == packet_tunnel::kPeerEndpointFamilyIpv6) {
        if (InetNtopA(AF_INET6, const_cast<uint8_t*>(addr), buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(port);
        }
    }
    return "unknown";
}

std::string SockaddrToString(const sockaddr_storage& addr, int addr_len) {
    (void)addr_len;
    char buffer[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&addr);
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&addr4->sin_addr), buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(ntohs(addr4->sin_port));
        }
    } else if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&addr6->sin6_addr), buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(ntohs(addr6->sin6_port));
        }
    }
    return "unknown";
}

void ClearSockaddrPort(sockaddr_storage* addr) {
    if (addr == NULL) {
        return;
    }

    if (addr->ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(addr)->sin_port = 0;
    } else if (addr->ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = 0;
    }
}

void SetSockaddrPort(sockaddr_storage* addr, uint16_t port_host_order) {
    if (addr == NULL) {
        return;
    }

    if (addr->ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(addr)->sin_port = htons(port_host_order);
    } else if (addr->ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = htons(port_host_order);
    }
}

bool IsUsableBindAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
        if (ip == 0 ||
            (ip & 0xff000000u) == 0x7f000000u ||
            (ip & 0xffff0000u) == 0xa9fe0000u ||
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
        return (addr6->sin6_addr.u.Byte[0] & 0xe0) == 0x20;
    }

    return false;
}

bool IsPublicInternetAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
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
        if ((addr6->sin6_addr.u.Byte[0] & 0xfe) == 0xfc) {
            return false;
        }
        return (addr6->sin6_addr.u.Byte[0] & 0xe0) == 0x20;
    }

    return false;
}

bool SockaddrEquals(const sockaddr_storage& left,
                    int left_len,
                    const sockaddr_storage& right,
                    int right_len);

bool TryFindBindAddressForInterface(ULONG interface_index,
                                    int family,
                                    sockaddr_storage* bind_addr,
                                    int* bind_addr_len,
                                    std::string* adapter_name);

bool BuildEndpointForSocketFamily(const sockaddr* source_addr,
                                  int source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  int* endpoint_addr_len);

struct RelayEndpointCandidate {
    sockaddr_storage endpoint_addr;
    int endpoint_addr_len;
    int socket_family;
    bool public_internet;
    size_t original_order;
};

int RelayEndpointPriority(const RelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? 0 : 1;
    }
    return (candidate.socket_family == AF_INET6) ? 2 : 3;
}

const char* RelayEndpointScopeName(const RelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? "public_ipv6" : "public_ipv4";
    }
    return (candidate.socket_family == AF_INET6) ? "non_public_ipv6" : "non_public_ipv4";
}

bool HasPublicRelayEndpointCandidate(const std::vector<RelayEndpointCandidate>& candidates) {
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].public_internet) {
            return true;
        }
    }
    return false;
}

void SortRelayEndpointCandidates(std::vector<RelayEndpointCandidate>* candidates) {
    if (candidates == NULL) {
        return;
    }

    std::stable_sort(candidates->begin(),
                     candidates->end(),
                     [](const RelayEndpointCandidate& left, const RelayEndpointCandidate& right) {
                         const int left_priority = RelayEndpointPriority(left);
                         const int right_priority = RelayEndpointPriority(right);
                         if (left_priority != right_priority) {
                             return left_priority < right_priority;
                         }
                         return left.original_order < right.original_order;
                     });
}

std::string BuildRelayEndpointCandidateSummary(const std::vector<RelayEndpointCandidate>& candidates) {
    if (candidates.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        ss << RelayEndpointScopeName(candidates[i]) << "="
           << SockaddrToString(candidates[i].endpoint_addr, candidates[i].endpoint_addr_len);
    }
    return ss.str();
}

bool AppendRelayEndpointCandidate(const sockaddr* source_addr,
                                  int source_addr_len,
                                  int socket_family,
                                  size_t original_order,
                                  std::vector<RelayEndpointCandidate>* out_candidates) {
    if (source_addr == NULL || out_candidates == NULL) {
        return false;
    }

    RelayEndpointCandidate candidate = {};
    if (!BuildEndpointForSocketFamily(source_addr,
                                      source_addr_len,
                                      socket_family,
                                      &candidate.endpoint_addr,
                                      &candidate.endpoint_addr_len)) {
        return false;
    }

    candidate.socket_family = socket_family;
    candidate.public_internet =
        IsPublicInternetAddress(reinterpret_cast<const sockaddr*>(&candidate.endpoint_addr));
    candidate.original_order = original_order;

    for (size_t i = 0; i < out_candidates->size(); ++i) {
        if (SockaddrEquals((*out_candidates)[i].endpoint_addr,
                           (*out_candidates)[i].endpoint_addr_len,
                           candidate.endpoint_addr,
                           candidate.endpoint_addr_len)) {
            return false;
        }
    }

    out_candidates->push_back(candidate);
    return true;
}

void BuildRelayEndpointCandidates(addrinfo* result,
                                  std::vector<RelayEndpointCandidate>* out_candidates) {
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

        AppendRelayEndpointCandidate(rp->ai_addr,
                                     static_cast<int>(rp->ai_addrlen),
                                     family,
                                     order,
                                     out_candidates);
    }

    SortRelayEndpointCandidates(out_candidates);
}

bool SockaddrAddressEquals(const sockaddr_storage& left, const sockaddr* right) {
    if (right == NULL || left.ss_family != right->sa_family) {
        return false;
    }

    if (left.ss_family == AF_INET) {
        const sockaddr_in* left4 = reinterpret_cast<const sockaddr_in*>(&left);
        const sockaddr_in* right4 = reinterpret_cast<const sockaddr_in*>(right);
        return left4->sin_addr.S_un.S_addr == right4->sin_addr.S_un.S_addr;
    }

    if (left.ss_family == AF_INET6) {
        const sockaddr_in6* left6 = reinterpret_cast<const sockaddr_in6*>(&left);
        const sockaddr_in6* right6 = reinterpret_cast<const sockaddr_in6*>(right);
        return memcmp(&left6->sin6_addr, &right6->sin6_addr, sizeof(left6->sin6_addr)) == 0;
    }

    return false;
}

bool LoadAdapterAddressesInternal(ULONG family,
                                  ULONG flags,
                                  std::vector<unsigned char>* buffer,
                                  IP_ADAPTER_ADDRESSES** adapters) {
    if (buffer == NULL || adapters == NULL) {
        return false;
    }

    flags |= GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    ULONG buffer_size = 16 * 1024;
    buffer->assign(buffer_size, 0);

    ULONG ret = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && ret == ERROR_BUFFER_OVERFLOW; ++attempt) {
        ret = GetAdaptersAddresses(family,
                                   flags,
                                   NULL,
                                   reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&(*buffer)[0]),
                                   &buffer_size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            buffer->assign(buffer_size, 0);
        }
    }

    if (ret != NO_ERROR) {
        return false;
    }

    *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&(*buffer)[0]);
    return true;
}

bool LoadAdapterAddresses(ULONG family,
                          std::vector<unsigned char>* buffer,
                          IP_ADAPTER_ADDRESSES** adapters) {
    return LoadAdapterAddressesInternal(family,
                                        GAA_FLAG_SKIP_DNS_SERVER,
                                        buffer,
                                        adapters);
}

bool LoadAdapterAddressesForDns(ULONG family,
                                std::vector<unsigned char>* buffer,
                                IP_ADAPTER_ADDRESSES** adapters) {
    return LoadAdapterAddressesInternal(family, 0, buffer, adapters);
}

std::string AdapterDisplayName(const IP_ADAPTER_ADDRESSES* adapter) {
    if (adapter == NULL) {
        return "unknown";
    }

    std::wstring name = adapter->FriendlyName ? adapter->FriendlyName : L"";
    if (name.empty() && adapter->Description != NULL) {
        name = adapter->Description;
    }
    return WideToUtf8(name);
}

bool IsPreferredPhysicalAdapter(const IP_ADAPTER_ADDRESSES* adapter) {
    if (adapter == NULL || adapter->OperStatus != IfOperStatusUp) {
        return false;
    }

    if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD &&
        adapter->IfType != IF_TYPE_IEEE80211) {
        return false;
    }

    MIB_IF_ROW2 row = {};
    row.InterfaceLuid = adapter->Luid;
    if (GetIfEntry2(&row) != NO_ERROR) {
        return false;
    }
    if (!row.InterfaceAndOperStatusFlags.HardwareInterface ||
        row.InterfaceAndOperStatusFlags.FilterInterface) {
        return false;
    }

    return true;
}

bool IsUsableDnsServerAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
        if (ip == 0 ||
            (ip & 0xff000000u) == 0x7f000000u ||
            (ip & 0xffff0000u) == 0xa9fe0000u) {
            return false;
        }
        return true;
    }

    if (addr->sa_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr)) {
            return false;
        }
        return true;
    }

    return false;
}

bool IsNumericHostLiteral(const std::string& value) {
    IN_ADDR addr4 = {};
    if (InetPtonA(AF_INET, value.c_str(), &addr4) == 1) {
        return true;
    }

    IN6_ADDR addr6 = {};
    return InetPtonA(AF_INET6, value.c_str(), &addr6) == 1;
}

struct PhysicalDnsServer {
    sockaddr_storage server_addr;
    int server_addr_len;
    ULONG interface_index;
    std::string adapter_name;
    size_t original_order;
};

std::string BuildPhysicalDnsServerSummary(const std::vector<PhysicalDnsServer>& servers) {
    if (servers.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < servers.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        ss << SockaddrToString(servers[i].server_addr, servers[i].server_addr_len)
           << "@if" << servers[i].interface_index;
        if (!servers[i].adapter_name.empty()) {
            ss << "(" << servers[i].adapter_name << ")";
        }
    }
    return ss.str();
}

void CollectPhysicalDnsServers(std::vector<PhysicalDnsServer>* out_servers) {
    if (out_servers == NULL) {
        return;
    }

    out_servers->clear();

    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddressesForDns(AF_UNSPEC, &buffer, &adapters)) {
        return;
    }

    size_t order = 0;
    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (!IsPreferredPhysicalAdapter(adapter)) {
            continue;
        }

        const std::string adapter_name = AdapterDisplayName(adapter);
        for (IP_ADAPTER_DNS_SERVER_ADDRESS* dns = adapter->FirstDnsServerAddress;
             dns != NULL;
             dns = dns->Next) {
            if (dns->Address.lpSockaddr == NULL ||
                !IsUsableDnsServerAddress(dns->Address.lpSockaddr)) {
                continue;
            }

            const int family = dns->Address.lpSockaddr->sa_family;
            if (family != AF_INET && family != AF_INET6) {
                continue;
            }

            PhysicalDnsServer server = {};
            if (family == AF_INET) {
                server.server_addr_len = sizeof(sockaddr_in);
                memcpy(&server.server_addr, dns->Address.lpSockaddr, sizeof(sockaddr_in));
                server.interface_index = adapter->IfIndex;
            } else {
                server.server_addr_len = sizeof(sockaddr_in6);
                memcpy(&server.server_addr, dns->Address.lpSockaddr, sizeof(sockaddr_in6));
                server.interface_index = (adapter->Ipv6IfIndex != 0)
                    ? adapter->Ipv6IfIndex
                    : adapter->IfIndex;
            }

            ClearSockaddrPort(&server.server_addr);
            SetSockaddrPort(&server.server_addr, 53);
            server.adapter_name = adapter_name;
            server.original_order = order++;

            bool duplicate = false;
            for (size_t i = 0; i < out_servers->size(); ++i) {
                if (SockaddrAddressEquals((*out_servers)[i].server_addr,
                                          reinterpret_cast<const sockaddr*>(&server.server_addr))) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                out_servers->push_back(server);
            }
        }
    }
}

const char* DnsRecordTypeName(WORD type) {
    switch (type) {
    case DNS_TYPE_A:
        return "A";
    case DNS_TYPE_AAAA:
        return "AAAA";
    default:
        return "?";
    }
}

uint16_t ReadDnsUInt16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                                 static_cast<uint16_t>(data[1]));
}

void AppendDnsUInt16(uint16_t value, std::vector<uint8_t>* out) {
    if (out == NULL) {
        return;
    }
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(value & 0xff));
}

bool AppendDnsQueryName(const std::string& host_name, std::vector<uint8_t>* out) {
    if (out == NULL || host_name.empty()) {
        return false;
    }

    size_t start = 0;
    while (start < host_name.size()) {
        size_t end = host_name.find('.', start);
        if (end == std::string::npos) {
            end = host_name.size();
        }

        const size_t label_len = end - start;
        if (label_len == 0 || label_len > 63) {
            return false;
        }

        out->push_back(static_cast<uint8_t>(label_len));
        out->insert(out->end(),
                    host_name.begin() + static_cast<std::ptrdiff_t>(start),
                    host_name.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }

    out->push_back(0);
    return true;
}

bool SkipDnsName(const uint8_t* packet, size_t packet_len, size_t* offset) {
    if (packet == NULL || offset == NULL || *offset >= packet_len) {
        return false;
    }

    size_t pos = *offset;
    int steps = 0;
    while (pos < packet_len && steps++ < 128) {
        const uint8_t label = packet[pos];
        if (label == 0) {
            *offset = pos + 1;
            return true;
        }
        if ((label & 0xc0) == 0xc0) {
            if (pos + 1 >= packet_len) {
                return false;
            }
            *offset = pos + 2;
            return true;
        }
        if ((label & 0xc0) != 0x00) {
            return false;
        }

        const size_t label_len = static_cast<size_t>(label);
        ++pos;
        if (pos + label_len > packet_len) {
            return false;
        }
        pos += label_len;
    }

    return false;
}

bool ParseDnsResponseRecords(const uint8_t* packet,
                             size_t packet_len,
                             uint16_t expected_txid,
                             uint16_t tunnel_port,
                             size_t* next_order,
                             std::vector<RelayEndpointCandidate>* out_candidates,
                             size_t* out_added) {
    if (packet == NULL || packet_len < 12 || next_order == NULL || out_candidates == NULL) {
        return false;
    }

    if (ReadDnsUInt16(packet) != expected_txid) {
        return false;
    }

    const uint16_t flags = ReadDnsUInt16(packet + 2);
    if ((flags & 0x8000u) == 0) {
        return false;
    }
    if ((flags & 0x000fu) != 0) {
        return false;
    }

    const uint16_t question_count = ReadDnsUInt16(packet + 4);
    const uint16_t answer_count = ReadDnsUInt16(packet + 6);
    const uint16_t authority_count = ReadDnsUInt16(packet + 8);
    const uint16_t additional_count = ReadDnsUInt16(packet + 10);

    size_t offset = 12;
    for (uint16_t i = 0; i < question_count; ++i) {
        if (!SkipDnsName(packet, packet_len, &offset) || offset + 4 > packet_len) {
            return false;
        }
        offset += 4;
    }

    size_t added = 0;
    const uint32_t total_records =
        static_cast<uint32_t>(answer_count) +
        static_cast<uint32_t>(authority_count) +
        static_cast<uint32_t>(additional_count);
    for (uint32_t i = 0; i < total_records; ++i) {
        if (!SkipDnsName(packet, packet_len, &offset) || offset + 10 > packet_len) {
            return false;
        }

        const uint16_t record_type = ReadDnsUInt16(packet + offset);
        const uint16_t record_class = ReadDnsUInt16(packet + offset + 2);
        const uint16_t record_len = ReadDnsUInt16(packet + offset + 8);
        offset += 10;
        if (offset + record_len > packet_len) {
            return false;
        }

        if (record_class == 1 && record_type == DNS_TYPE_A && record_len == 4) {
            sockaddr_in addr4 = {};
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(tunnel_port);
            memcpy(&addr4.sin_addr, packet + offset, 4);
            if (AppendRelayEndpointCandidate(reinterpret_cast<const sockaddr*>(&addr4),
                                             sizeof(addr4),
                                             AF_INET,
                                             *next_order,
                                             out_candidates)) {
                ++(*next_order);
                ++added;
            }
        } else if (record_class == 1 && record_type == DNS_TYPE_AAAA && record_len == 16) {
            sockaddr_in6 addr6 = {};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(tunnel_port);
            memcpy(&addr6.sin6_addr, packet + offset, 16);
            if (AppendRelayEndpointCandidate(reinterpret_cast<const sockaddr*>(&addr6),
                                             sizeof(addr6),
                                             AF_INET6,
                                             *next_order,
                                             out_candidates)) {
                ++(*next_order);
                ++added;
            }
        }

        offset += record_len;
    }

    if (out_added != NULL) {
        *out_added = added;
    }
    return true;
}

bool QueryRelayEndpointsViaSingleDnsServer(const std::string& host_name,
                                           uint16_t tunnel_port,
                                           const PhysicalDnsServer& dns_server,
                                           WORD query_type,
                                           size_t* next_order,
                                           std::vector<RelayEndpointCandidate>* out_candidates) {
    if (next_order == NULL || out_candidates == NULL) {
        return false;
    }

    sockaddr_storage bind_addr = {};
    int bind_addr_len = 0;
    std::string bind_adapter_name;
    if (!TryFindBindAddressForInterface(dns_server.interface_index,
                                        dns_server.server_addr.ss_family,
                                        &bind_addr,
                                        &bind_addr_len,
                                        &bind_adapter_name)) {
        PacketTunnelDebugLog("physical dns bind address not found: server=" +
                             SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                             " if=" + std::to_string(dns_server.interface_index));
        return false;
    }

    SOCKET sock = socket(dns_server.server_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        PacketTunnelDebugLog("physical dns socket create failed: server=" +
                             SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                             " wsa=" + std::to_string(WSAGetLastError()));
        return false;
    }

    DWORD timeout = kPhysicalDnsQueryTimeoutMs;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    BOOL disable_udp_connreset = FALSE;
    DWORD bytes_returned = 0;
    WSAIoctl(sock,
             SIO_UDP_CONNRESET,
             &disable_udp_connreset,
             sizeof(disable_udp_connreset),
             NULL,
             0,
             &bytes_returned,
             NULL,
             NULL);

    bool success = false;
    do {
        if (bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), bind_addr_len) != 0) {
            PacketTunnelDebugLog("physical dns bind failed: server=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " bind=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " wsa=" + std::to_string(WSAGetLastError()));
            break;
        }

        if (connect(sock,
                    reinterpret_cast<const sockaddr*>(&dns_server.server_addr),
                    dns_server.server_addr_len) != 0) {
            PacketTunnelDebugLog("physical dns connect failed: server=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " bind=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " wsa=" + std::to_string(WSAGetLastError()));
            break;
        }

        const uint16_t txid =
            static_cast<uint16_t>((GetTickCount64() + (*next_order * 97) + query_type) & 0xffffu);
        std::vector<uint8_t> query;
        query.reserve(512);
        AppendDnsUInt16(txid, &query);
        AppendDnsUInt16(0x0100u, &query);
        AppendDnsUInt16(1, &query);
        AppendDnsUInt16(0, &query);
        AppendDnsUInt16(0, &query);
        AppendDnsUInt16(0, &query);
        if (!AppendDnsQueryName(host_name, &query)) {
            break;
        }
        AppendDnsUInt16(query_type, &query);
        AppendDnsUInt16(1, &query);

        const int sent = send(sock,
                              reinterpret_cast<const char*>(query.data()),
                              static_cast<int>(query.size()),
                              0);
        if (sent != static_cast<int>(query.size())) {
            PacketTunnelDebugLog("physical dns send failed: server=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " bind=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " type=" + DnsRecordTypeName(query_type) +
                                 " wsa=" + std::to_string(WSAGetLastError()));
            break;
        }

        uint8_t response[2048] = {};
        const int received = recv(sock, reinterpret_cast<char*>(response), sizeof(response), 0);
        if (received <= 0) {
            PacketTunnelDebugLog("physical dns recv failed: server=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " bind=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " type=" + DnsRecordTypeName(query_type) +
                                 " wsa=" + std::to_string(WSAGetLastError()));
            break;
        }

        size_t added = 0;
        if (!ParseDnsResponseRecords(response,
                                     static_cast<size_t>(received),
                                     txid,
                                     tunnel_port,
                                     next_order,
                                     out_candidates,
                                     &added)) {
            PacketTunnelDebugLog("physical dns parse failed: server=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " bind=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " type=" + DnsRecordTypeName(query_type) +
                                 " bytes=" + std::to_string(received));
            break;
        }

        PacketTunnelDebugLog("physical dns query result: server=" +
                             SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                             " bind=" + SockaddrToString(bind_addr, bind_addr_len) +
                             " type=" + DnsRecordTypeName(query_type) +
                             " added=" + std::to_string(added));
        success = added > 0;
    } while (false);

    closesocket(sock);
    return success;
}

bool QueryRelayEndpointsViaPhysicalDns(const std::string& host_name,
                                       uint16_t tunnel_port,
                                       const std::vector<PhysicalDnsServer>& dns_servers,
                                       std::vector<RelayEndpointCandidate>* out_candidates) {
    if (out_candidates == NULL || dns_servers.empty()) {
        return false;
    }

    bool added_any = false;
    size_t next_order = out_candidates->size();
    for (size_t server_index = 0; server_index < dns_servers.size(); ++server_index) {
        const PhysicalDnsServer& dns_server = dns_servers[server_index];

        for (int type_index = 0; type_index < 2; ++type_index) {
            const WORD query_type = (type_index == 0) ? DNS_TYPE_AAAA : DNS_TYPE_A;
            if (QueryRelayEndpointsViaSingleDnsServer(host_name,
                                                      tunnel_port,
                                                      dns_server,
                                                      query_type,
                                                      &next_order,
                                                      out_candidates)) {
                added_any = true;
            }
        }

        if (HasPublicRelayEndpointCandidate(*out_candidates)) {
            break;
        }
    }

    if (added_any) {
        SortRelayEndpointCandidates(out_candidates);
    }
    return added_any;
}

bool TryResolveBindAdapter(const sockaddr_storage& addr,
                           int family,
                           std::string* adapter_name,
                           bool* preferred) {
    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddresses(static_cast<ULONG>(family), &buffer, &adapters)) {
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != family) {
                continue;
            }
            if (!SockaddrAddressEquals(addr, unicast->Address.lpSockaddr)) {
                continue;
            }

            if (adapter_name != NULL) {
                *adapter_name = AdapterDisplayName(adapter);
            }
            if (preferred != NULL) {
                *preferred = IsPreferredPhysicalAdapter(adapter);
            }
            return true;
        }
    }

    return false;
}

bool TryFindBindAddressForInterface(ULONG interface_index,
                                    int family,
                                    sockaddr_storage* bind_addr,
                                    int* bind_addr_len,
                                    std::string* adapter_name) {
    if (bind_addr == NULL || bind_addr_len == NULL) {
        return false;
    }

    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddresses(static_cast<ULONG>(family), &buffer, &adapters)) {
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (!IsPreferredPhysicalAdapter(adapter)) {
            continue;
        }

        const ULONG adapter_index = (family == AF_INET6 && adapter->Ipv6IfIndex != 0)
            ? adapter->Ipv6IfIndex
            : adapter->IfIndex;
        if (adapter_index != interface_index) {
            continue;
        }

        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != family ||
                !IsUsableBindAddress(unicast->Address.lpSockaddr)) {
                continue;
            }

            if (family == AF_INET) {
                *bind_addr_len = sizeof(sockaddr_in);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in));
            } else if (family == AF_INET6) {
                *bind_addr_len = sizeof(sockaddr_in6);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in6));
            } else {
                continue;
            }

            ClearSockaddrPort(bind_addr);
            if (adapter_name != NULL) {
                *adapter_name = AdapterDisplayName(adapter);
            }
            return true;
        }
    }

    return false;
}

bool TryFindPreferredBindAddress(int family,
                                 sockaddr_storage* bind_addr,
                                 int* bind_addr_len,
                                 std::string* adapter_name) {
    if (bind_addr == NULL || bind_addr_len == NULL) {
        return false;
    }

    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddresses(static_cast<ULONG>(family), &buffer, &adapters)) {
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (!IsPreferredPhysicalAdapter(adapter)) {
            continue;
        }

        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != family ||
                !IsUsableBindAddress(unicast->Address.lpSockaddr)) {
                continue;
            }

            if (family == AF_INET) {
                *bind_addr_len = sizeof(sockaddr_in);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in));
            } else if (family == AF_INET6) {
                *bind_addr_len = sizeof(sockaddr_in6);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in6));
            } else {
                continue;
            }

            ClearSockaddrPort(bind_addr);
            if (adapter_name != NULL) {
                *adapter_name = AdapterDisplayName(adapter);
            }
            return true;
        }
    }

    return false;
}

bool ParsePeerOfferPayload(const uint8_t* payload, size_t length, ParsedPeerOffer* out_offer) {
    if (payload == NULL || out_offer == NULL || length != packet_tunnel::kPeerOfferPayloadSize) {
        return false;
    }

    out_offer->peer_virtual_ip = Ipv4ToString(payload);
    out_offer->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_offer->endpoint_family = payload[12];
    out_offer->endpoint_port = packet_tunnel::read_u16_be(payload + 14);
    memset(out_offer->endpoint_addr, 0, sizeof(out_offer->endpoint_addr));
    memcpy(out_offer->endpoint_addr, payload + 16, sizeof(out_offer->endpoint_addr));
    out_offer->endpoint = PeerEndpointToString(out_offer->endpoint_family, payload + 16, out_offer->endpoint_port);
    return true;
}

bool ParsePeerSignalPayload(const uint8_t* payload, size_t length, ParsedPeerSignal* out_signal) {
    if (payload == NULL || out_signal == NULL || length != packet_tunnel::kPeerSignalPayloadSize) {
        return false;
    }

    out_signal->peer_virtual_ip = Ipv4ToString(payload);
    out_signal->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_signal->nonce = packet_tunnel::read_u32_be(payload + 12);
    return true;
}

bool ParsePeerDisablePayload(const uint8_t* payload, size_t length, ParsedPeerDisable* out_disable) {
    if (payload == NULL || out_disable == NULL || length != packet_tunnel::kPeerDisablePayloadSize) {
        return false;
    }

    out_disable->peer_virtual_ip = Ipv4ToString(payload);
    out_disable->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_disable->reason = payload[12];
    return true;
}

bool SockaddrEquals(const sockaddr_storage& left,
                    int left_len,
                    const sockaddr_storage& right,
                    int right_len) {
    (void)left_len;
    (void)right_len;
    if (left.ss_family != right.ss_family) {
        return false;
    }

    if (left.ss_family == AF_INET) {
        const sockaddr_in* left4 = reinterpret_cast<const sockaddr_in*>(&left);
        const sockaddr_in* right4 = reinterpret_cast<const sockaddr_in*>(&right);
        return left4->sin_port == right4->sin_port &&
               left4->sin_addr.S_un.S_addr == right4->sin_addr.S_un.S_addr;
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
                                  int source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  int* endpoint_addr_len) {
    if (source_addr == NULL || endpoint_addr == NULL || endpoint_addr_len == NULL) {
        return false;
    }

    sockaddr_storage out_addr = {};
    int out_len = 0;
    if (socket_family == AF_INET6 && source_addr->sa_family == AF_INET6) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&out_addr);
        ZeroMemory(addr6, sizeof(*addr6));
        addr6->sin6_family = AF_INET6;
        const sockaddr_in6* source6 = reinterpret_cast<const sockaddr_in6*>(source_addr);
        memcpy(addr6, source6, sizeof(*source6));
        out_len = sizeof(sockaddr_in6);
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

PacketTunnelClient::PacketTunnelClient(const std::string& tunnel_ip,
                                       uint16_t tunnel_port,
                                       const std::string& session_uuid,
                                       const std::string& virtual_ip,
                                       uint16_t mtu,
                                       WintunManager* wintun_manager)
    : tunnel_server_ip_(tunnel_ip),
      tunnel_port_(tunnel_port),
      session_uuid_(session_uuid),
      virtual_ip_(virtual_ip),
      mtu_(mtu),
      wintun_manager_(wintun_manager),
      sock_(INVALID_SOCKET),
      socket_family_(AF_UNSPEC),
      connected_(false),
      stop_requested_(false),
      last_receive_tick_(0),
      last_network_activity_tick_(0),
      peer_link_manager_(new PeerLinkManager()),
      peer_signal_nonce_(1),
      peer_direct_allowed_(true) {
    InitializeCriticalSection(&send_lock_);
}

PacketTunnelClient::~PacketTunnelClient() {
    Stop();
    delete peer_link_manager_;
    peer_link_manager_ = NULL;
    DeleteCriticalSection(&send_lock_);
}

bool PacketTunnelClient::Start(std::wstring* error_msg) {
    Stop();
    stop_requested_ = false;
    if (peer_link_manager_ != NULL) {
        peer_link_manager_->SetLocalVirtualIp(virtual_ip_);
    }
    PacketTunnelDebugLog("packet tunnel start: server=" + tunnel_server_ip_ +
                         ":" + std::to_string(tunnel_port_) +
                         " virtual_ip=" + virtual_ip_);

    if (!ConnectSocket(error_msg)) {
        if (error_msg != NULL) {
            PacketTunnelDebugLog("connect failed: " + WideToUtf8(*error_msg));
        }
        return false;
    }
    if (!SendHandshake(error_msg)) {
        if (error_msg != NULL) {
            PacketTunnelDebugLog("handshake send failed: " + WideToUtf8(*error_msg));
        }
        Stop();
        return false;
    }
    if (!ReceiveHandshakeAck(error_msg)) {
        if (error_msg != NULL) {
            PacketTunnelDebugLog("handshake ack failed: " + WideToUtf8(*error_msg));
        }
        Stop();
        return false;
    }
    if (!StartThreads(error_msg)) {
        Stop();
        return false;
    }

    connected_ = true;
    PacketTunnelDebugLog("packet tunnel ready");
    return true;
}

void PacketTunnelClient::Stop() {
    stop_requested_ = true;
    connected_ = false;
    if (sock_ != INVALID_SOCKET && peer_link_manager_ != NULL) {
        std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
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

    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }

    if (socket_read_thread_.joinable()) {
        socket_read_thread_.join();
    }
    if (wintun_read_thread_.joinable()) {
        wintun_read_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }

    PacketTunnelDebugLog("packet tunnel stopped");
}

bool PacketTunnelClient::ConnectSocket(std::wstring* error_msg) {
    server_endpoint_ = UdpEndpoint();
    socket_family_ = AF_UNSPEC;
    peer_direct_allowed_ = true;

    struct addrinfo hints = {};
    struct addrinfo* result = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    std::string port_str = std::to_string(tunnel_port_);
    int ret = getaddrinfo(tunnel_server_ip_.c_str(), port_str.c_str(), &hints, &result);
    std::vector<RelayEndpointCandidate> relay_candidates;
    if (ret == 0) {
        BuildRelayEndpointCandidates(result, &relay_candidates);
        freeaddrinfo(result);
        result = NULL;
    } else {
        PacketTunnelDebugLog("system dns resolve failed for relay host " + tunnel_server_ip_ +
                             " status=" + std::to_string(ret));
    }

    if (!IsNumericHostLiteral(tunnel_server_ip_) &&
        !HasPublicRelayEndpointCandidate(relay_candidates)) {
        std::vector<PhysicalDnsServer> physical_dns_servers;
        CollectPhysicalDnsServers(&physical_dns_servers);
        if (!physical_dns_servers.empty()) {
            PacketTunnelDebugLog("relay endpoint physical dns servers: " +
                                 BuildPhysicalDnsServerSummary(physical_dns_servers));
            if (QueryRelayEndpointsViaPhysicalDns(tunnel_server_ip_,
                                                  tunnel_port_,
                                                  physical_dns_servers,
                                                  &relay_candidates)) {
                PacketTunnelDebugLog("relay endpoint candidates after physical dns: " +
                                     BuildRelayEndpointCandidateSummary(relay_candidates));
            } else {
                PacketTunnelDebugLog("relay endpoint physical dns returned no additional endpoint");
            }
        }
    }

    if (relay_candidates.empty()) {
        if (error_msg != NULL) {
            if (ret != 0) {
                *error_msg = L"IP Tunnel DNS resolve failed: " + Utf8ToWide(tunnel_server_ip_);
            } else {
                *error_msg = L"IP Tunnel resolve returned no usable endpoint: " + Utf8ToWide(tunnel_server_ip_);
            }
        }
        return false;
    }

    PacketTunnelDebugLog("relay endpoint candidates: " +
                         BuildRelayEndpointCandidateSummary(relay_candidates));

    auto configure_socket = [&](SOCKET sock, int family) {
        if (family == AF_INET6) {
            DWORD dual_stack = 0;
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&dual_stack), sizeof(dual_stack));
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&kSocketBufferBytes, sizeof(kSocketBufferBytes));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&kSocketBufferBytes, sizeof(kSocketBufferBytes));

        DWORD send_timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&send_timeout, sizeof(send_timeout));
        DWORD recv_timeout = kSocketReadTimeoutMs;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&recv_timeout, sizeof(recv_timeout));

        BOOL disable_udp_connreset = FALSE;
        DWORD bytes_returned = 0;
        WSAIoctl(sock,
                 SIO_UDP_CONNRESET,
                 &disable_udp_connreset,
                 sizeof(disable_udp_connreset),
                 NULL,
                 0,
                 &bytes_returned,
                 NULL,
                 NULL);
    };

    auto try_connect_candidate = [&](const RelayEndpointCandidate& candidate) -> bool {
        const sockaddr_storage endpoint_addr = candidate.endpoint_addr;
        const int endpoint_addr_len = candidate.endpoint_addr_len;
        const int preferred_family = candidate.socket_family;
        const bool public_relay_target = candidate.public_internet;
        peer_direct_allowed_ = public_relay_target;

        sockaddr_storage local_bind_addr = {};
        int local_bind_addr_len = 0;
        bool has_local_bind = false;
        std::string bind_adapter_name;

        SOCKET probe_sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (probe_sock != INVALID_SOCKET) {
            configure_socket(probe_sock, preferred_family);
            if (connect(probe_sock,
                        reinterpret_cast<const sockaddr*>(&endpoint_addr),
                        endpoint_addr_len) == 0) {
                local_bind_addr_len = static_cast<int>(sizeof(local_bind_addr));
                if (getsockname(probe_sock,
                                reinterpret_cast<sockaddr*>(&local_bind_addr),
                                &local_bind_addr_len) == 0) {
                    ClearSockaddrPort(&local_bind_addr);
                    if (!public_relay_target) {
                        has_local_bind = true;
                    } else {
                        bool preferred_adapter = false;
                        if (IsUsableBindAddress(reinterpret_cast<const sockaddr*>(&local_bind_addr)) &&
                            TryResolveBindAdapter(local_bind_addr,
                                                  preferred_family,
                                                  &bind_adapter_name,
                                                  &preferred_adapter) &&
                            preferred_adapter) {
                            has_local_bind = true;
                        } else {
                            PacketTunnelDebugLog("udp socket local bind rejected: " +
                                                 SockaddrToString(local_bind_addr, local_bind_addr_len) +
                                                 (bind_adapter_name.empty()
                                                      ? std::string()
                                                      : (" adapter=" + bind_adapter_name)));
                        }
                    }
                }
            }
            closesocket(probe_sock);
        }

        if (public_relay_target && !has_local_bind) {
            if (!TryFindPreferredBindAddress(preferred_family,
                                             &local_bind_addr,
                                             &local_bind_addr_len,
                                             &bind_adapter_name)) {
                PacketTunnelDebugLog("udp socket preferred bind not found for family=" +
                                     std::to_string(preferred_family));
                return false;
            }
            has_local_bind = true;
            PacketTunnelDebugLog("udp socket local bind override: " +
                                 SockaddrToString(local_bind_addr, local_bind_addr_len) +
                                 " adapter=" + bind_adapter_name);
        }

        SOCKET sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            return false;
        }

        configure_socket(sock, preferred_family);

        if (public_relay_target &&
            has_local_bind &&
            bind(sock,
                 reinterpret_cast<const sockaddr*>(&local_bind_addr),
                 local_bind_addr_len) != 0) {
            PacketTunnelDebugLog("udp socket local bind fallback: " +
                                 WideToUtf8(BuildSocketError(L"bind failed", WSAGetLastError())));
            closesocket(sock);
            return false;
        }

        sock_ = sock;
        socket_family_ = preferred_family;
        server_endpoint_.addr = endpoint_addr;
        server_endpoint_.addr_len = endpoint_addr_len;
        server_endpoint_.valid = true;
        if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("peer direct disabled: relay target is non-public " +
                                 SockaddrToString(endpoint_addr, endpoint_addr_len));
        }
        PacketTunnelDebugLog("udp socket ready for relay server " + tunnel_server_ip_ +
                             ":" + std::to_string(tunnel_port_) +
                             " scope=" + RelayEndpointScopeName(candidate) +
                             " family=" + std::to_string(socket_family_) +
                             ((public_relay_target && has_local_bind)
                                  ? (" local=" + SockaddrToString(local_bind_addr, local_bind_addr_len))
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
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel connect failed: " + Utf8ToWide(tunnel_server_ip_) +
                         L":" + Utf8ToWide(std::to_string(tunnel_port_));
        }
        return false;
    }
    return true;
}

bool PacketTunnelClient::SendHandshake(std::wstring* error_msg) {
    uint8_t session_uuid_len = static_cast<uint8_t>(session_uuid_.size());
    std::vector<uint8_t> handshake(7 + session_uuid_len + packet_tunnel::kHandshakeTailSize, 0);

    uint32_t conn_id_be = htonl(packet_tunnel::kHandshakeConnId);
    uint16_t port_be = htons(packet_tunnel::kHandshakePortMarker);
    memcpy(&handshake[0], &conn_id_be, sizeof(conn_id_be));
    memcpy(&handshake[4], &port_be, sizeof(port_be));
    handshake[6] = session_uuid_len;
    if (session_uuid_len > 0) {
        memcpy(&handshake[7], session_uuid_.data(), session_uuid_len);
    }

    uint32_t virtual_ip_be = ParseVirtualIp(error_msg);
    if (virtual_ip_be == 0) {
        return false;
    }

    size_t tail = 7 + session_uuid_len;
    handshake[tail + 0] = packet_tunnel::kProtocolVersion;
    handshake[tail + 1] = peer_direct_allowed_
        ? packet_tunnel::kHandshakeFlagNone
        : packet_tunnel::kHandshakeFlagRelayOnly;
    uint16_t mtu_be = htons(mtu_);
    memcpy(&handshake[tail + 2], &mtu_be, sizeof(mtu_be));
    memcpy(&handshake[tail + 4], &virtual_ip_be, sizeof(virtual_ip_be));

    PacketTunnelDebugLog("sending handshake: session=" + session_uuid_ +
                         " mtu=" + std::to_string(mtu_) +
                         " virtual_ip=" + virtual_ip_);
    return SendDatagramToEndpoint(server_endpoint_, handshake.data(), handshake.size(), error_msg);
}

void PacketTunnelClient::MarkNetworkActivity() {
    last_network_activity_tick_ = GetTickCount64();
}

bool PacketTunnelClient::ReceiveHandshakeAck(std::wstring* error_msg) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    while (!stop_requested_) {
        sockaddr_storage source_addr = {};
        int source_addr_len = 0;
        int received = RecvDatagramFrom(ack, sizeof(ack), &source_addr, &source_addr_len, error_msg);
        if (received < 0) {
            return false;
        }
        if (received == 0) {
            continue;
        }
        if (!IsServerEndpoint(source_addr, source_addr_len)) {
            continue;
        }
        if (received != (int)sizeof(ack)) {
            if (error_msg != NULL) {
                *error_msg = L"IP Tunnel ack size mismatch";
            }
            return false;
        }

        if (ack[0] != packet_tunnel::kProtocolVersion) {
            if (error_msg != NULL) {
                *error_msg = L"IP Tunnel ack version mismatch";
            }
            return false;
        }

        if (ack[1] != packet_tunnel::kStatusOk) {
            if (error_msg != NULL) {
                *error_msg = L"IP Tunnel ack rejected, status=" + Utf8ToWide(std::to_string((int)ack[1]));
            }
            return false;
        }

        last_receive_tick_ = GetTickCount64();
        MarkNetworkActivity();
        PacketTunnelDebugLog("received handshake ack: mtu=" + std::to_string(mtu_) +
                             " virtual_ip=" + virtual_ip_);
        return true;
    }
    if (error_msg != NULL) {
        *error_msg = L"IP Tunnel handshake interrupted";
    }
    return false;
}

bool PacketTunnelClient::StartThreads(std::wstring* error_msg) {
    if (wintun_manager_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun manager is null";
        }
        return false;
    }

    socket_read_thread_ = std::thread(&PacketTunnelClient::SocketReadLoop, this);
    wintun_read_thread_ = std::thread(&PacketTunnelClient::WintunReadLoop, this);
    heartbeat_thread_ = std::thread(&PacketTunnelClient::HeartbeatLoop, this);
    return true;
}

void PacketTunnelClient::SocketReadLoop() {
    std::vector<uint8_t> buffer(65535);
    while (!stop_requested_) {
        std::wstring err;
        sockaddr_storage source_addr = {};
        int source_addr_len = 0;
        int received = RecvDatagramFrom(buffer.data(),
                                        buffer.size(),
                                        &source_addr,
                                        &source_addr_len,
                                        &err);
        if (received < 0) {
            if (!err.empty()) {
                PacketTunnelDebugLog("socket read loop stopped: " + WideToUtf8(err));
            }
            break;
        }
        if (received == 0) {
            continue;
        }

        if (received < (int)packet_tunnel::kFrameHeaderSize) {
            continue;
        }

        uint8_t frame_type = buffer[0];
        uint16_t payload_len = ntohs(*(uint16_t*)(buffer.data() + 1));
        if (received != (int)(packet_tunnel::kFrameHeaderSize + payload_len)) {
            continue;
        }

        const bool from_server = IsServerEndpoint(source_addr, source_addr_len);
        std::string peer_virtual_ip;
        const bool from_known_peer = !from_server &&
                                     TryResolvePeerBySource(source_addr, source_addr_len, &peer_virtual_ip);
        auto has_fresh_direct_route = [this](const std::string& candidate_peer_virtual_ip) -> bool {
            if (candidate_peer_virtual_ip.empty() || peer_link_manager_ == NULL) {
                return false;
            }

            PeerRouteStatus route = {};
            const unsigned long long now_tick = GetTickCount64();
            if (!peer_link_manager_->TryGetDirectRoute(candidate_peer_virtual_ip,
                                                       now_tick,
                                                       kPeerDirectDataTimeoutMs,
                                                       kPeerDirectProbeGraceMs,
                                                       &route)) {
                return false;
            }
            return route.active_direct && IsDirectPathFresh(route, now_tick);
        };

        if (from_server) {
            last_receive_tick_ = GetTickCount64();
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

        if (frame_type == packet_tunnel::kFrameIpv4Packet && wintun_manager_ != NULL) {
            const uint8_t* payload = buffer.data() + packet_tunnel::kFrameHeaderSize;
            if (!from_server && !from_known_peer) {
                PacketTunnelDebugLog("ignore ipv4 packet from unknown endpoint source=" +
                                     SockaddrToString(source_addr, source_addr_len));
                continue;
            }
            if (from_known_peer &&
                (payload_len < 20 ||
                 Ipv4ToString(payload + 12) != peer_virtual_ip)) {
                PacketTunnelDebugLog("ignore peer ipv4 packet with mismatched inner src peer=" +
                                     peer_virtual_ip);
                continue;
            }
            if (from_known_peer) {
                MarkNetworkActivity();
                if (peer_link_manager_ != NULL) {
                    peer_link_manager_->TouchPeerDirectData(peer_virtual_ip, 0);
                }
                if (!has_fresh_direct_route(peer_virtual_ip)) {
                    continue;
                }
            } else if (payload_len >= 20 && has_fresh_direct_route(Ipv4ToString(payload + 12))) {
                continue;
            }
            std::string desc;
            if (!IsNoisyUdpForLogging(payload, payload_len) &&
                TryDescribeUdpPacket(payload, payload_len, &desc)) {
                PacketTunnelDebugLog(std::string(from_known_peer ? "udp peer->wintun " : "udp tunnel->wintun ") + desc);
            }
            wintun_manager_->WritePacket(payload, payload_len, NULL);
            continue;
        }

    if (!from_server && !from_known_peer) {
        PacketTunnelDebugLog("ignore packet from unknown endpoint source=" +
                             SockaddrToString(source_addr, source_addr_len) +
                             " frame=" + PacketTunnelFrameName(frame_type));
    }
    }

    connected_ = false;
    stop_requested_ = true;
}

void PacketTunnelClient::WintunReadLoop() {
    uint32_t virtual_ip_be = ParseVirtualIp(NULL);
    uint8_t leased_src_ip[4] = {};
    if (virtual_ip_be != 0) {
        memcpy(leased_src_ip, &virtual_ip_be, sizeof(leased_src_ip));
    }

    while (!stop_requested_) {
        std::vector<uint8_t> packet;
        std::wstring err;
        if (!wintun_manager_ || !wintun_manager_->ReadPacket(&packet, kWintunReadWaitMs, &err)) {
            continue;
        }

        if (packet.empty()) {
            continue;
        }

        uint8_t version = (packet[0] >> 4) & 0x0F;
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

        if (virtual_ip_be != 0 && packet.size() >= 20 &&
            memcmp(packet.data() + 12, leased_src_ip, sizeof(leased_src_ip)) != 0) {
            continue;
        }

        std::string desc;
        const bool has_desc =
            !IsNoisyUdpForLogging(packet.data(), packet.size()) &&
            TryDescribeUdpPacket(packet.data(), packet.size(), &desc);
        const bool is_udp = packet.size() >= 20 && packet[9] == IPPROTO_UDP;
        if (is_udp && peer_direct_allowed_) {
            const std::string dst_virtual_ip = Ipv4ToString(packet.data() + 16);
            const std::string route_desc =
                has_desc ? desc : ("dst=" + dst_virtual_ip + " len=" + std::to_string(packet.size()));
            UdpEndpoint peer_endpoint;
            bool direct_path_fresh = false;
            bool active_direct = false;
            if (TryBuildPeerEndpoint(dst_virtual_ip,
                                     &peer_endpoint,
                                     &direct_path_fresh,
                                     &active_direct)) {
                if (SendFrameToEndpoint(peer_endpoint,
                                        packet_tunnel::kFrameIpv4Packet,
                                        packet.data(),
                                        packet.size(),
                                        NULL)) {
                    PacketTunnelDebugLog(std::string(direct_path_fresh ? "udp wintun->peer "
                                                                         : "udp wintun->peer-probe ")
                                         + route_desc);
                    if (direct_path_fresh) {
                        continue;
                    }
                    PacketTunnelDebugLog(std::string(active_direct
                                                         ? "udp active direct stale, relay stays primary "
                                                         : "udp direct evaluation mirror relay ")
                                         + route_desc);
                } else {
                    PeerRouteStatus failed_status = {};
                    const bool state_changed =
                        peer_link_manager_ != NULL &&
                        peer_link_manager_->RecordDirectSendFailure(dst_virtual_ip,
                                                                    0,
                                                                    active_direct,
                                                                    &failed_status);
                    if (active_direct) {
                        PacketTunnelDebugLog("udp active direct send failed, fallback to relay " +
                                             route_desc);
                    } else {
                        PacketTunnelDebugLog("udp direct probe send failed, keep relay primary " +
                                             route_desc);
                    }
                    if (state_changed && failed_status.state == PeerRouteState::Cooldown) {
                        PacketTunnelDebugLog("udp direct route entered cooldown peer=" +
                                             failed_status.peer_virtual_ip);
                    }
                }
            } else {
                MaybeLogDirectRouteFallback(dst_virtual_ip, "route_unavailable");
            }
        }

        if (!SendFrame(packet_tunnel::kFrameIpv4Packet, packet.data(), packet.size(), NULL)) {
            PacketTunnelDebugLog("wintun read loop send failed");
            break;
        }

        if (has_desc) {
            PacketTunnelDebugLog("udp wintun->tunnel " + desc);
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void PacketTunnelClient::HeartbeatLoop() {
    unsigned long long last_peer_snapshot_log_tick = 0;
    while (!stop_requested_) {
        for (DWORD waited = 0; waited < kHeartbeatIntervalMs && !stop_requested_; waited += 200) {
            Sleep(200);
        }
        if (stop_requested_) {
            break;
        }

        if (!SendFrame(packet_tunnel::kFrameHeartbeat, NULL, 0, NULL)) {
            PacketTunnelDebugLog("heartbeat send failed");
            break;
        }

        unsigned long long now_tick = GetTickCount64();

        if (peer_direct_allowed_ && peer_link_manager_ != NULL) {
            std::vector<PeerRouteStatus> expired = peer_link_manager_->ExpireStalePeers(
                now_tick,
                kPeerOfferTimeoutMs,
                kPeerDirectReadyTimeoutMs,
                kPeerCooldownTimeoutMs);
            for (size_t i = 0; i < expired.size(); ++i) {
                PacketTunnelDebugLog("peer control state transition: peer=" +
                                     expired[i].peer_virtual_ip +
                                     " state=" + PeerRouteStateName(expired[i].state) +
                                     " version=" + std::to_string(expired[i].endpoint_version));
            }

            std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
            if (!peers.empty() &&
                (last_peer_snapshot_log_tick == 0 ||
                 now_tick < last_peer_snapshot_log_tick ||
                 (now_tick - last_peer_snapshot_log_tick) >= kPeerSnapshotLogIntervalMs)) {
                PacketTunnelDebugLog("peer control snapshot: " +
                                     BuildPeerRouteSnapshotSummary(peers, now_tick));
                last_peer_snapshot_log_tick = now_tick;
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
                    PacketTunnelDebugLog("peer control send peer_keepalive: peer=" +
                                         peers[i].peer_virtual_ip +
                                         " version=" + std::to_string(peers[i].endpoint_version) +
                                         " nonce=" + std::to_string(nonce));
                }
            }
        }

        unsigned long long last_tick = last_network_activity_tick_.load();
        if (last_tick != 0 && now_tick > last_tick && (now_tick - last_tick) > kHeartbeatTimeoutMs) {
            PacketTunnelDebugLog("heartbeat timeout: idle_ms=" + std::to_string(now_tick - last_tick));
            break;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void PacketTunnelClient::MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip,
                                                     const std::string& reason) {
    if (peer_link_manager_ == NULL || peer_virtual_ip.empty()) {
        return;
    }

    const unsigned long long now_tick = GetTickCount64();
    std::map<std::string, unsigned long long>::iterator it = peer_route_debug_log_tick_.find(peer_virtual_ip);
    if (it != peer_route_debug_log_tick_.end() &&
        now_tick >= it->second &&
        (now_tick - it->second) < kPeerRouteDebugLogIntervalMs) {
        return;
    }

    const std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
    const std::string detail = DescribeSinglePeerRoute(peers, peer_virtual_ip, now_tick);
    if (detail.empty()) {
        return;
    }

    peer_route_debug_log_tick_[peer_virtual_ip] = now_tick;
    PacketTunnelDebugLog("udp direct route fallback: reason=" + reason + " peer=" + detail);
}

bool PacketTunnelClient::HandlePeerControlFrame(uint8_t frame_type,
                                                const uint8_t* payload,
                                                size_t length) {
    if (frame_type == packet_tunnel::kFramePeerOffer) {
        ParsedPeerOffer offer = {};
        if (!ParsePeerOfferPayload(payload, length, &offer)) {
            PacketTunnelDebugLog("ignore invalid peer_offer frame len=" + std::to_string(length));
            return true;
        }
        if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("peer control ignore peer_offer: relay-only mode peer=" +
                                 offer.peer_virtual_ip +
                                 " endpoint=" + offer.endpoint);
            if (offer.endpoint_version != 0) {
                SendPeerDisableFrame(offer.peer_virtual_ip,
                                     offer.endpoint_version,
                                     packet_tunnel::kPeerDisableReasonCooldown);
            }
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
        PacketTunnelDebugLog("peer control peer_offer: peer=" + offer.peer_virtual_ip +
                             " version=" + std::to_string(offer.endpoint_version) +
                             " endpoint=" + offer.endpoint);
        if (!should_send_hello) {
            PacketTunnelDebugLog("peer control ignore stable peer_offer: peer=" + offer.peer_virtual_ip +
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
            PacketTunnelDebugLog("peer control send peer_hello: peer=" + offer.peer_virtual_ip +
                                 " version=" + std::to_string(offer.endpoint_version) +
                                 " nonce=" + std::to_string(nonce));
        } else {
            PacketTunnelDebugLog("peer control send peer_hello failed: peer=" + offer.peer_virtual_ip +
                                 " version=" + std::to_string(offer.endpoint_version) +
                                 " nonce=" + std::to_string(nonce));
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerHello ||
        frame_type == packet_tunnel::kFramePeerAck ||
        frame_type == packet_tunnel::kFramePeerKeepalive) {
        ParsedPeerSignal signal = {};
        if (!ParsePeerSignalPayload(payload, length, &signal)) {
            PacketTunnelDebugLog("ignore invalid " + PacketTunnelFrameName(frame_type) +
                                 " frame len=" + std::to_string(length));
            return true;
        }

        if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("peer control ignore " + PacketTunnelFrameName(frame_type) +
                                 ": relay-only mode peer=" + signal.peer_virtual_ip +
                                 " version=" + std::to_string(signal.endpoint_version) +
                                 " nonce=" + std::to_string(signal.nonce));
            if (frame_type != packet_tunnel::kFramePeerAck && signal.endpoint_version != 0) {
                SendPeerDisableFrame(signal.peer_virtual_ip,
                                     signal.endpoint_version,
                                     packet_tunnel::kPeerDisableReasonCooldown);
            }
            return true;
        }

        if (peer_link_manager_ != NULL) {
            if (frame_type == packet_tunnel::kFramePeerHello) {
                peer_link_manager_->MarkPeerProbing(signal.peer_virtual_ip, signal.endpoint_version);
            } else if (frame_type == packet_tunnel::kFramePeerAck) {
                if (!peer_link_manager_->TryPromotePeerDirectReady(signal.peer_virtual_ip,
                                                                   signal.endpoint_version,
                                                                   signal.nonce)) {
                    PacketTunnelDebugLog("peer control ignore unexpected peer_ack: peer=" +
                                         signal.peer_virtual_ip +
                                         " version=" + std::to_string(signal.endpoint_version) +
                                         " nonce=" + std::to_string(signal.nonce));
                    return true;
                }
            } else {
                peer_link_manager_->TouchPeer(signal.peer_virtual_ip, signal.endpoint_version);
            }
        }

        PacketTunnelDebugLog("peer control " + PacketTunnelFrameName(frame_type) +
                             ": peer=" + signal.peer_virtual_ip +
                             " version=" + std::to_string(signal.endpoint_version) +
                             " nonce=" + std::to_string(signal.nonce));

        if (frame_type == packet_tunnel::kFramePeerHello) {
            if (SendPeerSignalFrame(packet_tunnel::kFramePeerAck,
                                    signal.peer_virtual_ip,
                                    signal.endpoint_version,
                                    signal.nonce)) {
                PacketTunnelDebugLog("peer control send peer_ack: peer=" + signal.peer_virtual_ip +
                                     " version=" + std::to_string(signal.endpoint_version) +
                                     " nonce=" + std::to_string(signal.nonce));
            } else {
                PacketTunnelDebugLog("peer control send peer_ack failed: peer=" + signal.peer_virtual_ip +
                                     " version=" + std::to_string(signal.endpoint_version) +
                                     " nonce=" + std::to_string(signal.nonce));
            }
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerDisable) {
        ParsedPeerDisable disable = {};
        if (!ParsePeerDisablePayload(payload, length, &disable)) {
            PacketTunnelDebugLog("ignore invalid peer_disable frame len=" + std::to_string(length));
            return true;
        }
        if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("peer control ignore peer_disable: relay-only mode peer=" +
                                 disable.peer_virtual_ip +
                                 " version=" + std::to_string(disable.endpoint_version) +
                                 " reason=" + std::to_string(disable.reason));
            return true;
        }
        if (peer_link_manager_ != NULL) {
            peer_link_manager_->MarkPeerCooldown(disable.peer_virtual_ip,
                                                 disable.endpoint_version);
        }
        PacketTunnelDebugLog("peer control peer_disable: peer=" + disable.peer_virtual_ip +
                             " version=" + std::to_string(disable.endpoint_version) +
                             " reason=" + std::to_string(disable.reason));
        return true;
    }

    return false;
}

bool PacketTunnelClient::SendPeerSignalFrame(uint8_t frame_type,
                                             const std::string& target_peer_virtual_ip,
                                             uint64_t endpoint_version,
                                             uint32_t nonce) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerSignalPayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    packet_tunnel::write_u32_be(payload.data() + 12, nonce);
    return SendFrame(frame_type, payload.data(), payload.size(), NULL);
}

bool PacketTunnelClient::SendPeerDisableFrame(const std::string& target_peer_virtual_ip,
                                              uint64_t endpoint_version,
                                              uint8_t reason) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerDisablePayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    payload[12] = reason;
    return SendFrame(packet_tunnel::kFramePeerDisable, payload.data(), payload.size(), NULL);
}

bool PacketTunnelClient::TryBuildPeerEndpoint(const std::string& peer_virtual_ip,
                                              UdpEndpoint* endpoint,
                                              bool* direct_path_fresh,
                                              bool* active_direct) const {
    if (endpoint == NULL || peer_link_manager_ == NULL) {
        return false;
    }

    PeerRouteStatus route = {};
    if (!peer_link_manager_->TryGetDirectRoute(peer_virtual_ip,
                                               GetTickCount64(),
                                               kPeerDirectDataTimeoutMs,
                                               kPeerDirectProbeGraceMs,
                                               &route)) {
        return false;
    }
    if (direct_path_fresh != NULL) {
        *direct_path_fresh = IsDirectPathFresh(route, GetTickCount64());
    }
    if (active_direct != NULL) {
        *active_direct = route.active_direct;
    }

    ZeroMemory(&endpoint->addr, sizeof(endpoint->addr));
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
            addr6->sin6_addr.u.Word[5] = 0xFFFF;
            memcpy(&addr6->sin6_addr.u.Byte[12], route.endpoint_addr, 4);
            endpoint->addr_len = sizeof(sockaddr_in6);
            endpoint->valid = true;
            return true;
        }
    }

    return false;
}

bool PacketTunnelClient::TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                                int source_addr_len,
                                                std::string* peer_virtual_ip) const {
    if (peer_link_manager_ == NULL) {
        return false;
    }

    uint8_t endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
    uint16_t endpoint_port = 0;
    uint8_t endpoint_addr[16] = {};

    if (source_addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&source_addr);
        endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
        endpoint_port = ntohs(addr4->sin_port);
        memcpy(endpoint_addr, &addr4->sin_addr, 4);
    } else if (source_addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&source_addr);
        endpoint_port = ntohs(addr6->sin6_port);
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&addr6->sin6_addr);
        const uint8_t v4_mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (memcmp(bytes, v4_mapped_prefix, sizeof(v4_mapped_prefix)) == 0) {
            endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
            memcpy(endpoint_addr, bytes + 12, 4);
        } else {
            endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv6;
            memcpy(endpoint_addr, bytes, 16);
        }
    } else {
        return false;
    }

    PeerRouteStatus route = {};
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

bool PacketTunnelClient::IsServerEndpoint(const sockaddr_storage& source_addr,
                                          int source_addr_len) const {
    if (!server_endpoint_.valid) {
        return false;
    }
    return SockaddrEquals(source_addr,
                          source_addr_len,
                          server_endpoint_.addr,
                          server_endpoint_.addr_len);
}

bool PacketTunnelClient::SendFrameToEndpoint(const UdpEndpoint& endpoint,
                                             uint8_t frame_type,
                                             const uint8_t* data,
                                             size_t length,
                                             std::wstring* error_msg) {
    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons((uint16_t)length);
    if (length > 0 && data != NULL) {
        memcpy(&frame[packet_tunnel::kFrameHeaderSize], data, length);
    }

    EnterCriticalSection(&send_lock_);
    bool ok = SendDatagramToEndpoint(endpoint, frame.data(), frame.size(), error_msg);
    LeaveCriticalSection(&send_lock_);
    return ok;
}

bool PacketTunnelClient::SendDatagramToEndpoint(const UdpEndpoint& endpoint,
                                                const uint8_t* data,
                                                size_t length,
                                                std::wstring* error_msg) {
    if (!endpoint.valid) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel send target is invalid";
        }
        return false;
    }

    int n = sendto(sock_,
                   reinterpret_cast<const char*>(data),
                   static_cast<int>(length),
                   0,
                   reinterpret_cast<const sockaddr*>(&endpoint.addr),
                   endpoint.addr_len);
    if (n != (int)length) {
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel send failed", WSAGetLastError());
        }
        return false;
    }
    MarkNetworkActivity();
    return true;
}

int PacketTunnelClient::RecvDatagramFrom(uint8_t* data,
                                         size_t length,
                                         sockaddr_storage* source_addr,
                                         int* source_addr_len,
                                         std::wstring* error_msg) {
    int addr_len = static_cast<int>(sizeof(sockaddr_storage));
    if (source_addr_len != NULL && *source_addr_len > 0) {
        addr_len = *source_addr_len;
    }
    int n = recvfrom(sock_,
                     reinterpret_cast<char*>(data),
                     static_cast<int>(length),
                     0,
                     (source_addr != NULL) ? reinterpret_cast<sockaddr*>(source_addr) : NULL,
                     (source_addr_len != NULL) ? &addr_len : NULL);
    if (source_addr_len != NULL) {
        *source_addr_len = addr_len;
    }
    if (n == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAECONNRESET) {
            return 0;
        }
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel recv failed", err);
        }
        return -1;
    }
    if (n == 0) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel peer closed";
        }
        return -1;
    }
    return n;
}

bool PacketTunnelClient::SendFrame(uint8_t frame_type, const uint8_t* data, size_t length, std::wstring* error_msg) {
    return SendFrameToEndpoint(server_endpoint_, frame_type, data, length, error_msg);
}

bool PacketTunnelClient::SendDatagram(const uint8_t* data, size_t length, std::wstring* error_msg) {
    return SendDatagramToEndpoint(server_endpoint_, data, length, error_msg);
}

int PacketTunnelClient::RecvDatagram(uint8_t* data, size_t length, std::wstring* error_msg) {
    sockaddr_storage source_addr = {};
    int source_addr_len = 0;
    return RecvDatagramFrom(data, length, &source_addr, &source_addr_len, error_msg);
}

uint32_t PacketTunnelClient::ParseVirtualIp(std::wstring* error_msg) const {
    IN_ADDR addr = {};
    if (InetPtonA(AF_INET, virtual_ip_.c_str(), &addr) != 1) {
        if (error_msg != NULL) {
            *error_msg = L"Invalid leased virtual IP: " + Utf8ToWide(virtual_ip_);
        }
        return 0;
    }
    return addr.S_un.S_addr;
}

std::wstring PacketTunnelClient::Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (required <= 1) {
        return std::wstring();
    }

    std::wstring wide(required - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &wide[0], required);
    return wide;
}
