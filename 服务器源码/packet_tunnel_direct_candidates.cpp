#include "packet_tunnel_direct_candidates.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

TcpDirectCandidate::TcpDirectCandidate()
    : endpoint_family(packet_tunnel::kPeerEndpointFamilyUnknown),
      endpoint_port(0) {
    memset(endpoint_addr, 0, sizeof(endpoint_addr));
}

PacketTunnelCandidateOwnerView::PacketTunnelCandidateOwnerView()
    : use_udp(false),
      udp_addr_len(0),
      tcp_direct_listen_port(0) {
    memset(&udp_addr, 0, sizeof(udp_addr));
}

bool ParsePacketTunnelClientEndpointString(const std::string& client_str,
                                          sockaddr_storage* out_addr,
                                          socklen_t* out_addr_len) {
    if (out_addr == nullptr || out_addr_len == nullptr || client_str.empty()) {
        return false;
    }

    memset(out_addr, 0, sizeof(*out_addr));
    *out_addr_len = 0;

    if (client_str[0] == '[') {
        size_t closing = client_str.find(']');
        size_t colon = client_str.rfind(':');
        if (closing == std::string::npos || colon == std::string::npos || colon <= closing + 1) {
            return false;
        }

        const std::string host = client_str.substr(1, closing - 1);
        const std::string port_str = client_str.substr(colon + 1);
        const int port = atoi(port_str.c_str());
        if (port <= 0 || port > 65535) {
            return false;
        }

        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(out_addr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET6, host.c_str(), &addr6->sin6_addr) != 1) {
            return false;
        }
        *out_addr_len = sizeof(sockaddr_in6);
        return true;
    }

    const size_t colon = client_str.rfind(':');
    if (colon == std::string::npos) {
        return false;
    }

    const std::string host = client_str.substr(0, colon);
    const std::string port_str = client_str.substr(colon + 1);
    const int port = atoi(port_str.c_str());
    if (port <= 0 || port > 65535) {
        return false;
    }

    if (host.find(':') != std::string::npos) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(out_addr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET6, host.c_str(), &addr6->sin6_addr) == 1) {
            *out_addr_len = sizeof(sockaddr_in6);
            return true;
        }
    }

    sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(out_addr);
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr4->sin_addr) != 1) {
        return false;
    }
    *out_addr_len = sizeof(sockaddr_in);
    return true;
}

bool BuildPacketTunnelDirectCandidateFromSockaddr(const sockaddr_storage& addr,
                                                  uint16_t port_override,
                                                  TcpDirectCandidate* out_candidate) {
    if (out_candidate == nullptr || port_override == 0) {
        return false;
    }

    TcpDirectCandidate candidate;
    if (addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&addr);
        candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
        candidate.endpoint_port = port_override;
        memcpy(candidate.endpoint_addr, &addr4->sin_addr, 4);
    } else if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv6;
        candidate.endpoint_port = port_override;
        memcpy(candidate.endpoint_addr, &addr6->sin6_addr, 16);
    } else {
        return false;
    }

    *out_candidate = candidate;
    return true;
}

bool PacketTunnelDirectCandidateEquals(const TcpDirectCandidate& left,
                                      const TcpDirectCandidate& right) {
    if (left.endpoint_family != right.endpoint_family ||
        left.endpoint_port != right.endpoint_port) {
        return false;
    }

    const size_t addr_len =
        left.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16;
    return memcmp(left.endpoint_addr, right.endpoint_addr, addr_len) == 0;
}

void AppendUniquePacketTunnelDirectCandidate(std::vector<TcpDirectCandidate>* candidates,
                                             const TcpDirectCandidate& candidate) {
    if (candidates == nullptr || candidate.endpoint_port == 0) {
        return;
    }

    for (size_t i = 0; i < candidates->size(); ++i) {
        if (PacketTunnelDirectCandidateEquals((*candidates)[i], candidate)) {
            return;
        }
    }

    candidates->push_back(candidate);
}

std::string PacketTunnelDirectCandidateToString(const TcpDirectCandidate& candidate) {
    char buffer[INET6_ADDRSTRLEN] = {};
    if (candidate.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        if (inet_ntop(AF_INET, candidate.endpoint_addr, buffer, sizeof(buffer)) != nullptr) {
            return std::string(buffer) + ":" + std::to_string(candidate.endpoint_port);
        }
    } else if (candidate.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv6) {
        if (inet_ntop(AF_INET6, candidate.endpoint_addr, buffer, sizeof(buffer)) != nullptr) {
            return "[" + std::string(buffer) + "]:" + std::to_string(candidate.endpoint_port);
        }
    }

    return "unknown";
}

std::vector<TcpDirectCandidate> BuildTcpDirectCandidatesForOwner(
    const PacketTunnelCandidateOwnerView& owner) {
    std::vector<TcpDirectCandidate> candidates;
    if (owner.tcp_direct_listen_port == 0) {
        return candidates;
    }

    sockaddr_storage observed_addr = {};
    socklen_t observed_addr_len = 0;
    if (ParsePacketTunnelClientEndpointString(owner.client_endpoint,
                                              &observed_addr,
                                              &observed_addr_len)) {
        TcpDirectCandidate observed;
        if (BuildPacketTunnelDirectCandidateFromSockaddr(observed_addr,
                                                         owner.tcp_direct_listen_port,
                                                         &observed)) {
            AppendUniquePacketTunnelDirectCandidate(&candidates, observed);
        }
    }

    for (size_t i = 0; i < owner.tcp_direct_candidates.size(); ++i) {
        AppendUniquePacketTunnelDirectCandidate(&candidates, owner.tcp_direct_candidates[i]);
    }

    return candidates;
}

std::vector<TcpDirectCandidate> BuildUdpDirectCandidatesForOwner(
    const PacketTunnelCandidateOwnerView& owner) {
    std::vector<TcpDirectCandidate> candidates;
    if (!owner.use_udp) {
        return candidates;
    }

    const uint16_t observed_port =
        owner.udp_addr.ss_family == AF_INET
            ? ntohs(reinterpret_cast<const sockaddr_in*>(&owner.udp_addr)->sin_port)
            : (owner.udp_addr.ss_family == AF_INET6
                   ? ntohs(reinterpret_cast<const sockaddr_in6*>(&owner.udp_addr)->sin6_port)
                   : 0);

    TcpDirectCandidate observed;
    if (BuildPacketTunnelDirectCandidateFromSockaddr(owner.udp_addr,
                                                     observed_port,
                                                     &observed)) {
        AppendUniquePacketTunnelDirectCandidate(&candidates, observed);
    }

    for (size_t i = 0; i < owner.udp_direct_candidates.size(); ++i) {
        AppendUniquePacketTunnelDirectCandidate(&candidates, owner.udp_direct_candidates[i]);
    }

    return candidates;
}
