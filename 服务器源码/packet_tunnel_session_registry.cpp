#include "packet_tunnel_session_registry.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

namespace {

std::string packet_tunnel_registry_ipv4_be_to_string(uint32_t ip_be) {
    char buffer[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &ip_be, buffer, sizeof(buffer)) == nullptr) {
        return "0.0.0.0";
    }
    return buffer;
}

}  // namespace

PacketTunnelSession::PacketTunnelSession(int fd,
                                         const std::string& client,
                                         const std::string& session,
                                         const std::string& scoped_server_key,
                                         uint32_t virtual_ip,
                                         uint16_t session_mtu,
                                         uint64_t established_tick_ms)
    : client_fd(fd),
      client_str(client),
      session_uuid(session),
      server_key(scoped_server_key),
      virtual_ip_be(virtual_ip),
      mtu(session_mtu),
      use_udp(false),
      udp_addr_len(0),
      active(true),
      established_ms(established_tick_ms),
      last_peer_offer_announce_ms(0),
      last_activity_ms(established_tick_ms),
      handshake_flags(packet_tunnel::kHandshakeFlagNone),
      allow_peer_direct(true),
      is_remote_linux_node(false),
      tcp_direct_listen_port(0) {
    memset(&udp_addr, 0, sizeof(udp_addr));
}

PacketTunnelSessionRemoval::PacketTunnelSessionRemoval(
    const std::shared_ptr<PacketTunnelSession>& s,
    const std::string& why)
    : session(s),
      reason(why) {
}

PacketTunnelSessionRegistry::PacketTunnelSessionRegistry(SessionMap* udp_sessions,
                                                         SessionMap* tcp_sessions,
                                                         SessionMap* endpoint_sessions)
    : udp_sessions_(udp_sessions),
      tcp_sessions_(tcp_sessions),
      endpoint_sessions_(endpoint_sessions) {
}

std::string PacketTunnelSessionRegistry::BuildEndpointKey(const sockaddr_storage& addr,
                                                          socklen_t addr_len) {
    (void)addr_len;
    char client_ip[INET6_ADDRSTRLEN] = {};
    int client_port = 0;

    if (addr.ss_family == AF_INET) {
        const sockaddr_in* addr_in = reinterpret_cast<const sockaddr_in*>(&addr);
        inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(addr_in->sin_port);
        return std::string(client_ip) + ":" + std::to_string(client_port);
    }

    if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr_in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(addr_in6->sin6_port);
        return "[" + std::string(client_ip) + "]:" + std::to_string(client_port);
    }

    return "unknown";
}

std::string PacketTunnelSessionRegistry::BuildScopedVirtualIpKey(const std::string& server_key,
                                                                 const std::string& virtual_ip) {
    if (server_key.empty()) {
        return virtual_ip;
    }
    return server_key + "|" + virtual_ip;
}

std::string PacketTunnelSessionRegistry::BuildScopedVirtualIpKey(const std::string& server_key,
                                                                 uint32_t virtual_ip_be) {
    return BuildScopedVirtualIpKey(server_key, packet_tunnel_registry_ipv4_be_to_string(virtual_ip_be));
}

std::string PacketTunnelSessionRegistry::BuildScopedUdpPortKey(const std::string& server_key,
                                                               uint16_t port) {
    if (server_key.empty()) {
        return "udp|" + std::to_string(port);
    }
    return server_key + "|udp|" + std::to_string(port);
}

std::string PacketTunnelSessionRegistry::DescribeScopedVirtualIp(const std::string& server_key,
                                                                 uint32_t virtual_ip_be) {
    const std::string virtual_ip = packet_tunnel_registry_ipv4_be_to_string(virtual_ip_be);
    if (server_key.empty()) {
        return virtual_ip;
    }
    return server_key + "/" + virtual_ip;
}

std::string PacketTunnelSessionRegistry::DescribeScopedVirtualIp(const SessionPtr& session) {
    if (!session) {
        return "unknown";
    }
    return DescribeScopedVirtualIp(session->server_key, session->virtual_ip_be);
}

bool PacketTunnelSessionRegistry::PacketTunnelPayloadIsTcp(const uint8_t* payload,
                                                           size_t payload_len) {
    return payload != nullptr &&
           payload_len >= 20 &&
           (((payload[0] >> 4) & 0x0F) == 4) &&
           payload[9] == IPPROTO_TCP;
}

PacketTunnelSessionRegistry::SessionPtr PacketTunnelSessionRegistry::FindUdpLocked(
    const std::string& server_key,
    uint32_t virtual_ip_be) const {
    if (udp_sessions_ == nullptr) {
        return SessionPtr();
    }
    SessionMap::const_iterator it =
        udp_sessions_->find(BuildScopedVirtualIpKey(server_key, virtual_ip_be));
    if (it == udp_sessions_->end()) {
        return SessionPtr();
    }
    return it->second;
}

PacketTunnelSessionRegistry::SessionPtr PacketTunnelSessionRegistry::FindTcpLocked(
    const std::string& server_key,
    uint32_t virtual_ip_be) const {
    if (tcp_sessions_ == nullptr) {
        return SessionPtr();
    }
    SessionMap::const_iterator it =
        tcp_sessions_->find(BuildScopedVirtualIpKey(server_key, virtual_ip_be));
    if (it == tcp_sessions_->end()) {
        return SessionPtr();
    }
    return it->second;
}

PacketTunnelSessionRegistry::SessionPtr PacketTunnelSessionRegistry::FindByEndpointLocked(
    const std::string& endpoint_key) const {
    if (endpoint_sessions_ == nullptr) {
        return SessionPtr();
    }
    SessionMap::const_iterator it = endpoint_sessions_->find(endpoint_key);
    if (it == endpoint_sessions_->end()) {
        return SessionPtr();
    }
    return it->second;
}

PacketTunnelSessionRegistry::SessionPtr PacketTunnelSessionRegistry::FindUniqueByVirtualIpLocked(
    const SessionMap* sessions,
    uint32_t virtual_ip_be) const {
    if (sessions == nullptr) {
        return SessionPtr();
    }

    SessionPtr matched_session;
    for (SessionMap::const_iterator it = sessions->begin(); it != sessions->end(); ++it) {
        const SessionPtr& session = it->second;
        if (!session || !session->active || session->virtual_ip_be != virtual_ip_be) {
            continue;
        }
        if (matched_session && matched_session != session) {
            return SessionPtr();
        }
        matched_session = session;
    }

    return matched_session;
}

PacketTunnelSessionRegistry::SessionPtr PacketTunnelSessionRegistry::SelectDeliveryLocked(
    const std::string& server_key,
    uint32_t virtual_ip_be,
    const uint8_t* payload,
    size_t payload_len) const {
    if (PacketTunnelPayloadIsTcp(payload, payload_len)) {
        SessionPtr tcp_session = FindTcpLocked(server_key, virtual_ip_be);
        if (tcp_session && tcp_session->active) {
            return tcp_session;
        }
    }

    SessionPtr udp_session = FindUdpLocked(server_key, virtual_ip_be);
    if (udp_session && udp_session->active) {
        return udp_session;
    }

    if (PacketTunnelPayloadIsTcp(payload, payload_len)) {
        SessionPtr tcp_session = FindTcpLocked(server_key, virtual_ip_be);
        if (tcp_session && tcp_session->active) {
            return tcp_session;
        }
    }

    return SessionPtr();
}

PacketTunnelSessionRegistry::SessionPtr
PacketTunnelSessionRegistry::SelectDeliveryAcrossScopesLocked(uint32_t virtual_ip_be,
                                                              const uint8_t* payload,
                                                              size_t payload_len) const {
    if (PacketTunnelPayloadIsTcp(payload, payload_len)) {
        SessionPtr tcp_session = FindUniqueByVirtualIpLocked(tcp_sessions_, virtual_ip_be);
        if (tcp_session) {
            return tcp_session;
        }
    }

    SessionPtr udp_session = FindUniqueByVirtualIpLocked(udp_sessions_, virtual_ip_be);
    if (udp_session) {
        return udp_session;
    }

    return SessionPtr();
}

PacketTunnelSessionRegistry::SessionList PacketTunnelSessionRegistry::CollectUdpPeersLocked(
    const SessionPtr& session,
    const SessionPredicate& predicate) const {
    SessionList peers;
    if (udp_sessions_ == nullptr) {
        return peers;
    }

    for (SessionMap::const_iterator it = udp_sessions_->begin(); it != udp_sessions_->end(); ++it) {
        const SessionPtr& peer = it->second;
        if (!peer || peer == session) {
            continue;
        }
        if (predicate && !predicate(peer)) {
            continue;
        }
        peers.push_back(peer);
    }
    return peers;
}

PacketTunnelSessionRegistry::SessionList PacketTunnelSessionRegistry::CollectTcpPeersLocked(
    const SessionPtr& session,
    const SessionPredicate& predicate) const {
    SessionList peers;
    if (tcp_sessions_ == nullptr) {
        return peers;
    }

    for (SessionMap::const_iterator it = tcp_sessions_->begin(); it != tcp_sessions_->end(); ++it) {
        const SessionPtr& peer = it->second;
        if (!peer || peer == session) {
            continue;
        }
        if (predicate && !predicate(peer)) {
            continue;
        }
        peers.push_back(peer);
    }
    return peers;
}

void PacketTunnelSessionRegistry::UpsertUdpLocked(const SessionPtr& session,
                                                  SessionPtr* replaced_by_virtual,
                                                  SessionPtr* replaced_by_endpoint) {
    if (replaced_by_virtual != nullptr) {
        *replaced_by_virtual = SessionPtr();
    }
    if (replaced_by_endpoint != nullptr) {
        *replaced_by_endpoint = SessionPtr();
    }
    if (!session || udp_sessions_ == nullptr || endpoint_sessions_ == nullptr) {
        return;
    }

    SessionPtr current_by_virtual = FindUdpLocked(session->server_key, session->virtual_ip_be);
    SessionPtr current_by_endpoint = FindByEndpointLocked(session->udp_endpoint_key);
    if (replaced_by_virtual != nullptr) {
        *replaced_by_virtual = current_by_virtual;
    }
    if (replaced_by_endpoint != nullptr) {
        *replaced_by_endpoint = current_by_endpoint;
    }

    EraseUdpLocked(current_by_virtual);
    if (current_by_endpoint != current_by_virtual) {
        EraseUdpLocked(current_by_endpoint);
    }

    (*udp_sessions_)[BuildScopedVirtualIpKey(session->server_key, session->virtual_ip_be)] = session;
    if (!session->udp_endpoint_key.empty()) {
        (*endpoint_sessions_)[session->udp_endpoint_key] = session;
    }
}

void PacketTunnelSessionRegistry::UpsertTcpLocked(const SessionPtr& session,
                                                  SessionPtr* replaced) {
    if (replaced != nullptr) {
        *replaced = SessionPtr();
    }
    if (!session || tcp_sessions_ == nullptr) {
        return;
    }

    SessionPtr current = FindTcpLocked(session->server_key, session->virtual_ip_be);
    if (replaced != nullptr) {
        *replaced = current;
    }

    EraseTcpLocked(current);
    (*tcp_sessions_)[BuildScopedVirtualIpKey(session->server_key, session->virtual_ip_be)] = session;
}

void PacketTunnelSessionRegistry::EraseUdpLocked(const SessionPtr& session) {
    if (!session || udp_sessions_ == nullptr || endpoint_sessions_ == nullptr) {
        return;
    }

    session->active = false;

    SessionMap::iterator by_virtual_it =
        udp_sessions_->find(BuildScopedVirtualIpKey(session->server_key, session->virtual_ip_be));
    if (by_virtual_it != udp_sessions_->end() && by_virtual_it->second == session) {
        udp_sessions_->erase(by_virtual_it);
    }

    if (!session->udp_endpoint_key.empty()) {
        SessionMap::iterator by_endpoint_it = endpoint_sessions_->find(session->udp_endpoint_key);
        if (by_endpoint_it != endpoint_sessions_->end() && by_endpoint_it->second == session) {
            endpoint_sessions_->erase(by_endpoint_it);
        }
    }
}

void PacketTunnelSessionRegistry::EraseTcpLocked(const SessionPtr& session) {
    if (!session || tcp_sessions_ == nullptr) {
        return;
    }

    session->active = false;

    SessionMap::iterator by_virtual_it =
        tcp_sessions_->find(BuildScopedVirtualIpKey(session->server_key, session->virtual_ip_be));
    if (by_virtual_it != tcp_sessions_->end() && by_virtual_it->second == session) {
        tcp_sessions_->erase(by_virtual_it);
    }
}

void PacketTunnelSessionRegistry::ClearLocked() {
    if (udp_sessions_ != nullptr) {
        udp_sessions_->clear();
    }
    if (tcp_sessions_ != nullptr) {
        tcp_sessions_->clear();
    }
    if (endpoint_sessions_ != nullptr) {
        endpoint_sessions_->clear();
    }
}
