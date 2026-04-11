#ifndef PACKET_TUNNEL_SERVICE_CONTEXT_H_
#define PACKET_TUNNEL_SERVICE_CONTEXT_H_

#include "packet_tunnel_session_registry.h"
#include "peer_coord.h"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct PacketTunnelServiceContext {
    typedef std::shared_ptr<PacketTunnelSession> SessionPtr;
    typedef std::vector<SessionPtr> SessionList;
    typedef std::map<std::string, SessionPtr> SessionMap;

    std::string server_name;
    std::mutex* session_mutex;
    SessionMap* udp_sessions;
    SessionMap* tcp_sessions;
    SessionMap* endpoint_sessions;
    PacketTunnelSessionRegistry* registry;
    PeerCoord* udp_peer_coord;
    PeerCoord* tcp_peer_coord;
    uint64_t peer_offer_timeout_ms;
    uint64_t peer_active_timeout_ms;
    uint64_t udp_idle_timeout_ms;

    std::function<std::string(const SessionPtr&)> describe_scoped_session;
    std::function<std::string(const std::string&, uint32_t)> describe_scoped_virtual_ip;
    std::function<std::string(const std::string&, uint32_t)> build_scoped_virtual_ip_key;
    std::function<bool(const SessionPtr&)> is_peer_direct_excluded_session;
    std::function<bool(const SessionPtr&)> session_allows_peer_direct;
    std::function<bool(const SessionPtr&, std::string*)> session_has_active_lease;
    std::function<bool(const SessionPtr&, uint8_t, const uint8_t*, size_t)> send_frame;
    std::function<void(const SessionPtr&,
                       const SessionPtr&,
                       uint32_t,
                       uint32_t,
                       uint16_t,
                       uint16_t,
                       size_t)> maybe_log_virtual_peer_udp_relay;
    std::function<std::vector<TcpDirectCandidate>(const SessionPtr&)> build_udp_direct_candidates;
    std::function<std::vector<TcpDirectCandidate>(const SessionPtr&)> build_tcp_direct_candidates;
    std::function<SessionList(const SessionPtr&)> collect_udp_offer_peers;
    std::function<SessionList(const SessionPtr&)> collect_tcp_offer_peers;

    PacketTunnelServiceContext()
        : session_mutex(NULL),
          udp_sessions(NULL),
          tcp_sessions(NULL),
          endpoint_sessions(NULL),
          registry(NULL),
          udp_peer_coord(NULL),
          tcp_peer_coord(NULL),
          peer_offer_timeout_ms(0),
          peer_active_timeout_ms(0),
          udp_idle_timeout_ms(0) {}
};

#endif
