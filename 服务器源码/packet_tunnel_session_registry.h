#ifndef PACKET_TUNNEL_SESSION_REGISTRY_H_
#define PACKET_TUNNEL_SESSION_REGISTRY_H_

#include "packet_tunnel_direct_candidates.h"
#include "packet_tunnel_protocol.h"

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <stdint.h>
#include <sys/socket.h>

struct PacketTunnelSession {
    int client_fd;
    std::string client_str;
    std::string session_uuid;
    std::string server_key;
    uint32_t virtual_ip_be;
    uint16_t mtu;
    bool use_udp;
    sockaddr_storage udp_addr;
    socklen_t udp_addr_len;
    std::string udp_endpoint_key;
    std::atomic<bool> active;
    uint64_t established_ms;
    uint64_t last_peer_offer_announce_ms;
    std::atomic<uint64_t> last_activity_ms;
    uint8_t handshake_flags;
    bool allow_peer_direct;
    bool is_remote_linux_node;
    uint16_t tcp_direct_listen_port;
    std::vector<TcpDirectCandidate> udp_direct_candidates;
    std::vector<TcpDirectCandidate> tcp_direct_candidates;
    std::mutex send_mutex;

    PacketTunnelSession(int fd,
                        const std::string& client,
                        const std::string& session,
                        const std::string& scoped_server_key,
                        uint32_t virtual_ip,
                        uint16_t session_mtu,
                        uint64_t established_tick_ms);
};

struct PacketTunnelSessionRemoval {
    std::shared_ptr<PacketTunnelSession> session;
    std::string reason;

    PacketTunnelSessionRemoval(const std::shared_ptr<PacketTunnelSession>& s,
                               const std::string& why);
};

class PacketTunnelSessionRegistry {
public:
    typedef std::shared_ptr<PacketTunnelSession> SessionPtr;
    typedef std::map<std::string, SessionPtr> SessionMap;
    typedef std::vector<SessionPtr> SessionList;
    typedef std::function<bool(const SessionPtr&)> SessionPredicate;

    PacketTunnelSessionRegistry(SessionMap* udp_sessions,
                                SessionMap* tcp_sessions,
                                SessionMap* endpoint_sessions);

    static std::string BuildEndpointKey(const sockaddr_storage& addr, socklen_t addr_len);
    static std::string BuildScopedVirtualIpKey(const std::string& server_key,
                                               const std::string& virtual_ip);
    static std::string BuildScopedVirtualIpKey(const std::string& server_key,
                                               uint32_t virtual_ip_be);
    static std::string BuildScopedUdpPortKey(const std::string& server_key, uint16_t port);
    static std::string DescribeScopedVirtualIp(const std::string& server_key,
                                               uint32_t virtual_ip_be);
    static std::string DescribeScopedVirtualIp(const SessionPtr& session);
    static bool PacketTunnelPayloadIsTcp(const uint8_t* payload, size_t payload_len);

    SessionPtr FindUdpLocked(const std::string& server_key, uint32_t virtual_ip_be) const;
    SessionPtr FindTcpLocked(const std::string& server_key, uint32_t virtual_ip_be) const;
    SessionPtr FindByEndpointLocked(const std::string& endpoint_key) const;
    SessionPtr SelectDeliveryLocked(const std::string& server_key,
                                    uint32_t virtual_ip_be,
                                    const uint8_t* payload,
                                    size_t payload_len) const;
    SessionList CollectUdpPeersLocked(const SessionPtr& session,
                                      const SessionPredicate& predicate) const;
    SessionList CollectTcpPeersLocked(const SessionPtr& session,
                                      const SessionPredicate& predicate) const;
    void UpsertUdpLocked(const SessionPtr& session,
                         SessionPtr* replaced_by_virtual,
                         SessionPtr* replaced_by_endpoint);
    void UpsertTcpLocked(const SessionPtr& session, SessionPtr* replaced);
    void EraseUdpLocked(const SessionPtr& session);
    void EraseTcpLocked(const SessionPtr& session);
    void ClearLocked();

private:
    SessionMap* udp_sessions_;
    SessionMap* tcp_sessions_;
    SessionMap* endpoint_sessions_;
};

#endif
