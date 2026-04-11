#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class PeerLinkManager;
class WintunManager;

class PacketTunnelClient {
public:
    PacketTunnelClient(const std::string& tunnel_ip,
                       uint16_t tunnel_port,
                       const std::string& session_uuid,
                       const std::string& client_id,
                       const std::string& server_virtual_ip,
                       const std::string& virtual_ip,
                       uint16_t mtu,
                       WintunManager* wintun_manager);
    ~PacketTunnelClient();

    bool Start(std::wstring* error_msg);
    void Stop();
    bool IsConnected() const { return connected_; }

private:
    struct UdpEndpoint {
        sockaddr_storage addr;
        int addr_len;
        bool valid;

        UdpEndpoint() : addr_len(0), valid(false) {
            ZeroMemory(&addr, sizeof(addr));
        }
    };

    struct PeerUdpPortOwner {
        std::string peer_virtual_ip;
        unsigned long long last_seen_ms;

        PeerUdpPortOwner() : last_seen_ms(0) {
        }
    };

    struct QueuedWintunPacket {
        std::vector<uint8_t> payload;
        bool from_known_peer;
        bool high_priority;
        bool business_priority;
        std::string inner_src_virtual_ip;
        std::string inner_dst_virtual_ip;
        uint16_t inner_src_port;
        uint16_t inner_dst_port;
        unsigned long long enqueue_tick_ms;

        QueuedWintunPacket()
            : from_known_peer(false),
              high_priority(false),
              business_priority(false),
              inner_src_port(0),
              inner_dst_port(0),
              enqueue_tick_ms(0) {
        }
    };

    struct WatchedTcpFlowTrace {
        std::string client_ip;
        std::string server_ip;
        uint16_t client_port;
        uint16_t server_port;
        unsigned long long created_ms;
        unsigned long long last_seen_ms;
        unsigned long long syn_ms;
        unsigned long long synack_ms;
        unsigned long long established_ms;
        unsigned long long first_client_payload_ms;
        unsigned long long first_server_payload_ms;
        unsigned long long last_client_payload_ms;
        unsigned long long last_server_payload_ms;
        unsigned long long last_client_ack_only_ms;
        unsigned long long pending_request_ms;
        unsigned long long pending_server_enqueue_ms;
        unsigned long long closed_ms;
        size_t client_payload_count;
        size_t server_payload_count;
        bool close_logged;

        WatchedTcpFlowTrace()
            : client_port(0),
              server_port(0),
              created_ms(0),
              last_seen_ms(0),
              syn_ms(0),
              synack_ms(0),
              established_ms(0),
              first_client_payload_ms(0),
              first_server_payload_ms(0),
              last_client_payload_ms(0),
              last_server_payload_ms(0),
              last_client_ack_only_ms(0),
              pending_request_ms(0),
              pending_server_enqueue_ms(0),
              closed_ms(0),
              client_payload_count(0),
              server_payload_count(0),
              close_logged(false) {
        }
    };

    struct TcpDirectCandidate {
        uint8_t endpoint_family;
        uint16_t endpoint_port;
        uint8_t endpoint_addr[16];
        uint32_t success_count;
        uint32_t failure_count;
        unsigned long long last_success_tick_ms;
        unsigned long long last_failure_tick_ms;
        unsigned long long last_connect_ms;

        TcpDirectCandidate()
            : endpoint_family(0),
              endpoint_port(0),
              success_count(0),
              failure_count(0),
              last_success_tick_ms(0),
              last_failure_tick_ms(0),
              last_connect_ms(0) {
            ZeroMemory(endpoint_addr, sizeof(endpoint_addr));
        }
    };

    struct TcpDirectOffer {
        uint64_t endpoint_version;
        uint8_t endpoint_family;
        uint16_t endpoint_port;
        uint8_t endpoint_addr[16];
        std::vector<TcpDirectCandidate> candidates;
        size_t next_candidate_index;
        unsigned long long last_offer_tick_ms;
        unsigned long long cooldown_until_tick_ms;
        bool connecting;

        TcpDirectOffer()
            : endpoint_version(0),
              endpoint_family(0),
              endpoint_port(0),
              next_candidate_index(0),
              last_offer_tick_ms(0),
              cooldown_until_tick_ms(0),
              connecting(false) {
            ZeroMemory(endpoint_addr, sizeof(endpoint_addr));
        }
    };

    struct TcpDirectConnection {
        SOCKET sock;
        std::string peer_virtual_ip;
        TcpDirectCandidate candidate;
        std::atomic<bool> active;
        std::atomic<unsigned long long> last_rx_tick_ms;
        std::atomic<unsigned long long> last_tx_tick_ms;
        CRITICAL_SECTION send_lock;
        std::thread read_thread;

        TcpDirectConnection()
            : sock(INVALID_SOCKET),
              active(false),
              last_rx_tick_ms(0),
              last_tx_tick_ms(0) {
            InitializeCriticalSection(&send_lock);
        }

        ~TcpDirectConnection() {
            DeleteCriticalSection(&send_lock);
        }
    };

    bool ConnectSocket(std::wstring* error_msg);
    bool ConnectTcpSocket(std::wstring* error_msg);
    bool StartTcpDirectListener(std::wstring* error_msg);
    bool BuildHandshakePayload(bool relay_only,
                               std::vector<uint8_t>* handshake,
                               std::wstring* error_msg) const;
    bool SendHandshake(std::wstring* error_msg);
    bool SendTcpHandshake(std::wstring* error_msg);
    bool SendUdpDirectCandidateAdvertises(std::wstring* error_msg);
    bool SendUdpDirectCandidateAdvertise(const TcpDirectCandidate& candidate,
                                         std::wstring* error_msg);
    bool SendTcpDirectAdvertise(std::wstring* error_msg);
    bool SendTcpDirectCandidateAdvertise(const TcpDirectCandidate& candidate,
                                         std::wstring* error_msg);
    bool ReceiveHandshakeAck(std::wstring* error_msg);
    bool ReceiveTcpHandshakeAck(std::wstring* error_msg);
    bool StartThreads(std::wstring* error_msg);
    void StopTcpDirectSockets();
    void SocketReadLoop();
    void TcpSocketReadLoop();
    void TcpDirectAcceptLoop();
    void TcpDirectReadLoop(const std::shared_ptr<TcpDirectConnection>& connection,
                           bool expect_open_frame);
    void WintunWriteLoop();
    void WintunReadLoop();
    void HeartbeatLoop();
    bool HandlePeerControlFrame(uint8_t frame_type, const uint8_t* payload, size_t length);
    bool SendPeerSignalFrame(uint8_t frame_type,
                             const std::string& target_peer_virtual_ip,
                             uint64_t endpoint_version,
                             uint32_t nonce);
    bool SendPeerDisableFrame(const std::string& target_peer_virtual_ip,
                              uint64_t endpoint_version,
                              uint8_t reason);
    bool TryBuildPeerEndpointFromCandidate(uint8_t endpoint_family,
                                           const uint8_t* endpoint_addr,
                                           uint16_t endpoint_port,
                                           UdpEndpoint* endpoint) const;
    bool SendImmediatePeerDirectProbe(const std::string& peer_virtual_ip,
                                      uint8_t endpoint_family,
                                      const uint8_t* endpoint_addr,
                                      uint16_t endpoint_port,
                                      const std::string& endpoint_text);
    bool TryBuildPeerEndpoint(const std::string& peer_virtual_ip,
                              UdpEndpoint* endpoint,
                              bool* direct_path_fresh = NULL,
                              bool* active_direct = NULL) const;
    bool TryResolveGatewayUdpPeerTarget(const std::string& dst_virtual_ip,
                                        uint16_t dst_port,
                                        std::string* peer_virtual_ip,
                                        std::string* resolution = NULL) const;
    bool TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                int source_addr_len,
                                std::string* peer_virtual_ip) const;
    bool IsServerEndpoint(const sockaddr_storage& source_addr,
                          int source_addr_len) const;
    bool IsServerVirtualPeer(const std::string& peer_virtual_ip) const;
    void LearnPeerUdpPortOwner(const std::string& peer_virtual_ip, uint16_t src_port);
    bool EnqueueWintunPacket(const uint8_t* payload,
                             size_t payload_len,
                             bool from_known_peer,
                             const std::string& inner_src_virtual_ip,
                             uint16_t inner_src_port,
                             const std::string& inner_dst_virtual_ip,
                             uint16_t inner_dst_port);
    bool SendFrameToEndpoint(const UdpEndpoint& endpoint,
                             uint8_t frame_type,
                             const uint8_t* data,
                             size_t length,
                             std::wstring* error_msg);
    bool SendDatagramToEndpoint(const UdpEndpoint& endpoint,
                                const uint8_t* data,
                                size_t length,
                                std::wstring* error_msg);
    int RecvDatagramFrom(uint8_t* data,
                         size_t length,
                         sockaddr_storage* source_addr,
                         int* source_addr_len,
                         std::wstring* error_msg);
    bool RecvTcpExact(uint8_t* data, size_t length, std::wstring* error_msg);
    bool RecvFrameFromSocket(SOCKET sock,
                             uint8_t* frame_type,
                             std::vector<uint8_t>* payload,
                             std::wstring* error_msg);
    bool SendFrame(uint8_t frame_type, const uint8_t* data, size_t length, std::wstring* error_msg);
    bool SendFrameOverTcp(uint8_t frame_type,
                          const uint8_t* data,
                          size_t length,
                          std::wstring* error_msg);
    bool SendFrameOverSocket(SOCKET sock,
                             CRITICAL_SECTION* send_lock,
                             uint8_t frame_type,
                             const uint8_t* data,
                             size_t length,
                             std::wstring* error_msg);
    bool TrySendTcpDirectPacket(const std::string& peer_virtual_ip,
                                const uint8_t* data,
                                size_t length);
    void MaybeStartTcpDirectConnect(const std::string& peer_virtual_ip);
    void TcpDirectConnectWorker(const std::string& peer_virtual_ip);
    void RegisterTcpDirectConnection(const std::string& peer_virtual_ip,
                                     const std::shared_ptr<TcpDirectConnection>& connection,
                                     bool incoming);
    void RemoveTcpDirectConnection(const std::string& peer_virtual_ip,
                                   SOCKET sock,
                                   bool enter_cooldown);
    void MaintainTcpDirectConnections(unsigned long long now_tick);
    void RecordTcpDirectCandidateResult(const std::string& peer_virtual_ip,
                                        const TcpDirectCandidate& candidate,
                                        bool success,
                                        unsigned long long connect_ms);
    std::vector<TcpDirectCandidate> BuildOrderedTcpDirectCandidates(
        const TcpDirectOffer& offer,
        unsigned long long now_tick) const;
    bool SendDatagram(const uint8_t* data, size_t length, std::wstring* error_msg);
    int RecvDatagram(uint8_t* data, size_t length, std::wstring* error_msg);
    uint32_t ParseVirtualIp(std::wstring* error_msg) const;
    static std::wstring Utf8ToWide(const std::string& value);
    void MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip,
                                     const std::string& reason);
    void MaybeLogWintunTargetIntent(const std::string& dst_virtual_ip,
                                    uint16_t dst_port,
                                    const std::string& route_desc);
    void MaybeLogIcmpPacket(const std::string& direction,
                            const uint8_t* packet,
                            size_t packet_len);
    void MaybeLogTcpPayloadIpHints(const std::string& direction,
                                   const uint8_t* packet,
                                   size_t packet_len);
    void MaybeLogUdpPayloadIpHints(const std::string& direction,
                                   const uint8_t* packet,
                                   size_t packet_len);
    void PruneWatchedTcpFlows(unsigned long long now_tick);
    void MarkWatchedTcpEnqueue(const uint8_t* packet,
                               size_t packet_len,
                               const char* origin);
    void TraceWatchedTcpPacket(const uint8_t* packet,
                               size_t packet_len,
                               const char* path);
    void MarkNetworkActivity();

    std::string tunnel_server_ip_;
    uint16_t tunnel_port_;
    std::string session_uuid_;
    std::string client_id_;
    std::string server_virtual_ip_;
    std::string virtual_ip_;
    uint16_t mtu_;
    WintunManager* wintun_manager_;
    SOCKET sock_;
    SOCKET tcp_sock_;
    SOCKET tcp_direct_listen_sock_;
    int socket_family_;
    uint16_t tcp_direct_listen_port_;
    UdpEndpoint server_endpoint_;
    std::atomic<bool> connected_;
    std::atomic<bool> stop_requested_;
    std::atomic<bool> tcp_connected_;
    std::atomic<unsigned long long> last_receive_tick_;
    std::atomic<unsigned long long> last_network_activity_tick_;
    std::thread socket_read_thread_;
    std::thread tcp_socket_read_thread_;
    std::thread tcp_direct_accept_thread_;
    std::thread wintun_write_thread_;
    std::thread wintun_read_thread_;
    std::thread heartbeat_thread_;
    CRITICAL_SECTION send_lock_;
    CRITICAL_SECTION tcp_send_lock_;
    std::mutex wintun_write_mutex_;
    std::condition_variable wintun_write_cv_;
    std::deque<QueuedWintunPacket> wintun_write_business_queue_;
    std::deque<QueuedWintunPacket> wintun_write_priority_queue_;
    std::deque<QueuedWintunPacket> wintun_write_queue_;
    std::mutex watched_tcp_mutex_;
    PeerLinkManager* peer_link_manager_;
    std::atomic<uint32_t> peer_signal_nonce_;
    std::map<std::string, unsigned long long> peer_route_debug_log_tick_;
    std::map<std::string, unsigned long long> wintun_target_debug_log_tick_;
    std::map<std::string, unsigned long long> icmp_debug_log_tick_;
    std::map<std::string, unsigned long long> payload_ip_debug_log_tick_;
    std::map<std::string, WatchedTcpFlowTrace> watched_tcp_flows_;
    std::map<std::string, unsigned long long> peer_probe_send_tick_;
    std::map<std::string, unsigned long long> mirrored_gateway_udp_signature_tick_;
    std::map<uint16_t, PeerUdpPortOwner> peer_udp_port_owners_;
    std::mutex tcp_direct_mutex_;
    std::map<std::string, TcpDirectOffer> tcp_direct_offers_;
    std::map<std::string, std::shared_ptr<TcpDirectConnection>> tcp_direct_connections_;
    std::vector<std::thread> tcp_direct_connect_threads_;
    bool peer_direct_allowed_;
};
