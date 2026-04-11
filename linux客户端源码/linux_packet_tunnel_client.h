#pragma once

#include "linux_tun_manager.h"

#include <atomic>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <vector>

class LinuxPeerLinkManager;

class LinuxPacketTunnelClient {
public:
    LinuxPacketTunnelClient(const std::string& tunnel_host,
                            uint16_t tunnel_port,
                            const std::string& session_uuid,
                            const std::string& client_id,
                            const std::string& virtual_ip,
                            uint16_t mtu,
                            LinuxTunManager* tun_manager);
    ~LinuxPacketTunnelClient();

    bool Start(std::string* error);
    void Stop();
    bool IsConnected() const { return connected_; }

private:
    struct UdpEndpoint {
        sockaddr_storage addr;
        socklen_t addr_len;
        bool valid;

        UdpEndpoint() : addr_len(0), valid(false) {
            memset(&addr, 0, sizeof(addr));
        }
    };

    struct PeerUdpPortOwner {
        std::string peer_virtual_ip;
        unsigned long long last_seen_ms;

        PeerUdpPortOwner() : last_seen_ms(0) {
        }
    };

    struct WatchedTcpFlowTrace {
        std::string client_ip;
        uint16_t client_port;
        std::string server_ip;
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
        unsigned long long pending_server_tun_read_ms;
        unsigned int client_payload_count;
        unsigned int server_payload_count;
        bool close_logged;
        unsigned long long closed_ms;

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
              pending_server_tun_read_ms(0),
              client_payload_count(0),
              server_payload_count(0),
              close_logged(false),
              closed_ms(0) {}
    };

    struct TcpDirectCandidate {
        uint8_t endpoint_family;
        uint16_t endpoint_port;
        uint8_t endpoint_addr[16];
        uint32_t success_count;
        uint32_t failure_count;
        unsigned long long last_success_ms;
        unsigned long long last_failure_ms;
        unsigned long long last_connect_ms;

        TcpDirectCandidate()
            : endpoint_family(0),
              endpoint_port(0),
              success_count(0),
              failure_count(0),
              last_success_ms(0),
              last_failure_ms(0),
              last_connect_ms(0) {
            memset(endpoint_addr, 0, sizeof(endpoint_addr));
        }
    };

    struct TcpDirectOffer {
        uint64_t endpoint_version;
        uint8_t endpoint_family;
        uint16_t endpoint_port;
        uint8_t endpoint_addr[16];
        std::vector<TcpDirectCandidate> candidates;
        size_t next_candidate_index;
        unsigned long long last_offer_ms;
        unsigned long long cooldown_until_ms;
        bool connecting;

        TcpDirectOffer()
            : endpoint_version(0),
              endpoint_family(0),
              endpoint_port(0),
              next_candidate_index(0),
              last_offer_ms(0),
              cooldown_until_ms(0),
              connecting(false) {
            memset(endpoint_addr, 0, sizeof(endpoint_addr));
        }
    };

    struct TcpDirectConnection {
        int sock;
        std::string peer_virtual_ip;
        TcpDirectCandidate candidate;
        std::atomic<bool> active;
        std::atomic<unsigned long long> last_rx_ms;
        std::atomic<unsigned long long> last_tx_ms;
        std::mutex send_mutex;
        std::thread read_thread;

        TcpDirectConnection()
            : sock(-1),
              active(false),
              last_rx_ms(0),
              last_tx_ms(0) {}
    };

    bool ConnectSocket(std::string* error);
    bool ConnectTcpSocket(std::string* error);
    bool StartTcpDirectListener(std::string* error);
    bool BuildHandshakePayload(bool relay_only,
                               std::vector<uint8_t>* handshake,
                               std::string* error) const;
    bool SendHandshake(std::string* error);
    bool SendTcpHandshake(std::string* error);
    bool SendUdpDirectCandidateAdvertises(std::string* error);
    bool SendUdpDirectCandidateAdvertise(const TcpDirectCandidate& candidate,
                                         std::string* error);
    bool SendTcpDirectAdvertise(std::string* error);
    bool SendTcpDirectCandidateAdvertise(const TcpDirectCandidate& candidate,
                                         std::string* error);
    bool ReceiveHandshakeAck(std::string* error);
    bool ReceiveTcpHandshakeAck(std::string* error);
    bool StartThreads(std::string* error);
    void StopTcpDirectSockets();
    bool HandlePeerControlFrame(uint8_t frame_type, const uint8_t* payload, size_t length);
    bool SendPeerSignalFrame(uint8_t frame_type,
                             const std::string& target_peer_virtual_ip,
                             uint64_t endpoint_version,
                             uint32_t nonce);
    bool SendPeerDisableFrame(const std::string& target_peer_virtual_ip,
                              uint64_t endpoint_version,
                              uint8_t reason);
    bool TryBuildPeerEndpoint(const std::string& peer_virtual_ip,
                              UdpEndpoint* endpoint,
                              bool* direct_path_fresh = NULL,
                              bool* active_direct = NULL) const;
    bool TryResolvePeerByCandidateAddress(const std::string& dst_virtual_ip,
                                          std::string* peer_virtual_ip,
                                          std::string* resolution = NULL) const;
    bool TryResolveGatewayUdpPeerTarget(const std::string& dst_virtual_ip,
                                        uint16_t dst_port,
                                        std::string* peer_virtual_ip,
                                        std::string* resolution = NULL) const;
    bool TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                socklen_t source_addr_len,
                                std::string* peer_virtual_ip) const;
    bool IsServerEndpoint(const sockaddr_storage& source_addr,
                          socklen_t source_addr_len) const;
    void LearnPeerUdpPortOwner(const std::string& peer_virtual_ip, uint16_t src_port);
    bool SendFrameToEndpoint(const UdpEndpoint& endpoint,
                             uint8_t frame_type,
                             const uint8_t* data,
                             size_t length,
                             std::string* error);
    bool SendDatagramToEndpoint(const UdpEndpoint& endpoint,
                                const uint8_t* data,
                                size_t length,
                                std::string* error);
    int RecvDatagramFrom(uint8_t* data,
                         size_t length,
                         sockaddr_storage* source_addr,
                         socklen_t* source_addr_len,
                         std::string* error);
    bool RecvTcpExact(uint8_t* data, size_t length, std::string* error);
    bool RecvFrameFromSocket(int sock,
                             uint8_t* frame_type,
                             std::vector<uint8_t>* payload,
                             std::string* error);
    void SocketReadLoop();
    void TcpSocketReadLoop();
    void TcpDirectAcceptLoop();
    void TcpDirectReadLoop(const std::shared_ptr<TcpDirectConnection>& connection,
                           bool expect_open_frame);
    void TunReadLoop();
    void HeartbeatLoop();
    bool SendFrame(uint8_t frame_type, const uint8_t* data, size_t length, std::string* error);
    bool SendFrameOverTcp(uint8_t frame_type,
                          const uint8_t* data,
                          size_t length,
                          std::string* error);
    bool SendFrameOverSocket(int sock,
                             std::mutex* send_mutex,
                             uint8_t frame_type,
                             const uint8_t* data,
                             size_t length,
                             std::string* error);
    bool TrySendTcpDirectPacket(const std::string& peer_virtual_ip,
                                const uint8_t* data,
                                size_t length);
    void MaybeStartTcpDirectConnect(const std::string& peer_virtual_ip);
    void TcpDirectConnectWorker(const std::string& peer_virtual_ip);
    void RegisterTcpDirectConnection(const std::string& peer_virtual_ip,
                                     const std::shared_ptr<TcpDirectConnection>& connection,
                                     bool incoming);
    void RemoveTcpDirectConnection(const std::string& peer_virtual_ip,
                                   int sock,
                                   bool enter_cooldown);
    void MaintainTcpDirectConnections(unsigned long long tick);
    void RecordTcpDirectCandidateResult(const std::string& peer_virtual_ip,
                                        const TcpDirectCandidate& candidate,
                                        bool success,
                                        unsigned long long connect_ms);
    std::vector<TcpDirectCandidate> BuildOrderedTcpDirectCandidates(
        const TcpDirectOffer& offer,
        unsigned long long tick) const;
    bool SendDatagram(const uint8_t* data, size_t length, std::string* error);
    int RecvDatagram(uint8_t* data, size_t length, std::string* error);
    uint32_t ParseVirtualIp(std::string* error) const;
    void MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip, const std::string& reason);
    void MaybeLogIcmpPacket(const std::string& direction,
                            const uint8_t* packet,
                            size_t packet_len);
    void MarkNetworkActivity();
    void MarkWatchedTcpTunRead(const uint8_t* packet,
                               size_t packet_len,
                               unsigned long long read_wait_ms);
    void TraceWatchedTcpPacket(const uint8_t* packet, size_t packet_len, const char* path);
    void PruneWatchedTcpFlows(unsigned long long now_tick);

    std::string tunnel_host_;
    uint16_t tunnel_port_;
    std::string session_uuid_;
    std::string client_id_;
    std::string virtual_ip_;
    uint16_t mtu_;
    LinuxTunManager* tun_manager_;
    int sock_;
    int tcp_sock_;
    int tcp_direct_listen_sock_;
    int socket_family_;
    uint16_t tcp_direct_listen_port_;
    UdpEndpoint server_endpoint_;
    std::atomic<bool> connected_;
    std::atomic<bool> stop_requested_;
    std::atomic<bool> tcp_connected_;
    std::atomic<unsigned long long> last_receive_ms_;
    std::atomic<unsigned long long> last_network_activity_ms_;
    std::thread socket_thread_;
    std::thread tcp_thread_;
    std::thread tcp_direct_accept_thread_;
    std::thread tun_thread_;
    std::thread heartbeat_thread_;
    std::mutex send_mutex_;
    std::mutex tcp_send_mutex_;
    std::mutex watched_tcp_mutex_;
    std::mutex tcp_direct_mutex_;
    LinuxPeerLinkManager* peer_link_manager_;
    std::atomic<uint32_t> peer_signal_nonce_;
    std::map<std::string, unsigned long long> peer_route_debug_log_tick_;
    std::map<std::string, unsigned long long> icmp_debug_log_tick_;
    std::map<std::string, unsigned long long> peer_probe_send_tick_;
    std::map<uint16_t, PeerUdpPortOwner> peer_udp_port_owners_;
    std::map<std::string, WatchedTcpFlowTrace> watched_tcp_flows_;
    std::map<std::string, TcpDirectOffer> tcp_direct_offers_;
    std::map<std::string, std::shared_ptr<TcpDirectConnection>> tcp_direct_connections_;
    std::vector<std::thread> tcp_direct_connect_threads_;
};
