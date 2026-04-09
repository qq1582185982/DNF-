#pragma once

#include "linux_tun_manager.h"

#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <thread>

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

    bool ConnectSocket(std::string* error);
    bool SendHandshake(std::string* error);
    bool ReceiveHandshakeAck(std::string* error);
    bool StartThreads(std::string* error);
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
    bool TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                socklen_t source_addr_len,
                                std::string* peer_virtual_ip) const;
    bool IsServerEndpoint(const sockaddr_storage& source_addr,
                          socklen_t source_addr_len) const;
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
    void SocketReadLoop();
    void TunReadLoop();
    void HeartbeatLoop();
    bool SendFrame(uint8_t frame_type, const uint8_t* data, size_t length, std::string* error);
    bool SendDatagram(const uint8_t* data, size_t length, std::string* error);
    int RecvDatagram(uint8_t* data, size_t length, std::string* error);
    uint32_t ParseVirtualIp(std::string* error) const;
    void MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip, const std::string& reason);
    void MarkNetworkActivity();
    void MarkWatchedTcpTunRead(const uint8_t* packet, size_t packet_len);
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
    int socket_family_;
    UdpEndpoint server_endpoint_;
    std::atomic<bool> connected_;
    std::atomic<bool> stop_requested_;
    std::atomic<unsigned long long> last_receive_ms_;
    std::atomic<unsigned long long> last_network_activity_ms_;
    std::thread socket_thread_;
    std::thread tun_thread_;
    std::thread heartbeat_thread_;
    std::mutex send_mutex_;
    std::mutex watched_tcp_mutex_;
    LinuxPeerLinkManager* peer_link_manager_;
    std::atomic<uint32_t> peer_signal_nonce_;
    std::map<std::string, unsigned long long> peer_route_debug_log_tick_;
    std::map<std::string, unsigned long long> peer_probe_send_tick_;
    std::map<std::string, WatchedTcpFlowTrace> watched_tcp_flows_;
};
