#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <vector>
#include <cstdint>
#include <map>
#include <string>
#include <thread>

class PeerLinkManager;
class WintunManager;

class PacketTunnelClient {
public:
    PacketTunnelClient(const std::string& tunnel_ip,
                       uint16_t tunnel_port,
                       const std::string& session_uuid,
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

    bool ConnectSocket(std::wstring* error_msg);
    bool SendHandshake(std::wstring* error_msg);
    bool ReceiveHandshakeAck(std::wstring* error_msg);
    bool StartThreads(std::wstring* error_msg);
    void SocketReadLoop();
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
    bool TryBuildPeerEndpoint(const std::string& peer_virtual_ip,
                              UdpEndpoint* endpoint) const;
    bool TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                int source_addr_len,
                                std::string* peer_virtual_ip) const;
    bool IsServerEndpoint(const sockaddr_storage& source_addr,
                          int source_addr_len) const;
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
    bool SendFrame(uint8_t frame_type, const uint8_t* data, size_t length, std::wstring* error_msg);
    bool SendDatagram(const uint8_t* data, size_t length, std::wstring* error_msg);
    int RecvDatagram(uint8_t* data, size_t length, std::wstring* error_msg);
    uint32_t ParseVirtualIp(std::wstring* error_msg) const;
    static std::wstring Utf8ToWide(const std::string& value);
    void MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip,
                                     const std::string& reason);
    void MarkNetworkActivity();
    void RefreshPeerDirectPolicy();

    std::string tunnel_server_ip_;
    uint16_t tunnel_port_;
    std::string session_uuid_;
    std::string virtual_ip_;
    uint16_t mtu_;
    WintunManager* wintun_manager_;
    SOCKET sock_;
    int socket_family_;
    UdpEndpoint server_endpoint_;
    std::atomic<bool> connected_;
    std::atomic<bool> stop_requested_;
    std::atomic<unsigned long long> last_receive_tick_;
    std::atomic<unsigned long long> last_network_activity_tick_;
    std::thread socket_read_thread_;
    std::thread wintun_read_thread_;
    std::thread heartbeat_thread_;
    CRITICAL_SECTION send_lock_;
    PeerLinkManager* peer_link_manager_;
    std::atomic<uint32_t> peer_signal_nonce_;
    std::map<std::string, unsigned long long> peer_route_debug_log_tick_;
    bool p2p_disabled_;
    bool p2p_disable_logged_;
    std::string p2p_disable_reason_;
    std::vector<std::string> p2p_disable_adapters_;
};
