#pragma once

#include "linux_tun_manager.h"

#include <atomic>
#include <cstring>
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
                              UdpEndpoint* endpoint) const;
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

    std::string tunnel_host_;
    uint16_t tunnel_port_;
    std::string session_uuid_;
    std::string virtual_ip_;
    uint16_t mtu_;
    LinuxTunManager* tun_manager_;
    int sock_;
    int socket_family_;
    UdpEndpoint server_endpoint_;
    std::atomic<bool> connected_;
    std::atomic<bool> stop_requested_;
    std::atomic<unsigned long long> last_receive_ms_;
    std::thread socket_thread_;
    std::thread tun_thread_;
    std::thread heartbeat_thread_;
    std::mutex send_mutex_;
    LinuxPeerLinkManager* peer_link_manager_;
    std::atomic<uint32_t> peer_signal_nonce_;
};
