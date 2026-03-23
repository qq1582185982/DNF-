#pragma once

#include "linux_tun_manager.h"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

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
    bool ConnectSocket(std::string* error);
    bool SendHandshake(std::string* error);
    bool ReceiveHandshakeAck(std::string* error);
    bool StartThreads(std::string* error);
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
    std::atomic<bool> connected_;
    std::atomic<bool> stop_requested_;
    std::atomic<unsigned long long> last_receive_ms_;
    std::thread socket_thread_;
    std::thread tun_thread_;
    std::thread heartbeat_thread_;
    std::mutex send_mutex_;
};
