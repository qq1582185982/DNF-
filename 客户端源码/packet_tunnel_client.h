#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include <atomic>
#include <cstdint>
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
    bool ConnectSocket(std::wstring* error_msg);
    bool SendHandshake(std::wstring* error_msg);
    bool ReceiveHandshakeAck(std::wstring* error_msg);
    bool StartThreads(std::wstring* error_msg);
    void SocketReadLoop();
    void WintunReadLoop();
    void HeartbeatLoop();
    bool SendFrame(uint8_t frame_type, const uint8_t* data, size_t length, std::wstring* error_msg);
    bool SendDatagram(const uint8_t* data, size_t length, std::wstring* error_msg);
    int RecvDatagram(uint8_t* data, size_t length, std::wstring* error_msg);
    uint32_t ParseVirtualIp(std::wstring* error_msg) const;
    static std::wstring Utf8ToWide(const std::string& value);

    std::string tunnel_server_ip_;
    uint16_t tunnel_port_;
    std::string session_uuid_;
    std::string virtual_ip_;
    uint16_t mtu_;
    WintunManager* wintun_manager_;
    SOCKET sock_;
    std::atomic<bool> connected_;
    std::atomic<bool> stop_requested_;
    std::atomic<unsigned long long> last_receive_tick_;
    std::thread socket_read_thread_;
    std::thread wintun_read_thread_;
    std::thread heartbeat_thread_;
    CRITICAL_SECTION send_lock_;
    PeerLinkManager* peer_link_manager_;
};
