#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>

#include <string>

class PacketTunnelClient {
public:
    PacketTunnelClient(const std::string& tunnel_ip,
                       uint16_t tunnel_port,
                       const std::string& session_uuid,
                       const std::string& virtual_ip,
                       uint16_t mtu);
    ~PacketTunnelClient();

    bool Start(std::wstring* error_msg);
    void Stop();
    bool IsConnected() const { return connected_; }

private:
    bool ConnectSocket(std::wstring* error_msg);
    bool SendHandshake(std::wstring* error_msg);
    bool ReceiveHandshakeAck(std::wstring* error_msg);
    bool SendAll(const uint8_t* data, size_t length, std::wstring* error_msg);
    bool RecvAll(uint8_t* data, size_t length, std::wstring* error_msg);
    uint32_t ParseVirtualIp(std::wstring* error_msg) const;
    static std::wstring Utf8ToWide(const std::string& value);

    std::string tunnel_server_ip_;
    uint16_t tunnel_port_;
    std::string session_uuid_;
    std::string virtual_ip_;
    uint16_t mtu_;
    SOCKET sock_;
    bool connected_;
};
