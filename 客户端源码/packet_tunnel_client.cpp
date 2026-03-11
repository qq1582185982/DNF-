#include "packet_tunnel_client.h"

#include "packet_tunnel_protocol.h"

#include <windows.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include <cstring>
#include <vector>
#include <sstream>

namespace {

std::wstring BuildSocketError(const wchar_t* prefix, int error_code) {
    std::wstringstream stream;
    stream << prefix << L" (WSA=" << error_code << L")";
    return stream.str();
}

}  // namespace

PacketTunnelClient::PacketTunnelClient(const std::string& tunnel_ip,
                                       uint16_t tunnel_port,
                                       const std::string& session_uuid,
                                       const std::string& virtual_ip,
                                       uint16_t mtu)
    : tunnel_server_ip_(tunnel_ip),
      tunnel_port_(tunnel_port),
      session_uuid_(session_uuid),
      virtual_ip_(virtual_ip),
      mtu_(mtu),
      sock_(INVALID_SOCKET),
      connected_(false) {}

PacketTunnelClient::~PacketTunnelClient() {
    Stop();
}

bool PacketTunnelClient::Start(std::wstring* error_msg) {
    Stop();

    if (!ConnectSocket(error_msg)) {
        return false;
    }
    if (!SendHandshake(error_msg)) {
        Stop();
        return false;
    }
    if (!ReceiveHandshakeAck(error_msg)) {
        Stop();
        return false;
    }

    connected_ = true;
    return true;
}

void PacketTunnelClient::Stop() {
    connected_ = false;
    if (sock_ != INVALID_SOCKET) {
        shutdown(sock_, SD_BOTH);
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
}

bool PacketTunnelClient::ConnectSocket(std::wstring* error_msg) {
    struct addrinfo hints = {};
    struct addrinfo* result = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(tunnel_port_);
    int ret = getaddrinfo(tunnel_server_ip_.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel DNS resolve failed: " + Utf8ToWide(tunnel_server_ip_);
        }
        return false;
    }

    bool connected = false;
    for (addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {
        SOCKET sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
        int keepalive = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepalive, sizeof(keepalive));

        tcp_keepalive ka_settings = {};
        ka_settings.onoff = 1;
        ka_settings.keepalivetime = 30000;
        ka_settings.keepaliveinterval = 5000;
        DWORD bytes_returned = 0;
        WSAIoctl(sock, SIO_KEEPALIVE_VALS, &ka_settings, sizeof(ka_settings),
                 NULL, 0, &bytes_returned, NULL, NULL);

        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        if (connect(sock, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR) {
            sock_ = sock;
            connected = true;
            break;
        }

        closesocket(sock);
    }

    freeaddrinfo(result);

    if (!connected) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel connect failed: " + Utf8ToWide(tunnel_server_ip_) +
                         L":" + Utf8ToWide(std::to_string(tunnel_port_));
        }
        return false;
    }
    return true;
}

bool PacketTunnelClient::SendHandshake(std::wstring* error_msg) {
    uint8_t session_uuid_len = static_cast<uint8_t>(session_uuid_.size());
    std::vector<uint8_t> handshake(7 + session_uuid_len + packet_tunnel::kHandshakeTailSize, 0);

    uint32_t conn_id_be = htonl(packet_tunnel::kHandshakeConnId);
    uint16_t port_be = htons(packet_tunnel::kHandshakePortMarker);
    memcpy(&handshake[0], &conn_id_be, sizeof(conn_id_be));
    memcpy(&handshake[4], &port_be, sizeof(port_be));
    handshake[6] = session_uuid_len;
    if (session_uuid_len > 0) {
        memcpy(&handshake[7], session_uuid_.data(), session_uuid_len);
    }

    uint32_t virtual_ip_be = ParseVirtualIp(error_msg);
    if (virtual_ip_be == 0) {
        return false;
    }

    size_t tail = 7 + session_uuid_len;
    handshake[tail + 0] = packet_tunnel::kProtocolVersion;
    handshake[tail + 1] = 0;
    uint16_t mtu_be = htons(mtu_);
    memcpy(&handshake[tail + 2], &mtu_be, sizeof(mtu_be));
    memcpy(&handshake[tail + 4], &virtual_ip_be, sizeof(virtual_ip_be));

    return SendAll(handshake.data(), handshake.size(), error_msg);
}

bool PacketTunnelClient::ReceiveHandshakeAck(std::wstring* error_msg) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    if (!RecvAll(ack, sizeof(ack), error_msg)) {
        return false;
    }

    if (ack[0] != packet_tunnel::kProtocolVersion) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel ack version mismatch";
        }
        return false;
    }

    if (ack[1] != packet_tunnel::kStatusOk) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel ack rejected, status=" + Utf8ToWide(std::to_string((int)ack[1]));
        }
        return false;
    }

    return true;
}

bool PacketTunnelClient::SendAll(const uint8_t* data, size_t length, std::wstring* error_msg) {
    size_t sent = 0;
    while (sent < length) {
        int n = send(sock_, reinterpret_cast<const char*>(data + sent), static_cast<int>(length - sent), 0);
        if (n <= 0) {
            if (error_msg != NULL) {
                *error_msg = BuildSocketError(L"IP Tunnel send failed", WSAGetLastError());
            }
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool PacketTunnelClient::RecvAll(uint8_t* data, size_t length, std::wstring* error_msg) {
    size_t received = 0;
    while (received < length) {
        int n = recv(sock_, reinterpret_cast<char*>(data + received), static_cast<int>(length - received), 0);
        if (n <= 0) {
            if (error_msg != NULL) {
                *error_msg = BuildSocketError(L"IP Tunnel recv failed", WSAGetLastError());
            }
            return false;
        }
        received += static_cast<size_t>(n);
    }
    return true;
}

uint32_t PacketTunnelClient::ParseVirtualIp(std::wstring* error_msg) const {
    IN_ADDR addr = {};
    if (InetPtonA(AF_INET, virtual_ip_.c_str(), &addr) != 1) {
        if (error_msg != NULL) {
            *error_msg = L"Invalid leased virtual IP: " + Utf8ToWide(virtual_ip_);
        }
        return 0;
    }
    return addr.S_un.S_addr;
}

std::wstring PacketTunnelClient::Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (required <= 1) {
        return std::wstring();
    }

    std::wstring wide(required - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &wide[0], required);
    return wide;
}
