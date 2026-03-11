#include "linux_packet_tunnel_client.h"

#include "packet_tunnel_protocol.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

const int kHeartbeatIntervalMs = 15000;
const int kTunReadWaitMs = 500;
const int kSocketBufferBytes = 256 * 1024;

}  // namespace

LinuxPacketTunnelClient::LinuxPacketTunnelClient(const std::string& tunnel_host,
                                                 uint16_t tunnel_port,
                                                 const std::string& session_uuid,
                                                 const std::string& virtual_ip,
                                                 uint16_t mtu,
                                                 LinuxTunManager* tun_manager)
    : tunnel_host_(tunnel_host),
      tunnel_port_(tunnel_port),
      session_uuid_(session_uuid),
      virtual_ip_(virtual_ip),
      mtu_(mtu),
      tun_manager_(tun_manager),
      sock_(-1),
      connected_(false),
      stop_requested_(false) {}

LinuxPacketTunnelClient::~LinuxPacketTunnelClient() {
    Stop();
}

bool LinuxPacketTunnelClient::Start(std::string* error) {
    Stop();
    stop_requested_ = false;

    if (!ConnectSocket(error)) {
        return false;
    }
    if (!SendHandshake(error)) {
        Stop();
        return false;
    }
    if (!ReceiveHandshakeAck(error)) {
        Stop();
        return false;
    }
    if (!StartThreads(error)) {
        Stop();
        return false;
    }

    connected_ = true;
    return true;
}

void LinuxPacketTunnelClient::Stop() {
    stop_requested_ = true;
    connected_ = false;

    if (sock_ >= 0) {
        shutdown(sock_, SHUT_RDWR);
        close(sock_);
        sock_ = -1;
    }

    if (socket_thread_.joinable()) {
        socket_thread_.join();
    }
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
}

bool LinuxPacketTunnelClient::ConnectSocket(std::string* error) {
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = NULL;
    const std::string port_str = std::to_string(tunnel_port_);
    int ret = getaddrinfo(tunnel_host_.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        if (error != NULL) {
            *error = "packet tunnel DNS resolve failed: " + tunnel_host_;
        }
        return false;
    }

    bool connected = false;
    for (addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {
        int sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }

        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));
#ifdef TCP_KEEPIDLE
        int keepidle = 30;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
#endif
#ifdef TCP_KEEPINTVL
        int keepintvl = 5;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
#endif
#ifdef TCP_KEEPCNT
        int keepcnt = 3;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
#endif

        timeval send_timeout = {};
        send_timeout.tv_sec = 5;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            sock_ = sock;
            connected = true;
            break;
        }

        close(sock);
    }

    freeaddrinfo(result);

    if (!connected) {
        if (error != NULL) {
            *error = "packet tunnel connect failed: " + tunnel_host_ + ":" + port_str;
        }
        return false;
    }
    return true;
}

bool LinuxPacketTunnelClient::SendHandshake(std::string* error) {
    const uint8_t session_uuid_len = (uint8_t)session_uuid_.size();
    std::vector<uint8_t> handshake(7 + session_uuid_len + packet_tunnel::kHandshakeTailSize, 0);

    uint32_t conn_id_be = htonl(packet_tunnel::kHandshakeConnId);
    uint16_t port_be = htons(packet_tunnel::kHandshakePortMarker);
    memcpy(&handshake[0], &conn_id_be, sizeof(conn_id_be));
    memcpy(&handshake[4], &port_be, sizeof(port_be));
    handshake[6] = session_uuid_len;
    if (session_uuid_len > 0) {
        memcpy(&handshake[7], session_uuid_.data(), session_uuid_len);
    }

    uint32_t virtual_ip_be = ParseVirtualIp(error);
    if (virtual_ip_be == 0) {
        return false;
    }

    const size_t tail = 7 + session_uuid_len;
    handshake[tail + 0] = packet_tunnel::kProtocolVersion;
    handshake[tail + 1] = 0;
    uint16_t mtu_be = htons(mtu_);
    memcpy(&handshake[tail + 2], &mtu_be, sizeof(mtu_be));
    memcpy(&handshake[tail + 4], &virtual_ip_be, sizeof(virtual_ip_be));

    return SendAll(handshake.data(), handshake.size(), error);
}

bool LinuxPacketTunnelClient::ReceiveHandshakeAck(std::string* error) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    if (!RecvAll(ack, sizeof(ack), error)) {
        return false;
    }

    if (ack[0] != packet_tunnel::kProtocolVersion) {
        if (error != NULL) {
            *error = "packet tunnel ack version mismatch";
        }
        return false;
    }
    if (ack[1] != packet_tunnel::kStatusOk) {
        if (error != NULL) {
            *error = "packet tunnel ack rejected";
        }
        return false;
    }
    return true;
}

bool LinuxPacketTunnelClient::StartThreads(std::string* error) {
    if (tun_manager_ == NULL) {
        if (error != NULL) {
            *error = "tun manager is null";
        }
        return false;
    }

    socket_thread_ = std::thread(&LinuxPacketTunnelClient::SocketReadLoop, this);
    tun_thread_ = std::thread(&LinuxPacketTunnelClient::TunReadLoop, this);
    heartbeat_thread_ = std::thread(&LinuxPacketTunnelClient::HeartbeatLoop, this);
    return true;
}

void LinuxPacketTunnelClient::SocketReadLoop() {
    while (!stop_requested_) {
        uint8_t header[packet_tunnel::kFrameHeaderSize] = {};
        std::string error;
        if (!RecvAll(header, sizeof(header), &error)) {
            break;
        }

        const uint8_t frame_type = header[0];
        const uint16_t payload_len = ntohs(*(uint16_t*)(&header[1]));
        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0 && !RecvAll(payload.data(), payload.size(), &error)) {
            break;
        }

        if (frame_type == packet_tunnel::kFrameHeartbeatAck) {
            continue;
        }

        if (frame_type == packet_tunnel::kFrameIpv4Packet && tun_manager_ != NULL) {
            tun_manager_->WritePacket(payload.data(), payload.size(), NULL);
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void LinuxPacketTunnelClient::TunReadLoop() {
    while (!stop_requested_) {
        std::vector<uint8_t> packet;
        std::string error;
        if (!tun_manager_ || !tun_manager_->ReadPacket(&packet, kTunReadWaitMs, &error)) {
            continue;
        }
        if (packet.empty()) {
            continue;
        }

        const uint8_t version = (packet[0] >> 4) & 0x0F;
        if (version != 4) {
            continue;
        }

        if (packet.size() >= 20) {
            const uint8_t dst_octet0 = packet[16];
            if ((dst_octet0 >= 224 && dst_octet0 <= 239) ||
                (packet[16] == 255 && packet[17] == 255 && packet[18] == 255 && packet[19] == 255)) {
                continue;
            }
        }

        if (!SendFrame(packet_tunnel::kFrameIpv4Packet, packet.data(), packet.size(), NULL)) {
            break;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void LinuxPacketTunnelClient::HeartbeatLoop() {
    while (!stop_requested_) {
        for (int waited = 0; waited < kHeartbeatIntervalMs && !stop_requested_; waited += 200) {
            usleep(200 * 1000);
        }
        if (stop_requested_) {
            break;
        }

        if (!SendFrame(packet_tunnel::kFrameHeartbeat, NULL, 0, NULL)) {
            break;
        }
    }
}

bool LinuxPacketTunnelClient::SendFrame(uint8_t frame_type,
                                        const uint8_t* data,
                                        size_t length,
                                        std::string* error) {
    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons((uint16_t)length);
    if (length > 0 && data != NULL) {
        memcpy(&frame[packet_tunnel::kFrameHeaderSize], data, length);
    }

    std::lock_guard<std::mutex> lock(send_mutex_);
    return SendAll(frame.data(), frame.size(), error);
}

bool LinuxPacketTunnelClient::SendAll(const uint8_t* data, size_t length, std::string* error) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(sock_, data + sent, length - sent, 0);
        if (n <= 0) {
            if (error != NULL) {
                *error = std::string("packet tunnel send failed: ") + strerror(errno);
            }
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

bool LinuxPacketTunnelClient::RecvAll(uint8_t* data, size_t length, std::string* error) {
    size_t received = 0;
    while (received < length) {
        ssize_t n = recv(sock_, data + received, length - received, 0);
        if (n <= 0) {
            if (error != NULL) {
                *error = std::string("packet tunnel recv failed: ") + strerror(errno);
            }
            return false;
        }
        received += (size_t)n;
    }
    return true;
}

uint32_t LinuxPacketTunnelClient::ParseVirtualIp(std::string* error) const {
    in_addr addr = {};
    if (inet_pton(AF_INET, virtual_ip_.c_str(), &addr) != 1) {
        if (error != NULL) {
            *error = "invalid virtual ip: " + virtual_ip_;
        }
        return 0;
    }
    return addr.s_addr;
}