#include "linux_packet_tunnel_client.h"

#include "linux_client_common.h"
#include "linux_peer_link_manager.h"
#include "packet_tunnel_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <vector>

namespace {

const int kHeartbeatIntervalMs = 3000;
const int kHeartbeatTimeoutMs = 12000;
const int kSocketReadTimeoutMs = 1000;
const int kTunReadWaitMs = 500;
const int kSocketBufferBytes = 256 * 1024;

unsigned long long now_ms() {
    return static_cast<unsigned long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct ParsedLinuxPeerOffer {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t endpoint_family;
    uint16_t endpoint_port;
    std::string endpoint;
};

struct ParsedLinuxPeerSignal {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint32_t nonce;
};

struct ParsedLinuxPeerDisable {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t reason;
};

std::string LinuxFrameName(uint8_t frame_type) {
    switch (frame_type) {
    case packet_tunnel::kFrameHeartbeat:
        return "heartbeat";
    case packet_tunnel::kFrameHeartbeatAck:
        return "heartbeat_ack";
    case packet_tunnel::kFrameIpv4Packet:
        return "ipv4_packet";
    case packet_tunnel::kFramePeerOffer:
        return "peer_offer";
    case packet_tunnel::kFramePeerHello:
        return "peer_hello";
    case packet_tunnel::kFramePeerAck:
        return "peer_ack";
    case packet_tunnel::kFramePeerKeepalive:
        return "peer_keepalive";
    case packet_tunnel::kFramePeerDisable:
        return "peer_disable";
    default:
        return "unknown";
    }
}

std::string LinuxIpv4ToString(const uint8_t* addr) {
    char buffer[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, addr, buffer, sizeof(buffer)) == NULL) {
        return "?";
    }
    return std::string(buffer);
}

bool ParseLinuxIpv4StringToBe(const std::string& value, uint32_t* out_ip_be) {
    if (out_ip_be == NULL || value.empty()) {
        return false;
    }

    in_addr addr = {};
    if (inet_pton(AF_INET, value.c_str(), &addr) != 1) {
        return false;
    }

    *out_ip_be = addr.s_addr;
    return true;
}

std::string LinuxPeerEndpointToString(uint8_t family, const uint8_t* addr, uint16_t port) {
    char buffer[INET6_ADDRSTRLEN] = {};
    if (family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        if (inet_ntop(AF_INET, addr, buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(port);
        }
    } else if (family == packet_tunnel::kPeerEndpointFamilyIpv6) {
        if (inet_ntop(AF_INET6, addr, buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(port);
        }
    }
    return "unknown";
}

bool ParseLinuxPeerOfferPayload(const uint8_t* payload, size_t length, ParsedLinuxPeerOffer* out_offer) {
    if (payload == NULL || out_offer == NULL || length != packet_tunnel::kPeerOfferPayloadSize) {
        return false;
    }

    out_offer->peer_virtual_ip = LinuxIpv4ToString(payload);
    out_offer->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_offer->endpoint_family = payload[12];
    out_offer->endpoint_port = packet_tunnel::read_u16_be(payload + 14);
    out_offer->endpoint = LinuxPeerEndpointToString(out_offer->endpoint_family, payload + 16, out_offer->endpoint_port);
    return true;
}

bool ParseLinuxPeerSignalPayload(const uint8_t* payload, size_t length, ParsedLinuxPeerSignal* out_signal) {
    if (payload == NULL || out_signal == NULL || length != packet_tunnel::kPeerSignalPayloadSize) {
        return false;
    }

    out_signal->peer_virtual_ip = LinuxIpv4ToString(payload);
    out_signal->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_signal->nonce = packet_tunnel::read_u32_be(payload + 12);
    return true;
}

bool ParseLinuxPeerDisablePayload(const uint8_t* payload, size_t length, ParsedLinuxPeerDisable* out_disable) {
    if (payload == NULL || out_disable == NULL || length != packet_tunnel::kPeerDisablePayloadSize) {
        return false;
    }

    out_disable->peer_virtual_ip = LinuxIpv4ToString(payload);
    out_disable->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_disable->reason = payload[12];
    return true;
}

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
      stop_requested_(false),
      last_receive_ms_(0),
      peer_link_manager_(new LinuxPeerLinkManager()),
      peer_signal_nonce_(1) {}

LinuxPacketTunnelClient::~LinuxPacketTunnelClient() {
    Stop();
    delete peer_link_manager_;
    peer_link_manager_ = NULL;
}

bool LinuxPacketTunnelClient::Start(std::string* error) {
    Stop();
    stop_requested_ = false;
    if (peer_link_manager_ != NULL) {
        peer_link_manager_->SetLocalVirtualIp(virtual_ip_);
    }

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
    if (peer_link_manager_ != NULL) {
        peer_link_manager_->ResetAll();
    }

    if (sock_ >= 0) {
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
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

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

        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));

        timeval send_timeout = {};
        send_timeout.tv_sec = 5;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));

        timeval recv_timeout = {};
        recv_timeout.tv_sec = kSocketReadTimeoutMs / 1000;
        recv_timeout.tv_usec = (kSocketReadTimeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));

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
    const uint8_t session_uuid_len = static_cast<uint8_t>(session_uuid_.size());
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

    return SendDatagram(handshake.data(), handshake.size(), error);
}

bool LinuxPacketTunnelClient::ReceiveHandshakeAck(std::string* error) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    int received = RecvDatagram(ack, sizeof(ack), error);
    if (received != static_cast<int>(sizeof(ack))) {
        if (received >= 0 && error != NULL) {
            *error = "packet tunnel ack size mismatch";
        }
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

    last_receive_ms_ = now_ms();
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
    std::vector<uint8_t> buffer(65535);
    while (!stop_requested_) {
        std::string error;
        int received = RecvDatagram(buffer.data(), buffer.size(), &error);
        if (received < 0) {
            break;
        }
        if (received == 0) {
            continue;
        }

        last_receive_ms_ = now_ms();

        if (received < static_cast<int>(packet_tunnel::kFrameHeaderSize)) {
            continue;
        }

        const uint8_t frame_type = buffer[0];
        const uint16_t payload_len = ntohs(*(uint16_t*)(&buffer[1]));
        if (received != static_cast<int>(packet_tunnel::kFrameHeaderSize + payload_len)) {
            continue;
        }

        if (frame_type == packet_tunnel::kFrameHeartbeatAck) {
            continue;
        }

        if (HandlePeerControlFrame(frame_type,
                                   buffer.data() + packet_tunnel::kFrameHeaderSize,
                                   payload_len)) {
            continue;
        }

        if (frame_type == packet_tunnel::kFrameIpv4Packet && tun_manager_ != NULL) {
            tun_manager_->WritePacket(buffer.data() + packet_tunnel::kFrameHeaderSize, payload_len, NULL);
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

bool LinuxPacketTunnelClient::HandlePeerControlFrame(uint8_t frame_type,
                                                     const uint8_t* payload,
                                                     size_t length) {
    if (frame_type == packet_tunnel::kFramePeerOffer) {
        ParsedLinuxPeerOffer offer = {};
        if (!ParseLinuxPeerOfferPayload(payload, length, &offer)) {
            LogWarn("ignore invalid peer_offer frame len=" + std::to_string(length));
            return true;
        }
        if (peer_link_manager_ != NULL) {
            peer_link_manager_->ObservePeerFrame(offer.peer_virtual_ip,
                                                 offer.endpoint_version,
                                                 LinuxPeerRouteState::OfferReceived);
        }
        LogInfo("peer control peer_offer: peer=" + offer.peer_virtual_ip +
                " version=" + std::to_string(offer.endpoint_version) +
                " endpoint=" + offer.endpoint);
        const uint32_t nonce = peer_signal_nonce_.fetch_add(1);
        if (SendPeerSignalFrame(packet_tunnel::kFramePeerHello,
                                offer.peer_virtual_ip,
                                offer.endpoint_version,
                                nonce)) {
            if (peer_link_manager_ != NULL) {
                peer_link_manager_->MarkPeerProbing(offer.peer_virtual_ip);
            }
            LogInfo("peer control send peer_hello: peer=" + offer.peer_virtual_ip +
                    " version=" + std::to_string(offer.endpoint_version) +
                    " nonce=" + std::to_string(nonce));
        } else {
            LogWarn("peer control send peer_hello failed: peer=" + offer.peer_virtual_ip +
                    " version=" + std::to_string(offer.endpoint_version) +
                    " nonce=" + std::to_string(nonce));
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerHello ||
        frame_type == packet_tunnel::kFramePeerAck ||
        frame_type == packet_tunnel::kFramePeerKeepalive) {
        ParsedLinuxPeerSignal signal = {};
        if (!ParseLinuxPeerSignalPayload(payload, length, &signal)) {
            LogWarn("ignore invalid " + LinuxFrameName(frame_type) +
                    " frame len=" + std::to_string(length));
            return true;
        }

        if (peer_link_manager_ != NULL) {
            LinuxPeerRouteState state = LinuxPeerRouteState::Probing;
            if (frame_type == packet_tunnel::kFramePeerAck ||
                frame_type == packet_tunnel::kFramePeerKeepalive) {
                state = LinuxPeerRouteState::DirectReady;
            }
            peer_link_manager_->ObservePeerFrame(signal.peer_virtual_ip,
                                                 signal.endpoint_version,
                                                 state);
        }

        LogInfo("peer control " + LinuxFrameName(frame_type) +
                ": peer=" + signal.peer_virtual_ip +
                " version=" + std::to_string(signal.endpoint_version) +
                " nonce=" + std::to_string(signal.nonce));
        if (frame_type == packet_tunnel::kFramePeerHello) {
            if (SendPeerSignalFrame(packet_tunnel::kFramePeerAck,
                                    signal.peer_virtual_ip,
                                    signal.endpoint_version,
                                    signal.nonce)) {
                LogInfo("peer control send peer_ack: peer=" + signal.peer_virtual_ip +
                        " version=" + std::to_string(signal.endpoint_version) +
                        " nonce=" + std::to_string(signal.nonce));
            } else {
                LogWarn("peer control send peer_ack failed: peer=" + signal.peer_virtual_ip +
                        " version=" + std::to_string(signal.endpoint_version) +
                        " nonce=" + std::to_string(signal.nonce));
            }
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerDisable) {
        ParsedLinuxPeerDisable disable = {};
        if (!ParseLinuxPeerDisablePayload(payload, length, &disable)) {
            LogWarn("ignore invalid peer_disable frame len=" + std::to_string(length));
            return true;
        }
        if (peer_link_manager_ != NULL) {
            peer_link_manager_->ObservePeerFrame(disable.peer_virtual_ip,
                                                 disable.endpoint_version,
                                                 LinuxPeerRouteState::Cooldown);
        }
        LogInfo("peer control peer_disable: peer=" + disable.peer_virtual_ip +
                " version=" + std::to_string(disable.endpoint_version) +
                " reason=" + std::to_string(disable.reason));
        return true;
    }

    return false;
}

bool LinuxPacketTunnelClient::SendPeerSignalFrame(uint8_t frame_type,
                                                  const std::string& target_peer_virtual_ip,
                                                  uint64_t endpoint_version,
                                                  uint32_t nonce) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseLinuxIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerSignalPayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    packet_tunnel::write_u32_be(payload.data() + 12, nonce);
    return SendFrame(frame_type, payload.data(), payload.size(), NULL);
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

        const unsigned long long last_ms = last_receive_ms_.load();
        const unsigned long long current_ms = now_ms();
        if (last_ms != 0 && current_ms > last_ms && (current_ms - last_ms) > kHeartbeatTimeoutMs) {
            break;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

bool LinuxPacketTunnelClient::SendFrame(uint8_t frame_type,
                                        const uint8_t* data,
                                        size_t length,
                                        std::string* error) {
    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons(static_cast<uint16_t>(length));
    if (length > 0 && data != NULL) {
        memcpy(&frame[packet_tunnel::kFrameHeaderSize], data, length);
    }

    std::lock_guard<std::mutex> lock(send_mutex_);
    return SendDatagram(frame.data(), frame.size(), error);
}

bool LinuxPacketTunnelClient::SendDatagram(const uint8_t* data, size_t length, std::string* error) {
    ssize_t n = send(sock_, data, length, 0);
    if (n != static_cast<ssize_t>(length)) {
        if (error != NULL) {
            *error = std::string("packet tunnel send failed: ") + strerror(errno);
        }
        return false;
    }
    return true;
}

int LinuxPacketTunnelClient::RecvDatagram(uint8_t* data, size_t length, std::string* error) {
    ssize_t n = recv(sock_, data, length, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (error != NULL) {
            *error = std::string("packet tunnel recv failed: ") + strerror(errno);
        }
        return -1;
    }
    if (n == 0) {
        if (error != NULL) {
            *error = "packet tunnel peer closed";
        }
        return -1;
    }
    return static_cast<int>(n);
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
