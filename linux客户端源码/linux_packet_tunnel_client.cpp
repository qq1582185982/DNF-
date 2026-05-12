#include "linux_packet_tunnel_client.h"

#include "linux_client_common.h"
#include "linux_peer_link_manager.h"
#include "packet_flow_router.h"
#include "packet_tunnel_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <deque>
#include <sstream>
#include <vector>

namespace {

const int kHeartbeatIntervalMs = 3000;
const int kHeartbeatTimeoutMs = 12000;
const int kPeerOfferTimeoutMs = 9000;
const int kPeerDirectReadyTimeoutMs = 15000;
const int kPeerCooldownTimeoutMs = 30000;
const int kPeerDirectProbeGraceMs = 3000;
const int kPeerDirectDataTimeoutMs = 5000;
const int kPeerDirectWarmupDurationMs = 15000;
const int kPeerBusinessHotWindowMs = 15000;
const int kPeerQuietKeepaliveIntervalMs = 15000;
const int kPeerSnapshotLogIntervalMs = 15000;
const int kPeerRouteDebugLogIntervalMs = 2000;
const int kPeerDirectProbeIntervalMs = 500;
const int kSocketReadTimeoutMs = 1000;
const int kSocketSendTimeoutMs = 50;
const int kSocketSendRetryCount = 2;
const int kSocketSendRetryDelayMs = 5;
const int kTcpDirectConnectTimeoutMs = 1200;
const int kTcpDirectRetryCooldownMs = 5000;
const int kTcpDirectAutoWarmRetryMs = 12000;
const int kTcpDirectHeartbeatIntervalMs = 3000;
const int kTcpDirectQuietHeartbeatIntervalMs = 12000;
const int kTcpDirectIdleTimeoutMs = 15000;
const int kTcpDirectListenBacklog = 32;
const int kTunReadWaitMs = 500;
const int kSocketBufferBytes = 4 * 1024 * 1024;
const unsigned long long kWatchedTcpFlowIdleCleanupMs = 180000;
const unsigned long long kWatchedTcpClosedRetentionMs = 10000;
const unsigned long long kWatchedTcpServerWaitLogMs = 200;
const size_t kPacketTunnelBatchMaxDatagramBytes = 1200;
const size_t kPacketTunnelBatchMaxFrames = 8;
const size_t kPacketTunnelBatchMaxTcpPayloadBytes = 320;
const bool kPacketTunnelEnableLinuxRelayTcpMicroBatch = false;
const uint16_t kPeerDirectProbeSrcPort = 65401;
const uint16_t kPeerDirectProbeDstPort = 65402;
const uint8_t kPeerDirectProbeMagic[4] = {'P', 'T', 'D', 'P'};
const uint8_t kPeerDirectProbeVersion = 1;
const uint8_t kPeerDirectProbeRequest = 1;
const uint8_t kPeerDirectProbeResponse = 2;
const bool kEnableLinuxGatewayUdpPeerHeuristics = true;
const unsigned long long kLinuxGatewayUdpPortOwnerTtlMs = 60000;

uint16_t ComputeLinuxIpv4HeaderChecksum(const uint8_t* header, size_t header_len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < header_len; i += 2) {
        sum += static_cast<uint16_t>((header[i] << 8) | header[i + 1]);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

uint16_t ComputeLinuxIpv4TransportChecksum(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
        return 0;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len) {
        return 0;
    }

    const size_t transport_len = packet_len - ip_header_len;
    uint32_t sum = 0;
    for (size_t i = 12; i < 20; i += 2) {
        sum += static_cast<uint16_t>((packet[i] << 8) | packet[i + 1]);
    }
    sum += static_cast<uint16_t>(packet[9]);
    sum += static_cast<uint16_t>(transport_len);

    const uint8_t* transport = packet + ip_header_len;
    size_t remaining = transport_len;
    while (remaining >= 2) {
        sum += static_cast<uint16_t>((transport[0] << 8) | transport[1]);
        transport += 2;
        remaining -= 2;
    }
    if (remaining == 1) {
        sum += static_cast<uint32_t>(transport[0]) << 8;
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    uint16_t checksum = static_cast<uint16_t>(~sum & 0xFFFFu);
    if (checksum == 0) {
        checksum = 0xFFFFu;
    }
    return checksum;
}

bool RewriteLinuxIpv4UdpDestinationIp(std::vector<uint8_t>* packet,
                                      uint32_t from_ip_be,
                                      uint32_t to_ip_be) {
    if (packet == NULL || packet->size() < 20) {
        return false;
    }

    std::vector<uint8_t>& bytes = *packet;
    if (((bytes[0] >> 4) & 0x0F) != 4) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(bytes[0] & 0x0F) * 4;
    if (ip_header_len < 20 || bytes.size() < ip_header_len + 8 || bytes[9] != IPPROTO_UDP) {
        return false;
    }

    uint32_t current_ip_be = 0;
    memcpy(&current_ip_be, &bytes[16], sizeof(current_ip_be));
    if (current_ip_be != from_ip_be || current_ip_be == to_ip_be) {
        return false;
    }

    memcpy(&bytes[16], &to_ip_be, sizeof(to_ip_be));
    bytes[10] = 0;
    bytes[11] = 0;
    packet_tunnel::write_u16_be(bytes.data() + 10,
                                ComputeLinuxIpv4HeaderChecksum(bytes.data(), ip_header_len));

    bytes[ip_header_len + 6] = 0;
    bytes[ip_header_len + 7] = 0;
    packet_tunnel::write_u16_be(bytes.data() + ip_header_len + 6,
                                ComputeLinuxIpv4TransportChecksum(bytes.data(), bytes.size()));
    return true;
}

bool BuildLinuxPeerDirectProbePacket(uint32_t src_ip_be,
                                     uint32_t dst_ip_be,
                                     uint8_t probe_type,
                                     std::vector<uint8_t>* out_packet) {
    if (out_packet == NULL ||
        (probe_type != kPeerDirectProbeRequest &&
         probe_type != kPeerDirectProbeResponse)) {
        return false;
    }

    const size_t packet_len = 20 + 8 + 8;
    out_packet->assign(packet_len, 0);
    uint8_t* packet = out_packet->data();
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = IPPROTO_UDP;
    packet_tunnel::write_u16_be(packet + 2, static_cast<uint16_t>(packet_len));
    memcpy(packet + 12, &src_ip_be, sizeof(src_ip_be));
    memcpy(packet + 16, &dst_ip_be, sizeof(dst_ip_be));

    const size_t udp_offset = 20;
    packet_tunnel::write_u16_be(packet + udp_offset,
                                probe_type == kPeerDirectProbeRequest
                                    ? kPeerDirectProbeSrcPort
                                    : kPeerDirectProbeDstPort);
    packet_tunnel::write_u16_be(packet + udp_offset + 2,
                                probe_type == kPeerDirectProbeRequest
                                    ? kPeerDirectProbeDstPort
                                    : kPeerDirectProbeSrcPort);
    packet_tunnel::write_u16_be(packet + udp_offset + 4, 16);

    uint8_t* payload = packet + udp_offset + 8;
    memcpy(payload, kPeerDirectProbeMagic, sizeof(kPeerDirectProbeMagic));
    payload[4] = kPeerDirectProbeVersion;
    payload[5] = probe_type;

    packet_tunnel::write_u16_be(packet + 10, ComputeLinuxIpv4HeaderChecksum(packet, 20));
    return true;
}

bool ParseLinuxPeerDirectProbePacket(const uint8_t* packet,
                                     size_t packet_len,
                                     uint8_t* out_probe_type) {
    if (packet == NULL || packet_len < 36 || ((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len != 20 || packet_len < ip_header_len + 16) {
        return false;
    }

    const uint16_t udp_len = ntohs(*(const uint16_t*)(packet + ip_header_len + 4));
    if (udp_len < 16 || packet_len < ip_header_len + udp_len) {
        return false;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    const uint8_t* payload = packet + ip_header_len + 8;
    if (!((src_port == kPeerDirectProbeSrcPort && dst_port == kPeerDirectProbeDstPort) ||
          (src_port == kPeerDirectProbeDstPort && dst_port == kPeerDirectProbeSrcPort))) {
        return false;
    }
    if (memcmp(payload, kPeerDirectProbeMagic, sizeof(kPeerDirectProbeMagic)) != 0 ||
        payload[4] != kPeerDirectProbeVersion) {
        return false;
    }
    if (payload[5] != kPeerDirectProbeRequest && payload[5] != kPeerDirectProbeResponse) {
        return false;
    }
    if (out_probe_type != NULL) {
        *out_probe_type = payload[5];
    }
    return true;
}

void AppendPacketTunnelFrame(std::vector<uint8_t>* datagram,
                             uint8_t frame_type,
                             const uint8_t* payload,
                             size_t payload_len) {
    if (datagram == NULL) {
        return;
    }

    const size_t frame_offset = datagram->size();
    datagram->resize(frame_offset + packet_tunnel::kFrameHeaderSize + payload_len, 0);
    (*datagram)[frame_offset] = frame_type;
    *(uint16_t*)(&(*datagram)[frame_offset + 1]) = htons(static_cast<uint16_t>(payload_len));
    if (payload_len > 0 && payload != NULL) {
        memcpy(datagram->data() + frame_offset + packet_tunnel::kFrameHeaderSize,
               payload,
               payload_len);
    }
}

bool TryConsumePacketTunnelFrame(const uint8_t* datagram,
                                 size_t datagram_len,
                                 size_t* offset,
                                 uint8_t* frame_type,
                                 const uint8_t** payload,
                                 uint16_t* payload_len) {
    if (datagram == NULL || offset == NULL || frame_type == NULL ||
        payload == NULL || payload_len == NULL) {
        return false;
    }
    if (*offset >= datagram_len ||
        datagram_len - *offset < packet_tunnel::kFrameHeaderSize) {
        return false;
    }

    const size_t frame_offset = *offset;
    const uint16_t next_payload_len = ntohs(*(const uint16_t*)(datagram + frame_offset + 1));
    const size_t frame_size = packet_tunnel::kFrameHeaderSize + next_payload_len;
    if (datagram_len - frame_offset < frame_size) {
        return false;
    }

    *frame_type = datagram[frame_offset];
    *payload_len = next_payload_len;
    *payload = datagram + frame_offset + packet_tunnel::kFrameHeaderSize;
    *offset = frame_offset + frame_size;
    return true;
}

bool IsPacketTunnelMicroBatchEligibleTcpPacket(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len || packet[9] != IPPROTO_TCP) {
        return false;
    }

    const uint16_t total_len = ntohs(*(const uint16_t*)(packet + 2));
    if (total_len < ip_header_len || packet_len < total_len || total_len > kPacketTunnelBatchMaxTcpPayloadBytes) {
        return false;
    }

    const size_t tcp_header_offset = ip_header_len;
    if (total_len < tcp_header_offset + 20) {
        return false;
    }

    const size_t tcp_header_len = static_cast<size_t>((packet[tcp_header_offset + 12] >> 4) & 0x0F) * 4;
    return tcp_header_len >= 20 && total_len >= tcp_header_offset + tcp_header_len;
}

bool TryParseLinuxTcpPorts(const uint8_t* packet,
                           size_t packet_len,
                           uint16_t* src_port,
                           uint16_t* dst_port) {
    if (src_port != NULL) {
        *src_port = 0;
    }
    if (dst_port != NULL) {
        *dst_port = 0;
    }
    if (packet == NULL || packet_len < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
        return false;
    }
    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 ||
        packet_len < ip_header_len + 20 ||
        packet[9] != IPPROTO_TCP) {
        return false;
    }
    const size_t tcp_header_len =
        static_cast<size_t>((packet[ip_header_len + 12] >> 4) & 0x0F) * 4;
    if (tcp_header_len < 20 || packet_len < ip_header_len + tcp_header_len) {
        return false;
    }
    if (src_port != NULL) {
        *src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    }
    if (dst_port != NULL) {
        *dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    }
    return true;
}

bool IsPacketTunnelRelayBatchEligibleTunPacket(const std::vector<uint8_t>& packet,
                                               const std::string& virtual_ip) {
    (void)virtual_ip;
    if (packet.size() < 20) {
        return false;
    }
    if (((packet[0] >> 4) & 0x0F) != 4) {
        return false;
    }

    const uint8_t dst_octet0 = packet[16];
    if ((dst_octet0 >= 224 && dst_octet0 <= 239) ||
        (packet[16] == 255 && packet[17] == 255 && packet[18] == 255 && packet[19] == 255)) {
        return false;
    }

    return IsPacketTunnelMicroBatchEligibleTcpPacket(packet.data(), packet.size());
}

bool IsLinuxTransientSendError(int error_code) {
    return error_code == EAGAIN ||
           error_code == EWOULDBLOCK ||
           error_code == ENOBUFS ||
           error_code == ETIMEDOUT ||
           error_code == EINTR;
}

bool IsDirectPathFresh(const LinuxPeerRouteStatus& route, unsigned long long now_tick) {
    if (!route.active_direct) {
        return false;
    }

    return
        route.last_direct_data_ms != 0 &&
        now_tick >= route.last_direct_data_ms &&
        (now_tick - route.last_direct_data_ms) <= kPeerDirectDataTimeoutMs;
}

bool IsKnownLinuxGameUdpPort(uint16_t port) {
    switch (port) {
    case 5063:
    case 2311:
    case 2312:
    case 2313:
        return true;
    default:
        return false;
    }
}

bool IsReservedLinuxPeerDirectPort(uint16_t port) {
    return port == kPeerDirectProbeSrcPort || port == kPeerDirectProbeDstPort;
}

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
    uint8_t endpoint_addr[16];
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

struct LinuxWatchedTcpPacketInfo {
    std::string flow_key;
    std::string client_ip;
    uint16_t client_port;
    std::string server_ip;
    uint16_t server_port;
    bool from_client;
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    bool has_payload;
    size_t payload_len;
    uint8_t flags;

    LinuxWatchedTcpPacketInfo()
        : client_port(0),
          server_port(0),
          from_client(false),
          syn(false),
          ack(false),
          fin(false),
          rst(false),
          has_payload(false),
          payload_len(0),
          flags(0) {}
};

std::string LinuxFrameName(uint8_t frame_type) {
    switch (frame_type) {
    case packet_tunnel::kFrameHeartbeat:
        return "心跳";
    case packet_tunnel::kFrameHeartbeatAck:
        return "心跳确认";
    case packet_tunnel::kFrameIpv4Packet:
        return "IPv4数据包";
    case packet_tunnel::kFramePeerOffer:
        return "对等提议";
    case packet_tunnel::kFramePeerHello:
        return "对等问候";
    case packet_tunnel::kFramePeerAck:
        return "对等确认";
    case packet_tunnel::kFramePeerKeepalive:
        return "对等保活";
    case packet_tunnel::kFramePeerDisable:
        return "对等端禁用";
    case packet_tunnel::kFrameTcpPeerOffer:
        return "TCP对等提议";
    case packet_tunnel::kFrameTcpDirectAdvertise:
        return "TCP直连通告";
    case packet_tunnel::kFrameTcpDirectOpen:
        return "TCP直连打开";
    case packet_tunnel::kFrameTcpDirectCandidateAdvertise:
        return "TCP直连候选通告";
    case packet_tunnel::kFrameUdpDirectCandidateAdvertise:
        return "UDP直连候选通告";
    default:
        return "未知";
    }
}

const char* LinuxPeerRouteStateName(LinuxPeerRouteState state) {
    switch (state) {
    case LinuxPeerRouteState::RelayOnly:
        return "relay_only";
    case LinuxPeerRouteState::OfferReceived:
        return "offer_received";
    case LinuxPeerRouteState::Probing:
        return "probing";
    case LinuxPeerRouteState::DirectActive:
        return "direct_active";
    case LinuxPeerRouteState::Cooldown:
        return "cooldown";
    default:
        return "unknown";
    }
}

std::string BuildLinuxPeerRouteSnapshotSummary(const std::vector<LinuxPeerRouteStatus>& peers,
                                               unsigned long long now_ms_value) {
    if (peers.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < peers.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_ms_value > peers[i].last_observed_ms)
                ? (now_ms_value - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_ms_value > peers[i].last_state_change_ms)
                ? (now_ms_value - peers[i].last_state_change_ms)
                : 0;
        ss << peers[i].peer_virtual_ip
           << "[" << LinuxPeerRouteStateName(peers[i].state)
           << " 版本=" << peers[i].endpoint_version
           << " 就绪=" << (peers[i].direct_ready ? "是" : "否")
           << " 可用=" << (peers[i].direct_eligible ? "是" : "否")
           << " 激活=" << (peers[i].active_direct ? "是" : "否")
           << " 观测=" << observed_age << "ms"
           << " 直连=" << ((peers[i].last_direct_data_ms != 0 && now_ms_value > peers[i].last_direct_data_ms)
                                ? (now_ms_value - peers[i].last_direct_data_ms)
                                : 0) << "ms"
           << " 样本=" << peers[i].direct_sample_count
           << " 失败=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " 状态=" << state_age << "ms]";
    }
    return ss.str();
}

std::string DescribeSingleLinuxPeerRoute(const std::vector<LinuxPeerRouteStatus>& peers,
                                         const std::string& peer_virtual_ip,
                                         unsigned long long now_ms_value) {
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip != peer_virtual_ip) {
            continue;
        }

        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_ms_value > peers[i].last_observed_ms)
                ? (now_ms_value - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_ms_value > peers[i].last_state_change_ms)
                ? (now_ms_value - peers[i].last_state_change_ms)
                : 0;

        std::ostringstream ss;
        ss << peers[i].peer_virtual_ip
           << "[" << LinuxPeerRouteStateName(peers[i].state)
           << " 版本=" << peers[i].endpoint_version
           << " 协议族=" << static_cast<int>(peers[i].endpoint_family)
           << " 端口=" << peers[i].endpoint_port
           << " 就绪=" << (peers[i].direct_ready ? "是" : "否")
           << " 可用=" << (peers[i].direct_eligible ? "是" : "否")
           << " 激活=" << (peers[i].active_direct ? "是" : "否")
           << " 观测=" << observed_age << "ms"
           << " 直连=" << ((peers[i].last_direct_data_ms != 0 && now_ms_value > peers[i].last_direct_data_ms)
                                ? (now_ms_value - peers[i].last_direct_data_ms)
                                : 0) << "ms"
           << " 样本=" << peers[i].direct_sample_count
           << " 失败=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " 状态=" << state_age << "ms]";
        return ss.str();
    }

    return std::string();
}

std::string LinuxIpv4ToString(const uint8_t* addr) {
    char buffer[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, addr, buffer, sizeof(buffer)) == NULL) {
        return "?";
    }
    return std::string(buffer);
}

bool IsLinuxNoisyUdpPacket(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 20) {
        return true;
    }
    if (((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return true;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return true;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    const uint8_t* dst_ip = packet + 16;

    const bool is_multicast = (dst_ip[0] >= 224 && dst_ip[0] <= 239);
    const bool is_limited_broadcast =
        (dst_ip[0] == 255 && dst_ip[1] == 255 && dst_ip[2] == 255 && dst_ip[3] == 255);
    const bool is_likely_subnet_broadcast = (dst_ip[3] == 255);
    const bool is_common_noise_port =
        (src_port == 137 || dst_port == 137 ||
         src_port == 138 || dst_port == 138 ||
         src_port == 1900 || dst_port == 1900 ||
         src_port == 5355 || dst_port == 5355);

    return is_multicast || is_limited_broadcast || is_likely_subnet_broadcast || is_common_noise_port;
}

bool TryDescribeLinuxUdpPacket(const uint8_t* packet, size_t packet_len, std::string* out_desc) {
    if (out_desc == NULL || packet == NULL || packet_len < 20) {
        return false;
    }
    if (((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return false;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    std::ostringstream ss;
    ss << "来源=" << LinuxIpv4ToString(packet + 12) << ":" << src_port
       << " 目标=" << LinuxIpv4ToString(packet + 16) << ":" << dst_port
       << " 长度=" << packet_len;
    *out_desc = ss.str();
    return true;
}

bool IsFocusedLinuxGameUdpPort(uint16_t port) {
    return port == 5063 || port == 2311 || port == 2312 || port == 2313;
}

bool IsFocusedLinuxGameUdpPacket(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 20) {
        return false;
    }
    if (((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return false;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    return IsFocusedLinuxGameUdpPort(src_port) || IsFocusedLinuxGameUdpPort(dst_port);
}

bool IsWatchedLinuxServiceTcpPort(uint16_t port) {
    return port == 7001 || port == 10011 || port == 3306;
}

bool TryParseLinuxWatchedTcpPacket(const uint8_t* packet,
                                   size_t packet_len,
                                   const std::string& local_virtual_ip,
                                   LinuxWatchedTcpPacketInfo* out_info) {
    if (packet == NULL || out_info == NULL || packet_len < 20) {
        return false;
    }
    if (((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_TCP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 20) {
        return false;
    }

    const uint16_t total_len = ntohs(*(const uint16_t*)(packet + 2));
    if (total_len < ip_header_len + 20 || packet_len < total_len) {
        return false;
    }

    const size_t tcp_header_offset = ip_header_len;
    const size_t tcp_header_len =
        static_cast<size_t>((packet[tcp_header_offset + 12] >> 4) & 0x0F) * 4;
    if (tcp_header_len < 20 || total_len < tcp_header_offset + tcp_header_len) {
        return false;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + tcp_header_offset));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + tcp_header_offset + 2));
    const std::string src_ip = LinuxIpv4ToString(packet + 12);
    const std::string dst_ip = LinuxIpv4ToString(packet + 16);

    LinuxWatchedTcpPacketInfo info;
    if (dst_ip == local_virtual_ip && IsWatchedLinuxServiceTcpPort(dst_port)) {
        info.client_ip = src_ip;
        info.client_port = src_port;
        info.server_ip = dst_ip;
        info.server_port = dst_port;
        info.from_client = true;
    } else if (src_ip == local_virtual_ip && IsWatchedLinuxServiceTcpPort(src_port)) {
        info.client_ip = dst_ip;
        info.client_port = dst_port;
        info.server_ip = src_ip;
        info.server_port = src_port;
        info.from_client = false;
    } else {
        return false;
    }

    info.flags = packet[tcp_header_offset + 13];
    info.syn = (info.flags & 0x02) != 0;
    info.ack = (info.flags & 0x10) != 0;
    info.fin = (info.flags & 0x01) != 0;
    info.rst = (info.flags & 0x04) != 0;
    info.payload_len = total_len - tcp_header_offset - tcp_header_len;
    info.has_payload = info.payload_len > 0;

    std::ostringstream flow_key;
    flow_key << info.client_ip << ":" << info.client_port
             << "->" << info.server_ip << ":" << info.server_port;
    info.flow_key = flow_key.str();
    *out_info = info;
    return true;
}

std::string LinuxFormatElapsedMs(unsigned long long start_ms, unsigned long long end_ms) {
    if (start_ms == 0 || end_ms < start_ms) {
        return "-";
    }
    return std::to_string(end_ms - start_ms);
}

std::string LinuxDescribeTcpTraceFlags(uint8_t flags) {
    std::string desc;
    if ((flags & 0x02) != 0) {
        desc += "SYN|";
    }
    if ((flags & 0x10) != 0) {
        desc += "ACK|";
    }
    if ((flags & 0x01) != 0) {
        desc += "FIN|";
    }
    if ((flags & 0x04) != 0) {
        desc += "RST|";
    }
    if ((flags & 0x08) != 0) {
        desc += "PSH|";
    }
    if (!desc.empty()) {
        desc.erase(desc.size() - 1);
    }
    return desc.empty() ? "NONE" : desc;
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

bool IsLinuxTunnelVirtualIpv4Candidate(uint32_t candidate_ip_be,
                                       const std::string& virtual_ip) {
    uint32_t virtual_ip_be = 0;
    return ParseLinuxIpv4StringToBe(virtual_ip, &virtual_ip_be) &&
           candidate_ip_be == virtual_ip_be;
}

bool ParseLinuxIpv4Octets(const std::string& ip, uint8_t out_octets[4]) {
    if (out_octets == NULL) {
        return false;
    }

    std::stringstream stream(ip);
    std::string part;
    for (size_t i = 0; i < 4; ++i) {
        if (!std::getline(stream, part, '.')) {
            return false;
        }

        char* end = NULL;
        const long octet = strtol(part.c_str(), &end, 10);
        if (end == NULL || *end != '\0' || octet < 0 || octet > 255) {
            return false;
        }
        out_octets[i] = static_cast<uint8_t>(octet);
    }

    return !std::getline(stream, part, '.');
}

bool IsLinuxKnownPeerVirtualIp(const std::vector<LinuxPeerRouteStatus>& peers,
                               const std::string& peer_virtual_ip) {
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip == peer_virtual_ip) {
            return true;
        }
    }
    return false;
}

bool IsLinuxGatewayPeerResolveCandidate(const std::string& local_virtual_ip,
                                        const std::string& dst_virtual_ip,
                                        const std::vector<LinuxPeerRouteStatus>& peers) {
    if (dst_virtual_ip.empty() ||
        dst_virtual_ip == local_virtual_ip ||
        IsLinuxKnownPeerVirtualIp(peers, dst_virtual_ip)) {
        return false;
    }

    uint8_t local_octets[4] = {};
    uint8_t dst_octets[4] = {};
    if (!ParseLinuxIpv4Octets(local_virtual_ip, local_octets) ||
        !ParseLinuxIpv4Octets(dst_virtual_ip, dst_octets)) {
        return false;
    }

    if (dst_octets[0] >= 224 && dst_octets[0] <= 239) {
        return false;
    }
    if (dst_octets[3] == 0 || dst_octets[3] == 255) {
        return false;
    }

    return local_octets[0] == dst_octets[0] &&
           local_octets[1] == dst_octets[1] &&
           local_octets[2] == dst_octets[2];
}

void CloseFdQuiet(int* fd) {
    if (fd == NULL || *fd < 0) {
        return;
    }
    const int stale = *fd;
    *fd = -1;
    shutdown(stale, SHUT_RDWR);
    close(stale);
}

void ConfigureLinuxTcpStreamSocket(int sock) {
    int buffer_bytes = kSocketBufferBytes;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_bytes, sizeof(buffer_bytes));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_bytes, sizeof(buffer_bytes));

    timeval send_timeout = {};
    send_timeout.tv_sec = kSocketSendTimeoutMs / 1000;
    send_timeout.tv_usec = (kSocketSendTimeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));

    timeval recv_timeout = {};
    recv_timeout.tv_sec = kSocketReadTimeoutMs / 1000;
    recv_timeout.tv_usec = (kSocketReadTimeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));

    int keepalive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
}

bool BuildLinuxTcpDirectSockaddr(uint8_t endpoint_family,
                                 const uint8_t* endpoint_addr,
                                 uint16_t endpoint_port,
                                 sockaddr_storage* out_addr,
                                 socklen_t* out_addr_len) {
    if (endpoint_addr == NULL || out_addr == NULL || out_addr_len == NULL ||
        endpoint_port == 0) {
        return false;
    }
    memset(out_addr, 0, sizeof(*out_addr));
    *out_addr_len = 0;
    if (endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(out_addr);
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(endpoint_port);
        memcpy(&addr4->sin_addr, endpoint_addr, 4);
        *out_addr_len = sizeof(sockaddr_in);
        return true;
    }
    if (endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv6) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(out_addr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(endpoint_port);
        memcpy(&addr6->sin6_addr, endpoint_addr, 16);
        *out_addr_len = sizeof(sockaddr_in6);
        return true;
    }
    return false;
}

bool ConnectLinuxSocketWithTimeout(int sock,
                                   const sockaddr_storage& addr,
                                   socklen_t addr_len,
                                   int timeout_ms,
                                   int* out_error) {
    if (out_error != NULL) {
        *out_error = 0;
    }

    const int old_flags = fcntl(sock, F_GETFL, 0);
    if (old_flags < 0 || fcntl(sock, F_SETFL, old_flags | O_NONBLOCK) != 0) {
        if (out_error != NULL) {
            *out_error = errno;
        }
        return false;
    }

    bool connected = false;
    int last_error = 0;
    if (connect(sock,
                reinterpret_cast<const sockaddr*>(&addr),
                addr_len) == 0) {
        connected = true;
    } else {
        last_error = errno;
        if (last_error == EINPROGRESS || last_error == EWOULDBLOCK || last_error == EAGAIN) {
            fd_set write_set;
            fd_set error_set;
            FD_ZERO(&write_set);
            FD_ZERO(&error_set);
            FD_SET(sock, &write_set);
            FD_SET(sock, &error_set);
            timeval tv = {};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            const int selected = select(sock + 1, NULL, &write_set, &error_set, &tv);
            if (selected > 0 && FD_ISSET(sock, &write_set)) {
                int so_error = 0;
                socklen_t so_error_len = sizeof(so_error);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) == 0 &&
                    so_error == 0) {
                    connected = true;
                } else {
                    last_error = so_error != 0 ? so_error : errno;
                }
            } else if (selected == 0) {
                last_error = ETIMEDOUT;
            } else {
                last_error = errno;
            }
        }
    }

    fcntl(sock, F_SETFL, old_flags);
    if (!connected && out_error != NULL) {
        *out_error = last_error;
    }
    return connected;
}

bool TryExtractLinuxPeerEndpointFromSockaddr(const sockaddr_storage& source_addr,
                                             uint8_t* endpoint_family,
                                             uint8_t* endpoint_addr,
                                             uint16_t* endpoint_port) {
    if (endpoint_family == NULL || endpoint_addr == NULL || endpoint_port == NULL) {
        return false;
    }

    *endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
    *endpoint_port = 0;
    memset(endpoint_addr, 0, 16);

    if (source_addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&source_addr);
        *endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
        *endpoint_port = ntohs(addr4->sin_port);
        memcpy(endpoint_addr, &addr4->sin_addr, 4);
        return true;
    }

    if (source_addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&source_addr);
        *endpoint_port = ntohs(addr6->sin6_port);
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&addr6->sin6_addr);
        static const uint8_t kV4MappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (memcmp(bytes, kV4MappedPrefix, sizeof(kV4MappedPrefix)) == 0) {
            *endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
            memcpy(endpoint_addr, bytes + 12, 4);
        } else {
            *endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv6;
            memcpy(endpoint_addr, bytes, 16);
        }
        return true;
    }

    return false;
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

void NormalizeLinuxPeerEndpointFamily(uint8_t* family, uint8_t* addr) {
    if (family == NULL || addr == NULL ||
        *family != packet_tunnel::kPeerEndpointFamilyIpv6) {
        return;
    }

    static const uint8_t kV4MappedPrefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
    };
    if (memcmp(addr, kV4MappedPrefix, sizeof(kV4MappedPrefix)) != 0) {
        return;
    }

    uint8_t ipv4_addr[4] = {};
    memcpy(ipv4_addr, addr + 12, sizeof(ipv4_addr));
    memset(addr, 0, packet_tunnel::kPeerEndpointAddrSize);
    memcpy(addr, ipv4_addr, sizeof(ipv4_addr));
    *family = packet_tunnel::kPeerEndpointFamilyIpv4;
}

std::string LinuxSockaddrToString(const sockaddr_storage& addr, socklen_t addr_len) {
    (void)addr_len;
    char buffer[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&addr);
        if (inet_ntop(AF_INET, &addr4->sin_addr, buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(ntohs(addr4->sin_port));
        }
    } else if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(ntohs(addr6->sin6_port));
        }
    }
    return "unknown";
}

void LinuxClearSockaddrPort(sockaddr_storage* addr) {
    if (addr == NULL) {
        return;
    }

    if (addr->ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(addr)->sin_port = 0;
    } else if (addr->ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = 0;
    }
}

bool LinuxIsPublicInternetAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        const uint32_t ip = ntohl(addr4->sin_addr.s_addr);
        if (ip == 0 ||
            (ip & 0xff000000u) == 0x0a000000u ||
            (ip & 0xfff00000u) == 0xac100000u ||
            (ip & 0xffff0000u) == 0xc0a80000u ||
            (ip & 0xff000000u) == 0x7f000000u ||
            (ip & 0xffff0000u) == 0xa9fe0000u ||
            (ip & 0xffc00000u) == 0x64400000u ||
            (ip & 0xfffe0000u) == 0xc6120000u) {
            return false;
        }
        return true;
    }

    if (addr->sa_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr) ||
            IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr)) {
            return false;
        }
        if ((addr6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc) {
            return false;
        }
        return (addr6->sin6_addr.s6_addr[0] & 0xe0) == 0x20;
    }

    return false;
}

bool LinuxSockaddrEquals(const sockaddr_storage& left,
                         socklen_t left_len,
                         const sockaddr_storage& right,
                         socklen_t right_len);

bool BuildEndpointForSocketFamily(const sockaddr* source_addr,
                                  socklen_t source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  socklen_t* endpoint_addr_len);

struct LinuxRelayEndpointCandidate {
    sockaddr_storage endpoint_addr;
    socklen_t endpoint_addr_len;
    int socket_family;
    bool public_internet;
    size_t original_order;
};

int LinuxRelayEndpointPriority(const LinuxRelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? 0 : 1;
    }
    return (candidate.socket_family == AF_INET6) ? 2 : 3;
}

const char* LinuxRelayEndpointScopeName(const LinuxRelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? "public_ipv6" : "public_ipv4";
    }
    return (candidate.socket_family == AF_INET6) ? "non_public_ipv6" : "non_public_ipv4";
}

std::string BuildLinuxRelayEndpointCandidateSummary(
    const std::vector<LinuxRelayEndpointCandidate>& candidates) {
    if (candidates.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        ss << LinuxRelayEndpointScopeName(candidates[i]) << "="
           << LinuxSockaddrToString(candidates[i].endpoint_addr, candidates[i].endpoint_addr_len);
    }
    return ss.str();
}

void BuildLinuxRelayEndpointCandidates(addrinfo* result,
                                       std::vector<LinuxRelayEndpointCandidate>* out_candidates) {
    if (out_candidates == NULL) {
        return;
    }

    out_candidates->clear();
    size_t order = 0;
    for (addrinfo* rp = result; rp != NULL; rp = rp->ai_next, ++order) {
        if (rp->ai_addr == NULL) {
            continue;
        }

        const int family = rp->ai_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) {
            continue;
        }

        LinuxRelayEndpointCandidate candidate = {};
        if (!BuildEndpointForSocketFamily(rp->ai_addr,
                                          static_cast<socklen_t>(rp->ai_addrlen),
                                          family,
                                          &candidate.endpoint_addr,
                                          &candidate.endpoint_addr_len)) {
            continue;
        }

        candidate.socket_family = family;
        candidate.public_internet =
            LinuxIsPublicInternetAddress(reinterpret_cast<const sockaddr*>(&candidate.endpoint_addr));
        candidate.original_order = order;

        bool duplicate = false;
        for (size_t i = 0; i < out_candidates->size(); ++i) {
            if (LinuxSockaddrEquals((*out_candidates)[i].endpoint_addr,
                                    (*out_candidates)[i].endpoint_addr_len,
                                    candidate.endpoint_addr,
                                    candidate.endpoint_addr_len)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            out_candidates->push_back(candidate);
        }
    }

    std::stable_sort(out_candidates->begin(),
                     out_candidates->end(),
                     [](const LinuxRelayEndpointCandidate& left,
                        const LinuxRelayEndpointCandidate& right) {
                         const int left_priority = LinuxRelayEndpointPriority(left);
                         const int right_priority = LinuxRelayEndpointPriority(right);
                         if (left_priority != right_priority) {
                             return left_priority < right_priority;
                         }
                         return left.original_order < right.original_order;
                     });
}

bool ParseLinuxPeerOfferPayload(const uint8_t* payload, size_t length, ParsedLinuxPeerOffer* out_offer) {
    if (payload == NULL || out_offer == NULL || length != packet_tunnel::kPeerOfferPayloadSize) {
        return false;
    }

    out_offer->peer_virtual_ip = LinuxIpv4ToString(payload);
    out_offer->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_offer->endpoint_family = payload[12];
    out_offer->endpoint_port = packet_tunnel::read_u16_be(payload + 14);
    memset(out_offer->endpoint_addr, 0, sizeof(out_offer->endpoint_addr));
    memcpy(out_offer->endpoint_addr, payload + 16, sizeof(out_offer->endpoint_addr));
    NormalizeLinuxPeerEndpointFamily(&out_offer->endpoint_family, out_offer->endpoint_addr);
    out_offer->endpoint = LinuxPeerEndpointToString(out_offer->endpoint_family,
                                                    out_offer->endpoint_addr,
                                                    out_offer->endpoint_port);
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

bool LinuxSockaddrEquals(const sockaddr_storage& left,
                         socklen_t left_len,
                         const sockaddr_storage& right,
                         socklen_t right_len) {
    (void)left_len;
    (void)right_len;
    if (left.ss_family != right.ss_family) {
        return false;
    }

    if (left.ss_family == AF_INET) {
        const sockaddr_in* left4 = reinterpret_cast<const sockaddr_in*>(&left);
        const sockaddr_in* right4 = reinterpret_cast<const sockaddr_in*>(&right);
        return left4->sin_port == right4->sin_port &&
               left4->sin_addr.s_addr == right4->sin_addr.s_addr;
    }

    if (left.ss_family == AF_INET6) {
        const sockaddr_in6* left6 = reinterpret_cast<const sockaddr_in6*>(&left);
        const sockaddr_in6* right6 = reinterpret_cast<const sockaddr_in6*>(&right);
        return left6->sin6_port == right6->sin6_port &&
               memcmp(&left6->sin6_addr, &right6->sin6_addr, sizeof(left6->sin6_addr)) == 0;
    }

    return false;
}

bool BuildEndpointForSocketFamily(const sockaddr* source_addr,
                                  socklen_t source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  socklen_t* endpoint_addr_len) {
    (void)source_addr_len;
    if (source_addr == NULL || endpoint_addr == NULL || endpoint_addr_len == NULL) {
        return false;
    }

    sockaddr_storage out_addr = {};
    socklen_t out_len = 0;
    if (socket_family == AF_INET6) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&out_addr);
        memset(addr6, 0, sizeof(*addr6));
        addr6->sin6_family = AF_INET6;

        if (source_addr->sa_family == AF_INET6) {
            const sockaddr_in6* source6 = reinterpret_cast<const sockaddr_in6*>(source_addr);
            memcpy(addr6, source6, sizeof(*source6));
            out_len = sizeof(sockaddr_in6);
        } else if (source_addr->sa_family == AF_INET) {
            const sockaddr_in* source4 = reinterpret_cast<const sockaddr_in*>(source_addr);
            addr6->sin6_port = source4->sin_port;
            addr6->sin6_addr.s6_addr[10] = 0xff;
            addr6->sin6_addr.s6_addr[11] = 0xff;
            memcpy(&addr6->sin6_addr.s6_addr[12], &source4->sin_addr, sizeof(source4->sin_addr));
            out_len = sizeof(sockaddr_in6);
        }
    } else if (socket_family == AF_INET && source_addr->sa_family == AF_INET) {
        memcpy(&out_addr, source_addr, sizeof(sockaddr_in));
        out_len = sizeof(sockaddr_in);
    }

    if (out_len == 0) {
        return false;
    }

    *endpoint_addr = out_addr;
    *endpoint_addr_len = out_len;
    return true;
}

}  // namespace

bool TryParseLinuxUdpPorts(const uint8_t* packet,
                           size_t packet_len,
                           uint16_t* src_port,
                           uint16_t* dst_port);

LinuxPacketTunnelClient::LinuxPacketTunnelClient(const std::string& tunnel_host,
                                                 uint16_t tunnel_port,
                                                 const std::string& session_uuid,
                                                 const std::string& client_id,
                                                 const std::string& virtual_ip,
                                                 uint16_t mtu,
                                                 LinuxTunManager* tun_manager)
    : tunnel_host_(tunnel_host),
      tunnel_port_(tunnel_port),
      session_uuid_(session_uuid),
      client_id_(client_id),
      virtual_ip_(virtual_ip),
      mtu_(mtu),
      tun_manager_(tun_manager),
      sock_(-1),
      tcp_sock_(-1),
      tcp_direct_listen_sock_(-1),
      socket_family_(AF_UNSPEC),
      tcp_direct_listen_port_(0),
      connected_(false),
      stop_requested_(false),
      tcp_connected_(false),
      last_receive_ms_(0),
      last_network_activity_ms_(0),
      peer_link_manager_(new LinuxPeerLinkManager()),
      peer_signal_nonce_(1) {}

LinuxPacketTunnelClient::~LinuxPacketTunnelClient() {
    Stop();
    delete peer_link_manager_;
    peer_link_manager_ = NULL;
}

void LinuxPacketTunnelClient::MarkNetworkActivity() {
    last_network_activity_ms_ = now_ms();
}

void LinuxPacketTunnelClient::PruneWatchedTcpFlows(unsigned long long now_tick) {
    for (std::map<std::string, WatchedTcpFlowTrace>::iterator it = watched_tcp_flows_.begin();
         it != watched_tcp_flows_.end();) {
        const WatchedTcpFlowTrace& trace = it->second;
        const bool closed_expired =
            trace.close_logged &&
            now_tick >= trace.closed_ms &&
            (now_tick - trace.closed_ms) > kWatchedTcpClosedRetentionMs;
        const bool idle_expired =
            trace.last_seen_ms != 0 &&
            now_tick >= trace.last_seen_ms &&
            (now_tick - trace.last_seen_ms) > kWatchedTcpFlowIdleCleanupMs;
        if (closed_expired || idle_expired) {
            it = watched_tcp_flows_.erase(it);
        } else {
            ++it;
        }
    }
}

void LinuxPacketTunnelClient::MarkWatchedTcpTunRead(const uint8_t* packet,
                                                    size_t packet_len,
                                                    unsigned long long read_wait_ms) {
    LinuxWatchedTcpPacketInfo info = {};
    if (!TryParseLinuxWatchedTcpPacket(packet, packet_len, virtual_ip_, &info) ||
        info.from_client ||
        !info.has_payload) {
        return;
    }

    const unsigned long long tick = now_ms();
    std::lock_guard<std::mutex> lock(watched_tcp_mutex_);
    PruneWatchedTcpFlows(tick);

    std::map<std::string, WatchedTcpFlowTrace>::iterator it = watched_tcp_flows_.find(info.flow_key);
    if (it == watched_tcp_flows_.end()) {
        return;
    }

    WatchedTcpFlowTrace& trace = it->second;
    if (read_wait_ms >= kWatchedTcpServerWaitLogMs) {
        std::ostringstream flow_ss;
        flow_ss << trace.client_ip << ":" << trace.client_port
                << " -> " << trace.server_ip << ":" << trace.server_port;
        LogDebug("TCP业务跟踪 TUN读取阻塞 流=" + flow_ss.str() +
                " 阻塞=" + std::to_string(read_wait_ms) + "ms" +
                " 字节数=" + std::to_string(info.payload_len));
    }
    trace.pending_server_tun_read_ms = tick;

    if (trace.pending_request_ms == 0 || tick < trace.pending_request_ms) {
        return;
    }

    const unsigned long long emit_wait = tick - trace.pending_request_ms;
    if (emit_wait < kWatchedTcpServerWaitLogMs) {
        return;
    }

    std::ostringstream flow_ss;
    flow_ss << trace.client_ip << ":" << trace.client_port
            << " -> " << trace.server_ip << ":" << trace.server_port;
    LogDebug("TCP业务跟踪 服务端发包等待 流=" + flow_ss.str() +
            " 来源=tun-read" +
            " 等待=" + std::to_string(emit_wait) + "ms" +
            " 字节数=" + std::to_string(info.payload_len));
}

void LinuxPacketTunnelClient::TraceWatchedTcpPacket(const uint8_t* packet,
                                                    size_t packet_len,
                                                    const char* path) {
    LinuxWatchedTcpPacketInfo info = {};
    if (!TryParseLinuxWatchedTcpPacket(packet, packet_len, virtual_ip_, &info)) {
        return;
    }

    const unsigned long long tick = now_ms();
    std::lock_guard<std::mutex> lock(watched_tcp_mutex_);
    PruneWatchedTcpFlows(tick);

    WatchedTcpFlowTrace& trace = watched_tcp_flows_[info.flow_key];
    if (trace.created_ms == 0 || (trace.close_logged && info.from_client && info.syn && !info.ack)) {
        trace = WatchedTcpFlowTrace();
        trace.client_ip = info.client_ip;
        trace.client_port = info.client_port;
        trace.server_ip = info.server_ip;
        trace.server_port = info.server_port;
        trace.created_ms = tick;
    }
    trace.last_seen_ms = tick;

    const std::string origin = (path != NULL) ? path : "?";
    std::ostringstream flow_ss;
    flow_ss << trace.client_ip << ":" << trace.client_port
            << " -> " << trace.server_ip << ":" << trace.server_port;
    const std::string flow = flow_ss.str();

    if (info.from_client && info.syn && !info.ack && trace.syn_ms == 0) {
        trace.syn_ms = tick;
        LogDebug("TCP业务跟踪 SYN 流=" + flow +
                " 来源=" + origin +
                " 端口=" + std::to_string(trace.server_port));
    }

    if (!info.from_client && info.syn && info.ack && trace.synack_ms == 0) {
        trace.synack_ms = tick;
        LogDebug("TCP业务跟踪 SYNACK 流=" + flow +
                " 来源=" + origin +
                " 自SYN起=" + LinuxFormatElapsedMs(trace.syn_ms, tick) + "ms");
    }

    if (info.from_client &&
        info.ack &&
        !info.syn &&
        !info.fin &&
        !info.rst &&
        !info.has_payload &&
        trace.synack_ms != 0 &&
        trace.established_ms == 0) {
        trace.established_ms = tick;
        LogDebug("TCP业务跟踪 已建立 流=" + flow +
                " 来源=" + origin +
                " 自SYN起=" + LinuxFormatElapsedMs(trace.syn_ms, tick) + "ms" +
                " 自SYNACK起=" + LinuxFormatElapsedMs(trace.synack_ms, tick) + "ms");
    }

    if (info.from_client &&
        info.ack &&
        !info.syn &&
        !info.fin &&
        !info.rst &&
        !info.has_payload) {
        if (trace.last_server_payload_ms != 0 &&
            trace.last_client_ack_only_ms < trace.last_server_payload_ms &&
            tick >= trace.last_server_payload_ms) {
            const unsigned long long ack_delay = tick - trace.last_server_payload_ms;
            if (ack_delay >= 80) {
                LogDebug("TCP业务跟踪 客户端确认延迟 流=" + flow +
                        " 来源=" + origin +
                        " 延迟=" + std::to_string(ack_delay) + "ms");
            }
        }
        trace.last_client_ack_only_ms = tick;
    }

    if (info.has_payload) {
        if (info.from_client) {
            ++trace.client_payload_count;
            trace.last_client_payload_ms = tick;
            trace.pending_request_ms = tick;
            if (trace.first_client_payload_ms == 0) {
                trace.first_client_payload_ms = tick;
                LogDebug("TCP业务跟踪 客户端首个负载 流=" + flow +
                        " 来源=" + origin +
                        " 字节数=" + std::to_string(info.payload_len) +
                        " 自SYN起=" + LinuxFormatElapsedMs(trace.syn_ms, tick) + "ms" +
                        " 自建立起=" +
                        LinuxFormatElapsedMs(trace.established_ms, tick) + "ms");
            }
        } else {
            ++trace.server_payload_count;
            if (trace.pending_server_tun_read_ms != 0 &&
                tick >= trace.pending_server_tun_read_ms) {
                const unsigned long long send_lag = tick - trace.pending_server_tun_read_ms;
                if (send_lag >= 20) {
                    LogDebug("TCP业务跟踪 服务端发送滞后 流=" + flow +
                            " 来源=" + origin +
                            " lag=" + std::to_string(send_lag) + "ms" +
                            " 字节数=" + std::to_string(info.payload_len));
                }
                trace.pending_server_tun_read_ms = 0;
            }
            if (trace.first_server_payload_ms == 0) {
                trace.first_server_payload_ms = tick;
                LogDebug("TCP业务跟踪 服务端首个负载 流=" + flow +
                        " 来源=" + origin +
                        " 字节数=" + std::to_string(info.payload_len) +
                        " 自SYN起=" + LinuxFormatElapsedMs(trace.syn_ms, tick) + "ms" +
                        " 自客户端首个负载起=" +
                        LinuxFormatElapsedMs(trace.first_client_payload_ms, tick) + "ms");
            } else if (trace.pending_request_ms != 0 &&
                       tick >= trace.pending_request_ms &&
                       (tick - trace.pending_request_ms) >= kWatchedTcpServerWaitLogMs) {
                LogDebug("TCP业务跟踪 等待服务端回复 流=" + flow +
                        " 来源=" + origin +
                        " 等待=" + std::to_string(tick - trace.pending_request_ms) + "ms" +
                        " 字节数=" + std::to_string(info.payload_len));
            }
            trace.last_server_payload_ms = tick;
            trace.pending_request_ms = 0;
        }
    }

    if ((info.fin || info.rst) && !trace.close_logged) {
        trace.close_logged = true;
        trace.closed_ms = tick;
        std::ostringstream close_ss;
        close_ss << "TCP业务跟踪 关闭 流=" << flow
                 << " 来源=" << origin
                 << " 标志=" << LinuxDescribeTcpTraceFlags(info.flags)
                 << " 存活=" << LinuxFormatElapsedMs(trace.created_ms, tick) << "ms"
                 << " 客户端负载数=" << trace.client_payload_count
                 << " 服务端负载数=" << trace.server_payload_count;
        if (trace.pending_request_ms != 0 && tick >= trace.pending_request_ms) {
            close_ss << " 挂起等待=" << (tick - trace.pending_request_ms) << "ms";
        }
        LogDebug(close_ss.str());
    }
}

bool LinuxPacketTunnelClient::Start(std::string* error) {
    Stop();
    stop_requested_ = false;
    last_receive_ms_ = 0;
    last_network_activity_ms_ = 0;
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
    std::string udp_candidate_error;
    if (!SendUdpDirectCandidateAdvertises(&udp_candidate_error) &&
        !udp_candidate_error.empty()) {
        LogWarn("上报UDP直连候选失败: " + udp_candidate_error);
    }
    std::string tcp_direct_listener_error;
    if (!StartTcpDirectListener(&tcp_direct_listener_error)) {
        if (!tcp_direct_listener_error.empty()) {
            LogWarn("TCP直连监听不可用，继续保留中转路径: " +
                    tcp_direct_listener_error);
        } else {
            LogWarn("TCP直连监听不可用，继续保留中转路径");
        }
    }
    std::string tcp_error;
    if (!ConnectTcpSocket(&tcp_error) ||
        !SendTcpHandshake(&tcp_error) ||
        !ReceiveTcpHandshakeAck(&tcp_error)) {
        if (tcp_sock_ >= 0) {
            close(tcp_sock_);
            tcp_sock_ = -1;
        }
        tcp_connected_ = false;
        if (!tcp_error.empty()) {
            LogWarn("TCP中转载体不可用，回退到UDP中转: " + tcp_error);
        } else {
            LogWarn("TCP中转载体不可用，回退到UDP中转");
        }
    } else {
        std::string advertise_error;
        if (!SendTcpDirectAdvertise(&advertise_error) && !advertise_error.empty()) {
            LogWarn("上报TCP直连监听信息失败: " + advertise_error);
        }
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
    tcp_connected_ = false;
    if (sock_ >= 0 && peer_link_manager_ != NULL) {
        std::vector<LinuxPeerRouteStatus> peers = peer_link_manager_->Snapshot();
        for (size_t i = 0; i < peers.size(); ++i) {
            if (peers[i].endpoint_version == 0) {
                continue;
            }
            SendPeerDisableFrame(peers[i].peer_virtual_ip,
                                 peers[i].endpoint_version,
                                 packet_tunnel::kPeerDisableReasonCooldown);
        }
    }
    if (peer_link_manager_ != NULL) {
        peer_link_manager_->ResetAll();
    }
    peer_route_debug_log_tick_.clear();
    peer_probe_send_tick_.clear();
    peer_keepalive_send_tick_.clear();
    peer_business_activity_tick_.clear();
    peer_warmup_until_tick_.clear();
    peer_tcp_autowarm_tick_.clear();
    peer_control_log_tick_.clear();
    watched_tcp_flows_.clear();
    last_receive_ms_ = 0;
    last_network_activity_ms_ = 0;

    if (sock_ >= 0) {
        close(sock_);
        sock_ = -1;
    }
    if (tcp_sock_ >= 0) {
        close(tcp_sock_);
        tcp_sock_ = -1;
    }
    StopTcpDirectSockets();

    if (socket_thread_.joinable()) {
        socket_thread_.join();
    }
    if (tcp_thread_.joinable()) {
        tcp_thread_.join();
    }
    if (tun_thread_.joinable()) {
        tun_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
}

bool LinuxPacketTunnelClient::ConnectSocket(std::string* error) {
    server_endpoint_ = UdpEndpoint();
    socket_family_ = AF_UNSPEC;

    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = NULL;
    const std::string port_str = std::to_string(tunnel_port_);
    int ret = getaddrinfo(tunnel_host_.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        if (error != NULL) {
            *error = "数据隧道 DNS 解析失败: " + tunnel_host_;
        }
        return false;
    }

    std::vector<LinuxRelayEndpointCandidate> relay_candidates;
    BuildLinuxRelayEndpointCandidates(result, &relay_candidates);
    freeaddrinfo(result);
    result = NULL;

    if (relay_candidates.empty()) {
        if (error != NULL) {
            *error = "数据隧道解析后未返回可用端点: " + tunnel_host_;
        }
        return false;
    }

    LogInfo("中转端点候选: " +
            BuildLinuxRelayEndpointCandidateSummary(relay_candidates));

    auto configure_socket = [&](int sock, int family) {
        if (family == AF_INET6) {
            int dual_stack = 0;
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &dual_stack, sizeof(dual_stack));
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &kSocketBufferBytes, sizeof(kSocketBufferBytes));

        timeval send_timeout = {};
        send_timeout.tv_sec = kSocketSendTimeoutMs / 1000;
        send_timeout.tv_usec = (kSocketSendTimeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));

        timeval recv_timeout = {};
        recv_timeout.tv_sec = kSocketReadTimeoutMs / 1000;
        recv_timeout.tv_usec = (kSocketReadTimeoutMs % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
    };

    auto try_connect_candidate = [&](const LinuxRelayEndpointCandidate& candidate) -> bool {
        const sockaddr_storage endpoint_addr = candidate.endpoint_addr;
        const socklen_t endpoint_addr_len = candidate.endpoint_addr_len;
        const int preferred_family = candidate.socket_family;

        sockaddr_storage local_bind_addr = {};
        socklen_t local_bind_addr_len = 0;
        bool has_local_bind = false;

        int probe_sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (probe_sock >= 0) {
            configure_socket(probe_sock, preferred_family);
            if (connect(probe_sock,
                        reinterpret_cast<const sockaddr*>(&endpoint_addr),
                        endpoint_addr_len) == 0) {
                local_bind_addr_len = sizeof(local_bind_addr);
                if (getsockname(probe_sock,
                                reinterpret_cast<sockaddr*>(&local_bind_addr),
                                &local_bind_addr_len) == 0) {
                    LinuxClearSockaddrPort(&local_bind_addr);
                    has_local_bind = true;
                }
            }
            close(probe_sock);
        }

        int sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            return false;
        }

        configure_socket(sock, preferred_family);

        if (has_local_bind &&
            bind(sock,
                 reinterpret_cast<const sockaddr*>(&local_bind_addr),
                 local_bind_addr_len) != 0) {
            LogWarn("本地绑定回退: " + std::string(strerror(errno)));
            has_local_bind = false;
        }

        sock_ = sock;
        socket_family_ = preferred_family;
        server_endpoint_.addr = endpoint_addr;
        server_endpoint_.addr_len = endpoint_addr_len;
        server_endpoint_.valid = true;
        LogInfo("UDP到中转服务器的套接字已就绪 " + tunnel_host_ +
                ":" + std::to_string(tunnel_port_) +
                " 作用域=" + LinuxRelayEndpointScopeName(candidate) +
                " 协议族=" + std::to_string(socket_family_) +
                (has_local_bind
                     ? (" 本地地址=" + LinuxSockaddrToString(local_bind_addr, local_bind_addr_len))
                     : std::string("")));
        return true;
    };

    bool connected = false;
    for (size_t i = 0; i < relay_candidates.size(); ++i) {
        if (try_connect_candidate(relay_candidates[i])) {
            connected = true;
            break;
        }
    }

    if (!connected) {
        if (error != NULL) {
            *error = "数据隧道连接失败: " + tunnel_host_ + ":" + port_str;
        }
        return false;
    }
    return true;
}

bool LinuxPacketTunnelClient::ConnectTcpSocket(std::string* error) {
    tcp_connected_ = false;
    if (tcp_sock_ >= 0) {
        close(tcp_sock_);
        tcp_sock_ = -1;
    }
    if (!server_endpoint_.valid) {
        if (error != NULL) {
            *error = "TCP中转载体端点无效";
        }
        return false;
    }

    const int family =
        server_endpoint_.addr.ss_family != AF_UNSPEC ? server_endpoint_.addr.ss_family : socket_family_;
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        if (error != NULL) {
            *error = std::string("创建TCP中转载体套接字失败: ") + strerror(errno);
        }
        return false;
    }

    int buffer_bytes = kSocketBufferBytes;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_bytes, sizeof(buffer_bytes));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_bytes, sizeof(buffer_bytes));
    timeval send_timeout = {};
    send_timeout.tv_sec = kSocketSendTimeoutMs / 1000;
    send_timeout.tv_usec = (kSocketSendTimeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
    timeval recv_timeout = {};
    recv_timeout.tv_sec = kSocketReadTimeoutMs / 1000;
    recv_timeout.tv_usec = (kSocketReadTimeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
    int keepalive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    int tcp_nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));

    if (connect(sock,
                reinterpret_cast<const sockaddr*>(&server_endpoint_.addr),
                server_endpoint_.addr_len) != 0) {
        const std::string connect_error = std::string(strerror(errno));
        close(sock);
        if (error != NULL) {
            *error = "TCP中转载体连接失败: " + connect_error;
        }
        return false;
    }

    tcp_sock_ = sock;
    tcp_connected_ = true;
    LogInfo("TCP中转载体已连接到 " +
            LinuxSockaddrToString(server_endpoint_.addr, server_endpoint_.addr_len));
    return true;
}

bool LinuxPacketTunnelClient::BuildHandshakePayload(bool relay_only,
                                                    std::vector<uint8_t>* handshake,
                                                    std::string* error) const {
    if (handshake == NULL) {
        if (error != NULL) {
            *error = "握手缓冲区为空";
        }
        return false;
    }

    const uint8_t session_uuid_len = static_cast<uint8_t>(session_uuid_.size());
    if (client_id_.empty()) {
        if (error != NULL) {
            *error = "客户端ID为空";
        }
        return false;
    }
    if (client_id_.size() > 255) {
        if (error != NULL) {
            *error = "客户端ID过长";
        }
        return false;
    }

    const uint8_t client_id_len = static_cast<uint8_t>(client_id_.size());
    handshake->assign(7 + session_uuid_len + 1 + client_id_len + packet_tunnel::kHandshakeTailSize, 0);

    uint32_t conn_id_be = htonl(packet_tunnel::kHandshakeConnId);
    uint16_t port_be = htons(packet_tunnel::kHandshakePortMarker);
    memcpy(&(*handshake)[0], &conn_id_be, sizeof(conn_id_be));
    memcpy(&(*handshake)[4], &port_be, sizeof(port_be));
    (*handshake)[6] = session_uuid_len;
    if (session_uuid_len > 0) {
        memcpy(&(*handshake)[7], session_uuid_.data(), session_uuid_len);
    }
    const size_t client_id_offset = 7 + session_uuid_len;
    (*handshake)[client_id_offset] = client_id_len;
    memcpy(&(*handshake)[client_id_offset + 1], client_id_.data(), client_id_len);

    uint32_t virtual_ip_be = ParseVirtualIp(error);
    if (virtual_ip_be == 0) {
        return false;
    }

    const size_t tail = client_id_offset + 1 + client_id_len;
    (*handshake)[tail + 0] = packet_tunnel::kProtocolVersion;
    (*handshake)[tail + 1] =
        relay_only ? packet_tunnel::kHandshakeFlagRelayOnly : packet_tunnel::kHandshakeFlagNone;
    uint16_t mtu_be = htons(mtu_);
    memcpy(&(*handshake)[tail + 2], &mtu_be, sizeof(mtu_be));
    memcpy(&(*handshake)[tail + 4], &virtual_ip_be, sizeof(virtual_ip_be));
    return true;
}

bool LinuxPacketTunnelClient::SendHandshake(std::string* error) {
    std::vector<uint8_t> handshake;
    if (!BuildHandshakePayload(false, &handshake, error)) {
        return false;
    }

    return SendDatagramToEndpoint(server_endpoint_, handshake.data(), handshake.size(), error);
}

bool LinuxPacketTunnelClient::SendTcpHandshake(std::string* error) {
    if (!tcp_connected_ || tcp_sock_ < 0) {
        if (error != NULL) {
            *error = "TCP中转载体尚未连接";
        }
        return false;
    }

    std::vector<uint8_t> handshake;
    if (!BuildHandshakePayload(true, &handshake, error)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(tcp_send_mutex_);
    size_t sent = 0;
    while (sent < handshake.size()) {
        ssize_t n = send(tcp_sock_,
                         handshake.data() + sent,
                         handshake.size() - sent,
                         MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            continue;
        }
        if (error != NULL) {
            *error = std::string("发送TCP中转载体握手失败: ") + strerror(errno);
        }
        return false;
    }

    LogInfo("已发送TCP中转载体握手");
    return true;
}

bool LinuxPacketTunnelClient::SendUdpDirectCandidateAdvertises(std::string* error) {
    if (sock_ < 0) {
        if (error != NULL) {
            *error = "UDP套接字尚未连接";
        }
        return false;
    }

    sockaddr_storage local_addr = {};
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(sock_, reinterpret_cast<sockaddr*>(&local_addr), &local_addr_len) != 0) {
        if (error != NULL) {
            *error = std::string("获取UDP套接字本地地址失败: ") + strerror(errno);
        }
        return false;
    }

    uint16_t local_port = 0;
    if (local_addr.ss_family == AF_INET) {
        local_port = ntohs(reinterpret_cast<sockaddr_in*>(&local_addr)->sin_port);
    } else if (local_addr.ss_family == AF_INET6) {
        local_port = ntohs(reinterpret_cast<sockaddr_in6*>(&local_addr)->sin6_port);
    }
    if (local_port == 0) {
        if (error != NULL) {
            *error = "UDP本地端口不可用";
        }
        return false;
    }

    size_t candidate_count = 0;
    ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) {
        if (error != NULL) {
            *error = std::string("枚举UDP网卡地址失败: ") +
                     strerror(errno);
        }
        return false;
    }

    for (ifaddrs* ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL ||
            (ifa->ifa_flags & IFF_UP) == 0 ||
            (ifa->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }
        if (tun_manager_ != NULL &&
            ifa->ifa_name != NULL &&
            tun_manager_->GetIfName() == ifa->ifa_name) {
            continue;
        }

        TcpDirectCandidate candidate;
        candidate.endpoint_port = local_port;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
            const uint32_t ip = ntohl(addr4->sin_addr.s_addr);
            if (ip == 0 ||
                (ip & 0xff000000u) == 0x7f000000u ||
                (ip & 0xffff0000u) == 0xa9fe0000u ||
                (ip & 0xf0000000u) == 0xe0000000u ||
                IsLinuxTunnelVirtualIpv4Candidate(addr4->sin_addr.s_addr,
                                                  virtual_ip_)) {
                continue;
            }
            candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
            memcpy(candidate.endpoint_addr, &addr4->sin_addr, 4);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr);
            if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) ||
                IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
                IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) ||
                IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr)) {
                continue;
            }
            candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv6;
            memcpy(candidate.endpoint_addr, &addr6->sin6_addr, 16);
        } else {
            continue;
        }

        if (SendUdpDirectCandidateAdvertise(candidate, NULL)) {
            ++candidate_count;
        }
    }
    freeifaddrs(interfaces);

    LogInfo("UDP直连本地候选已上报，数量=" +
            std::to_string(candidate_count));
    return true;
}

bool LinuxPacketTunnelClient::SendUdpDirectCandidateAdvertise(
    const TcpDirectCandidate& candidate,
    std::string* error) {
    if (candidate.endpoint_port == 0 ||
        (candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv4 &&
         candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv6)) {
        if (error != NULL) {
            *error = "UDP直连候选无效";
        }
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kUdpDirectCandidateAdvertisePayloadSize, 0);
    payload[0] = candidate.endpoint_family;
    packet_tunnel::write_u16_be(payload.data() + 2, candidate.endpoint_port);
    memcpy(payload.data() + 4,
           candidate.endpoint_addr,
           candidate.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16);
    return SendFrame(packet_tunnel::kFrameUdpDirectCandidateAdvertise,
                     payload.data(),
                     payload.size(),
                     error);
}

bool LinuxPacketTunnelClient::ReceiveHandshakeAck(std::string* error) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    while (!stop_requested_) {
        sockaddr_storage source_addr = {};
        socklen_t source_addr_len = sizeof(source_addr);
        int received = RecvDatagramFrom(ack, sizeof(ack), &source_addr, &source_addr_len, error);
        if (received < 0) {
            return false;
        }
        if (received == 0) {
            continue;
        }
        if (!IsServerEndpoint(source_addr, source_addr_len)) {
            continue;
        }
        if (received != static_cast<int>(sizeof(ack))) {
            if (error != NULL) {
                *error = "握手确认长度不匹配";
            }
            return false;
        }

        if (ack[0] != packet_tunnel::kProtocolVersion) {
            if (error != NULL) {
                *error = "握手确认协议版本不匹配";
            }
            return false;
        }
        if (ack[1] != packet_tunnel::kStatusOk) {
            if (error != NULL) {
                *error = "握手确认被拒绝";
            }
            return false;
        }

        last_receive_ms_ = now_ms();
        MarkNetworkActivity();
        return true;
    }
    if (error != NULL) {
        *error = "握手已中断";
    }
    return false;
}

bool LinuxPacketTunnelClient::ReceiveTcpHandshakeAck(std::string* error) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    if (!RecvTcpExact(ack, sizeof(ack), error)) {
        return false;
    }

    if (ack[0] != packet_tunnel::kProtocolVersion) {
        if (error != NULL) {
            *error = "TCP握手确认协议版本不匹配";
        }
        return false;
    }
    if (ack[1] != packet_tunnel::kStatusOk) {
        if (error != NULL) {
            *error = "TCP握手确认被拒绝";
        }
        return false;
    }

    LogInfo("TCP中转载体握手已确认");
    return true;
}

bool LinuxPacketTunnelClient::StartTcpDirectListener(std::string* error) {
    StopTcpDirectSockets();

    auto try_listen_family = [&](int family, int* out_sock, uint16_t* out_port) -> bool {
        int listen_sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock < 0) {
            return false;
        }

        if (family == AF_INET6) {
            int dual_stack = 0;
            setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &dual_stack, sizeof(dual_stack));
        }
        ConfigureLinuxTcpStreamSocket(listen_sock);

        sockaddr_storage bind_addr = {};
        socklen_t bind_addr_len = 0;
        if (family == AF_INET6) {
            sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&bind_addr);
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(0);
            addr6->sin6_addr = in6addr_any;
            bind_addr_len = sizeof(sockaddr_in6);
        } else {
            sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&bind_addr);
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(0);
            addr4->sin_addr.s_addr = htonl(INADDR_ANY);
            bind_addr_len = sizeof(sockaddr_in);
        }

        if (bind(listen_sock,
                 reinterpret_cast<const sockaddr*>(&bind_addr),
                 bind_addr_len) != 0 ||
            listen(listen_sock, kTcpDirectListenBacklog) != 0) {
            close(listen_sock);
            return false;
        }

        sockaddr_storage actual_addr = {};
        socklen_t actual_addr_len = sizeof(actual_addr);
        if (getsockname(listen_sock,
                        reinterpret_cast<sockaddr*>(&actual_addr),
                        &actual_addr_len) != 0) {
            close(listen_sock);
            return false;
        }

        uint16_t port = 0;
        if (actual_addr.ss_family == AF_INET) {
            port = ntohs(reinterpret_cast<sockaddr_in*>(&actual_addr)->sin_port);
        } else if (actual_addr.ss_family == AF_INET6) {
            port = ntohs(reinterpret_cast<sockaddr_in6*>(&actual_addr)->sin6_port);
        }
        if (port == 0) {
            close(listen_sock);
            return false;
        }

        *out_sock = listen_sock;
        *out_port = port;
        return true;
    };

    const int preferred_family = socket_family_ == AF_INET6 ? AF_INET6 : AF_INET;
    const int fallback_family = preferred_family == AF_INET6 ? AF_INET : AF_INET6;
    int listen_sock = -1;
    uint16_t listen_port = 0;
    if (!try_listen_family(preferred_family, &listen_sock, &listen_port) &&
        !try_listen_family(fallback_family, &listen_sock, &listen_port)) {
        if (error != NULL) {
            *error = std::string("TCP直连监听失败: ") + strerror(errno);
        }
        return false;
    }

    tcp_direct_listen_sock_ = listen_sock;
    tcp_direct_listen_port_ = listen_port;
    LogInfo("TCP直连监听已就绪，端口=" +
            std::to_string(tcp_direct_listen_port_));
    return true;
}

bool LinuxPacketTunnelClient::SendTcpDirectAdvertise(std::string* error) {
    if (!tcp_connected_ || tcp_sock_ < 0) {
        if (error != NULL) {
            *error = "TCP中转载体尚未连接";
        }
        return false;
    }
    if (tcp_direct_listen_port_ == 0) {
        if (error != NULL) {
            *error = "TCP直连监听不可用";
        }
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kTcpDirectAdvertisePayloadSize, 0);
    packet_tunnel::write_u16_be(payload.data(), tcp_direct_listen_port_);
    if (!SendFrameOverTcp(packet_tunnel::kFrameTcpDirectAdvertise,
                          payload.data(),
                          payload.size(),
                          error)) {
        return false;
    }

    LogInfo("已上报TCP直连监听端口=" +
            std::to_string(tcp_direct_listen_port_));

    size_t candidate_count = 0;
    ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {
        for (ifaddrs* ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL ||
                (ifa->ifa_flags & IFF_UP) == 0 ||
                (ifa->ifa_flags & IFF_LOOPBACK) != 0) {
                continue;
            }
            if (tun_manager_ != NULL &&
                ifa->ifa_name != NULL &&
                tun_manager_->GetIfName() == ifa->ifa_name) {
                continue;
            }

            TcpDirectCandidate candidate;
            candidate.endpoint_port = tcp_direct_listen_port_;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
                const uint32_t ip = ntohl(addr4->sin_addr.s_addr);
                if (ip == 0 ||
                    (ip & 0xff000000u) == 0x7f000000u ||
                    (ip & 0xffff0000u) == 0xa9fe0000u ||
                    (ip & 0xf0000000u) == 0xe0000000u ||
                    IsLinuxTunnelVirtualIpv4Candidate(addr4->sin_addr.s_addr,
                                                      virtual_ip_)) {
                    continue;
                }
                candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
                memcpy(candidate.endpoint_addr, &addr4->sin_addr, 4);
            } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr);
                if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) ||
                    IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
                    IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) ||
                    IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr)) {
                    continue;
                }
                candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv6;
                memcpy(candidate.endpoint_addr, &addr6->sin6_addr, 16);
            } else {
                continue;
            }

            if (SendTcpDirectCandidateAdvertise(candidate, NULL)) {
                ++candidate_count;
            }
        }
        freeifaddrs(interfaces);
    }

    LogInfo("TCP直连本地候选已上报，数量=" +
            std::to_string(candidate_count));
    return true;
}

bool LinuxPacketTunnelClient::SendTcpDirectCandidateAdvertise(
    const TcpDirectCandidate& candidate,
    std::string* error) {
    if (!tcp_connected_ || tcp_sock_ < 0) {
        if (error != NULL) {
            *error = "TCP中转载体尚未连接";
        }
        return false;
    }
    if (candidate.endpoint_port == 0 ||
        (candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv4 &&
         candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv6)) {
        if (error != NULL) {
            *error = "TCP直连候选无效";
        }
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kTcpDirectCandidateAdvertisePayloadSize, 0);
    payload[0] = candidate.endpoint_family;
    packet_tunnel::write_u16_be(payload.data() + 2, candidate.endpoint_port);
    memcpy(payload.data() + 4,
           candidate.endpoint_addr,
           candidate.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16);
    return SendFrameOverTcp(packet_tunnel::kFrameTcpDirectCandidateAdvertise,
                            payload.data(),
                            payload.size(),
                            error);
}

bool LinuxPacketTunnelClient::StartThreads(std::string* error) {
    if (tun_manager_ == NULL) {
        if (error != NULL) {
            *error = "tun manager is null";
        }
        return false;
    }

    socket_thread_ = std::thread(&LinuxPacketTunnelClient::SocketReadLoop, this);
    if (tcp_connected_ && tcp_sock_ >= 0) {
        tcp_thread_ = std::thread(&LinuxPacketTunnelClient::TcpSocketReadLoop, this);
    }
    if (tcp_direct_listen_sock_ >= 0) {
        tcp_direct_accept_thread_ =
            std::thread(&LinuxPacketTunnelClient::TcpDirectAcceptLoop, this);
    }
    tun_thread_ = std::thread(&LinuxPacketTunnelClient::TunReadLoop, this);
    heartbeat_thread_ = std::thread(&LinuxPacketTunnelClient::HeartbeatLoop, this);
    return true;
}

void LinuxPacketTunnelClient::StopTcpDirectSockets() {
    int listen_sock = -1;
    std::vector<std::shared_ptr<TcpDirectConnection>> connections;
    std::vector<std::thread> connect_threads;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        listen_sock = tcp_direct_listen_sock_;
        tcp_direct_listen_sock_ = -1;
        tcp_direct_listen_port_ = 0;
        for (std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator it =
                 tcp_direct_connections_.begin();
             it != tcp_direct_connections_.end();
             ++it) {
            connections.push_back(it->second);
        }
        tcp_direct_connections_.clear();
        tcp_direct_offers_.clear();
        connect_threads.swap(tcp_direct_connect_threads_);
    }

    CloseFdQuiet(&listen_sock);

    for (size_t i = 0; i < connections.size(); ++i) {
        if (!connections[i]) {
            continue;
        }
        connections[i]->active = false;
        CloseFdQuiet(&connections[i]->sock);
    }

    if (tcp_direct_accept_thread_.joinable()) {
        tcp_direct_accept_thread_.join();
    }
    for (size_t i = 0; i < connect_threads.size(); ++i) {
        if (!connect_threads[i].joinable()) {
            continue;
        }
        if (connect_threads[i].get_id() == std::this_thread::get_id()) {
            connect_threads[i].detach();
        } else {
            connect_threads[i].join();
        }
    }
}

void LinuxPacketTunnelClient::SocketReadLoop() {
    std::vector<uint8_t> buffer(65535);
    while (!stop_requested_) {
        std::string error;
        sockaddr_storage source_addr = {};
        socklen_t source_addr_len = sizeof(source_addr);
        int received = RecvDatagramFrom(buffer.data(),
                                        buffer.size(),
                                        &source_addr,
                                        &source_addr_len,
                                        &error);
        if (received < 0) {
            break;
        }
        if (received == 0) {
            continue;
        }

        if (received < static_cast<int>(packet_tunnel::kFrameHeaderSize)) {
            continue;
        }

        const bool from_server = IsServerEndpoint(source_addr, source_addr_len);
        std::string datagram_peer_virtual_ip;
        bool datagram_from_known_peer = !from_server &&
                                        TryResolvePeerBySource(source_addr,
                                                               source_addr_len,
                                                               &datagram_peer_virtual_ip);
        auto has_fresh_direct_route = [this](const std::string& candidate_peer_virtual_ip) -> bool {
            if (candidate_peer_virtual_ip.empty() || peer_link_manager_ == NULL) {
                return false;
            }

            LinuxPeerRouteStatus route = {};
            const unsigned long long current_ms = now_ms();
            if (!peer_link_manager_->TryGetDirectRoute(candidate_peer_virtual_ip,
                                                       current_ms,
                                                       kPeerDirectDataTimeoutMs,
                                                       kPeerDirectProbeGraceMs,
                                                       &route)) {
                return false;
            }
            return route.active_direct && IsDirectPathFresh(route, current_ms);
        };

        size_t frame_offset = 0;
        bool datagram_valid = true;
        while (frame_offset < static_cast<size_t>(received)) {
            uint8_t frame_type = 0;
            uint16_t payload_len = 0;
            const uint8_t* payload = NULL;
            if (!TryConsumePacketTunnelFrame(buffer.data(),
                                             static_cast<size_t>(received),
                                             &frame_offset,
                                             &frame_type,
                                             &payload,
                                             &payload_len)) {
                datagram_valid = false;
                break;
            }

            std::string peer_virtual_ip = datagram_peer_virtual_ip;
            bool from_known_peer = datagram_from_known_peer;
            bool learned_direct_probe = false;
            bool learned_direct_endpoint_changed = false;

            if (from_server) {
                last_receive_ms_ = now_ms();
                MarkNetworkActivity();

                if (frame_type == packet_tunnel::kFrameHeartbeatAck) {
                    continue;
                }

                if (HandlePeerControlFrame(frame_type, payload, payload_len)) {
                    continue;
                }
            }

            if (frame_type == packet_tunnel::kFrameIpv4Packet && tun_manager_ != NULL) {
            uint8_t probe_type = 0;
            const bool is_direct_probe =
                ParseLinuxPeerDirectProbePacket(payload, payload_len, &probe_type);
            const bool has_inner_ipv4 =
                payload_len >= 20 && ((payload[0] >> 4) & 0x0F) == 4;
            const bool inner_is_udp =
                has_inner_ipv4 && payload[9] == IPPROTO_UDP;
            const std::string inner_src_virtual_ip =
                has_inner_ipv4 ? LinuxIpv4ToString(payload + 12) : std::string();
            const std::string inner_dst_virtual_ip =
                has_inner_ipv4 ? LinuxIpv4ToString(payload + 16) : std::string();
            uint16_t inner_src_port = 0;
            uint16_t inner_dst_port = 0;
            if (inner_is_udp) {
                TryParseLinuxUdpPorts(payload,
                                      payload_len,
                                      &inner_src_port,
                                      &inner_dst_port);
            }
            std::string relay_peer_virtual_ip;
            if (from_server &&
                inner_is_udp &&
                inner_dst_virtual_ip == virtual_ip_ &&
                peer_link_manager_ != NULL &&
                !inner_src_virtual_ip.empty() &&
                peer_link_manager_->CanRouteDirect(inner_src_virtual_ip)) {
                relay_peer_virtual_ip = inner_src_virtual_ip;
            }
            if (!from_server && !from_known_peer && is_direct_probe && peer_link_manager_ != NULL &&
                payload_len >= 20) {
                const std::string inferred_peer_virtual_ip = LinuxIpv4ToString(payload + 12);
                const std::string inferred_local_virtual_ip = LinuxIpv4ToString(payload + 16);
                uint8_t endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
                uint16_t endpoint_port = 0;
                uint8_t endpoint_addr[16] = {};
                if (!inferred_peer_virtual_ip.empty() &&
                    inferred_peer_virtual_ip != virtual_ip_ &&
                    inferred_local_virtual_ip == virtual_ip_ &&
                    TryExtractLinuxPeerEndpointFromSockaddr(source_addr,
                                                           &endpoint_family,
                                                           endpoint_addr,
                                                           &endpoint_port) &&
                    peer_link_manager_->ObserveDirectEndpoint(inferred_peer_virtual_ip,
                                                              endpoint_family,
                                                              endpoint_addr,
                                                              endpoint_port,
                                                              &learned_direct_endpoint_changed,
                                                              NULL)) {
                    peer_virtual_ip = inferred_peer_virtual_ip;
                    from_known_peer = true;
                    datagram_peer_virtual_ip = peer_virtual_ip;
                    datagram_from_known_peer = true;
                    learned_direct_probe = true;
                    LogInfo("通过直连探测学习到对端地址: 对端=" + peer_virtual_ip +
                            " 来源=" + LinuxSockaddrToString(source_addr, source_addr_len) +
                            (learned_direct_endpoint_changed ? " 已变化=是" : " 已变化=否"));
                }
            }
            if (!from_server && !from_known_peer) {
                LogWarn("忽略来自未知端点的IPv4数据包: 来源=" +
                        LinuxSockaddrToString(source_addr, source_addr_len));
                continue;
            }
            if (from_known_peer &&
                (payload_len < 20 ||
                 LinuxIpv4ToString(payload + 12) != peer_virtual_ip)) {
                LogWarn("忽略内部源地址不匹配的对端IPv4数据包: 对端=" + peer_virtual_ip);
                continue;
            }
            if (from_known_peer) {
                datagram_peer_virtual_ip = peer_virtual_ip;
                datagram_from_known_peer = true;
                if (inner_is_udp) {
                    LearnPeerUdpPortOwner(peer_virtual_ip, inner_src_port);
                }
                MarkNetworkActivity();
                if (peer_link_manager_ != NULL) {
                    peer_link_manager_->TouchPeerDirectData(peer_virtual_ip, 0);
                }
                if (is_direct_probe) {
                    if (probe_type == kPeerDirectProbeRequest) {
                        uint32_t peer_virtual_ip_be = 0;
                        uint32_t local_virtual_ip_be = ParseVirtualIp(NULL);
                        if (local_virtual_ip_be != 0 &&
                            ParseLinuxIpv4StringToBe(peer_virtual_ip, &peer_virtual_ip_be)) {
                            std::vector<uint8_t> probe_response;
                            if (BuildLinuxPeerDirectProbePacket(local_virtual_ip_be,
                                                                peer_virtual_ip_be,
                                                                kPeerDirectProbeResponse,
                                                                &probe_response)) {
                                UdpEndpoint reply_endpoint;
                                reply_endpoint.addr = source_addr;
                                reply_endpoint.addr_len = source_addr_len;
                                reply_endpoint.valid = true;
                                SendFrameToEndpoint(reply_endpoint,
                                                    packet_tunnel::kFrameIpv4Packet,
                                                    probe_response.data(),
                                                    probe_response.size(),
                                                    NULL);
                            }
                        }
                    }
                    if (learned_direct_probe) {
                        MaybeLogDirectRouteFallback(peer_virtual_ip,
                                                    learned_direct_endpoint_changed
                                                        ? "probe_endpoint_updated"
                                                        : "probe_endpoint_confirmed");
                    }
                    continue;
                }
                if (!has_fresh_direct_route(peer_virtual_ip)) {
                    continue;
                }
            } else {
                if (!relay_peer_virtual_ip.empty()) {
                    LearnPeerUdpPortOwner(relay_peer_virtual_ip, inner_src_port);
                }
                if (inner_is_udp &&
                    payload_len >= 20 &&
                    has_fresh_direct_route(LinuxIpv4ToString(payload + 12))) {
                    continue;
                }
            }
            const bool should_log_focused_udp = IsFocusedLinuxGameUdpPacket(payload, payload_len);
            std::string udp_desc;
            if (should_log_focused_udp) {
                TryDescribeLinuxUdpPacket(payload, payload_len, &udp_desc);
            }

            std::string tun_error;
            if (!tun_manager_->WritePacket(payload, payload_len, &tun_error)) {
                if (should_log_focused_udp && !udp_desc.empty()) {
                    LogWarn(std::string(from_known_peer ? "UDP 对端->TUN 写入失败 " :
                                                           "UDP 中转->TUN 写入失败 ") +
                            udp_desc + " 错误=" + tun_error);
                } else {
                    LogWarn("写入TUN失败: " + tun_error);
                }
                continue;
            }

            if (should_log_focused_udp && !udp_desc.empty()) {
                LogDebug(std::string(from_known_peer ? "UDP 对端->TUN " : "UDP 中转->TUN ") +
                        udp_desc);
            }
            TraceWatchedTcpPacket(payload,
                                  payload_len,
                                  from_known_peer ? "peer->tun" : "tunnel->tun");
            continue;
        }
        }
        if (!datagram_valid) {
            continue;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

bool LinuxPacketTunnelClient::HandlePeerControlFrame(uint8_t frame_type,
                                                     const uint8_t* payload,
                                                     size_t length) {
    if (frame_type == packet_tunnel::kFrameTcpPeerOffer) {
        ParsedLinuxPeerOffer offer = {};
        if (!ParseLinuxPeerOfferPayload(payload, length, &offer)) {
            LogWarn("忽略无效的TCP对等提议帧，长度=" + std::to_string(length));
            return true;
        }
        if (offer.peer_virtual_ip.empty() ||
            offer.peer_virtual_ip == virtual_ip_ ||
            offer.endpoint_port == 0) {
            LogDebug("忽略不可用的TCP对等提议: 对端=" +
                    offer.peer_virtual_ip +
                    " 端点=" + offer.endpoint);
            return true;
        }

        bool changed = false;
        {
            std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
            TcpDirectOffer& stored = tcp_direct_offers_[offer.peer_virtual_ip];
            if (stored.endpoint_version != 0 &&
                offer.endpoint_version < stored.endpoint_version) {
                LogDebug("忽略过期的TCP对等提议: 对端=" +
                        offer.peer_virtual_ip +
                        " 版本=" + std::to_string(offer.endpoint_version));
                return true;
            }
            std::vector<TcpDirectCandidate> previous_candidates;
            if (stored.endpoint_version != offer.endpoint_version) {
                previous_candidates = stored.candidates;
                stored.candidates.clear();
                stored.next_candidate_index = 0;
                changed = true;
            }
            TcpDirectCandidate candidate;
            candidate.endpoint_family = offer.endpoint_family;
            candidate.endpoint_port = offer.endpoint_port;
            memcpy(candidate.endpoint_addr,
                   offer.endpoint_addr,
                   sizeof(candidate.endpoint_addr));
            for (size_t i = 0; i < previous_candidates.size(); ++i) {
                const TcpDirectCandidate& previous = previous_candidates[i];
                const size_t addr_len =
                    previous.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16;
                if (previous.endpoint_family == candidate.endpoint_family &&
                    previous.endpoint_port == candidate.endpoint_port &&
                    memcmp(previous.endpoint_addr,
                           candidate.endpoint_addr,
                           addr_len) == 0) {
                    candidate.success_count = previous.success_count;
                    candidate.failure_count = previous.failure_count;
                    candidate.last_success_ms = previous.last_success_ms;
                    candidate.last_failure_ms = previous.last_failure_ms;
                    candidate.last_connect_ms = previous.last_connect_ms;
                    break;
                }
            }
            bool candidate_found = false;
            for (size_t i = 0; i < stored.candidates.size(); ++i) {
                const TcpDirectCandidate& existing = stored.candidates[i];
                const size_t addr_len =
                    existing.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16;
                if (existing.endpoint_family == candidate.endpoint_family &&
                    existing.endpoint_port == candidate.endpoint_port &&
                    memcmp(existing.endpoint_addr,
                           candidate.endpoint_addr,
                           addr_len) == 0) {
                    candidate_found = true;
                    break;
                }
            }
            if (!candidate_found) {
                stored.candidates.push_back(candidate);
                changed = true;
            }
            if (stored.endpoint_port == 0 || changed) {
                stored.endpoint_family = offer.endpoint_family;
                stored.endpoint_port = offer.endpoint_port;
                memcpy(stored.endpoint_addr,
                       offer.endpoint_addr,
                       sizeof(stored.endpoint_addr));
            }
            stored.endpoint_version = offer.endpoint_version;
            stored.last_offer_ms = now_ms();
            if (changed) {
                stored.cooldown_until_ms = 0;
                stored.connecting = false;
            }
        }

        const unsigned long long tick = now_ms();
        if (changed) {
            LogDebug("对等端控制 TCP对等提议: 对端=" +
                    offer.peer_virtual_ip +
                    " 版本=" + std::to_string(offer.endpoint_version) +
                    " 端点=" + offer.endpoint +
                    " 已变化=是");
            MarkPeerWarmupWindow(offer.peer_virtual_ip);
            if (ShouldAutoWarmTcpPeer(offer.peer_virtual_ip, tick)) {
                MaybeStartTcpDirectConnect(offer.peer_virtual_ip);
            }
        } else if (ShouldLogPeerControlEvent("stable_tcp_offer:" + offer.peer_virtual_ip,
                                             tick,
                                             static_cast<unsigned long long>(kPeerSnapshotLogIntervalMs))) {
            LogDebug("对等端控制 忽略稳定的TCP对等提议: 对端=" +
                    offer.peer_virtual_ip +
                    " 版本=" + std::to_string(offer.endpoint_version));
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerOffer) {
        ParsedLinuxPeerOffer offer = {};
        if (!ParseLinuxPeerOfferPayload(payload, length, &offer)) {
            LogWarn("忽略无效的对等提议帧，长度=" + std::to_string(length));
            return true;
        }
        bool should_send_hello = true;
        if (peer_link_manager_ != NULL) {
            should_send_hello = peer_link_manager_->UpdatePeerOffer(offer.peer_virtual_ip,
                                                                    offer.endpoint_version,
                                                                    offer.endpoint_family,
                                                                    offer.endpoint_addr,
                                                                    offer.endpoint_port);
        }
        if (!should_send_hello) {
            const unsigned long long tick = now_ms();
            if (ShouldLogPeerControlEvent("stable_udp_offer:" + offer.peer_virtual_ip,
                                          tick,
                                          static_cast<unsigned long long>(kPeerSnapshotLogIntervalMs))) {
                LogDebug("对等端控制 忽略稳定的对等提议: 对端=" + offer.peer_virtual_ip +
                        " 版本=" + std::to_string(offer.endpoint_version));
            }
            return true;
        }
        LogDebug("对等端控制 对等提议: 对端=" + offer.peer_virtual_ip +
                " 版本=" + std::to_string(offer.endpoint_version) +
                " 端点=" + offer.endpoint);
        MarkPeerWarmupWindow(offer.peer_virtual_ip);
        const uint32_t nonce = peer_signal_nonce_.fetch_add(1);
        if (SendPeerSignalFrame(packet_tunnel::kFramePeerHello,
                                offer.peer_virtual_ip,
                                offer.endpoint_version,
                                nonce)) {
            if (peer_link_manager_ != NULL) {
                peer_link_manager_->RecordPeerHelloSent(offer.peer_virtual_ip,
                                                        offer.endpoint_version,
                                                        nonce);
            }
            LogDebug("对等端控制 发送对等问候: 对端=" + offer.peer_virtual_ip +
                    " 版本=" + std::to_string(offer.endpoint_version) +
                    " 随机数=" + std::to_string(nonce));
        } else {
            LogWarn("对等端控制 发送对等问候失败: 对端=" + offer.peer_virtual_ip +
                    " 版本=" + std::to_string(offer.endpoint_version) +
                    " 随机数=" + std::to_string(nonce));
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerHello ||
        frame_type == packet_tunnel::kFramePeerAck ||
        frame_type == packet_tunnel::kFramePeerKeepalive) {
        ParsedLinuxPeerSignal signal = {};
        if (!ParseLinuxPeerSignalPayload(payload, length, &signal)) {
            LogWarn("忽略无效的" + LinuxFrameName(frame_type) +
                    "帧，长度=" + std::to_string(length));
            return true;
        }

        if (peer_link_manager_ != NULL) {
            if (frame_type == packet_tunnel::kFramePeerHello) {
                peer_link_manager_->MarkPeerProbing(signal.peer_virtual_ip, signal.endpoint_version);
            } else if (frame_type == packet_tunnel::kFramePeerAck) {
                if (!peer_link_manager_->TryPromotePeerDirectReady(signal.peer_virtual_ip,
                                                                   signal.endpoint_version,
                                                                   signal.nonce)) {
                    LogDebug("对等端控制 忽略非预期的对等确认: 对端=" + signal.peer_virtual_ip +
                            " 版本=" + std::to_string(signal.endpoint_version) +
                            " 随机数=" + std::to_string(signal.nonce));
                    return true;
                }
            } else {
                peer_link_manager_->TouchPeer(signal.peer_virtual_ip, signal.endpoint_version);
            }
        }

        LogDebug("对等端控制 " + LinuxFrameName(frame_type) +
                ": 对端=" + signal.peer_virtual_ip +
                " 版本=" + std::to_string(signal.endpoint_version) +
                " 随机数=" + std::to_string(signal.nonce));
        if (frame_type == packet_tunnel::kFramePeerHello) {
            if (SendPeerSignalFrame(packet_tunnel::kFramePeerAck,
                                    signal.peer_virtual_ip,
                                    signal.endpoint_version,
                                    signal.nonce)) {
                LogDebug("对等端控制 发送对等确认: 对端=" + signal.peer_virtual_ip +
                        " 版本=" + std::to_string(signal.endpoint_version) +
                        " 随机数=" + std::to_string(signal.nonce));
            } else {
                LogWarn("对等端控制 发送对等确认失败: 对端=" + signal.peer_virtual_ip +
                        " 版本=" + std::to_string(signal.endpoint_version) +
                        " 随机数=" + std::to_string(signal.nonce));
            }
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerDisable) {
        ParsedLinuxPeerDisable disable = {};
        if (!ParseLinuxPeerDisablePayload(payload, length, &disable)) {
            LogWarn("忽略无效的对等端禁用帧，长度=" + std::to_string(length));
            return true;
        }
        if (peer_link_manager_ != NULL) {
            peer_link_manager_->MarkPeerCooldown(disable.peer_virtual_ip,
                                                 disable.endpoint_version);
        }
        LogInfo("对等端控制 对等端禁用: 对端=" + disable.peer_virtual_ip +
                " 版本=" + std::to_string(disable.endpoint_version) +
                " 原因=" + std::to_string(disable.reason));
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

bool LinuxPacketTunnelClient::SendPeerDisableFrame(const std::string& target_peer_virtual_ip,
                                                   uint64_t endpoint_version,
                                                   uint8_t reason) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseLinuxIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerDisablePayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    payload[12] = reason;
    return SendFrame(packet_tunnel::kFramePeerDisable, payload.data(), payload.size(), NULL);
}

bool LinuxPacketTunnelClient::TryBuildPeerEndpoint(const std::string& peer_virtual_ip,
                                                   UdpEndpoint* endpoint,
                                                   bool* direct_path_fresh,
                                                   bool* active_direct) const {
    if (endpoint == NULL || peer_link_manager_ == NULL) {
        return false;
    }

    LinuxPeerRouteStatus route = {};
    if (!peer_link_manager_->TryGetDirectRoute(peer_virtual_ip,
                                               now_ms(),
                                               kPeerDirectDataTimeoutMs,
                                               kPeerDirectProbeGraceMs,
                                               &route)) {
        return false;
    }
    if (direct_path_fresh != NULL) {
        *direct_path_fresh = IsDirectPathFresh(route, now_ms());
    }
    if (active_direct != NULL) {
        *active_direct = route.active_direct;
    }

    memset(&endpoint->addr, 0, sizeof(endpoint->addr));
    endpoint->addr_len = 0;
    endpoint->valid = false;

    if (socket_family_ == AF_INET && route.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&endpoint->addr);
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(route.endpoint_port);
        memcpy(&addr4->sin_addr, route.endpoint_addr, 4);
        endpoint->addr_len = sizeof(sockaddr_in);
        endpoint->valid = true;
        return true;
    }

    if (socket_family_ == AF_INET6) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&endpoint->addr);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(route.endpoint_port);
        if (route.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv6) {
            memcpy(&addr6->sin6_addr, route.endpoint_addr, 16);
            endpoint->addr_len = sizeof(sockaddr_in6);
            endpoint->valid = true;
            return true;
        }
        if (route.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4) {
            memset(&addr6->sin6_addr, 0, sizeof(addr6->sin6_addr));
            addr6->sin6_addr.s6_addr[10] = 0xFF;
            addr6->sin6_addr.s6_addr[11] = 0xFF;
            memcpy(&addr6->sin6_addr.s6_addr[12], route.endpoint_addr, 4);
            endpoint->addr_len = sizeof(sockaddr_in6);
            endpoint->valid = true;
            return true;
        }
    }

    return false;
}

bool LinuxPacketTunnelClient::TryResolvePeerByCandidateAddress(const std::string& dst_virtual_ip,
                                                               std::string* peer_virtual_ip,
                                                               std::string* resolution) const {
    if (peer_virtual_ip != NULL) {
        peer_virtual_ip->clear();
    }
    if (resolution != NULL) {
        resolution->clear();
    }
    if (peer_link_manager_ == NULL || dst_virtual_ip.empty()) {
        return false;
    }

    uint32_t dst_ip_be = 0;
    if (!ParseLinuxIpv4StringToBe(dst_virtual_ip, &dst_ip_be)) {
        return false;
    }

    uint8_t endpoint_addr[16] = {};
    memcpy(endpoint_addr, &dst_ip_be, sizeof(dst_ip_be));
    LinuxPeerRouteStatus route = {};
    if (!peer_link_manager_->TryResolveUniquePeerByAddress(packet_tunnel::kPeerEndpointFamilyIpv4,
                                                           endpoint_addr,
                                                           &route) ||
        route.peer_virtual_ip.empty() ||
        route.peer_virtual_ip == virtual_ip_) {
        return false;
    }

    if (peer_virtual_ip != NULL) {
        *peer_virtual_ip = route.peer_virtual_ip;
    }
    if (resolution != NULL) {
        *resolution = "candidate_address";
    }
    return true;
}

bool TryParseLinuxUdpPorts(const uint8_t* packet,
                           size_t packet_len,
                           uint16_t* src_port,
                           uint16_t* dst_port) {
    if (src_port != NULL) {
        *src_port = 0;
    }
    if (dst_port != NULL) {
        *dst_port = 0;
    }
    if (packet == NULL || packet_len < 20 || ((packet[0] >> 4) & 0x0F) != 4) {
        return false;
    }
    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 ||
        packet_len < ip_header_len + 8 ||
        packet[9] != IPPROTO_UDP) {
        return false;
    }
    if (src_port != NULL) {
        *src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    }
    if (dst_port != NULL) {
        *dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    }
    return true;
}

bool LinuxPacketTunnelClient::TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                                     socklen_t source_addr_len,
                                                     std::string* peer_virtual_ip) const {
    (void)source_addr_len;
    if (peer_link_manager_ == NULL) {
        return false;
    }

    uint8_t endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
    uint16_t endpoint_port = 0;
    uint8_t endpoint_addr[16] = {};
    if (!TryExtractLinuxPeerEndpointFromSockaddr(source_addr,
                                                 &endpoint_family,
                                                 endpoint_addr,
                                                 &endpoint_port)) {
        return false;
    }

    LinuxPeerRouteStatus route = {};
    if (!peer_link_manager_->TryResolveByEndpoint(endpoint_family,
                                                  endpoint_addr,
                                                  endpoint_port,
                                                  &route)) {
        return false;
    }

    if (peer_virtual_ip != NULL) {
        *peer_virtual_ip = route.peer_virtual_ip;
    }
    return true;
}

bool LinuxPacketTunnelClient::IsServerEndpoint(const sockaddr_storage& source_addr,
                                               socklen_t source_addr_len) const {
    if (!server_endpoint_.valid) {
        return false;
    }
    return LinuxSockaddrEquals(source_addr,
                               source_addr_len,
                               server_endpoint_.addr,
                               server_endpoint_.addr_len);
}

void LinuxPacketTunnelClient::LearnPeerUdpPortOwner(const std::string& peer_virtual_ip,
                                                    uint16_t src_port) {
    if (peer_virtual_ip.empty() ||
        peer_virtual_ip == virtual_ip_ ||
        src_port == 0 ||
        IsKnownLinuxGameUdpPort(src_port) ||
        IsReservedLinuxPeerDirectPort(src_port)) {
        return;
    }

    PeerUdpPortOwner& owner = peer_udp_port_owners_[src_port];
    owner.peer_virtual_ip = peer_virtual_ip;
    owner.last_seen_ms = now_ms();
}

bool LinuxPacketTunnelClient::TryResolveGatewayUdpPeerTarget(const std::string& dst_virtual_ip,
                                                             uint16_t dst_port,
                                                             std::string* peer_virtual_ip,
                                                             std::string* resolution) const {
    if (peer_virtual_ip != NULL) {
        peer_virtual_ip->clear();
    }
    if (resolution != NULL) {
        resolution->clear();
    }
    if (dst_port == 0 || peer_link_manager_ == NULL || dst_virtual_ip.empty()) {
        return false;
    }

    if (!kEnableLinuxGatewayUdpPeerHeuristics) {
        if (resolution != NULL) {
            *resolution = "route_only";
        }
        return false;
    }

    const unsigned long long tick = now_ms();
    const std::vector<LinuxPeerRouteStatus> peers = peer_link_manager_->Snapshot();
    if (!IsLinuxGatewayPeerResolveCandidate(virtual_ip_, dst_virtual_ip, peers)) {
        if (resolution != NULL) {
            *resolution = "ineligible_dst";
        }
        return false;
    }

    size_t candidate_count = 0;
    std::string sole_candidate_peer_virtual_ip;
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip.empty() ||
            peers[i].peer_virtual_ip == virtual_ip_ ||
            peers[i].state == LinuxPeerRouteState::Cooldown ||
            !peers[i].direct_ready ||
            peers[i].endpoint_family == packet_tunnel::kPeerEndpointFamilyUnknown ||
            peers[i].endpoint_port == 0) {
            continue;
        }
        ++candidate_count;
        if (candidate_count == 1) {
            sole_candidate_peer_virtual_ip = peers[i].peer_virtual_ip;
        } else {
            sole_candidate_peer_virtual_ip.clear();
        }
    }
    if (candidate_count == 1 && !sole_candidate_peer_virtual_ip.empty()) {
        if (peer_virtual_ip != NULL) {
            *peer_virtual_ip = sole_candidate_peer_virtual_ip;
        }
        if (resolution != NULL) {
            *resolution = "single_candidate";
        }
        return true;
    }

    std::map<uint16_t, PeerUdpPortOwner>::const_iterator owner_it =
        peer_udp_port_owners_.find(dst_port);
    if (owner_it == peer_udp_port_owners_.end()) {
        return false;
    }

    const PeerUdpPortOwner& owner = owner_it->second;
    if (owner.last_seen_ms == 0 ||
        tick < owner.last_seen_ms ||
        (tick - owner.last_seen_ms) > kLinuxGatewayUdpPortOwnerTtlMs ||
        owner.peer_virtual_ip.empty() ||
        owner.peer_virtual_ip == virtual_ip_) {
        return false;
    }

    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip != owner.peer_virtual_ip ||
            peers[i].state == LinuxPeerRouteState::Cooldown ||
            !peers[i].direct_ready ||
            peers[i].endpoint_family == packet_tunnel::kPeerEndpointFamilyUnknown ||
            peers[i].endpoint_port == 0) {
            continue;
        }
        if (peer_virtual_ip != NULL) {
            *peer_virtual_ip = owner.peer_virtual_ip;
        }
        if (resolution != NULL) {
            *resolution = "port_owner";
        }
        return true;
    }

    return false;
}

bool LinuxPacketTunnelClient::SendFrameToEndpoint(const UdpEndpoint& endpoint,
                                                  uint8_t frame_type,
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
    return SendDatagramToEndpoint(endpoint, frame.data(), frame.size(), error);
}

bool LinuxPacketTunnelClient::SendDatagramToEndpoint(const UdpEndpoint& endpoint,
                                                     const uint8_t* data,
                                                     size_t length,
                                                     std::string* error) {
    if (!endpoint.valid) {
        if (error != NULL) {
            *error = "数据隧道发送目标无效";
        }
        return false;
    }

    int last_error = 0;
    for (int attempt = 0; attempt < kSocketSendRetryCount; ++attempt) {
        ssize_t n = sendto(sock_,
                           data,
                           length,
                           0,
                           reinterpret_cast<const sockaddr*>(&endpoint.addr),
                           endpoint.addr_len);
        if (n == static_cast<ssize_t>(length)) {
            MarkNetworkActivity();
            return true;
        }

        last_error = errno;
        if (IsLinuxTransientSendError(last_error) && attempt + 1 < kSocketSendRetryCount) {
            usleep(kSocketSendRetryDelayMs * 1000);
            continue;
        }
        if (!IsLinuxTransientSendError(last_error)) {
            if (error != NULL) {
                *error = std::string("数据隧道发送失败: ") + strerror(last_error);
            }
            return false;
        }
        break;
    }

    LogWarn("数据隧道发送在短暂阻塞后丢弃: 错误=" +
            std::string(strerror(last_error)));
    if (error != NULL) {
        *error = std::string("数据隧道发送已丢弃: ") + strerror(last_error);
    }
    return true;
}

int LinuxPacketTunnelClient::RecvDatagramFrom(uint8_t* data,
                                              size_t length,
                                              sockaddr_storage* source_addr,
                                              socklen_t* source_addr_len,
                                              std::string* error) {
    socklen_t addr_len = static_cast<socklen_t>(sizeof(sockaddr_storage));
    if (source_addr_len != NULL && *source_addr_len > 0) {
        addr_len = *source_addr_len;
    }
    ssize_t n = recvfrom(sock_,
                         data,
                         length,
                         0,
                         (source_addr != NULL) ? reinterpret_cast<sockaddr*>(source_addr) : NULL,
                         (source_addr_len != NULL) ? &addr_len : NULL);
    if (source_addr_len != NULL) {
        *source_addr_len = addr_len;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ECONNREFUSED || errno == ECONNRESET) {
            return 0;
        }
        if (error != NULL) {
            *error = std::string("数据隧道接收失败: ") + strerror(errno);
        }
        return -1;
    }
    if (n == 0) {
        if (error != NULL) {
            *error = "数据隧道对端已关闭";
        }
        return -1;
    }
    return static_cast<int>(n);
}

void LinuxPacketTunnelClient::TcpSocketReadLoop() {
    while (!stop_requested_ && tcp_connected_) {
        uint8_t header[packet_tunnel::kFrameHeaderSize] = {};
        std::string error;
        if (!RecvTcpExact(header, sizeof(header), &error)) {
            if (!stop_requested_ && tcp_connected_ && !error.empty()) {
                LogWarn("TCP中转载体读取已停止: " + error);
            }
            break;
        }

        const uint8_t frame_type = header[0];
        const uint16_t payload_len = ntohs(*(const uint16_t*)(&header[1]));
        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0 &&
            !RecvTcpExact(payload.data(), payload_len, &error)) {
            if (!stop_requested_ && tcp_connected_ && !error.empty()) {
                LogWarn("TCP中转载体负载读取已停止: " + error);
            }
            break;
        }

        last_receive_ms_ = now_ms();
        MarkNetworkActivity();
        if (frame_type == packet_tunnel::kFrameHeartbeatAck) {
            continue;
        }
        if (HandlePeerControlFrame(frame_type, payload.data(), payload.size())) {
            continue;
        }
        if (frame_type != packet_tunnel::kFrameIpv4Packet || tun_manager_ == NULL) {
            LogDebug("忽略TCP中转载体帧: 类型=" + std::to_string(frame_type) +
                    " 长度=" + std::to_string(payload.size()));
            continue;
        }

        std::string tun_error;
        if (!tun_manager_->WritePacket(payload.data(), payload.size(), &tun_error)) {
            if (!stop_requested_) {
                LogWarn("TCP中转载体写入TUN失败: " + tun_error);
            }
            continue;
        }

        TraceWatchedTcpPacket(payload.data(), payload.size(), "tunnel->tun/tcp");
    }

    const int stale_sock = tcp_sock_;
    tcp_connected_ = false;
    if (stale_sock >= 0) {
        close(stale_sock);
        if (tcp_sock_ == stale_sock) {
            tcp_sock_ = -1;
        }
    }
}

bool LinuxPacketTunnelClient::RecvFrameFromSocket(int sock,
                                                  uint8_t* frame_type,
                                                  std::vector<uint8_t>* payload,
                                                  std::string* error) {
    if (sock < 0 || frame_type == NULL || payload == NULL) {
        if (error != NULL) {
            *error = "TCP直连接收参数无效";
        }
        return false;
    }

    auto recv_exact = [&](uint8_t* data, size_t length) -> bool {
        size_t received = 0;
        while (received < length && !stop_requested_) {
            ssize_t n = recv(sock,
                             data + received,
                             length - received,
                             0);
            if (n > 0) {
                received += static_cast<size_t>(n);
                continue;
            }
            if (n == 0) {
                if (error != NULL) {
                    *error = "TCP直连对端已关闭";
                }
                return false;
            }
            if ((errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) &&
                !stop_requested_) {
                continue;
            }
            if (error != NULL) {
                *error = std::string("TCP直连接收失败: ") + strerror(errno);
            }
            return false;
        }
        return received == length;
    };

    uint8_t header[packet_tunnel::kFrameHeaderSize] = {};
    if (!recv_exact(header, sizeof(header))) {
        return false;
    }

    *frame_type = header[0];
    const uint16_t payload_len = ntohs(*(const uint16_t*)(&header[1]));
    payload->assign(payload_len, 0);
    if (payload_len > 0 && !recv_exact(payload->data(), payload_len)) {
        return false;
    }
    return true;
}

bool LinuxPacketTunnelClient::SendFrameOverSocket(int sock,
                                                  std::mutex* send_mutex,
                                                  uint8_t frame_type,
                                                  const uint8_t* data,
                                                  size_t length,
                                                  std::string* error) {
    if (sock < 0 || length > 0xFFFFu) {
        if (error != NULL) {
            *error = "TCP直连发送参数无效";
        }
        return false;
    }

    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons(static_cast<uint16_t>(length));
    if (length > 0 && data != NULL) {
        memcpy(frame.data() + packet_tunnel::kFrameHeaderSize, data, length);
    }

    std::unique_lock<std::mutex> lock;
    if (send_mutex != NULL) {
        lock = std::unique_lock<std::mutex>(*send_mutex);
    }

    size_t sent = 0;
    int transient_retries = 0;
    int last_error = 0;
    while (sent < frame.size() && !stop_requested_) {
        ssize_t n = send(sock,
                         frame.data() + sent,
                         frame.size() - sent,
                         MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            transient_retries = 0;
            continue;
        }
        last_error = errno;
        if ((last_error == EINTR || last_error == EAGAIN || last_error == EWOULDBLOCK) &&
            transient_retries + 1 < kSocketSendRetryCount) {
            ++transient_retries;
            usleep(kSocketSendRetryDelayMs * 1000);
            continue;
        }
        break;
    }

    if (sent == frame.size()) {
        return true;
    }
    if (error != NULL) {
        if (last_error != 0) {
            *error = std::string("TCP直连发送失败: ") + strerror(last_error);
        } else {
            *error = "TCP直连发送被中断";
        }
    }
    return false;
}

void LinuxPacketTunnelClient::TcpDirectAcceptLoop() {
    while (!stop_requested_) {
        const int listen_sock = tcp_direct_listen_sock_;
        if (listen_sock < 0) {
            break;
        }

        sockaddr_storage peer_addr = {};
        socklen_t peer_addr_len = sizeof(peer_addr);
        int accepted = accept(listen_sock,
                              reinterpret_cast<sockaddr*>(&peer_addr),
                              &peer_addr_len);
        if (accepted < 0) {
            if (!stop_requested_ &&
                errno != EBADF &&
                errno != EINTR &&
                errno != EAGAIN &&
                errno != EWOULDBLOCK) {
                LogWarn("接受TCP直连接入失败: " +
                        std::string(strerror(errno)));
            }
            continue;
        }
        if (stop_requested_) {
            close(accepted);
            break;
        }

        ConfigureLinuxTcpStreamSocket(accepted);
        std::shared_ptr<TcpDirectConnection> connection =
            std::make_shared<TcpDirectConnection>();
        connection->sock = accepted;
        connection->active = true;
        connection->read_thread =
            std::thread(&LinuxPacketTunnelClient::TcpDirectReadLoop, this, connection, true);
        connection->read_thread.detach();
        LogDebug("已接受TCP直连接入，来源=" +
                LinuxSockaddrToString(peer_addr, peer_addr_len));
    }
}

void LinuxPacketTunnelClient::TcpDirectReadLoop(
    const std::shared_ptr<TcpDirectConnection>& connection,
    bool expect_open_frame) {
    if (!connection) {
        return;
    }

    const int socket_for_remove = connection->sock;
    std::string peer_virtual_ip = connection->peer_virtual_ip;

    if (expect_open_frame) {
        uint8_t open_frame_type = 0;
        std::vector<uint8_t> open_payload;
        std::string open_error;
        if (!RecvFrameFromSocket(connection->sock,
                                 &open_frame_type,
                                 &open_payload,
                                 &open_error) ||
            open_frame_type != packet_tunnel::kFrameTcpDirectOpen ||
            open_payload.size() != packet_tunnel::kTcpDirectOpenPayloadSize) {
            if (!stop_requested_) {
                LogDebug("TCP直连接入打开失败: " + open_error);
            }
            CloseFdQuiet(&connection->sock);
            connection->active = false;
            return;
        }

        const std::string src_virtual_ip = LinuxIpv4ToString(open_payload.data());
        const std::string dst_virtual_ip = LinuxIpv4ToString(open_payload.data() + 4);
        if (src_virtual_ip.empty() ||
            src_virtual_ip == virtual_ip_ ||
            dst_virtual_ip != virtual_ip_) {
            LogDebug("拒绝TCP直连接入，来源=" +
                    src_virtual_ip +
                    " 目标=" + dst_virtual_ip);
            CloseFdQuiet(&connection->sock);
            connection->active = false;
            return;
        }

        connection->peer_virtual_ip = src_virtual_ip;
        peer_virtual_ip = src_virtual_ip;
        RegisterTcpDirectConnection(peer_virtual_ip, connection, true);
    }

    while (!stop_requested_ && connection->active && connection->sock >= 0) {
        uint8_t frame_type = 0;
        std::vector<uint8_t> payload;
        std::string error;
        if (!RecvFrameFromSocket(connection->sock, &frame_type, &payload, &error)) {
            if (!stop_requested_ && !error.empty()) {
                LogDebug("TCP直连读取结束，对端=" +
                        (peer_virtual_ip.empty() ? std::string("?") : peer_virtual_ip) +
                        " 原因=" + error);
            }
            break;
        }

        connection->last_rx_ms = now_ms();
        if (frame_type == packet_tunnel::kFrameHeartbeat && payload.empty()) {
            if (SendFrameOverSocket(connection->sock,
                                    &connection->send_mutex,
                                    packet_tunnel::kFrameHeartbeatAck,
                                    NULL,
                                    0,
                                    NULL)) {
                connection->last_tx_ms = now_ms();
            }
            continue;
        }
        if (frame_type == packet_tunnel::kFrameHeartbeatAck && payload.empty()) {
            continue;
        }

        if (frame_type != packet_tunnel::kFrameIpv4Packet ||
            payload.size() < 20 ||
            (((payload[0] >> 4) & 0x0F) != 4)) {
            LogDebug("忽略TCP直连帧，类型=" +
                    LinuxFrameName(frame_type) +
                    " 长度=" + std::to_string(payload.size()));
            continue;
        }

        const std::string inner_src_virtual_ip = LinuxIpv4ToString(payload.data() + 12);
        if (!peer_virtual_ip.empty() && inner_src_virtual_ip != peer_virtual_ip) {
            LogDebug("忽略源地址不匹配的TCP直连包，对端=" +
                    peer_virtual_ip +
                    " inner_来源=" + inner_src_virtual_ip);
            continue;
        }

        std::string tun_error;
        MarkNetworkActivity();
        if (!tun_manager_ ||
            !tun_manager_->WritePacket(payload.data(), payload.size(), &tun_error)) {
            if (!stop_requested_) {
                LogWarn("写入TUN失败，TCP直连数据入队失败: " + tun_error);
            }
            break;
        }

        TraceWatchedTcpPacket(payload.data(), payload.size(), "tcp-peer->tun");
    }

    RemoveTcpDirectConnection(peer_virtual_ip, socket_for_remove, true);
}

void LinuxPacketTunnelClient::RegisterTcpDirectConnection(
    const std::string& peer_virtual_ip,
    const std::shared_ptr<TcpDirectConnection>& connection,
    bool incoming) {
    if (peer_virtual_ip.empty() || !connection) {
        return;
    }

    std::shared_ptr<TcpDirectConnection> old_connection;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator old_it =
            tcp_direct_connections_.find(peer_virtual_ip);
        if (old_it != tcp_direct_connections_.end() &&
            old_it->second &&
            old_it->second->sock != connection->sock) {
            old_connection = old_it->second;
        }
        tcp_direct_connections_[peer_virtual_ip] = connection;
        const unsigned long long tick = now_ms();
        connection->last_rx_ms = tick;
        connection->last_tx_ms = tick;
        TcpDirectOffer& offer = tcp_direct_offers_[peer_virtual_ip];
        offer.connecting = false;
        offer.cooldown_until_ms = 0;
    }

    if (old_connection) {
        old_connection->active = false;
        CloseFdQuiet(&old_connection->sock);
    }

    LogInfo(std::string("TCP直连 ") +
            (incoming ? "入站" : "出站") +
            " active 对端=" + peer_virtual_ip);
}

void LinuxPacketTunnelClient::RemoveTcpDirectConnection(const std::string& peer_virtual_ip,
                                                        int sock,
                                                        bool enter_cooldown) {
    if (peer_virtual_ip.empty()) {
        return;
    }

    std::shared_ptr<TcpDirectConnection> removed;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator it =
            tcp_direct_connections_.find(peer_virtual_ip);
        if (it == tcp_direct_connections_.end() ||
            !it->second ||
            (sock >= 0 && it->second->sock != sock)) {
            return;
        }
        removed = it->second;
        tcp_direct_connections_.erase(it);

        std::map<std::string, TcpDirectOffer>::iterator offer_it =
            tcp_direct_offers_.find(peer_virtual_ip);
        if (offer_it != tcp_direct_offers_.end()) {
            offer_it->second.connecting = false;
            if (enter_cooldown) {
                offer_it->second.cooldown_until_ms =
                    now_ms() + kTcpDirectRetryCooldownMs;
            }
        }
    }

    if (removed) {
        removed->active = false;
        CloseFdQuiet(&removed->sock);
    }
}

void LinuxPacketTunnelClient::MaintainTcpDirectConnections(unsigned long long tick) {
    std::vector<std::pair<std::string, int>> stale_connections;
    std::vector<std::shared_ptr<TcpDirectConnection>> heartbeat_connections;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        for (std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator it =
                 tcp_direct_connections_.begin();
             it != tcp_direct_connections_.end();
             ++it) {
            const std::shared_ptr<TcpDirectConnection>& connection = it->second;
            if (!connection || !connection->active || connection->sock < 0) {
                stale_connections.push_back(std::make_pair(it->first, -1));
                continue;
            }

            const unsigned long long last_rx = connection->last_rx_ms.load();
            const unsigned long long last_tx = connection->last_tx_ms.load();
            if (last_rx != 0 &&
                tick >= last_rx &&
                (tick - last_rx) > static_cast<unsigned long long>(kTcpDirectIdleTimeoutMs)) {
                stale_connections.push_back(std::make_pair(it->first, connection->sock));
                continue;
            }
            const bool high_frequency =
                ShouldUseHighFrequencyPeerMaintenance(it->first, tick);
            const unsigned long long heartbeat_interval =
                static_cast<unsigned long long>(high_frequency
                                                    ? kTcpDirectHeartbeatIntervalMs
                                                    : kTcpDirectQuietHeartbeatIntervalMs);
            if (last_tx == 0 ||
                tick < last_tx ||
                (tick - last_tx) >= heartbeat_interval) {
                heartbeat_connections.push_back(connection);
            }
        }
    }

    for (size_t i = 0; i < stale_connections.size(); ++i) {
        LogInfo("TCP直连空闲超时，对端=" + stale_connections[i].first);
        RemoveTcpDirectConnection(stale_connections[i].first,
                                  stale_connections[i].second,
                                  true);
    }

    for (size_t i = 0; i < heartbeat_connections.size(); ++i) {
        const std::shared_ptr<TcpDirectConnection>& connection = heartbeat_connections[i];
        if (!connection || !connection->active || connection->sock < 0) {
            continue;
        }
        if (SendFrameOverSocket(connection->sock,
                                &connection->send_mutex,
                                packet_tunnel::kFrameHeartbeat,
                                NULL,
                                0,
                                NULL)) {
            connection->last_tx_ms = tick;
        } else {
            RemoveTcpDirectConnection(connection->peer_virtual_ip,
                                      connection->sock,
                                      true);
        }
    }
}

void LinuxPacketTunnelClient::RecordTcpDirectCandidateResult(
    const std::string& peer_virtual_ip,
    const TcpDirectCandidate& candidate,
    bool success,
    unsigned long long connect_ms) {
    if (peer_virtual_ip.empty()) {
        return;
    }

    const unsigned long long tick = now_ms();
    std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
    std::map<std::string, TcpDirectOffer>::iterator offer_it =
        tcp_direct_offers_.find(peer_virtual_ip);
    if (offer_it == tcp_direct_offers_.end()) {
        return;
    }

    std::vector<TcpDirectCandidate>& candidates = offer_it->second.candidates;
    for (size_t i = 0; i < candidates.size(); ++i) {
        TcpDirectCandidate& existing = candidates[i];
        const size_t addr_len =
            existing.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16;
        if (existing.endpoint_family != candidate.endpoint_family ||
            existing.endpoint_port != candidate.endpoint_port ||
            memcmp(existing.endpoint_addr, candidate.endpoint_addr, addr_len) != 0) {
            continue;
        }
        if (success) {
            ++existing.success_count;
            existing.last_success_ms = tick;
            existing.last_connect_ms = connect_ms;
            offer_it->second.next_candidate_index = i;
        } else {
            ++existing.failure_count;
            existing.last_failure_ms = tick;
        }
        return;
    }
}

std::vector<LinuxPacketTunnelClient::TcpDirectCandidate>
LinuxPacketTunnelClient::BuildOrderedTcpDirectCandidates(const TcpDirectOffer& offer,
                                                         unsigned long long tick) const {
    std::vector<TcpDirectCandidate> ordered = offer.candidates;
    if (ordered.empty() && offer.endpoint_port != 0) {
        TcpDirectCandidate fallback_candidate;
        fallback_candidate.endpoint_family = offer.endpoint_family;
        fallback_candidate.endpoint_port = offer.endpoint_port;
        memcpy(fallback_candidate.endpoint_addr,
               offer.endpoint_addr,
               sizeof(fallback_candidate.endpoint_addr));
        ordered.push_back(fallback_candidate);
    }
    if (ordered.size() <= 1) {
        return ordered;
    }

    std::stable_sort(ordered.begin(),
                     ordered.end(),
                     [tick](const TcpDirectCandidate& left,
                            const TcpDirectCandidate& right) {
                         const bool left_recent_fail =
                             left.last_failure_ms != 0 &&
                             tick >= left.last_failure_ms &&
                             (tick - left.last_failure_ms) <
                                 static_cast<unsigned long long>(kTcpDirectRetryCooldownMs);
                         const bool right_recent_fail =
                             right.last_failure_ms != 0 &&
                             tick >= right.last_failure_ms &&
                             (tick - right.last_failure_ms) <
                                 static_cast<unsigned long long>(kTcpDirectRetryCooldownMs);
                         if (left_recent_fail != right_recent_fail) {
                             return !left_recent_fail;
                         }
                         if ((left.success_count > 0) != (right.success_count > 0)) {
                             return left.success_count > 0;
                         }
                         if (left.success_count != right.success_count) {
                             return left.success_count > right.success_count;
                         }
                         const unsigned long long left_connect =
                             left.last_connect_ms != 0 ? left.last_connect_ms : 0xffffffffull;
                         const unsigned long long right_connect =
                             right.last_connect_ms != 0 ? right.last_connect_ms : 0xffffffffull;
                         if (left_connect != right_connect) {
                             return left_connect < right_connect;
                         }
                         return left.failure_count < right.failure_count;
                     });
    return ordered;
}

bool LinuxPacketTunnelClient::TrySendTcpDirectPacket(const std::string& peer_virtual_ip,
                                                     const uint8_t* data,
                                                     size_t length) {
    if (peer_virtual_ip.empty() || data == NULL || length == 0 || length > 0xFFFFu) {
        return false;
    }

    std::shared_ptr<TcpDirectConnection> connection;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator it =
            tcp_direct_connections_.find(peer_virtual_ip);
        if (it != tcp_direct_connections_.end() &&
            it->second &&
            it->second->active &&
            it->second->sock >= 0) {
            connection = it->second;
        }
    }

    if (!connection) {
        MaybeStartTcpDirectConnect(peer_virtual_ip);
        return false;
    }

    if (SendFrameOverSocket(connection->sock,
                            &connection->send_mutex,
                            packet_tunnel::kFrameIpv4Packet,
                            data,
                            length,
                            NULL)) {
        connection->last_tx_ms = now_ms();
        return true;
    }

    LogWarn("TCP直连发送失败，回退到中转，对端=" +
            peer_virtual_ip);
    RecordTcpDirectCandidateResult(peer_virtual_ip, connection->candidate, false, 0);
    RemoveTcpDirectConnection(peer_virtual_ip, connection->sock, true);
    MaybeStartTcpDirectConnect(peer_virtual_ip);
    return false;
}

void LinuxPacketTunnelClient::MaybeStartTcpDirectConnect(const std::string& peer_virtual_ip) {
    if (stop_requested_ || peer_virtual_ip.empty() || peer_virtual_ip == virtual_ip_) {
        return;
    }

    const unsigned long long tick = now_ms();
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, TcpDirectOffer>::iterator offer_it =
            tcp_direct_offers_.find(peer_virtual_ip);
        if (offer_it == tcp_direct_offers_.end() ||
            (offer_it->second.candidates.empty() &&
             offer_it->second.endpoint_port == 0) ||
            offer_it->second.connecting ||
            (offer_it->second.cooldown_until_ms != 0 &&
             tick < offer_it->second.cooldown_until_ms)) {
            return;
        }
        std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator conn_it =
            tcp_direct_connections_.find(peer_virtual_ip);
        if (conn_it != tcp_direct_connections_.end() &&
            conn_it->second &&
            conn_it->second->active &&
            conn_it->second->sock >= 0) {
            return;
        }
        offer_it->second.connecting = true;
        tcp_direct_connect_threads_.push_back(
            std::thread(&LinuxPacketTunnelClient::TcpDirectConnectWorker, this, peer_virtual_ip));
    }
}

void LinuxPacketTunnelClient::TcpDirectConnectWorker(const std::string& peer_virtual_ip) {
    TcpDirectOffer offer;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, TcpDirectOffer>::const_iterator it =
            tcp_direct_offers_.find(peer_virtual_ip);
        if (it == tcp_direct_offers_.end()) {
            return;
        }
        offer = it->second;
    }

    auto finish_connect_attempt = [&](bool cooldown) {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, TcpDirectOffer>::iterator it =
            tcp_direct_offers_.find(peer_virtual_ip);
        if (it != tcp_direct_offers_.end()) {
            it->second.connecting = false;
            if (cooldown) {
                it->second.cooldown_until_ms = now_ms() + kTcpDirectRetryCooldownMs;
            }
        }
    };

    std::vector<TcpDirectCandidate> candidates =
        BuildOrderedTcpDirectCandidates(offer, now_ms());
    if (candidates.empty()) {
        finish_connect_attempt(true);
        return;
    }

    uint32_t local_virtual_ip_be = ParseVirtualIp(NULL);
    uint32_t peer_virtual_ip_be = 0;
    if (local_virtual_ip_be == 0 ||
        !ParseLinuxIpv4StringToBe(peer_virtual_ip, &peer_virtual_ip_be)) {
        finish_connect_attempt(true);
        return;
    }

    const size_t candidate_count = candidates.size();
    for (size_t attempt = 0; attempt < candidate_count && !stop_requested_; ++attempt) {
        const size_t candidate_index = attempt;
        const TcpDirectCandidate& candidate = candidates[candidate_index];

        sockaddr_storage peer_addr = {};
        socklen_t peer_addr_len = 0;
        if (!BuildLinuxTcpDirectSockaddr(candidate.endpoint_family,
                                         candidate.endpoint_addr,
                                         candidate.endpoint_port,
                                         &peer_addr,
                                         &peer_addr_len)) {
            continue;
        }

        int direct_sock = socket(peer_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (direct_sock < 0) {
            continue;
        }
        ConfigureLinuxTcpStreamSocket(direct_sock);

        int connect_error = 0;
        const unsigned long long connect_start_ms = now_ms();
        if (!ConnectLinuxSocketWithTimeout(direct_sock,
                                           peer_addr,
                                           peer_addr_len,
                                           kTcpDirectConnectTimeoutMs,
                                           &connect_error)) {
            if (!stop_requested_) {
                LogDebug("TCP直连候选连接失败，对端=" + peer_virtual_ip +
                        " 端点=" + LinuxSockaddrToString(peer_addr, peer_addr_len) +
                        " 错误码=" + std::to_string(connect_error));
            }
            close(direct_sock);
            RecordTcpDirectCandidateResult(peer_virtual_ip, candidate, false, 0);
            continue;
        }
        const unsigned long long connect_end_ms = now_ms();
        const unsigned long long connect_elapsed =
            connect_end_ms >= connect_start_ms ? (connect_end_ms - connect_start_ms) : 0;

        std::shared_ptr<TcpDirectConnection> connection =
            std::make_shared<TcpDirectConnection>();
        connection->sock = direct_sock;
        connection->peer_virtual_ip = peer_virtual_ip;
        connection->candidate = candidate;
        connection->active = true;

        std::vector<uint8_t> open_payload(packet_tunnel::kTcpDirectOpenPayloadSize, 0);
        packet_tunnel::write_u32_be(open_payload.data(), ntohl(local_virtual_ip_be));
        packet_tunnel::write_u32_be(open_payload.data() + 4, ntohl(peer_virtual_ip_be));
        if (!SendFrameOverSocket(connection->sock,
                                 &connection->send_mutex,
                                 packet_tunnel::kFrameTcpDirectOpen,
                                 open_payload.data(),
                                 open_payload.size(),
                                 NULL)) {
            CloseFdQuiet(&connection->sock);
            RecordTcpDirectCandidateResult(peer_virtual_ip, candidate, false, 0);
            continue;
        }
        if (stop_requested_) {
            CloseFdQuiet(&connection->sock);
            finish_connect_attempt(false);
            return;
        }

        RecordTcpDirectCandidateResult(peer_virtual_ip, candidate, true, connect_elapsed);
        RegisterTcpDirectConnection(peer_virtual_ip, connection, false);
        connection->read_thread =
            std::thread(&LinuxPacketTunnelClient::TcpDirectReadLoop, this, connection, false);
        connection->read_thread.detach();
        LogInfo("TCP直连已连接，对端=" + peer_virtual_ip +
                " 端点=" + LinuxSockaddrToString(peer_addr, peer_addr_len) +
                " 候选=" + std::to_string(candidate_index + 1) +
                "/" + std::to_string(candidate_count));
        return;
    }

    finish_connect_attempt(!stop_requested_);
}

void LinuxPacketTunnelClient::TunReadLoop() {
    uint32_t local_virtual_ip_be = 0;
    std::deque<std::vector<uint8_t>> deferred_packets;
    ParseLinuxIpv4StringToBe(virtual_ip_, &local_virtual_ip_be);
    while (!stop_requested_) {
        std::vector<uint8_t> packet;
        std::string error;
        unsigned long long read_wait_ms = 0;
        if (!deferred_packets.empty()) {
            packet = std::move(deferred_packets.front());
            deferred_packets.pop_front();
        } else {
            const unsigned long long read_start_ms = now_ms();
            if (!tun_manager_ || !tun_manager_->ReadPacket(&packet, kTunReadWaitMs, &error)) {
                continue;
            }
            const unsigned long long read_end_ms = now_ms();
            if (read_end_ms >= read_start_ms) {
                read_wait_ms = read_end_ms - read_start_ms;
            }
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

        std::string desc;
        const bool has_desc =
            !IsLinuxNoisyUdpPacket(packet.data(), packet.size()) &&
            TryDescribeLinuxUdpPacket(packet.data(), packet.size(), &desc);
        const bool is_udp = packet.size() >= 20 && packet[9] == IPPROTO_UDP;
        const bool is_tcp = packet.size() >= 20 && packet[9] == IPPROTO_TCP;
        const std::string inner_proto_name = is_udp ? "udp" : (is_tcp ? "tcp" : "ip");
        const std::string dst_virtual_ip =
            packet.size() >= 20 ? LinuxIpv4ToString(packet.data() + 16) : "";
        MarkWatchedTcpTunRead(packet.data(), packet.size(), read_wait_ms);
        const std::string route_desc =
            (has_desc && is_udp)
                ? desc
                : ("目标=" + dst_virtual_ip +
                   " 协议=" + inner_proto_name +
                   " 长度=" + std::to_string(packet.size()));
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        if (is_tcp) {
            TryParseLinuxTcpPorts(packet.data(), packet.size(), &src_port, &dst_port);
        }
        if (!is_tcp && !dst_virtual_ip.empty()) {
            const std::string original_dst_virtual_ip = dst_virtual_ip;
            std::string target_peer_virtual_ip = dst_virtual_ip;
            std::string target_resolution = "direct_ip";
            bool resolved_gateway_target = false;
            UdpEndpoint peer_endpoint;
            bool direct_path_fresh = false;
            bool active_direct = false;
            bool have_peer_endpoint =
                TryBuildPeerEndpoint(target_peer_virtual_ip,
                                     &peer_endpoint,
                                     &direct_path_fresh,
                                     &active_direct);
            if (is_udp && !have_peer_endpoint) {
                std::string resolved_peer_virtual_ip;
                std::string resolution;
                if (TryResolvePeerByCandidateAddress(dst_virtual_ip,
                                                     &resolved_peer_virtual_ip,
                                                     &resolution) &&
                    !resolved_peer_virtual_ip.empty()) {
                    target_peer_virtual_ip = resolved_peer_virtual_ip;
                    target_resolution = resolution;
                    resolved_gateway_target =
                        target_peer_virtual_ip != original_dst_virtual_ip;
                    have_peer_endpoint =
                        TryBuildPeerEndpoint(target_peer_virtual_ip,
                                             &peer_endpoint,
                                             &direct_path_fresh,
                                             &active_direct);
                }
            }
            if (is_udp && !have_peer_endpoint) {
                std::string resolved_peer_virtual_ip;
                std::string resolution;
                if (TryResolveGatewayUdpPeerTarget(dst_virtual_ip,
                                                   dst_port,
                                                   &resolved_peer_virtual_ip,
                                                   &resolution) &&
                    !resolved_peer_virtual_ip.empty()) {
                    target_peer_virtual_ip = resolved_peer_virtual_ip;
                    target_resolution = resolution;
                    resolved_gateway_target =
                        target_peer_virtual_ip != original_dst_virtual_ip;
                    have_peer_endpoint =
                        TryBuildPeerEndpoint(target_peer_virtual_ip,
                                             &peer_endpoint,
                                             &direct_path_fresh,
                                             &active_direct);
                }
            }

            if (!target_peer_virtual_ip.empty()) {
                MarkPeerBusinessActivity(target_peer_virtual_ip);
            }

            std::vector<uint8_t> direct_packet;
            const std::vector<uint8_t>* direct_packet_view = &packet;
            bool direct_payload_ready = true;
            if (have_peer_endpoint && resolved_gateway_target && is_udp) {
                uint32_t original_dst_ip_be = 0;
                uint32_t target_peer_ip_be = 0;
                memcpy(&original_dst_ip_be, packet.data() + 16, sizeof(original_dst_ip_be));
                direct_packet = packet;
                if (!ParseLinuxIpv4StringToBe(target_peer_virtual_ip, &target_peer_ip_be) ||
                    !RewriteLinuxIpv4UdpDestinationIp(&direct_packet,
                                                      original_dst_ip_be,
                                                      target_peer_ip_be)) {
                    direct_payload_ready = false;
                } else {
                    direct_packet_view = &direct_packet;
                }
            }

            if (have_peer_endpoint) {
                PacketFlowRouterInput direct_flow_input;
                direct_flow_input.is_udp = true;
                direct_flow_input.has_udp_peer_endpoint = true;
                direct_flow_input.direct_path_fresh = direct_path_fresh;
                direct_flow_input.active_direct = active_direct;
                direct_flow_input.resolved_gateway_target = resolved_gateway_target;
                direct_flow_input.direct_payload_ready = direct_payload_ready;
                direct_flow_input.route_desc_seed = route_desc;
                direct_flow_input.target_peer_virtual_ip = target_peer_virtual_ip;
                direct_flow_input.original_dst_virtual_ip = original_dst_virtual_ip;
                direct_flow_input.target_resolution = target_resolution;
                const PacketFlowRouterDecision direct_flow_decision =
                    PacketFlowRouter::Decide(direct_flow_input);
                const std::string direct_route_desc = direct_flow_decision.route_desc;

                if (direct_flow_decision.primary_route == PacketFlowRoute::UdpDirect) {
                    if (direct_flow_decision.try_udp_direct_now &&
                        SendFrameToEndpoint(peer_endpoint,
                                            packet_tunnel::kFrameIpv4Packet,
                                            direct_packet_view->data(),
                                            direct_packet_view->size(),
                                            NULL)) {
                        LogDebug(inner_proto_name + " TUN->对端 " + direct_route_desc);
                        TraceWatchedTcpPacket(packet.data(), packet.size(), "tun->peer");
                        continue;
                    }
                    if (!direct_flow_decision.try_udp_direct_now) {
                        MaybeLogDirectRouteFallback(target_peer_virtual_ip, "payload_unavailable");
                        continue;
                    }
                    LinuxPeerRouteStatus failed_status = {};
                    const bool state_changed =
                        peer_link_manager_ != NULL &&
                        peer_link_manager_->RecordDirectSendFailure(target_peer_virtual_ip,
                                                                    0,
                                                                    active_direct,
                                                                    &failed_status);
                    LogWarn(inner_proto_name + " 激活直连发送失败，回退到中转 " +
                            direct_route_desc);
                    if (state_changed && failed_status.state == LinuxPeerRouteState::Cooldown) {
                        LogDebug("UDP直连进入冷却: 对端=" +
                                failed_status.peer_virtual_ip);
                    }
                } else if (direct_flow_decision.try_udp_probe) {
                    const unsigned long long tick = now_ms();
                    std::map<std::string, unsigned long long>::iterator probe_it =
                        peer_probe_send_tick_.find(target_peer_virtual_ip);
                    const bool should_send_probe =
                        probe_it == peer_probe_send_tick_.end() ||
                        tick < probe_it->second ||
                        (tick - probe_it->second) >= static_cast<unsigned long long>(kPeerDirectProbeIntervalMs);
                    if (should_send_probe) {
                        uint32_t target_peer_ip_be = 0;
                        std::vector<uint8_t> probe_packet;
                        if (ParseLinuxIpv4StringToBe(virtual_ip_, &local_virtual_ip_be) &&
                            ParseLinuxIpv4StringToBe(target_peer_virtual_ip, &target_peer_ip_be) &&
                            BuildLinuxPeerDirectProbePacket(local_virtual_ip_be,
                                                            target_peer_ip_be,
                                                            kPeerDirectProbeRequest,
                                                            &probe_packet) &&
                            SendFrameToEndpoint(peer_endpoint,
                                                packet_tunnel::kFrameIpv4Packet,
                                                probe_packet.data(),
                                                probe_packet.size(),
                                                NULL)) {
                            peer_probe_send_tick_[target_peer_virtual_ip] = tick;
                            LogDebug(inner_proto_name + " 直连探测请求 " + direct_route_desc);
                        } else {
                            LinuxPeerRouteStatus failed_status = {};
                            const bool state_changed =
                                peer_link_manager_ != NULL &&
                                peer_link_manager_->RecordDirectSendFailure(target_peer_virtual_ip,
                                                                            0,
                                                                            active_direct,
                                                                            &failed_status);
                            if (active_direct) {
                                LogWarn(inner_proto_name +
                                        " active direct probe failed, fallback to relay " +
                                        direct_route_desc);
                            } else {
                                LogDebug(inner_proto_name +
                                        " 直连探测发送失败，继续以中转为主 " +
                                        direct_route_desc);
                            }
                            if (state_changed && failed_status.state == LinuxPeerRouteState::Cooldown) {
                                LogDebug("UDP直连进入冷却: 对端=" +
                                        failed_status.peer_virtual_ip);
                            }
                        }
                    }
                }
            } else {
                MaybeLogDirectRouteFallback(target_peer_virtual_ip,
                                            target_peer_virtual_ip != original_dst_virtual_ip
                                                ? ("route_unavailable_" + target_resolution)
                                                : "route_unavailable");
            }
        }

        PacketFlowRouterInput flow_input;
        flow_input.is_tcp = is_tcp;
        flow_input.has_tcp_direct_target = !dst_virtual_ip.empty();
        flow_input.tcp_relay_available = tcp_connected_ && tcp_sock_ >= 0;
        flow_input.udp_relay_batch_eligible =
            kPacketTunnelEnableLinuxRelayTcpMicroBatch &&
            IsPacketTunnelMicroBatchEligibleTcpPacket(packet.data(), packet.size());
        const PacketFlowRouterDecision flow_decision = PacketFlowRouter::Decide(flow_input);

        if (is_tcp && !dst_virtual_ip.empty()) {
            MarkPeerBusinessActivity(dst_virtual_ip);
        }

        if (flow_decision.try_tcp_direct_now &&
            TrySendTcpDirectPacket(dst_virtual_ip, packet.data(), packet.size())) {
            LogDebug("TCP TUN->TCP对端 目标=" + dst_virtual_ip + ":" +
                    std::to_string(dst_port) +
                    " 长度=" + std::to_string(packet.size()));
            TraceWatchedTcpPacket(packet.data(), packet.size(), "tun->tcp-peer");
            continue;
        }

        bool relay_send_ok = true;
        size_t relay_batch_frames = 1;
        bool attempted_tcp_relay = false;
        if (flow_decision.try_tcp_relay_now) {
            attempted_tcp_relay = true;
            relay_send_ok = SendFrameOverTcp(packet_tunnel::kFrameIpv4Packet,
                                             packet.data(),
                                             packet.size(),
                                             NULL);
            if (!relay_send_ok) {
                LogWarn("TCP中转载体发送失败，回退到UDP中转");
                tcp_connected_ = false;
                const int stale_tcp_sock = tcp_sock_;
                tcp_sock_ = -1;
                if (stale_tcp_sock >= 0) {
                    close(stale_tcp_sock);
                }
            }
        }
        if (!attempted_tcp_relay || !relay_send_ok) {
            relay_batch_frames = 1;
            if (flow_decision.allow_udp_relay_batch) {
                std::vector<uint8_t> relay_datagram;
                AppendPacketTunnelFrame(&relay_datagram,
                                        packet_tunnel::kFrameIpv4Packet,
                                        packet.data(),
                                        packet.size());

                while (relay_batch_frames < kPacketTunnelBatchMaxFrames &&
                       relay_datagram.size() < kPacketTunnelBatchMaxDatagramBytes) {
                    std::vector<uint8_t> next_packet;
                    std::string next_error;
                    if (!tun_manager_ ||
                        !tun_manager_->ReadPacket(&next_packet, 0, &next_error) ||
                        next_packet.empty()) {
                        break;
                    }

                    if (!IsPacketTunnelRelayBatchEligibleTunPacket(next_packet, virtual_ip_)) {
                        deferred_packets.push_front(std::move(next_packet));
                        break;
                    }

                    const size_t next_frame_size =
                        packet_tunnel::kFrameHeaderSize + next_packet.size();
                    if (relay_datagram.size() + next_frame_size > kPacketTunnelBatchMaxDatagramBytes) {
                        deferred_packets.push_front(std::move(next_packet));
                        break;
                    }

                    AppendPacketTunnelFrame(&relay_datagram,
                                            packet_tunnel::kFrameIpv4Packet,
                                            next_packet.data(),
                                            next_packet.size());
                    ++relay_batch_frames;
                }

                std::lock_guard<std::mutex> lock(send_mutex_);
                relay_send_ok = SendDatagramToEndpoint(server_endpoint_,
                                                       relay_datagram.data(),
                                                       relay_datagram.size(),
                                                       NULL);
                if (relay_batch_frames > 1) {
                    LogDebug("TCP TUN->中转 批量帧数=" +
                            std::to_string(relay_batch_frames) +
                            " 字节数=" + std::to_string(relay_datagram.size()));
                }
            } else {
                relay_send_ok = SendFrame(packet_tunnel::kFrameIpv4Packet,
                                          packet.data(),
                                          packet.size(),
                                          NULL);
            }
        }

        if (!relay_send_ok) {
            break;
        }

        TraceWatchedTcpPacket(packet.data(), packet.size(), "tun->tunnel");
        if (has_desc) {
            LogDebug("UDP TUN->中转 " + desc);
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void LinuxPacketTunnelClient::MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip,
                                                          const std::string& reason) {
    if (peer_link_manager_ == NULL || peer_virtual_ip.empty()) {
        return;
    }

    const unsigned long long tick = now_ms();
    std::map<std::string, unsigned long long>::iterator it = peer_route_debug_log_tick_.find(peer_virtual_ip);
    if (it != peer_route_debug_log_tick_.end() &&
        tick >= it->second &&
        (tick - it->second) < static_cast<unsigned long long>(kPeerRouteDebugLogIntervalMs)) {
        return;
    }

    const std::vector<LinuxPeerRouteStatus> peers = peer_link_manager_->Snapshot();
    const std::string detail = DescribeSingleLinuxPeerRoute(peers, peer_virtual_ip, tick);
    if (detail.empty()) {
        return;
    }

    peer_route_debug_log_tick_[peer_virtual_ip] = tick;
    LogDebug("UDP直连回退: 原因=" + reason + " 对端=" + detail);
}

void LinuxPacketTunnelClient::MarkPeerBusinessActivity(const std::string& peer_virtual_ip) {
    if (peer_virtual_ip.empty()) {
        return;
    }
    peer_business_activity_tick_[peer_virtual_ip] = now_ms();
}

void LinuxPacketTunnelClient::MarkPeerWarmupWindow(const std::string& peer_virtual_ip) {
    if (peer_virtual_ip.empty()) {
        return;
    }
    const unsigned long long tick = now_ms();
    const unsigned long long warmup_until =
        tick + static_cast<unsigned long long>(kPeerDirectWarmupDurationMs);
    std::map<std::string, unsigned long long>::iterator it =
        peer_warmup_until_tick_.find(peer_virtual_ip);
    if (it == peer_warmup_until_tick_.end() ||
        it->second < tick ||
        it->second < warmup_until) {
        peer_warmup_until_tick_[peer_virtual_ip] = warmup_until;
    }
}

bool LinuxPacketTunnelClient::ShouldUseHighFrequencyPeerMaintenance(
    const std::string& peer_virtual_ip,
    unsigned long long tick) const {
    if (peer_virtual_ip.empty()) {
        return false;
    }

    std::map<std::string, unsigned long long>::const_iterator business_it =
        peer_business_activity_tick_.find(peer_virtual_ip);
    if (business_it != peer_business_activity_tick_.end() &&
        (tick < business_it->second ||
         (tick - business_it->second) <
             static_cast<unsigned long long>(kPeerBusinessHotWindowMs))) {
        return true;
    }

    std::map<std::string, unsigned long long>::const_iterator warmup_it =
        peer_warmup_until_tick_.find(peer_virtual_ip);
    return warmup_it != peer_warmup_until_tick_.end() &&
           tick < warmup_it->second;
}

bool LinuxPacketTunnelClient::ShouldAutoWarmTcpPeer(const std::string& peer_virtual_ip,
                                                    unsigned long long tick) {
    if (peer_virtual_ip.empty()) {
        return false;
    }

    std::map<std::string, unsigned long long>::iterator it =
        peer_tcp_autowarm_tick_.find(peer_virtual_ip);
    if (it != peer_tcp_autowarm_tick_.end() &&
        tick >= it->second &&
        (tick - it->second) <
            static_cast<unsigned long long>(kTcpDirectAutoWarmRetryMs)) {
        return false;
    }

    peer_tcp_autowarm_tick_[peer_virtual_ip] = tick;
    return true;
}

bool LinuxPacketTunnelClient::ShouldLogPeerControlEvent(const std::string& key,
                                                        unsigned long long tick,
                                                        unsigned long long interval_ms) {
    if (key.empty()) {
        return false;
    }

    std::map<std::string, unsigned long long>::iterator it =
        peer_control_log_tick_.find(key);
    if (it != peer_control_log_tick_.end() &&
        tick >= it->second &&
        (tick - it->second) < interval_ms) {
        return false;
    }

    peer_control_log_tick_[key] = tick;
    return true;
}

void LinuxPacketTunnelClient::HeartbeatLoop() {
    unsigned long long last_peer_snapshot_log_ms = 0;
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

        const unsigned long long current_ms = now_ms();
        MaintainTcpDirectConnections(current_ms);

        if (peer_link_manager_ != NULL) {
            std::vector<LinuxPeerRouteStatus> expired = peer_link_manager_->ExpireStalePeers(
                current_ms,
                kPeerOfferTimeoutMs,
                kPeerDirectReadyTimeoutMs,
                kPeerCooldownTimeoutMs);
            for (size_t i = 0; i < expired.size(); ++i) {
                LogInfo("对等端控制 状态切换: 对端=" + expired[i].peer_virtual_ip +
                        " 状态=" + LinuxPeerRouteStateName(expired[i].state) +
                        " 版本=" + std::to_string(expired[i].endpoint_version));
            }

            std::vector<LinuxPeerRouteStatus> peers = peer_link_manager_->Snapshot();
            if (!peers.empty() &&
                (last_peer_snapshot_log_ms == 0 ||
                 current_ms < last_peer_snapshot_log_ms ||
                 (current_ms - last_peer_snapshot_log_ms) >= kPeerSnapshotLogIntervalMs)) {
                LogDebug("对等端控制 快照: " +
                        BuildLinuxPeerRouteSnapshotSummary(peers, current_ms));
                last_peer_snapshot_log_ms = current_ms;
            }
            const uint32_t local_virtual_ip_be = ParseVirtualIp(NULL);
            for (size_t i = 0; i < peers.size(); ++i) {
                const bool high_frequency =
                    ShouldUseHighFrequencyPeerMaintenance(peers[i].peer_virtual_ip, current_ms);
                if (peers[i].direct_ready &&
                    peers[i].endpoint_version != 0 &&
                    local_virtual_ip_be != 0) {
                    UdpEndpoint peer_endpoint;
                    bool direct_path_fresh = false;
                    bool active_direct = false;
                    if (TryBuildPeerEndpoint(peers[i].peer_virtual_ip,
                                             &peer_endpoint,
                                             &direct_path_fresh,
                                             &active_direct)) {
                        std::map<std::string, unsigned long long>::iterator probe_it =
                            peer_probe_send_tick_.find(peers[i].peer_virtual_ip);
                        bool should_send_probe = false;
                        if (high_frequency) {
                            should_send_probe =
                                probe_it == peer_probe_send_tick_.end() ||
                                current_ms < probe_it->second ||
                                (current_ms - probe_it->second) >=
                                    static_cast<unsigned long long>(kPeerDirectProbeIntervalMs);
                        }
                        if (should_send_probe) {
                            uint32_t target_peer_ip_be = 0;
                            std::vector<uint8_t> probe_packet;
                            if (ParseLinuxIpv4StringToBe(peers[i].peer_virtual_ip, &target_peer_ip_be) &&
                                BuildLinuxPeerDirectProbePacket(local_virtual_ip_be,
                                                                target_peer_ip_be,
                                                                kPeerDirectProbeRequest,
                                                                &probe_packet) &&
                                SendFrameToEndpoint(peer_endpoint,
                                                    packet_tunnel::kFrameIpv4Packet,
                                                    probe_packet.data(),
                                                    probe_packet.size(),
                                                    NULL)) {
                                peer_probe_send_tick_[peers[i].peer_virtual_ip] = current_ms;
                                LogDebug("对等端控制 主动直连探测: 对端=" +
                                        peers[i].peer_virtual_ip +
                                        " 状态=" + LinuxPeerRouteStateName(peers[i].state) +
                                        " 激活=" + (active_direct ? std::string("是")
                                                                  : std::string("否")));
                            } else {
                                LinuxPeerRouteStatus failed_status = {};
                                const bool state_changed =
                                    peer_link_manager_->RecordDirectSendFailure(
                                        peers[i].peer_virtual_ip,
                                        peers[i].endpoint_version,
                                        active_direct,
                                        &failed_status);
                                LogDebug("对等端控制 主动直连探测失败: 对端=" +
                                        peers[i].peer_virtual_ip);
                                if (state_changed &&
                                    failed_status.state == LinuxPeerRouteState::Cooldown) {
                                    LogDebug("UDP直连进入冷却: 对端=" +
                                            failed_status.peer_virtual_ip);
                                }
                            }
                        }
                    }
                }
                if (!peers[i].direct_ready || peers[i].endpoint_version == 0) {
                    continue;
                }
                std::map<std::string, unsigned long long>::iterator keepalive_it =
                    peer_keepalive_send_tick_.find(peers[i].peer_virtual_ip);
                const unsigned long long keepalive_interval =
                    static_cast<unsigned long long>(high_frequency
                                                        ? kHeartbeatIntervalMs
                                                        : kPeerQuietKeepaliveIntervalMs);
                const bool should_send_keepalive =
                    keepalive_it == peer_keepalive_send_tick_.end() ||
                    current_ms < keepalive_it->second ||
                    (current_ms - keepalive_it->second) >= keepalive_interval;
                if (!should_send_keepalive) {
                    continue;
                }
                const uint32_t nonce = peer_signal_nonce_.fetch_add(1);
                if (SendPeerSignalFrame(packet_tunnel::kFramePeerKeepalive,
                                        peers[i].peer_virtual_ip,
                                        peers[i].endpoint_version,
                                        nonce)) {
                    peer_keepalive_send_tick_[peers[i].peer_virtual_ip] = current_ms;
                    LogDebug("对等端控制 发送对等保活: 对端=" + peers[i].peer_virtual_ip +
                            " 版本=" + std::to_string(peers[i].endpoint_version) +
                            " 随机数=" + std::to_string(nonce));
                }
            }
        }

        const unsigned long long last_activity_ms = last_network_activity_ms_.load();
        if (last_activity_ms != 0 &&
            current_ms > last_activity_ms &&
            (current_ms - last_activity_ms) > kHeartbeatTimeoutMs) {
            LogDebug("Heartbeat idle timeout: idle_ms=" +
                     std::to_string(current_ms - last_activity_ms));
            break;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

bool LinuxPacketTunnelClient::RecvTcpExact(uint8_t* data,
                                           size_t length,
                                           std::string* error) {
    size_t received = 0;
    while (received < length && !stop_requested_ && tcp_connected_) {
        if (tcp_sock_ < 0) {
            break;
        }

        ssize_t n = recv(tcp_sock_, data + received, length - received, 0);
        if (n > 0) {
            received += static_cast<size_t>(n);
            continue;
        }
        if (n == 0) {
            if (error != NULL) {
                *error = "TCP中转载体已关闭";
            }
            return false;
        }

        if ((errno == EAGAIN || errno == EWOULDBLOCK) &&
            !stop_requested_ &&
            tcp_connected_) {
            continue;
        }
        if (error != NULL) {
            *error = std::string("TCP中转载体接收失败: ") + strerror(errno);
        }
        return false;
    }

    if (received == length) {
        return true;
    }
    if (error != NULL && error->empty() && !stop_requested_) {
        *error = "TCP中转载体接收被中断";
    }
    return false;
}

bool LinuxPacketTunnelClient::SendFrame(uint8_t frame_type,
                                        const uint8_t* data,
                                        size_t length,
                                        std::string* error) {
    return SendFrameToEndpoint(server_endpoint_, frame_type, data, length, error);
}

bool LinuxPacketTunnelClient::SendFrameOverTcp(uint8_t frame_type,
                                               const uint8_t* data,
                                               size_t length,
                                               std::string* error) {
    if (!tcp_connected_ || tcp_sock_ < 0) {
        if (error != NULL) {
            *error = "TCP中转载体尚未连接";
        }
        return false;
    }

    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons(static_cast<uint16_t>(length));
    if (length > 0 && data != NULL) {
        memcpy(&frame[packet_tunnel::kFrameHeaderSize], data, length);
    }

    std::lock_guard<std::mutex> lock(tcp_send_mutex_);
    size_t sent = 0;
    int transient_retries = 0;
    while (sent < frame.size() && tcp_connected_ && tcp_sock_ >= 0) {
        ssize_t n = send(tcp_sock_,
                         frame.data() + sent,
                         frame.size() - sent,
                         MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            transient_retries = 0;
            continue;
        }

        const int send_errno = errno;
        if (IsLinuxTransientSendError(send_errno) &&
            transient_retries + 1 < kSocketSendRetryCount) {
            ++transient_retries;
            usleep(kSocketSendRetryDelayMs * 1000);
            continue;
        }
        if (error != NULL) {
            *error = std::string("TCP中转载体发送失败: ") + strerror(send_errno);
        }
        return false;
    }

    if (sent == frame.size()) {
        return true;
    }
    if (error != NULL && error->empty()) {
        *error = "TCP中转载体发送被中断";
    }
    return false;
}

bool LinuxPacketTunnelClient::SendDatagram(const uint8_t* data, size_t length, std::string* error) {
    return SendDatagramToEndpoint(server_endpoint_, data, length, error);
}

int LinuxPacketTunnelClient::RecvDatagram(uint8_t* data, size_t length, std::string* error) {
    sockaddr_storage source_addr = {};
    socklen_t source_addr_len = sizeof(source_addr);
    return RecvDatagramFrom(data, length, &source_addr, &source_addr_len, error);
}

uint32_t LinuxPacketTunnelClient::ParseVirtualIp(std::string* error) const {
    in_addr addr = {};
    if (inet_pton(AF_INET, virtual_ip_.c_str(), &addr) != 1) {
        if (error != NULL) {
            *error = "无效的虚拟IP: " + virtual_ip_;
        }
        return 0;
    }
    return addr.s_addr;
}
