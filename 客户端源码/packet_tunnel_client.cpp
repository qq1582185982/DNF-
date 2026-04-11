#include "packet_tunnel_client.h"

#include "packet_flow_router.h"
#include "packet_tunnel_protocol.h"
#include "peer_link_manager.h"
#include "wintun_manager.h"

#include <windows.h>
#include <windns.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <netioapi.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#pragma comment(lib, "dnsapi.lib")

void PacketTunnelDebugLog(const std::string& msg);
void PacketTunnelWarnLog(const std::string& msg);
void PacketTunnelInfoLog(const std::string& msg);
bool PacketTunnelDebugEnabled();

#define PT_DEBUG(message_expr)            \
    do {                                  \
        if (PacketTunnelDebugEnabled()) { \
            PacketTunnelDebugLog((message_expr)); \
        }                                 \
    } while (0)

namespace {

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

const DWORD kHeartbeatIntervalMs = 3000;
const DWORD kHeartbeatTimeoutMs = 12000;
const DWORD kPeerOfferTimeoutMs = 9000;
const DWORD kPeerDirectReadyTimeoutMs = 15000;
const DWORD kPeerCooldownTimeoutMs = 30000;
const DWORD kPeerDirectProbeGraceMs = 3000;
const DWORD kPeerDirectDataTimeoutMs = 5000;
const DWORD kPeerSnapshotLogIntervalMs = 15000;
const DWORD kPeerRouteDebugLogIntervalMs = 2000;
const DWORD kPeerDirectProbeIntervalMs = 500;
const bool kEnableGatewayUdpPeerHeuristics = false;
const DWORD kSocketReadTimeoutMs = 1000;
const DWORD kSocketSendTimeoutMs = 50;
const int kSocketSendRetryCount = 2;
const DWORD kSocketSendRetryDelayMs = 5;
const DWORD kTcpDirectConnectTimeoutMs = 1200;
const DWORD kTcpDirectRetryCooldownMs = 5000;
const DWORD kTcpDirectPassiveWaitMs = 1800;
const DWORD kTcpDirectHeartbeatIntervalMs = 3000;
const DWORD kTcpDirectIdleTimeoutMs = 15000;
const int kTcpDirectListenBacklog = 32;
const DWORD kPhysicalDnsQueryTimeoutMs = 1500;
const DWORD kWintunReadWaitMs = 500;
const DWORD kGatewayUdpPortOwnerTtlMs = 60000;
const DWORD kMirroredGatewayUdpSignatureTtlMs = 1000;
const uint16_t kPeerToWintunPacedBusinessTcpPort = 10011;
const unsigned int kPeerToWintunBusinessTcpPaceUs = 500;
const int kSocketBufferBytes = 4 * 1024 * 1024;
const unsigned long long kSlowSocketSendWarnMs = 10;
const unsigned long long kSlowWintunWriteWarnMs = 10;
const unsigned long long kSlowPacketProcessWarnMs = 20;
const unsigned long long kSlowWintunQueueWarnMs = 10;
const unsigned long long kWatchedTcpFlowIdleCleanupMs = 180000;
const unsigned long long kWatchedTcpClosedRetentionMs = 10000;
const unsigned long long kWatchedTcpServerWaitLogMs = 200;
const size_t kPacketTunnelBatchMaxDatagramBytes = 1200;
const size_t kPacketTunnelBatchMaxFrames = 8;
const size_t kPacketTunnelBatchMaxTcpPayloadBytes = 320;
const bool kPacketTunnelEnableWinRelayTcpMicroBatch = false;
const uint16_t kPeerDirectProbeSrcPort = 65401;
const uint16_t kPeerDirectProbeDstPort = 65402;
const uint8_t kPeerDirectProbeMagic[4] = {'P', 'T', 'D', 'P'};
const uint8_t kPeerDirectProbeVersion = 1;
const uint8_t kPeerDirectProbeRequest = 1;
const uint8_t kPeerDirectProbeResponse = 2;

bool IsKnownGameUdpPort(uint16_t port);
bool IsWatchedBusinessTcpPort(uint16_t port);

std::string HexPrefix(const uint8_t* data, size_t length, size_t max_bytes) {
    if (data == NULL || length == 0 || max_bytes == 0) {
        return "";
    }

    static const char kHex[] = "0123456789abcdef";
    const size_t limit = std::min(length, max_bytes);
    std::string out;
    out.reserve(limit * 2);
    for (size_t i = 0; i < limit; ++i) {
        const uint8_t value = data[i];
        out.push_back(kHex[(value >> 4) & 0x0F]);
        out.push_back(kHex[value & 0x0F]);
    }
    return out;
}

void MaybeLogDnfUdpSignature(const std::string& direction,
                             const std::string& src_virtual_ip,
                             uint16_t src_port,
                             const std::string& dst_virtual_ip,
                             uint16_t dst_port,
                             const uint8_t* udp_payload,
                             size_t udp_payload_len) {
    if (!PacketTunnelDebugEnabled()) {
        return;
    }

    if (udp_payload == NULL) {
        return;
    }

    const bool interesting =
        IsKnownGameUdpPort(src_port) || IsKnownGameUdpPort(dst_port);
    if (!interesting) {
        return;
    }

    PacketTunnelDebugLog("dnf udp signature dir=" + direction +
                         " src=" + src_virtual_ip + ":" + std::to_string(src_port) +
                         " dst=" + dst_virtual_ip + ":" + std::to_string(dst_port) +
                         " payload_len=" + std::to_string(udp_payload_len) +
                         " hex=" + HexPrefix(udp_payload, udp_payload_len, 24));
}

uint16_t ComputeIpv4HeaderChecksum(const uint8_t* header, size_t header_len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < header_len; i += 2) {
        sum += static_cast<uint16_t>((header[i] << 8) | header[i + 1]);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

uint16_t ComputeIpv4TransportChecksum(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 20) {
        return 0;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len) {
        return 0;
    }

    const uint16_t total_len =
        static_cast<uint16_t>((packet[2] << 8) | packet[3]);
    if (total_len < ip_header_len || packet_len < total_len) {
        return 0;
    }

    const uint8_t protocol = packet[9];
    const size_t transport_len = static_cast<size_t>(total_len - ip_header_len);
    const uint8_t* transport = packet + ip_header_len;

    uint32_t sum = 0;
    for (int i = 12; i < 20; i += 2) {
        sum += (static_cast<uint32_t>(packet[i]) << 8) |
               static_cast<uint32_t>(packet[i + 1]);
    }
    sum += static_cast<uint32_t>(protocol);
    sum += static_cast<uint32_t>(transport_len);

    size_t remaining = transport_len;
    while (remaining >= 2) {
        sum += (static_cast<uint32_t>(transport[0]) << 8) |
               static_cast<uint32_t>(transport[1]);
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

bool RewriteIpv4UdpDestinationIp(std::vector<uint8_t>* packet,
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
    if (ip_header_len < 20 || bytes.size() < ip_header_len + 8 ||
        bytes[9] != IPPROTO_UDP) {
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
                                ComputeIpv4HeaderChecksum(bytes.data(), ip_header_len));

    bytes[ip_header_len + 6] = 0;
    bytes[ip_header_len + 7] = 0;
    packet_tunnel::write_u16_be(bytes.data() + ip_header_len + 6,
                                ComputeIpv4TransportChecksum(bytes.data(), bytes.size()));
    return true;
}

bool IsKnownGameUdpPort(uint16_t port) {
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

bool IsReservedPeerDirectPort(uint16_t port) {
    return port == kPeerDirectProbeSrcPort || port == kPeerDirectProbeDstPort;
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

bool IsPacketTunnelRelayBatchEligibleWintunPacket(const std::vector<uint8_t>& packet,
                                                  const uint8_t leased_src_ip[4],
                                                  bool enforce_virtual_src) {
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

    if (enforce_virtual_src &&
        memcmp(packet.data() + 12, leased_src_ip, 4) != 0) {
        return false;
    }

    return IsPacketTunnelMicroBatchEligibleTcpPacket(packet.data(), packet.size());
}

bool IsKnownPeerVirtualIp(const std::vector<PeerRouteStatus>& peers,
                          const std::string& peer_virtual_ip) {
    if (peer_virtual_ip.empty()) {
        return false;
    }
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip == peer_virtual_ip) {
            return true;
        }
    }
    return false;
}

bool ParseIpv4Octets(const std::string& value, uint8_t octets[4]) {
    if (octets == NULL || value.empty()) {
        return false;
    }

    std::istringstream stream(value);
    std::string part;
    for (size_t i = 0; i < 4; ++i) {
        if (!std::getline(stream, part, '.')) {
            return false;
        }
        if (part.empty()) {
            return false;
        }

        char* end = NULL;
        const long octet = strtol(part.c_str(), &end, 10);
        if (end == NULL || *end != '\0' || octet < 0 || octet > 255) {
            return false;
        }
        octets[i] = static_cast<uint8_t>(octet);
    }

    return !std::getline(stream, part, '.');
}

bool IsGatewayPeerResolveCandidate(const std::string& local_virtual_ip,
                                   const std::string& dst_virtual_ip,
                                   const std::vector<PeerRouteStatus>& peers) {
    if (dst_virtual_ip.empty() ||
        dst_virtual_ip == local_virtual_ip ||
        IsKnownPeerVirtualIp(peers, dst_virtual_ip)) {
        return false;
    }

    uint8_t local_octets[4] = {};
    uint8_t dst_octets[4] = {};
    if (!ParseIpv4Octets(local_virtual_ip, local_octets) ||
        !ParseIpv4Octets(dst_virtual_ip, dst_octets)) {
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

bool BuildPeerDirectProbePacket(uint32_t src_ip_be,
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

    packet_tunnel::write_u16_be(packet + 10, ComputeIpv4HeaderChecksum(packet, 20));
    return true;
}

bool ParsePeerDirectProbePacket(const uint8_t* packet,
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

bool IsDirectPathFresh(const PeerRouteStatus& route, unsigned long long now_tick) {
    if (!route.active_direct) {
        return false;
    }

    return
        route.last_direct_data_ms != 0 &&
        now_tick >= route.last_direct_data_ms &&
        (now_tick - route.last_direct_data_ms) <= kPeerDirectDataTimeoutMs;
}

std::wstring BuildSocketError(const wchar_t* prefix, int error_code) {
    std::wstringstream stream;
    stream << prefix << L" (WSA=" << error_code << L")";
    return stream.str();
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, NULL, 0, NULL, NULL);
    if (required <= 1) {
        return std::string();
    }

    std::string utf8(required - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &utf8[0], required, NULL, NULL);
    return utf8;
}

std::wstring Utf8ToWideString(const std::string& value) {
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

std::string Ipv4ToString(const uint8_t* addr) {
    IN_ADDR in_addr = {};
    memcpy(&in_addr, addr, sizeof(in_addr));
    char ip_buf[INET_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET, &in_addr, ip_buf, sizeof(ip_buf)) == NULL) {
        return std::string("?");
    }
    return std::string(ip_buf);
}

bool ParseIpv4StringToBe(const std::string& value, uint32_t* out_ip_be) {
    if (out_ip_be == NULL || value.empty()) {
        return false;
    }

    IN_ADDR addr = {};
    if (InetPtonA(AF_INET, value.c_str(), &addr) != 1) {
        return false;
    }

    *out_ip_be = addr.S_un.S_addr;
    return true;
}

void CloseSocketQuiet(SOCKET* sock) {
    if (sock == NULL || *sock == INVALID_SOCKET) {
        return;
    }
    SOCKET stale = *sock;
    *sock = INVALID_SOCKET;
    shutdown(stale, SD_BOTH);
    closesocket(stale);
}

void ConfigureTcpStreamSocket(SOCKET sock) {
    int buffer_bytes = kSocketBufferBytes;
    setsockopt(sock,
               SOL_SOCKET,
               SO_RCVBUF,
               reinterpret_cast<const char*>(&buffer_bytes),
               sizeof(buffer_bytes));
    setsockopt(sock,
               SOL_SOCKET,
               SO_SNDBUF,
               reinterpret_cast<const char*>(&buffer_bytes),
               sizeof(buffer_bytes));
    DWORD send_timeout = kSocketSendTimeoutMs;
    setsockopt(sock,
               SOL_SOCKET,
               SO_SNDTIMEO,
               reinterpret_cast<const char*>(&send_timeout),
               sizeof(send_timeout));
    DWORD recv_timeout = kSocketReadTimeoutMs;
    setsockopt(sock,
               SOL_SOCKET,
               SO_RCVTIMEO,
               reinterpret_cast<const char*>(&recv_timeout),
               sizeof(recv_timeout));
    BOOL keepalive = TRUE;
    setsockopt(sock,
               SOL_SOCKET,
               SO_KEEPALIVE,
               reinterpret_cast<const char*>(&keepalive),
               sizeof(keepalive));
    BOOL tcp_nodelay = TRUE;
    setsockopt(sock,
               IPPROTO_TCP,
               TCP_NODELAY,
               reinterpret_cast<const char*>(&tcp_nodelay),
               sizeof(tcp_nodelay));
}

bool BuildTcpDirectSockaddr(uint8_t endpoint_family,
                            const uint8_t* endpoint_addr,
                            uint16_t endpoint_port,
                            sockaddr_storage* out_addr,
                            int* out_addr_len) {
    if (endpoint_addr == NULL || out_addr == NULL || out_addr_len == NULL ||
        endpoint_port == 0) {
        return false;
    }

    ZeroMemory(out_addr, sizeof(*out_addr));
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

bool ConnectSocketWithTimeout(SOCKET sock,
                              const sockaddr_storage& addr,
                              int addr_len,
                              DWORD timeout_ms,
                              int* out_error) {
    if (out_error != NULL) {
        *out_error = 0;
    }

    u_long nonblocking = 1;
    if (ioctlsocket(sock, FIONBIO, &nonblocking) != 0) {
        if (out_error != NULL) {
            *out_error = WSAGetLastError();
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
        last_error = WSAGetLastError();
        if (last_error == WSAEWOULDBLOCK ||
            last_error == WSAEINPROGRESS ||
            last_error == WSAEINVAL) {
            fd_set write_set;
            fd_set except_set;
            FD_ZERO(&write_set);
            FD_ZERO(&except_set);
            FD_SET(sock, &write_set);
            FD_SET(sock, &except_set);
            timeval tv = {};
            tv.tv_sec = static_cast<long>(timeout_ms / 1000);
            tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
            int selected = select(0, NULL, &write_set, &except_set, &tv);
            if (selected > 0 && FD_ISSET(sock, &write_set)) {
                int so_error = 0;
                int so_error_len = sizeof(so_error);
                if (getsockopt(sock,
                               SOL_SOCKET,
                               SO_ERROR,
                               reinterpret_cast<char*>(&so_error),
                               &so_error_len) == 0 &&
                    so_error == 0) {
                    connected = true;
                } else {
                    last_error = so_error != 0 ? so_error : WSAGetLastError();
                }
            } else if (selected == 0) {
                last_error = WSAETIMEDOUT;
            } else {
                last_error = WSAGetLastError();
            }
        }
    }

    nonblocking = 0;
    ioctlsocket(sock, FIONBIO, &nonblocking);
    if (!connected && out_error != NULL) {
        *out_error = last_error;
    }
    return connected;
}

bool TryExtractPeerEndpointFromSockaddr(const sockaddr_storage& source_addr,
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
        const uint8_t v4_mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (memcmp(bytes, v4_mapped_prefix, sizeof(v4_mapped_prefix)) == 0) {
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

const char* PeerRouteStateName(PeerRouteState state) {
    switch (state) {
    case PeerRouteState::RelayOnly:
        return "仅中转";
    case PeerRouteState::OfferReceived:
        return "已收提议";
    case PeerRouteState::Probing:
        return "探测中";
    case PeerRouteState::DirectActive:
        return "直连激活";
    case PeerRouteState::Cooldown:
        return "冷却中";
    default:
        return "未知";
    }
}

std::string BuildPeerRouteSnapshotSummary(const std::vector<PeerRouteStatus>& peers,
                                          unsigned long long now_tick) {
    if (peers.empty()) {
        return "无";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < peers.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_tick > peers[i].last_observed_ms)
                ? (now_tick - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_tick > peers[i].last_state_change_ms)
                ? (now_tick - peers[i].last_state_change_ms)
                : 0;
        ss << peers[i].peer_virtual_ip
           << "[" << PeerRouteStateName(peers[i].state)
           << " 版本=" << peers[i].endpoint_version
           << " 就绪=" << (peers[i].direct_ready ? "是" : "否")
           << " 可切换=" << (peers[i].direct_eligible ? "是" : "否")
           << " 激活=" << (peers[i].active_direct ? "是" : "否")
           << " 观测=" << observed_age << "ms"
           << " 直连=" << ((peers[i].last_direct_data_ms != 0 && now_tick > peers[i].last_direct_data_ms)
                              ? (now_tick - peers[i].last_direct_data_ms)
                              : 0) << "ms"
           << " 样本=" << peers[i].direct_sample_count
           << " 失败=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " 状态时长=" << state_age << "ms]";
    }
    return ss.str();
}

std::string DescribeSinglePeerRoute(const std::vector<PeerRouteStatus>& peers,
                                    const std::string& peer_virtual_ip,
                                    unsigned long long now_tick) {
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip != peer_virtual_ip) {
            continue;
        }

        const unsigned long long observed_age =
            (peers[i].last_observed_ms != 0 && now_tick > peers[i].last_observed_ms)
                ? (now_tick - peers[i].last_observed_ms)
                : 0;
        const unsigned long long state_age =
            (peers[i].last_state_change_ms != 0 && now_tick > peers[i].last_state_change_ms)
                ? (now_tick - peers[i].last_state_change_ms)
                : 0;

        std::ostringstream ss;
        ss << peers[i].peer_virtual_ip
           << "[" << PeerRouteStateName(peers[i].state)
           << " 版本=" << peers[i].endpoint_version
           << " 地址族=" << static_cast<int>(peers[i].endpoint_family)
           << " 端口=" << peers[i].endpoint_port
           << " 就绪=" << (peers[i].direct_ready ? "是" : "否")
           << " 可切换=" << (peers[i].direct_eligible ? "是" : "否")
           << " 激活=" << (peers[i].active_direct ? "是" : "否")
           << " 观测=" << observed_age << "ms"
           << " 直连=" << ((peers[i].last_direct_data_ms != 0 && now_tick > peers[i].last_direct_data_ms)
                              ? (now_tick - peers[i].last_direct_data_ms)
                              : 0) << "ms"
           << " 样本=" << peers[i].direct_sample_count
           << " 失败=" << peers[i].active_failures << "/" << peers[i].probe_failures
           << " 状态时长=" << state_age << "ms]";
        return ss.str();
    }

    return std::string();
}

bool IsNoisyUdpForLogging(const uint8_t* packet, size_t packet_len) {
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

bool TryDescribeUdpPacket(const uint8_t* packet, size_t packet_len, std::string* out_desc) {
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

    uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    std::ostringstream ss;
    ss << "src=" << Ipv4ToString(packet + 12) << ":" << src_port
       << " dst=" << Ipv4ToString(packet + 16) << ":" << dst_port
       << " len=" << packet_len;
    *out_desc = ss.str();
    return true;
}

bool IsMirrorEligibleUdpFlow(uint16_t src_port, uint16_t dst_port) {
    return kEnableGatewayUdpPeerHeuristics &&
           !IsKnownGameUdpPort(src_port) &&
           !IsKnownGameUdpPort(dst_port) &&
           !IsReservedPeerDirectPort(src_port) &&
           !IsReservedPeerDirectPort(dst_port);
}

uint32_t HashBytesFnv1a32(const uint8_t* data, size_t length) {
    const uint32_t kFnvOffset = 2166136261u;
    const uint32_t kFnvPrime = 16777619u;
    uint32_t hash = kFnvOffset;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= kFnvPrime;
    }
    return hash;
}

std::string BuildMirroredGatewayUdpSignature(const uint8_t* packet, size_t packet_len) {
    if (packet == NULL || packet_len < 28 || ((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return std::string();
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return std::string();
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    const uint8_t* udp_payload = packet + ip_header_len + 8;
    const size_t udp_payload_len = packet_len - ip_header_len - 8;

    std::ostringstream ss;
    ss << Ipv4ToString(packet + 12) << ":" << src_port
       << ">" << dst_port
       << "/len=" << udp_payload_len
       << "/hash=" << HashBytesFnv1a32(udp_payload, udp_payload_len);
    return ss.str();
}

void BusyWaitMicroseconds(unsigned int microseconds) {
    if (microseconds == 0) {
        return;
    }

    LARGE_INTEGER frequency = {};
    LARGE_INTEGER start = {};
    if (!QueryPerformanceFrequency(&frequency) ||
        frequency.QuadPart <= 0 ||
        !QueryPerformanceCounter(&start)) {
        return;
    }

    const LONGLONG target_ticks =
        static_cast<LONGLONG>((static_cast<unsigned long long>(frequency.QuadPart) *
                               static_cast<unsigned long long>(microseconds)) / 1000000ull);
    if (target_ticks <= 0) {
        return;
    }

    while (true) {
        LARGE_INTEGER now = {};
        if (!QueryPerformanceCounter(&now)) {
            return;
        }
        if ((now.QuadPart - start.QuadPart) >= target_ticks) {
            return;
        }
        YieldProcessor();
    }
}

void PruneMirroredGatewayUdpSignatureTicks(std::map<std::string, unsigned long long>* ticks,
                                           unsigned long long now_tick) {
    if (ticks == NULL) {
        return;
    }

    for (std::map<std::string, unsigned long long>::iterator it = ticks->begin();
         it != ticks->end();) {
        const bool expired =
            now_tick < it->second ||
            (now_tick - it->second) > kMirroredGatewayUdpSignatureTtlMs;
        if (!expired) {
            ++it;
            continue;
        }
        std::map<std::string, unsigned long long>::iterator erase_it = it++;
        ticks->erase(erase_it);
    }
}

struct TcpPayloadVirtualIpHit {
    std::string ip;
    bool little_endian;
    size_t offset;
    bool has_next_port;
    uint16_t next_port_be;
    uint16_t next_port_le;
    std::string context_hex;
};

struct WatchedTcpPacketInfo {
    std::string flow_key;
    std::string client_ip;
    std::string server_ip;
    uint16_t client_port;
    uint16_t server_port;
    uint8_t flags;
    size_t payload_len;
    bool from_client;
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    bool has_payload;

    WatchedTcpPacketInfo()
        : client_port(0),
          server_port(0),
          flags(0),
          payload_len(0),
          from_client(false),
          syn(false),
          ack(false),
          fin(false),
          rst(false),
          has_payload(false) {
    }
};

bool TryParseTcpPacket(const uint8_t* packet,
                       size_t packet_len,
                       size_t* out_ip_header_len,
                       size_t* out_tcp_header_len,
                       uint16_t* out_src_port,
                       uint16_t* out_dst_port) {
    if (packet == NULL || packet_len < 20 || ((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_TCP) {
        return false;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 20) {
        return false;
    }

    const size_t tcp_header_len =
        static_cast<size_t>((packet[ip_header_len + 12] >> 4) & 0x0F) * 4;
    if (tcp_header_len < 20 || packet_len < ip_header_len + tcp_header_len) {
        return false;
    }

    if (out_ip_header_len != NULL) {
        *out_ip_header_len = ip_header_len;
    }
    if (out_tcp_header_len != NULL) {
        *out_tcp_header_len = tcp_header_len;
    }
    if (out_src_port != NULL) {
        *out_src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    }
    if (out_dst_port != NULL) {
        *out_dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    }
    return true;
}

std::string FormatWatchedTcpElapsed(unsigned long long start_ms, unsigned long long now_ms) {
    if (start_ms == 0 || now_ms < start_ms) {
        return "-";
    }
    return std::to_string(now_ms - start_ms);
}

std::string DescribeWatchedTcpFlags(uint8_t flags) {
    std::vector<std::string> parts;
    if ((flags & 0x10) != 0) {
        parts.push_back("ACK");
    }
    if ((flags & 0x02) != 0) {
        parts.push_back("SYN");
    }
    if ((flags & 0x01) != 0) {
        parts.push_back("FIN");
    }
    if ((flags & 0x04) != 0) {
        parts.push_back("RST");
    }
    if ((flags & 0x08) != 0) {
        parts.push_back("PSH");
    }
    if ((flags & 0x20) != 0) {
        parts.push_back("URG");
    }
    if (parts.empty()) {
        parts.push_back("NONE");
    }

    std::ostringstream ss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            ss << "|";
        }
        ss << parts[i];
    }
    return ss.str();
}

bool TryParseWatchedTcpPacket(const uint8_t* packet,
                              size_t packet_len,
                              const std::string& local_virtual_ip,
                              WatchedTcpPacketInfo* out_info) {
    if (out_info == NULL) {
        return false;
    }

    size_t ip_header_len = 0;
    size_t tcp_header_len = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (!TryParseTcpPacket(packet,
                           packet_len,
                           &ip_header_len,
                           &tcp_header_len,
                           &src_port,
                           &dst_port)) {
        return false;
    }

    if (!IsWatchedBusinessTcpPort(src_port) && !IsWatchedBusinessTcpPort(dst_port)) {
        return false;
    }

    const uint16_t total_len = ntohs(*(const uint16_t*)(packet + 2));
    if (total_len < ip_header_len + tcp_header_len || packet_len < total_len) {
        return false;
    }

    const std::string src_ip = Ipv4ToString(packet + 12);
    const std::string dst_ip = Ipv4ToString(packet + 16);
    if (src_ip != local_virtual_ip && dst_ip != local_virtual_ip) {
        return false;
    }

    const bool from_client = src_ip == local_virtual_ip;
    out_info->client_ip = from_client ? src_ip : dst_ip;
    out_info->server_ip = from_client ? dst_ip : src_ip;
    out_info->client_port = from_client ? src_port : dst_port;
    out_info->server_port = from_client ? dst_port : src_port;
    out_info->flow_key = out_info->client_ip + ":" + std::to_string(out_info->client_port) +
                         ">" + out_info->server_ip + ":" + std::to_string(out_info->server_port);
    out_info->from_client = from_client;

    const size_t tcp_header_offset = ip_header_len;
    out_info->flags = packet[tcp_header_offset + 13];
    out_info->syn = (out_info->flags & 0x02) != 0;
    out_info->ack = (out_info->flags & 0x10) != 0;
    out_info->fin = (out_info->flags & 0x01) != 0;
    out_info->rst = (out_info->flags & 0x04) != 0;
    out_info->payload_len = total_len - ip_header_len - tcp_header_len;
    out_info->has_payload = out_info->payload_len != 0;
    return true;
}

bool IsTransientSocketSendError(int error_code) {
    return error_code == WSAETIMEDOUT ||
           error_code == WSAEWOULDBLOCK ||
           error_code == WSAENOBUFS ||
           error_code == WSAEINTR;
}

bool IsWatchedBusinessTcpPort(uint16_t port) {
    switch (port) {
        case 7000:
        case 7001:
        case 7200:
        case 10011:
        case 10015:
        case 10056:
            return true;
        default:
            return false;
    }
}

std::vector<TcpPayloadVirtualIpHit> FindVirtualSubnetIpHits(const uint8_t* payload,
                                                            size_t payload_len,
                                                            size_t max_hits) {
    std::vector<TcpPayloadVirtualIpHit> hits;
    if (payload == NULL || payload_len < 4 || max_hits == 0) {
        return hits;
    }

    for (size_t i = 0; i + 3 < payload_len && hits.size() < max_hits; ++i) {
        bool little_endian = false;
        uint8_t last_octet = 0;
        if (payload[i] == 192 && payload[i + 1] == 168 && payload[i + 2] == 200) {
            last_octet = payload[i + 3];
        } else if (payload[i + 1] == 200 && payload[i + 2] == 168 && payload[i + 3] == 192) {
            little_endian = true;
            last_octet = payload[i];
        } else {
            continue;
        }

        TcpPayloadVirtualIpHit hit = {};
        hit.ip = "192.168.200." + std::to_string(last_octet);
        hit.little_endian = little_endian;
        hit.offset = i;
        if (i + 5 < payload_len) {
            hit.has_next_port = true;
            hit.next_port_be =
                static_cast<uint16_t>((payload[i + 4] << 8) | payload[i + 5]);
            hit.next_port_le =
                static_cast<uint16_t>(payload[i + 4] | (payload[i + 5] << 8));
        }

        const size_t context_start = (i > 8) ? (i - 8) : 0;
        const size_t context_len = std::min(payload_len - context_start, static_cast<size_t>(20));
        hit.context_hex = HexPrefix(payload + context_start, context_len, context_len);
        hits.push_back(hit);
    }

    return hits;
}

std::string DescribeVirtualIpRole(const std::string& ip,
                                  const std::string& local_virtual_ip,
                                  const std::string& inner_src_ip,
                                  const std::string& inner_dst_ip,
                                  const std::vector<PeerRouteStatus>& peers) {
    std::vector<std::string> labels;
    if (!local_virtual_ip.empty() && ip == local_virtual_ip) {
        labels.push_back("local_virtual");
    }
    if (!inner_src_ip.empty() && ip == inner_src_ip) {
        labels.push_back("inner_src");
    }
    if (!inner_dst_ip.empty() && ip == inner_dst_ip) {
        labels.push_back("inner_dst");
    }
    for (size_t i = 0; i < peers.size(); ++i) {
        if (peers[i].peer_virtual_ip == ip) {
            labels.push_back("known_peer");
            break;
        }
    }
    if (labels.empty()) {
        labels.push_back("virtual_subnet");
    }

    std::ostringstream ss;
    for (size_t i = 0; i < labels.size(); ++i) {
        if (i != 0) {
            ss << ",";
        }
        ss << labels[i];
    }
    return ss.str();
}

struct ParsedPeerOffer {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t endpoint_family;
    uint16_t endpoint_port;
    uint8_t endpoint_addr[16];
    std::string endpoint;
};

struct ParsedPeerSignal {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint32_t nonce;
};

struct ParsedPeerDisable {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    uint8_t reason;
};

std::string PacketTunnelFrameName(uint8_t frame_type) {
    switch (frame_type) {
    case packet_tunnel::kFrameHeartbeat:
        return "心跳";
    case packet_tunnel::kFrameHeartbeatAck:
        return "心跳确认";
    case packet_tunnel::kFrameIpv4Packet:
        return "IPv4数据";
    case packet_tunnel::kFramePeerOffer:
        return "对等端提议";
    case packet_tunnel::kFramePeerHello:
        return "对等端问候";
    case packet_tunnel::kFramePeerAck:
        return "对等端确认";
    case packet_tunnel::kFramePeerKeepalive:
        return "对等端保活";
    case packet_tunnel::kFramePeerDisable:
        return "对等端禁用";
    case packet_tunnel::kFrameTcpPeerOffer:
        return "TCP对等端提议";
    case packet_tunnel::kFrameTcpDirectAdvertise:
        return "TCP直连监听通告";
    case packet_tunnel::kFrameTcpDirectOpen:
        return "TCP直连打开";
    case packet_tunnel::kFrameTcpDirectCandidateAdvertise:
        return "TCP直连候选通告";
    case packet_tunnel::kFrameUdpDirectCandidateAdvertise:
        return "UDP直连候选通告";
    default:
        return "未知帧";
    }
}

std::string PeerEndpointToString(uint8_t family, const uint8_t* addr, uint16_t port) {
    char buffer[INET6_ADDRSTRLEN] = {};
    if (family == packet_tunnel::kPeerEndpointFamilyIpv4) {
        if (InetNtopA(AF_INET, const_cast<uint8_t*>(addr), buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(port);
        }
    } else if (family == packet_tunnel::kPeerEndpointFamilyIpv6) {
        if (InetNtopA(AF_INET6, const_cast<uint8_t*>(addr), buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(port);
        }
    }
    return "unknown";
}

void NormalizePeerEndpointFamily(uint8_t* family, uint8_t* addr) {
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

std::string SockaddrToString(const sockaddr_storage& addr, int addr_len) {
    (void)addr_len;
    char buffer[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(&addr);
        if (InetNtopA(AF_INET, const_cast<IN_ADDR*>(&addr4->sin_addr), buffer, sizeof(buffer)) != NULL) {
            return std::string(buffer) + ":" + std::to_string(ntohs(addr4->sin_port));
        }
    } else if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&addr6->sin6_addr), buffer, sizeof(buffer)) != NULL) {
            return "[" + std::string(buffer) + "]:" + std::to_string(ntohs(addr6->sin6_port));
        }
    }
    return "unknown";
}

void ClearSockaddrPort(sockaddr_storage* addr) {
    if (addr == NULL) {
        return;
    }

    if (addr->ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(addr)->sin_port = 0;
    } else if (addr->ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = 0;
    }
}

void SetSockaddrPort(sockaddr_storage* addr, uint16_t port_host_order) {
    if (addr == NULL) {
        return;
    }

    if (addr->ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in*>(addr)->sin_port = htons(port_host_order);
    } else if (addr->ss_family == AF_INET6) {
        reinterpret_cast<sockaddr_in6*>(addr)->sin6_port = htons(port_host_order);
    }
}

bool IsUsableBindAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
        if (ip == 0 ||
            (ip & 0xff000000u) == 0x7f000000u ||
            (ip & 0xffff0000u) == 0xa9fe0000u ||
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
        return (addr6->sin6_addr.u.Byte[0] & 0xe0) == 0x20;
    }

    return false;
}

bool IsPublicInternetAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
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
        if ((addr6->sin6_addr.u.Byte[0] & 0xfe) == 0xfc) {
            return false;
        }
        return (addr6->sin6_addr.u.Byte[0] & 0xe0) == 0x20;
    }

    return false;
}

bool SockaddrEquals(const sockaddr_storage& left,
                    int left_len,
                    const sockaddr_storage& right,
                    int right_len);

bool TryFindBindAddressForInterface(ULONG interface_index,
                                    int family,
                                    sockaddr_storage* bind_addr,
                                    int* bind_addr_len,
                                    std::string* adapter_name);

bool BuildEndpointForSocketFamily(const sockaddr* source_addr,
                                  int source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  int* endpoint_addr_len);

struct RelayEndpointCandidate {
    sockaddr_storage endpoint_addr;
    int endpoint_addr_len;
    int socket_family;
    bool public_internet;
    size_t original_order;
};

int RelayEndpointPriority(const RelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? 0 : 1;
    }
    return (candidate.socket_family == AF_INET6) ? 2 : 3;
}

const char* RelayEndpointScopeName(const RelayEndpointCandidate& candidate) {
    if (candidate.public_internet) {
        return (candidate.socket_family == AF_INET6) ? "public_ipv6" : "public_ipv4";
    }
    return (candidate.socket_family == AF_INET6) ? "non_public_ipv6" : "non_public_ipv4";
}

bool HasPublicRelayEndpointCandidate(const std::vector<RelayEndpointCandidate>& candidates) {
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].public_internet) {
            return true;
        }
    }
    return false;
}

void SortRelayEndpointCandidates(std::vector<RelayEndpointCandidate>* candidates) {
    if (candidates == NULL) {
        return;
    }

    std::stable_sort(candidates->begin(),
                     candidates->end(),
                     [](const RelayEndpointCandidate& left, const RelayEndpointCandidate& right) {
                         const int left_priority = RelayEndpointPriority(left);
                         const int right_priority = RelayEndpointPriority(right);
                         if (left_priority != right_priority) {
                             return left_priority < right_priority;
                         }
                         return left.original_order < right.original_order;
                     });
}

std::string BuildRelayEndpointCandidateSummary(const std::vector<RelayEndpointCandidate>& candidates) {
    if (candidates.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        ss << RelayEndpointScopeName(candidates[i]) << "="
           << SockaddrToString(candidates[i].endpoint_addr, candidates[i].endpoint_addr_len);
    }
    return ss.str();
}

bool AppendRelayEndpointCandidate(const sockaddr* source_addr,
                                  int source_addr_len,
                                  int socket_family,
                                  size_t original_order,
                                  std::vector<RelayEndpointCandidate>* out_candidates) {
    if (source_addr == NULL || out_candidates == NULL) {
        return false;
    }

    RelayEndpointCandidate candidate = {};
    if (!BuildEndpointForSocketFamily(source_addr,
                                      source_addr_len,
                                      socket_family,
                                      &candidate.endpoint_addr,
                                      &candidate.endpoint_addr_len)) {
        return false;
    }

    candidate.socket_family = socket_family;
    candidate.public_internet =
        IsPublicInternetAddress(reinterpret_cast<const sockaddr*>(&candidate.endpoint_addr));
    candidate.original_order = original_order;

    for (size_t i = 0; i < out_candidates->size(); ++i) {
        if (SockaddrEquals((*out_candidates)[i].endpoint_addr,
                           (*out_candidates)[i].endpoint_addr_len,
                           candidate.endpoint_addr,
                           candidate.endpoint_addr_len)) {
            return false;
        }
    }

    out_candidates->push_back(candidate);
    return true;
}

void BuildRelayEndpointCandidates(addrinfo* result,
                                  std::vector<RelayEndpointCandidate>* out_candidates) {
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

        AppendRelayEndpointCandidate(rp->ai_addr,
                                     static_cast<int>(rp->ai_addrlen),
                                     family,
                                     order,
                                     out_candidates);
    }

    SortRelayEndpointCandidates(out_candidates);
}

bool SockaddrAddressEquals(const sockaddr_storage& left, const sockaddr* right) {
    if (right == NULL || left.ss_family != right->sa_family) {
        return false;
    }

    if (left.ss_family == AF_INET) {
        const sockaddr_in* left4 = reinterpret_cast<const sockaddr_in*>(&left);
        const sockaddr_in* right4 = reinterpret_cast<const sockaddr_in*>(right);
        return left4->sin_addr.S_un.S_addr == right4->sin_addr.S_un.S_addr;
    }

    if (left.ss_family == AF_INET6) {
        const sockaddr_in6* left6 = reinterpret_cast<const sockaddr_in6*>(&left);
        const sockaddr_in6* right6 = reinterpret_cast<const sockaddr_in6*>(right);
        return memcmp(&left6->sin6_addr, &right6->sin6_addr, sizeof(left6->sin6_addr)) == 0;
    }

    return false;
}

bool LoadAdapterAddressesInternal(ULONG family,
                                  ULONG flags,
                                  std::vector<unsigned char>* buffer,
                                  IP_ADAPTER_ADDRESSES** adapters) {
    if (buffer == NULL || adapters == NULL) {
        return false;
    }

    flags |= GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    ULONG buffer_size = 16 * 1024;
    buffer->assign(buffer_size, 0);

    ULONG ret = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && ret == ERROR_BUFFER_OVERFLOW; ++attempt) {
        ret = GetAdaptersAddresses(family,
                                   flags,
                                   NULL,
                                   reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&(*buffer)[0]),
                                   &buffer_size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            buffer->assign(buffer_size, 0);
        }
    }

    if (ret != NO_ERROR) {
        return false;
    }

    *adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&(*buffer)[0]);
    return true;
}

bool LoadAdapterAddresses(ULONG family,
                          std::vector<unsigned char>* buffer,
                          IP_ADAPTER_ADDRESSES** adapters) {
    return LoadAdapterAddressesInternal(family,
                                        GAA_FLAG_SKIP_DNS_SERVER,
                                        buffer,
                                        adapters);
}

bool LoadAdapterAddressesForDns(ULONG family,
                                std::vector<unsigned char>* buffer,
                                IP_ADAPTER_ADDRESSES** adapters) {
    return LoadAdapterAddressesInternal(family, 0, buffer, adapters);
}

std::string AdapterDisplayName(const IP_ADAPTER_ADDRESSES* adapter) {
    if (adapter == NULL) {
        return "unknown";
    }

    std::wstring name = adapter->FriendlyName ? adapter->FriendlyName : L"";
    if (name.empty() && adapter->Description != NULL) {
        name = adapter->Description;
    }
    return WideToUtf8(name);
}

bool IsPreferredPhysicalAdapter(const IP_ADAPTER_ADDRESSES* adapter) {
    if (adapter == NULL || adapter->OperStatus != IfOperStatusUp) {
        return false;
    }

    if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD &&
        adapter->IfType != IF_TYPE_IEEE80211) {
        return false;
    }

    MIB_IF_ROW2 row = {};
    row.InterfaceLuid = adapter->Luid;
    if (GetIfEntry2(&row) != NO_ERROR) {
        return false;
    }
    if (!row.InterfaceAndOperStatusFlags.HardwareInterface ||
        row.InterfaceAndOperStatusFlags.FilterInterface) {
        return false;
    }

    return true;
}

bool IsUsableDnsServerAddress(const sockaddr* addr) {
    if (addr == NULL) {
        return false;
    }

    if (addr->sa_family == AF_INET) {
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
        if (ip == 0 ||
            (ip & 0xff000000u) == 0x7f000000u ||
            (ip & 0xffff0000u) == 0xa9fe0000u) {
            return false;
        }
        return true;
    }

    if (addr->sa_family == AF_INET6) {
        const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr) ||
            IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr)) {
            return false;
        }
        return true;
    }

    return false;
}

bool IsNumericHostLiteral(const std::string& value) {
    IN_ADDR addr4 = {};
    if (InetPtonA(AF_INET, value.c_str(), &addr4) == 1) {
        return true;
    }

    IN6_ADDR addr6 = {};
    return InetPtonA(AF_INET6, value.c_str(), &addr6) == 1;
}

struct PhysicalDnsServer {
    sockaddr_storage server_addr;
    int server_addr_len;
    ULONG interface_index;
    std::string adapter_name;
    size_t original_order;
};

std::string BuildPhysicalDnsServerSummary(const std::vector<PhysicalDnsServer>& servers) {
    if (servers.empty()) {
        return "none";
    }

    std::ostringstream ss;
    for (size_t i = 0; i < servers.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        ss << SockaddrToString(servers[i].server_addr, servers[i].server_addr_len)
           << "@if" << servers[i].interface_index;
        if (!servers[i].adapter_name.empty()) {
            ss << "(" << servers[i].adapter_name << ")";
        }
    }
    return ss.str();
}

void CollectPhysicalDnsServers(std::vector<PhysicalDnsServer>* out_servers) {
    if (out_servers == NULL) {
        return;
    }

    out_servers->clear();

    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddressesForDns(AF_UNSPEC, &buffer, &adapters)) {
        return;
    }

    size_t order = 0;
    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (!IsPreferredPhysicalAdapter(adapter)) {
            continue;
        }

        const std::string adapter_name = AdapterDisplayName(adapter);
        for (IP_ADAPTER_DNS_SERVER_ADDRESS* dns = adapter->FirstDnsServerAddress;
             dns != NULL;
             dns = dns->Next) {
            if (dns->Address.lpSockaddr == NULL ||
                !IsUsableDnsServerAddress(dns->Address.lpSockaddr)) {
                continue;
            }

            const int family = dns->Address.lpSockaddr->sa_family;
            if (family != AF_INET && family != AF_INET6) {
                continue;
            }

            PhysicalDnsServer server = {};
            if (family == AF_INET) {
                server.server_addr_len = sizeof(sockaddr_in);
                memcpy(&server.server_addr, dns->Address.lpSockaddr, sizeof(sockaddr_in));
                server.interface_index = adapter->IfIndex;
            } else {
                server.server_addr_len = sizeof(sockaddr_in6);
                memcpy(&server.server_addr, dns->Address.lpSockaddr, sizeof(sockaddr_in6));
                server.interface_index = (adapter->Ipv6IfIndex != 0)
                    ? adapter->Ipv6IfIndex
                    : adapter->IfIndex;
            }

            ClearSockaddrPort(&server.server_addr);
            SetSockaddrPort(&server.server_addr, 53);
            server.adapter_name = adapter_name;
            server.original_order = order++;

            bool duplicate = false;
            for (size_t i = 0; i < out_servers->size(); ++i) {
                if (SockaddrAddressEquals((*out_servers)[i].server_addr,
                                          reinterpret_cast<const sockaddr*>(&server.server_addr))) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                out_servers->push_back(server);
            }
        }
    }
}

const char* DnsRecordTypeName(WORD type) {
    switch (type) {
    case DNS_TYPE_A:
        return "A";
    case DNS_TYPE_AAAA:
        return "AAAA";
    default:
        return "?";
    }
}

uint16_t ReadDnsUInt16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                                 static_cast<uint16_t>(data[1]));
}

void AppendDnsUInt16(uint16_t value, std::vector<uint8_t>* out) {
    if (out == NULL) {
        return;
    }
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(value & 0xff));
}

bool AppendDnsQueryName(const std::string& host_name, std::vector<uint8_t>* out) {
    if (out == NULL || host_name.empty()) {
        return false;
    }

    size_t start = 0;
    while (start < host_name.size()) {
        size_t end = host_name.find('.', start);
        if (end == std::string::npos) {
            end = host_name.size();
        }

        const size_t label_len = end - start;
        if (label_len == 0 || label_len > 63) {
            return false;
        }

        out->push_back(static_cast<uint8_t>(label_len));
        out->insert(out->end(),
                    host_name.begin() + static_cast<std::ptrdiff_t>(start),
                    host_name.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }

    out->push_back(0);
    return true;
}

bool SkipDnsName(const uint8_t* packet, size_t packet_len, size_t* offset) {
    if (packet == NULL || offset == NULL || *offset >= packet_len) {
        return false;
    }

    size_t pos = *offset;
    int steps = 0;
    while (pos < packet_len && steps++ < 128) {
        const uint8_t label = packet[pos];
        if (label == 0) {
            *offset = pos + 1;
            return true;
        }
        if ((label & 0xc0) == 0xc0) {
            if (pos + 1 >= packet_len) {
                return false;
            }
            *offset = pos + 2;
            return true;
        }
        if ((label & 0xc0) != 0x00) {
            return false;
        }

        const size_t label_len = static_cast<size_t>(label);
        ++pos;
        if (pos + label_len > packet_len) {
            return false;
        }
        pos += label_len;
    }

    return false;
}

bool ParseDnsResponseRecords(const uint8_t* packet,
                             size_t packet_len,
                             uint16_t expected_txid,
                             uint16_t tunnel_port,
                             size_t* next_order,
                             std::vector<RelayEndpointCandidate>* out_candidates,
                             size_t* out_added) {
    if (packet == NULL || packet_len < 12 || next_order == NULL || out_candidates == NULL) {
        return false;
    }

    if (ReadDnsUInt16(packet) != expected_txid) {
        return false;
    }

    const uint16_t flags = ReadDnsUInt16(packet + 2);
    if ((flags & 0x8000u) == 0) {
        return false;
    }
    if ((flags & 0x000fu) != 0) {
        return false;
    }

    const uint16_t question_count = ReadDnsUInt16(packet + 4);
    const uint16_t answer_count = ReadDnsUInt16(packet + 6);
    const uint16_t authority_count = ReadDnsUInt16(packet + 8);
    const uint16_t additional_count = ReadDnsUInt16(packet + 10);

    size_t offset = 12;
    for (uint16_t i = 0; i < question_count; ++i) {
        if (!SkipDnsName(packet, packet_len, &offset) || offset + 4 > packet_len) {
            return false;
        }
        offset += 4;
    }

    size_t added = 0;
    const uint32_t total_records =
        static_cast<uint32_t>(answer_count) +
        static_cast<uint32_t>(authority_count) +
        static_cast<uint32_t>(additional_count);
    for (uint32_t i = 0; i < total_records; ++i) {
        if (!SkipDnsName(packet, packet_len, &offset) || offset + 10 > packet_len) {
            return false;
        }

        const uint16_t record_type = ReadDnsUInt16(packet + offset);
        const uint16_t record_class = ReadDnsUInt16(packet + offset + 2);
        const uint16_t record_len = ReadDnsUInt16(packet + offset + 8);
        offset += 10;
        if (offset + record_len > packet_len) {
            return false;
        }

        if (record_class == 1 && record_type == DNS_TYPE_A && record_len == 4) {
            sockaddr_in addr4 = {};
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(tunnel_port);
            memcpy(&addr4.sin_addr, packet + offset, 4);
            if (AppendRelayEndpointCandidate(reinterpret_cast<const sockaddr*>(&addr4),
                                             sizeof(addr4),
                                             AF_INET,
                                             *next_order,
                                             out_candidates)) {
                ++(*next_order);
                ++added;
            }
        } else if (record_class == 1 && record_type == DNS_TYPE_AAAA && record_len == 16) {
            sockaddr_in6 addr6 = {};
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(tunnel_port);
            memcpy(&addr6.sin6_addr, packet + offset, 16);
            if (AppendRelayEndpointCandidate(reinterpret_cast<const sockaddr*>(&addr6),
                                             sizeof(addr6),
                                             AF_INET6,
                                             *next_order,
                                             out_candidates)) {
                ++(*next_order);
                ++added;
            }
        }

        offset += record_len;
    }

    if (out_added != NULL) {
        *out_added = added;
    }
    return true;
}

bool QueryRelayEndpointsViaSingleDnsServer(const std::string& host_name,
                                           uint16_t tunnel_port,
                                           const PhysicalDnsServer& dns_server,
                                           WORD query_type,
                                           size_t* next_order,
                                           std::vector<RelayEndpointCandidate>* out_candidates) {
    if (next_order == NULL || out_candidates == NULL) {
        return false;
    }

    sockaddr_storage bind_addr = {};
    int bind_addr_len = 0;
    std::string bind_adapter_name;
    if (!TryFindBindAddressForInterface(dns_server.interface_index,
                                        dns_server.server_addr.ss_family,
                                        &bind_addr,
                                        &bind_addr_len,
                                        &bind_adapter_name)) {
        PacketTunnelDebugLog("未找到物理DNS绑定地址: 服务器=" +
                             SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                             " 接口=" + std::to_string(dns_server.interface_index));
        return false;
    }

    SOCKET sock = socket(dns_server.server_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        PacketTunnelDebugLog("创建物理DNS套接字失败: 服务器=" +
                             SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                             " WSA错误=" + std::to_string(WSAGetLastError()));
        return false;
    }

    DWORD timeout = kPhysicalDnsQueryTimeoutMs;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    BOOL disable_udp_connreset = FALSE;
    DWORD bytes_returned = 0;
    WSAIoctl(sock,
             SIO_UDP_CONNRESET,
             &disable_udp_connreset,
             sizeof(disable_udp_connreset),
             NULL,
             0,
             &bytes_returned,
             NULL,
             NULL);

    bool success = false;
    do {
        if (bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), bind_addr_len) != 0) {
            PacketTunnelDebugLog("物理DNS绑定失败: 服务器=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " 绑定地址=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " WSA错误=" + std::to_string(WSAGetLastError()));
            break;
        }

        if (connect(sock,
                    reinterpret_cast<const sockaddr*>(&dns_server.server_addr),
                    dns_server.server_addr_len) != 0) {
            PacketTunnelDebugLog("物理DNS连接失败: 服务器=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " 绑定地址=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " WSA错误=" + std::to_string(WSAGetLastError()));
            break;
        }

        const uint16_t txid =
            static_cast<uint16_t>((GetTickCount64() + (*next_order * 97) + query_type) & 0xffffu);
        std::vector<uint8_t> query;
        query.reserve(512);
        AppendDnsUInt16(txid, &query);
        AppendDnsUInt16(0x0100u, &query);
        AppendDnsUInt16(1, &query);
        AppendDnsUInt16(0, &query);
        AppendDnsUInt16(0, &query);
        AppendDnsUInt16(0, &query);
        if (!AppendDnsQueryName(host_name, &query)) {
            break;
        }
        AppendDnsUInt16(query_type, &query);
        AppendDnsUInt16(1, &query);

        const int sent = send(sock,
                              reinterpret_cast<const char*>(query.data()),
                              static_cast<int>(query.size()),
                              0);
        if (sent != static_cast<int>(query.size())) {
            PacketTunnelDebugLog("物理DNS发送失败: 服务器=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " 绑定地址=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " 类型=" + DnsRecordTypeName(query_type) +
                                 " WSA错误=" + std::to_string(WSAGetLastError()));
            break;
        }

        uint8_t response[2048] = {};
        const int received = recv(sock, reinterpret_cast<char*>(response), sizeof(response), 0);
        if (received <= 0) {
            PacketTunnelDebugLog("物理DNS接收失败: 服务器=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " 绑定地址=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " 类型=" + DnsRecordTypeName(query_type) +
                                 " WSA错误=" + std::to_string(WSAGetLastError()));
            break;
        }

        size_t added = 0;
        if (!ParseDnsResponseRecords(response,
                                     static_cast<size_t>(received),
                                     txid,
                                     tunnel_port,
                                     next_order,
                                     out_candidates,
                                     &added)) {
            PacketTunnelDebugLog("物理DNS解析失败: 服务器=" +
                                 SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                                 " 绑定地址=" + SockaddrToString(bind_addr, bind_addr_len) +
                                 " 类型=" + DnsRecordTypeName(query_type) +
                                 " 字节数=" + std::to_string(received));
            break;
        }

        PacketTunnelDebugLog("物理DNS查询结果: 服务器=" +
                             SockaddrToString(dns_server.server_addr, dns_server.server_addr_len) +
                             " 绑定地址=" + SockaddrToString(bind_addr, bind_addr_len) +
                             " 类型=" + DnsRecordTypeName(query_type) +
                             " 新增候选=" + std::to_string(added));
        success = added > 0;
    } while (false);

    closesocket(sock);
    return success;
}

bool QueryRelayEndpointsViaPhysicalDns(const std::string& host_name,
                                       uint16_t tunnel_port,
                                       const std::vector<PhysicalDnsServer>& dns_servers,
                                       std::vector<RelayEndpointCandidate>* out_candidates) {
    if (out_candidates == NULL || dns_servers.empty()) {
        return false;
    }

    bool added_any = false;
    size_t next_order = out_candidates->size();
    for (size_t server_index = 0; server_index < dns_servers.size(); ++server_index) {
        const PhysicalDnsServer& dns_server = dns_servers[server_index];

        for (int type_index = 0; type_index < 2; ++type_index) {
            const WORD query_type = (type_index == 0) ? DNS_TYPE_AAAA : DNS_TYPE_A;
            if (QueryRelayEndpointsViaSingleDnsServer(host_name,
                                                      tunnel_port,
                                                      dns_server,
                                                      query_type,
                                                      &next_order,
                                                      out_candidates)) {
                added_any = true;
            }
        }

        if (HasPublicRelayEndpointCandidate(*out_candidates)) {
            break;
        }
    }

    if (added_any) {
        SortRelayEndpointCandidates(out_candidates);
    }
    return added_any;
}

bool TryResolveBindAdapter(const sockaddr_storage& addr,
                           int family,
                           std::string* adapter_name,
                           bool* preferred) {
    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddresses(static_cast<ULONG>(family), &buffer, &adapters)) {
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != family) {
                continue;
            }
            if (!SockaddrAddressEquals(addr, unicast->Address.lpSockaddr)) {
                continue;
            }

            if (adapter_name != NULL) {
                *adapter_name = AdapterDisplayName(adapter);
            }
            if (preferred != NULL) {
                *preferred = IsPreferredPhysicalAdapter(adapter);
            }
            return true;
        }
    }

    return false;
}

bool TryFindBindAddressForInterface(ULONG interface_index,
                                    int family,
                                    sockaddr_storage* bind_addr,
                                    int* bind_addr_len,
                                    std::string* adapter_name) {
    if (bind_addr == NULL || bind_addr_len == NULL) {
        return false;
    }

    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddresses(static_cast<ULONG>(family), &buffer, &adapters)) {
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (!IsPreferredPhysicalAdapter(adapter)) {
            continue;
        }

        const ULONG adapter_index = (family == AF_INET6 && adapter->Ipv6IfIndex != 0)
            ? adapter->Ipv6IfIndex
            : adapter->IfIndex;
        if (adapter_index != interface_index) {
            continue;
        }

        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != family ||
                !IsUsableBindAddress(unicast->Address.lpSockaddr)) {
                continue;
            }

            if (family == AF_INET) {
                *bind_addr_len = sizeof(sockaddr_in);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in));
            } else if (family == AF_INET6) {
                *bind_addr_len = sizeof(sockaddr_in6);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in6));
            } else {
                continue;
            }

            ClearSockaddrPort(bind_addr);
            if (adapter_name != NULL) {
                *adapter_name = AdapterDisplayName(adapter);
            }
            return true;
        }
    }

    return false;
}

bool TryFindPreferredBindAddress(int family,
                                 sockaddr_storage* bind_addr,
                                 int* bind_addr_len,
                                 std::string* adapter_name) {
    if (bind_addr == NULL || bind_addr_len == NULL) {
        return false;
    }

    std::vector<unsigned char> buffer;
    IP_ADAPTER_ADDRESSES* adapters = NULL;
    if (!LoadAdapterAddresses(static_cast<ULONG>(family), &buffer, &adapters)) {
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (!IsPreferredPhysicalAdapter(adapter)) {
            continue;
        }

        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != family ||
                !IsUsableBindAddress(unicast->Address.lpSockaddr)) {
                continue;
            }

            if (family == AF_INET) {
                *bind_addr_len = sizeof(sockaddr_in);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in));
            } else if (family == AF_INET6) {
                *bind_addr_len = sizeof(sockaddr_in6);
                memcpy(bind_addr, unicast->Address.lpSockaddr, sizeof(sockaddr_in6));
            } else {
                continue;
            }

            ClearSockaddrPort(bind_addr);
            if (adapter_name != NULL) {
                *adapter_name = AdapterDisplayName(adapter);
            }
            return true;
        }
    }

    return false;
}

bool ParsePeerOfferPayload(const uint8_t* payload, size_t length, ParsedPeerOffer* out_offer) {
    if (payload == NULL || out_offer == NULL || length != packet_tunnel::kPeerOfferPayloadSize) {
        return false;
    }

    out_offer->peer_virtual_ip = Ipv4ToString(payload);
    out_offer->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_offer->endpoint_family = payload[12];
    out_offer->endpoint_port = packet_tunnel::read_u16_be(payload + 14);
    memset(out_offer->endpoint_addr, 0, sizeof(out_offer->endpoint_addr));
    memcpy(out_offer->endpoint_addr, payload + 16, sizeof(out_offer->endpoint_addr));
    NormalizePeerEndpointFamily(&out_offer->endpoint_family, out_offer->endpoint_addr);
    out_offer->endpoint = PeerEndpointToString(out_offer->endpoint_family,
                                               out_offer->endpoint_addr,
                                               out_offer->endpoint_port);
    return true;
}

bool ParsePeerSignalPayload(const uint8_t* payload, size_t length, ParsedPeerSignal* out_signal) {
    if (payload == NULL || out_signal == NULL || length != packet_tunnel::kPeerSignalPayloadSize) {
        return false;
    }

    out_signal->peer_virtual_ip = Ipv4ToString(payload);
    out_signal->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_signal->nonce = packet_tunnel::read_u32_be(payload + 12);
    return true;
}

bool ParsePeerDisablePayload(const uint8_t* payload, size_t length, ParsedPeerDisable* out_disable) {
    if (payload == NULL || out_disable == NULL || length != packet_tunnel::kPeerDisablePayloadSize) {
        return false;
    }

    out_disable->peer_virtual_ip = Ipv4ToString(payload);
    out_disable->endpoint_version = packet_tunnel::read_u64_be(payload + 4);
    out_disable->reason = payload[12];
    return true;
}

bool SockaddrEquals(const sockaddr_storage& left,
                    int left_len,
                    const sockaddr_storage& right,
                    int right_len) {
    (void)left_len;
    (void)right_len;
    if (left.ss_family != right.ss_family) {
        return false;
    }

    if (left.ss_family == AF_INET) {
        const sockaddr_in* left4 = reinterpret_cast<const sockaddr_in*>(&left);
        const sockaddr_in* right4 = reinterpret_cast<const sockaddr_in*>(&right);
        return left4->sin_port == right4->sin_port &&
               left4->sin_addr.S_un.S_addr == right4->sin_addr.S_un.S_addr;
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
                                  int source_addr_len,
                                  int socket_family,
                                  sockaddr_storage* endpoint_addr,
                                  int* endpoint_addr_len) {
    if (source_addr == NULL || endpoint_addr == NULL || endpoint_addr_len == NULL) {
        return false;
    }

    sockaddr_storage out_addr = {};
    int out_len = 0;
    if (socket_family == AF_INET6 && source_addr->sa_family == AF_INET6) {
        sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&out_addr);
        ZeroMemory(addr6, sizeof(*addr6));
        addr6->sin6_family = AF_INET6;
        const sockaddr_in6* source6 = reinterpret_cast<const sockaddr_in6*>(source_addr);
        memcpy(addr6, source6, sizeof(*source6));
        out_len = sizeof(sockaddr_in6);
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

PacketTunnelClient::PacketTunnelClient(const std::string& tunnel_ip,
                                       uint16_t tunnel_port,
                                       const std::string& session_uuid,
                                       const std::string& client_id,
                                       const std::string& server_virtual_ip,
                                       const std::string& virtual_ip,
                                       uint16_t mtu,
                                       WintunManager* wintun_manager)
    : tunnel_server_ip_(tunnel_ip),
      tunnel_port_(tunnel_port),
      session_uuid_(session_uuid),
      client_id_(client_id),
      server_virtual_ip_(server_virtual_ip),
      virtual_ip_(virtual_ip),
      mtu_(mtu),
      wintun_manager_(wintun_manager),
      sock_(INVALID_SOCKET),
      tcp_sock_(INVALID_SOCKET),
      tcp_direct_listen_sock_(INVALID_SOCKET),
      socket_family_(AF_UNSPEC),
      tcp_direct_listen_port_(0),
      connected_(false),
      stop_requested_(false),
      tcp_connected_(false),
      last_receive_tick_(0),
      last_network_activity_tick_(0),
      peer_link_manager_(new PeerLinkManager()),
      peer_signal_nonce_(1),
      peer_direct_allowed_(true) {
    InitializeCriticalSection(&send_lock_);
    InitializeCriticalSection(&tcp_send_lock_);
}

PacketTunnelClient::~PacketTunnelClient() {
    Stop();
    delete peer_link_manager_;
    peer_link_manager_ = NULL;
    DeleteCriticalSection(&send_lock_);
    DeleteCriticalSection(&tcp_send_lock_);
}

bool PacketTunnelClient::IsServerVirtualPeer(const std::string& peer_virtual_ip) const {
    return !server_virtual_ip_.empty() &&
           peer_virtual_ip == server_virtual_ip_;
}

bool PacketTunnelClient::Start(std::wstring* error_msg) {
    Stop();
    stop_requested_ = false;
    peer_route_debug_log_tick_.clear();
    wintun_target_debug_log_tick_.clear();
    payload_ip_debug_log_tick_.clear();
    peer_probe_send_tick_.clear();
    mirrored_gateway_udp_signature_tick_.clear();
    peer_udp_port_owners_.clear();
    {
        std::lock_guard<std::mutex> tcp_lock(tcp_direct_mutex_);
        tcp_direct_offers_.clear();
        tcp_direct_connections_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(wintun_write_mutex_);
        wintun_write_business_queue_.clear();
        wintun_write_priority_queue_.clear();
        wintun_write_queue_.clear();
    }
    if (peer_link_manager_ != NULL) {
        peer_link_manager_->SetLocalVirtualIp(virtual_ip_);
    }
    PacketTunnelDebugLog("数据隧道启动: 服务器=" + tunnel_server_ip_ +
                         ":" + std::to_string(tunnel_port_) +
                         " 虚拟IP=" + virtual_ip_ +
                         " 服务端虚拟IP=" + server_virtual_ip_);

    if (!ConnectSocket(error_msg)) {
        if (error_msg != NULL) {
            PacketTunnelDebugLog("连接失败: " + WideToUtf8(*error_msg));
        }
        return false;
    }
    if (!SendHandshake(error_msg)) {
        if (error_msg != NULL) {
            PacketTunnelDebugLog("发送握手失败: " + WideToUtf8(*error_msg));
        }
        Stop();
        return false;
    }
    if (!ReceiveHandshakeAck(error_msg)) {
        if (error_msg != NULL) {
            PacketTunnelDebugLog("接收握手确认失败: " + WideToUtf8(*error_msg));
        }
        Stop();
        return false;
    }
    std::wstring udp_candidate_error;
    if (!SendUdpDirectCandidateAdvertises(&udp_candidate_error) && !udp_candidate_error.empty()) {
        PacketTunnelWarnLog("上报UDP直连候选失败: " +
                            WideToUtf8(udp_candidate_error));
    }
    std::wstring tcp_direct_listener_error;
    if (!StartTcpDirectListener(&tcp_direct_listener_error)) {
        if (!tcp_direct_listener_error.empty()) {
            PacketTunnelWarnLog("TCP直连监听不可用，继续保留中转路径: " +
                                WideToUtf8(tcp_direct_listener_error));
        } else {
            PacketTunnelWarnLog("TCP直连监听不可用，继续保留中转路径");
        }
    }
    std::wstring tcp_error;
    if (!ConnectTcpSocket(&tcp_error) ||
        !SendTcpHandshake(&tcp_error) ||
        !ReceiveTcpHandshakeAck(&tcp_error)) {
        if (tcp_sock_ != INVALID_SOCKET) {
            closesocket(tcp_sock_);
            tcp_sock_ = INVALID_SOCKET;
        }
        tcp_connected_ = false;
        if (!tcp_error.empty()) {
            PacketTunnelWarnLog("TCP中转载体不可用，回退到UDP中转: " +
                                WideToUtf8(tcp_error));
        } else {
            PacketTunnelWarnLog("TCP中转载体不可用，回退到UDP中转");
        }
    } else {
        std::wstring advertise_error;
        if (!SendTcpDirectAdvertise(&advertise_error) && !advertise_error.empty()) {
            PacketTunnelWarnLog("上报TCP直连监听信息失败: " + WideToUtf8(advertise_error));
        }
    }
    if (!StartThreads(error_msg)) {
        Stop();
        return false;
    }

    connected_ = true;
    PacketTunnelDebugLog("数据隧道已就绪");
    return true;
}

void PacketTunnelClient::Stop() {
    stop_requested_ = true;
    connected_ = false;
    tcp_connected_ = false;
    if (sock_ != INVALID_SOCKET && peer_link_manager_ != NULL) {
        std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
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

    if (sock_ != INVALID_SOCKET) {
        closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }
    if (tcp_sock_ != INVALID_SOCKET) {
        closesocket(tcp_sock_);
        tcp_sock_ = INVALID_SOCKET;
    }
    StopTcpDirectSockets();
    {
        std::lock_guard<std::mutex> lock(wintun_write_mutex_);
        wintun_write_business_queue_.clear();
        wintun_write_priority_queue_.clear();
        wintun_write_queue_.clear();
    }
    wintun_write_cv_.notify_all();

    if (socket_read_thread_.joinable()) {
        socket_read_thread_.join();
    }
    if (tcp_socket_read_thread_.joinable()) {
        tcp_socket_read_thread_.join();
    }
    if (wintun_write_thread_.joinable()) {
        wintun_write_thread_.join();
    }
    if (wintun_read_thread_.joinable()) {
        wintun_read_thread_.join();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    peer_probe_send_tick_.clear();
    mirrored_gateway_udp_signature_tick_.clear();
    peer_udp_port_owners_.clear();

    PacketTunnelDebugLog("数据隧道已停止");
}

bool PacketTunnelClient::ConnectSocket(std::wstring* error_msg) {
    server_endpoint_ = UdpEndpoint();
    socket_family_ = AF_UNSPEC;
    peer_direct_allowed_ = true;

    struct addrinfo hints = {};
    struct addrinfo* result = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    std::string port_str = std::to_string(tunnel_port_);
    int ret = getaddrinfo(tunnel_server_ip_.c_str(), port_str.c_str(), &hints, &result);
    std::vector<RelayEndpointCandidate> relay_candidates;
    if (ret == 0) {
        BuildRelayEndpointCandidates(result, &relay_candidates);
        freeaddrinfo(result);
        result = NULL;
    } else {
        PacketTunnelDebugLog("system dns resolve failed for relay host " + tunnel_server_ip_ +
                             " status=" + std::to_string(ret));
    }

    if (!IsNumericHostLiteral(tunnel_server_ip_) &&
        !HasPublicRelayEndpointCandidate(relay_candidates)) {
        std::vector<PhysicalDnsServer> physical_dns_servers;
        CollectPhysicalDnsServers(&physical_dns_servers);
        if (!physical_dns_servers.empty()) {
            PacketTunnelDebugLog("中转端点使用的物理DNS服务器: " +
                                 BuildPhysicalDnsServerSummary(physical_dns_servers));
            if (QueryRelayEndpointsViaPhysicalDns(tunnel_server_ip_,
                                                  tunnel_port_,
                                                  physical_dns_servers,
                                                  &relay_candidates)) {
                PacketTunnelDebugLog("物理DNS补充后的中转端点候选: " +
                                     BuildRelayEndpointCandidateSummary(relay_candidates));
            } else {
                PacketTunnelDebugLog("物理DNS未返回额外中转端点");
            }
        }
    }

    if (relay_candidates.empty()) {
        if (error_msg != NULL) {
            if (ret != 0) {
                *error_msg = L"IP Tunnel DNS解析失败: " + Utf8ToWide(tunnel_server_ip_);
            } else {
                *error_msg = L"IP Tunnel解析未返回可用端点: " + Utf8ToWide(tunnel_server_ip_);
            }
        }
        return false;
    }

    PacketTunnelInfoLog("中转端点候选: " +
                        BuildRelayEndpointCandidateSummary(relay_candidates));

    auto configure_socket = [&](SOCKET sock, int family) {
        if (family == AF_INET6) {
            DWORD dual_stack = 0;
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&dual_stack), sizeof(dual_stack));
        }

        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&kSocketBufferBytes, sizeof(kSocketBufferBytes));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&kSocketBufferBytes, sizeof(kSocketBufferBytes));

        DWORD send_timeout = kSocketSendTimeoutMs;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&send_timeout, sizeof(send_timeout));
        DWORD recv_timeout = kSocketReadTimeoutMs;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&recv_timeout, sizeof(recv_timeout));

        BOOL disable_udp_connreset = FALSE;
        DWORD bytes_returned = 0;
        WSAIoctl(sock,
                 SIO_UDP_CONNRESET,
                 &disable_udp_connreset,
                 sizeof(disable_udp_connreset),
                 NULL,
                 0,
                 &bytes_returned,
                 NULL,
                 NULL);
    };

    auto try_connect_candidate = [&](const RelayEndpointCandidate& candidate) -> bool {
        const sockaddr_storage endpoint_addr = candidate.endpoint_addr;
        const int endpoint_addr_len = candidate.endpoint_addr_len;
        const int preferred_family = candidate.socket_family;
        const bool public_relay_target = candidate.public_internet;
        const bool ipv4_direct_test_override = (!public_relay_target && preferred_family == AF_INET);
        peer_direct_allowed_ = public_relay_target || ipv4_direct_test_override;

        sockaddr_storage local_bind_addr = {};
        int local_bind_addr_len = 0;
        bool has_local_bind_hint = false;
        std::string bind_adapter_name;

        SOCKET probe_sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (probe_sock != INVALID_SOCKET) {
            configure_socket(probe_sock, preferred_family);
            if (connect(probe_sock,
                        reinterpret_cast<const sockaddr*>(&endpoint_addr),
                        endpoint_addr_len) == 0) {
                local_bind_addr_len = static_cast<int>(sizeof(local_bind_addr));
                if (getsockname(probe_sock,
                                reinterpret_cast<sockaddr*>(&local_bind_addr),
                                &local_bind_addr_len) == 0) {
                    ClearSockaddrPort(&local_bind_addr);
                    if (!public_relay_target) {
                        has_local_bind_hint = true;
                    } else {
                        bool preferred_adapter = false;
                        if (IsUsableBindAddress(reinterpret_cast<const sockaddr*>(&local_bind_addr)) &&
                            TryResolveBindAdapter(local_bind_addr,
                                                  preferred_family,
                                                  &bind_adapter_name,
                                                  &preferred_adapter) &&
                            preferred_adapter) {
                            has_local_bind_hint = true;
                        } else {
                            PacketTunnelDebugLog("udp socket local bind rejected: " +
                                                 SockaddrToString(local_bind_addr, local_bind_addr_len) +
                                                 (bind_adapter_name.empty()
                                                      ? std::string()
                                                      : (" adapter=" + bind_adapter_name)));
                        }
                    }
                }
            }
            closesocket(probe_sock);
        }

        SOCKET sock = socket(preferred_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            return false;
        }

        configure_socket(sock, preferred_family);

        if (public_relay_target) {
            if (!has_local_bind_hint &&
                TryFindPreferredBindAddress(preferred_family,
                                            &local_bind_addr,
                                            &local_bind_addr_len,
                                            &bind_adapter_name)) {
                has_local_bind_hint = true;
                PacketTunnelDebugLog("udp socket route hint override: " +
                                     SockaddrToString(local_bind_addr, local_bind_addr_len) +
                                     " adapter=" + bind_adapter_name);
            } else if (!has_local_bind_hint) {
                PacketTunnelDebugLog("udp socket route hint not found for family=" +
                                     std::to_string(preferred_family));
            }

            // Keep the public relay socket on a wildcard bind so peer-direct packets can
            // arrive on whichever adapter/NAT path the OS selects at runtime.
            PacketTunnelDebugLog("udp socket using wildcard local bind for public relay candidate");
        }

        sock_ = sock;
        socket_family_ = preferred_family;
        server_endpoint_.addr = endpoint_addr;
        server_endpoint_.addr_len = endpoint_addr_len;
        server_endpoint_.valid = true;
        if (ipv4_direct_test_override) {
            PacketTunnelInfoLog("peer direct test override enabled for non-public IPv4 relay " +
                                SockaddrToString(endpoint_addr, endpoint_addr_len));
        } else if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("peer direct disabled: relay target is non-public " +
                                 SockaddrToString(endpoint_addr, endpoint_addr_len));
        }
        PacketTunnelDebugLog("udp socket ready for relay server " + tunnel_server_ip_ +
                             ":" + std::to_string(tunnel_port_) +
                             " scope=" + RelayEndpointScopeName(candidate) +
                             " family=" + std::to_string(socket_family_) +
                             ((public_relay_target && has_local_bind_hint)
                                  ? (" local_hint=" + SockaddrToString(local_bind_addr, local_bind_addr_len))
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
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel连接失败: " + Utf8ToWide(tunnel_server_ip_) +
                         L":" + Utf8ToWide(std::to_string(tunnel_port_));
        }
        return false;
    }
    return true;
}

bool PacketTunnelClient::ConnectTcpSocket(std::wstring* error_msg) {
    tcp_connected_ = false;
    if (tcp_sock_ != INVALID_SOCKET) {
        closesocket(tcp_sock_);
        tcp_sock_ = INVALID_SOCKET;
    }
    if (!server_endpoint_.valid) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP中转端点无效";
        }
        return false;
    }

    const int family =
        server_endpoint_.addr.ss_family != AF_UNSPEC ? server_endpoint_.addr.ss_family : socket_family_;
    SOCKET sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel TCP socket create failed", WSAGetLastError());
        }
        return false;
    }

    int buffer_bytes = kSocketBufferBytes;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buffer_bytes), sizeof(buffer_bytes));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buffer_bytes), sizeof(buffer_bytes));
    DWORD send_timeout = kSocketSendTimeoutMs;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&send_timeout), sizeof(send_timeout));
    DWORD recv_timeout = kSocketReadTimeoutMs;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recv_timeout), sizeof(recv_timeout));
    BOOL keepalive = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&keepalive), sizeof(keepalive));
    BOOL tcp_nodelay = TRUE;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&tcp_nodelay), sizeof(tcp_nodelay));

    if (connect(sock,
                reinterpret_cast<const sockaddr*>(&server_endpoint_.addr),
                server_endpoint_.addr_len) != 0) {
        const int err = WSAGetLastError();
        closesocket(sock);
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel TCP connect failed", err);
        }
        return false;
    }

    tcp_sock_ = sock;
    tcp_connected_ = true;
    PacketTunnelInfoLog("TCP中转载体已连接到 " +
                        SockaddrToString(server_endpoint_.addr, server_endpoint_.addr_len));
    return true;
}

bool PacketTunnelClient::BuildHandshakePayload(bool relay_only,
                                               std::vector<uint8_t>* handshake,
                                               std::wstring* error_msg) const {
    if (handshake == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel handshake buffer is null";
        }
        return false;
    }

    uint8_t session_uuid_len = static_cast<uint8_t>(session_uuid_.size());
    if (client_id_.empty()) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel client_id is empty";
        }
        return false;
    }
    if (client_id_.size() > 255) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel client_id is too long";
        }
        return false;
    }

    uint8_t client_id_len = static_cast<uint8_t>(client_id_.size());
    handshake->assign(7 + session_uuid_len + 1 + client_id_len + packet_tunnel::kHandshakeTailSize, 0);

    uint32_t conn_id_be = htonl(packet_tunnel::kHandshakeConnId);
    uint16_t port_be = htons(packet_tunnel::kHandshakePortMarker);
    memcpy(&(*handshake)[0], &conn_id_be, sizeof(conn_id_be));
    memcpy(&(*handshake)[4], &port_be, sizeof(port_be));
    (*handshake)[6] = session_uuid_len;
    if (session_uuid_len > 0) {
        memcpy(&(*handshake)[7], session_uuid_.data(), session_uuid_len);
    }
    size_t client_id_offset = 7 + session_uuid_len;
    (*handshake)[client_id_offset] = client_id_len;
    memcpy(&(*handshake)[client_id_offset + 1], client_id_.data(), client_id_len);

    uint32_t virtual_ip_be = ParseVirtualIp(error_msg);
    if (virtual_ip_be == 0) {
        return false;
    }

    size_t tail = client_id_offset + 1 + client_id_len;
    (*handshake)[tail + 0] = packet_tunnel::kProtocolVersion;
    (*handshake)[tail + 1] =
        relay_only || !peer_direct_allowed_
            ? packet_tunnel::kHandshakeFlagRelayOnly
            : packet_tunnel::kHandshakeFlagNone;
    uint16_t mtu_be = htons(mtu_);
    memcpy(&(*handshake)[tail + 2], &mtu_be, sizeof(mtu_be));
    memcpy(&(*handshake)[tail + 4], &virtual_ip_be, sizeof(virtual_ip_be));
    return true;
}

bool PacketTunnelClient::SendHandshake(std::wstring* error_msg) {
    std::vector<uint8_t> handshake;
    if (!BuildHandshakePayload(false, &handshake, error_msg)) {
        return false;
    }

    PacketTunnelDebugLog("发送握手: 会话=" + session_uuid_ +
                         " 客户端ID=" + client_id_.substr(0, std::min<size_t>(client_id_.size(), 16)) +
                         " MTU=" + std::to_string(mtu_) +
                         " 虚拟IP=" + virtual_ip_);
    return SendDatagramToEndpoint(server_endpoint_, handshake.data(), handshake.size(), error_msg);
}

bool PacketTunnelClient::SendTcpHandshake(std::wstring* error_msg) {
    if (!tcp_connected_ || tcp_sock_ == INVALID_SOCKET) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP relay is not connected";
        }
        return false;
    }

    std::vector<uint8_t> handshake;
    if (!BuildHandshakePayload(true, &handshake, error_msg)) {
        return false;
    }

    EnterCriticalSection(&tcp_send_lock_);
    size_t sent = 0;
    bool ok = true;
    int last_error = 0;
    while (sent < handshake.size()) {
        int n = send(tcp_sock_,
                     reinterpret_cast<const char*>(handshake.data() + sent),
                     static_cast<int>(handshake.size() - sent),
                     0);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            continue;
        }
        last_error = WSAGetLastError();
        ok = false;
        break;
    }
    LeaveCriticalSection(&tcp_send_lock_);

    if (!ok) {
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel TCP握手发送失败", last_error);
        }
        return false;
    }

    PacketTunnelInfoLog("已发送TCP中转载体握手");
    return true;
}

bool PacketTunnelClient::SendUdpDirectCandidateAdvertises(std::wstring* error_msg) {
    if (sock_ == INVALID_SOCKET) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel UDP socket is not connected";
        }
        return false;
    }

    sockaddr_storage local_addr = {};
    int local_addr_len = sizeof(local_addr);
    if (getsockname(sock_,
                    reinterpret_cast<sockaddr*>(&local_addr),
                    &local_addr_len) != 0) {
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel UDP getsockname failed", WSAGetLastError());
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
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel UDP local port is unavailable";
        }
        return false;
    }

    ULONG buffer_size = 16 * 1024;
    std::vector<uint8_t> adapter_buffer(buffer_size);
    IP_ADAPTER_ADDRESSES* adapters =
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapter_buffer.data());
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC,
                                     GAA_FLAG_SKIP_ANYCAST |
                                         GAA_FLAG_SKIP_MULTICAST |
                                         GAA_FLAG_SKIP_DNS_SERVER,
                                     NULL,
                                     adapters,
                                     &buffer_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        adapter_buffer.assign(buffer_size, 0);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapter_buffer.data());
        ret = GetAdaptersAddresses(AF_UNSPEC,
                                   GAA_FLAG_SKIP_ANYCAST |
                                       GAA_FLAG_SKIP_MULTICAST |
                                       GAA_FLAG_SKIP_DNS_SERVER,
                                   NULL,
                                   adapters,
                                   &buffer_size);
    }
    if (ret != NO_ERROR) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel adapter enumeration failed";
        }
        return false;
    }

    size_t candidate_count = 0;
    for (IP_ADAPTER_ADDRESSES* adapter = adapters;
         adapter != NULL;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp ||
            adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }
        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL) {
                continue;
            }

            TcpDirectCandidate candidate;
            candidate.endpoint_port = local_port;
            const sockaddr* sa = unicast->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(sa);
                const uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
                if (ip == 0 ||
                    (ip & 0xff000000u) == 0x7f000000u ||
                    (ip & 0xffff0000u) == 0xa9fe0000u ||
                    (ip & 0xf0000000u) == 0xe0000000u) {
                    continue;
                }
                candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
                memcpy(candidate.endpoint_addr, &addr4->sin_addr, 4);
            } else if (sa->sa_family == AF_INET6) {
                const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(sa);
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
    }

    PacketTunnelInfoLog("UDP直连本地候选已上报，数量=" +
                        std::to_string(candidate_count));
    return true;
}

bool PacketTunnelClient::SendUdpDirectCandidateAdvertise(
    const TcpDirectCandidate& candidate,
    std::wstring* error_msg) {
    if (candidate.endpoint_port == 0 ||
        (candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv4 &&
         candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv6)) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel UDP direct candidate is invalid";
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
                     error_msg);
}

void PacketTunnelClient::MarkNetworkActivity() {
    last_network_activity_tick_ = GetTickCount64();
}

bool PacketTunnelClient::ReceiveHandshakeAck(std::wstring* error_msg) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    while (!stop_requested_) {
        sockaddr_storage source_addr = {};
        int source_addr_len = 0;
        int received = RecvDatagramFrom(ack, sizeof(ack), &source_addr, &source_addr_len, error_msg);
        if (received < 0) {
            return false;
        }
        if (received == 0) {
            continue;
        }
        if (!IsServerEndpoint(source_addr, source_addr_len)) {
            continue;
        }
        if (received != (int)sizeof(ack)) {
            if (error_msg != NULL) {
                *error_msg = L"IP Tunnel握手确认长度不匹配";
            }
            return false;
        }

        if (ack[0] != packet_tunnel::kProtocolVersion) {
            if (error_msg != NULL) {
                *error_msg = L"IP Tunnel握手确认版本不匹配";
            }
            return false;
        }

        if (ack[1] != packet_tunnel::kStatusOk) {
            if (error_msg != NULL) {
                *error_msg = L"IP Tunnel ack rejected, status=" + Utf8ToWide(std::to_string((int)ack[1]));
            }
            return false;
        }

        last_receive_tick_ = GetTickCount64();
        MarkNetworkActivity();
        PacketTunnelDebugLog("已收到握手确认: MTU=" + std::to_string(mtu_) +
                             " 虚拟IP=" + virtual_ip_);
        return true;
    }
    if (error_msg != NULL) {
        *error_msg = L"IP Tunnel握手被中断";
    }
    return false;
}

bool PacketTunnelClient::ReceiveTcpHandshakeAck(std::wstring* error_msg) {
    uint8_t ack[packet_tunnel::kHandshakeAckSize] = {};
    if (!RecvTcpExact(ack, sizeof(ack), error_msg)) {
        return false;
    }

    if (ack[0] != packet_tunnel::kProtocolVersion) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP握手确认版本不匹配";
        }
        return false;
    }
    if (ack[1] != packet_tunnel::kStatusOk) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP握手确认被拒绝，状态=" +
                         Utf8ToWide(std::to_string((int)ack[1]));
        }
        return false;
    }

    PacketTunnelInfoLog("TCP中转载体握手已确认");
    return true;
}

bool PacketTunnelClient::StartTcpDirectListener(std::wstring* error_msg) {
    StopTcpDirectSockets();

    auto try_listen_family = [&](int family, SOCKET* out_sock, uint16_t* out_port) -> bool {
        SOCKET listen_sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock == INVALID_SOCKET) {
            return false;
        }

        if (family == AF_INET6) {
            DWORD dual_stack = 0;
            setsockopt(listen_sock,
                       IPPROTO_IPV6,
                       IPV6_V6ONLY,
                       reinterpret_cast<const char*>(&dual_stack),
                       sizeof(dual_stack));
        }
        ConfigureTcpStreamSocket(listen_sock);

        sockaddr_storage bind_addr = {};
        int bind_addr_len = 0;
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
            closesocket(listen_sock);
            return false;
        }

        sockaddr_storage actual_addr = {};
        int actual_addr_len = sizeof(actual_addr);
        if (getsockname(listen_sock,
                        reinterpret_cast<sockaddr*>(&actual_addr),
                        &actual_addr_len) != 0) {
            closesocket(listen_sock);
            return false;
        }

        uint16_t port = 0;
        if (actual_addr.ss_family == AF_INET) {
            port = ntohs(reinterpret_cast<sockaddr_in*>(&actual_addr)->sin_port);
        } else if (actual_addr.ss_family == AF_INET6) {
            port = ntohs(reinterpret_cast<sockaddr_in6*>(&actual_addr)->sin6_port);
        }
        if (port == 0) {
            closesocket(listen_sock);
            return false;
        }

        *out_sock = listen_sock;
        *out_port = port;
        return true;
    };

    const int preferred_family = socket_family_ == AF_INET6 ? AF_INET6 : AF_INET;
    const int fallback_family = preferred_family == AF_INET6 ? AF_INET : AF_INET6;
    SOCKET listen_sock = INVALID_SOCKET;
    uint16_t listen_port = 0;
    if (!try_listen_family(preferred_family, &listen_sock, &listen_port) &&
        !try_listen_family(fallback_family, &listen_sock, &listen_port)) {
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel TCP direct listen failed", WSAGetLastError());
        }
        return false;
    }

    tcp_direct_listen_sock_ = listen_sock;
    tcp_direct_listen_port_ = listen_port;
    PacketTunnelInfoLog("TCP直连监听已就绪，端口=" + std::to_string(tcp_direct_listen_port_));
    return true;
}

bool PacketTunnelClient::SendTcpDirectAdvertise(std::wstring* error_msg) {
    if (!tcp_connected_ || tcp_sock_ == INVALID_SOCKET) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP relay is not connected";
        }
        return false;
    }
    if (tcp_direct_listen_port_ == 0) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP direct listener is not available";
        }
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kTcpDirectAdvertisePayloadSize, 0);
    packet_tunnel::write_u16_be(payload.data(), tcp_direct_listen_port_);
    if (!SendFrameOverTcp(packet_tunnel::kFrameTcpDirectAdvertise,
                          payload.data(),
                          payload.size(),
                          error_msg)) {
        return false;
    }

    PacketTunnelInfoLog("已上报TCP直连监听端口=" +
                        std::to_string(tcp_direct_listen_port_));

    ULONG buffer_size = 16 * 1024;
    std::vector<uint8_t> adapter_buffer(buffer_size);
    IP_ADAPTER_ADDRESSES* adapters =
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapter_buffer.data());
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC,
                                     GAA_FLAG_SKIP_ANYCAST |
                                         GAA_FLAG_SKIP_MULTICAST |
                                         GAA_FLAG_SKIP_DNS_SERVER,
                                     NULL,
                                     adapters,
                                     &buffer_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        adapter_buffer.assign(buffer_size, 0);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(adapter_buffer.data());
        ret = GetAdaptersAddresses(AF_UNSPEC,
                                   GAA_FLAG_SKIP_ANYCAST |
                                       GAA_FLAG_SKIP_MULTICAST |
                                       GAA_FLAG_SKIP_DNS_SERVER,
                                   NULL,
                                   adapters,
                                   &buffer_size);
    }

    size_t candidate_count = 0;
    if (ret == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* adapter = adapters;
             adapter != NULL;
             adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp ||
                adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                continue;
            }
            for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
                 unicast != NULL;
                 unicast = unicast->Next) {
                if (unicast->Address.lpSockaddr == NULL) {
                    continue;
                }

                TcpDirectCandidate candidate;
                candidate.endpoint_port = tcp_direct_listen_port_;
                const sockaddr* sa = unicast->Address.lpSockaddr;
                if (sa->sa_family == AF_INET) {
                    const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(sa);
                    const uint32_t ip = ntohl(addr4->sin_addr.S_un.S_addr);
                    if (ip == 0 ||
                        (ip & 0xff000000u) == 0x7f000000u ||
                        (ip & 0xffff0000u) == 0xa9fe0000u ||
                        (ip & 0xf0000000u) == 0xe0000000u) {
                        continue;
                    }
                    candidate.endpoint_family = packet_tunnel::kPeerEndpointFamilyIpv4;
                    memcpy(candidate.endpoint_addr, &addr4->sin_addr, 4);
                } else if (sa->sa_family == AF_INET6) {
                    const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(sa);
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
        }
    }

    PacketTunnelInfoLog("TCP直连本地候选已上报，数量=" +
                        std::to_string(candidate_count));
    return true;
}

bool PacketTunnelClient::SendTcpDirectCandidateAdvertise(
    const TcpDirectCandidate& candidate,
    std::wstring* error_msg) {
    if (!tcp_connected_ || tcp_sock_ == INVALID_SOCKET) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP relay is not connected";
        }
        return false;
    }
    if (candidate.endpoint_port == 0 ||
        (candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv4 &&
         candidate.endpoint_family != packet_tunnel::kPeerEndpointFamilyIpv6)) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP direct candidate is invalid";
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
                            error_msg);
}

bool PacketTunnelClient::StartThreads(std::wstring* error_msg) {
    if (wintun_manager_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun manager is null";
        }
        return false;
    }

    socket_read_thread_ = std::thread(&PacketTunnelClient::SocketReadLoop, this);
    if (tcp_connected_ && tcp_sock_ != INVALID_SOCKET) {
        tcp_socket_read_thread_ = std::thread(&PacketTunnelClient::TcpSocketReadLoop, this);
    }
    if (tcp_direct_listen_sock_ != INVALID_SOCKET) {
        tcp_direct_accept_thread_ = std::thread(&PacketTunnelClient::TcpDirectAcceptLoop, this);
    }
    wintun_write_thread_ = std::thread(&PacketTunnelClient::WintunWriteLoop, this);
    wintun_read_thread_ = std::thread(&PacketTunnelClient::WintunReadLoop, this);
    heartbeat_thread_ = std::thread(&PacketTunnelClient::HeartbeatLoop, this);
    return true;
}

void PacketTunnelClient::StopTcpDirectSockets() {
    SOCKET listen_sock = INVALID_SOCKET;
    std::vector<std::shared_ptr<TcpDirectConnection>> connections;
    std::vector<std::thread> connect_threads;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        listen_sock = tcp_direct_listen_sock_;
        tcp_direct_listen_sock_ = INVALID_SOCKET;
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

    CloseSocketQuiet(&listen_sock);

    for (size_t i = 0; i < connections.size(); ++i) {
        if (!connections[i]) {
            continue;
        }
        connections[i]->active = false;
        CloseSocketQuiet(&connections[i]->sock);
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

void PacketTunnelClient::PruneWatchedTcpFlows(unsigned long long now_tick) {
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

void PacketTunnelClient::MarkWatchedTcpEnqueue(const uint8_t* packet,
                                               size_t packet_len,
                                               const char* origin) {
    WatchedTcpPacketInfo info;
    if (!TryParseWatchedTcpPacket(packet, packet_len, virtual_ip_, &info) ||
        info.from_client ||
        !info.has_payload) {
        return;
    }

    const unsigned long long tick = GetTickCount64();
    std::lock_guard<std::mutex> lock(watched_tcp_mutex_);
    PruneWatchedTcpFlows(tick);

    std::map<std::string, WatchedTcpFlowTrace>::iterator it = watched_tcp_flows_.find(info.flow_key);
    if (it == watched_tcp_flows_.end()) {
        return;
    }

    WatchedTcpFlowTrace& trace = it->second;
    trace.pending_server_enqueue_ms = tick;
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
    PacketTunnelDebugLog("TCP服务跟踪 服务端发送等待 流=" + flow_ss.str() +
                         " 来源=" + ((origin != NULL) ? origin : "套接字接收") +
                         " 等待=" + std::to_string(emit_wait) + "ms" +
                         " 字节=" + std::to_string(info.payload_len));
}

void PacketTunnelClient::TraceWatchedTcpPacket(const uint8_t* packet,
                                               size_t packet_len,
                                               const char* path) {
    WatchedTcpPacketInfo info;
    if (!TryParseWatchedTcpPacket(packet, packet_len, virtual_ip_, &info)) {
        return;
    }

    const unsigned long long tick = GetTickCount64();
    std::lock_guard<std::mutex> lock(watched_tcp_mutex_);
    PruneWatchedTcpFlows(tick);

    WatchedTcpFlowTrace& trace = watched_tcp_flows_[info.flow_key];
    if (trace.created_ms == 0 || (trace.close_logged && info.from_client && info.syn && !info.ack)) {
        trace = WatchedTcpFlowTrace();
        trace.client_ip = info.client_ip;
        trace.server_ip = info.server_ip;
        trace.client_port = info.client_port;
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
        PacketTunnelDebugLog("TCP服务跟踪 SYN 流=" + flow +
                             " 来源=" + origin +
                             " 端口=" + std::to_string(trace.server_port));
    }

    if (!info.from_client && info.syn && info.ack && trace.synack_ms == 0) {
        trace.synack_ms = tick;
        PacketTunnelDebugLog("TCP服务跟踪 SYN-ACK 流=" + flow +
                             " 来源=" + origin +
                             " 距SYN=" + FormatWatchedTcpElapsed(trace.syn_ms, tick) + "ms");
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
        PacketTunnelDebugLog("TCP服务跟踪 已建立 流=" + flow +
                             " 来源=" + origin +
                             " 距SYN=" + FormatWatchedTcpElapsed(trace.syn_ms, tick) + "ms" +
                             " 距SYN-ACK=" + FormatWatchedTcpElapsed(trace.synack_ms, tick) + "ms");
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
                PacketTunnelDebugLog("TCP服务跟踪 客户端ACK延迟 流=" + flow +
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
                PacketTunnelDebugLog("TCP服务跟踪 首个客户端负载 流=" + flow +
                                     " 来源=" + origin +
                                     " 字节=" + std::to_string(info.payload_len) +
                                     " 距SYN=" + FormatWatchedTcpElapsed(trace.syn_ms, tick) + "ms" +
                                     " 距建立=" +
                                     FormatWatchedTcpElapsed(trace.established_ms, tick) + "ms");
            }
        } else {
            ++trace.server_payload_count;
            if (trace.pending_server_enqueue_ms != 0 &&
                tick >= trace.pending_server_enqueue_ms) {
                const unsigned long long queue_lag = tick - trace.pending_server_enqueue_ms;
                if (queue_lag >= 20) {
                    PacketTunnelDebugLog("TCP服务跟踪 服务端发送滞后 流=" + flow +
                                         " 来源=" + origin +
                                         " 滞后=" + std::to_string(queue_lag) + "ms" +
                                         " 字节=" + std::to_string(info.payload_len));
                }
                trace.pending_server_enqueue_ms = 0;
            }
            if (trace.first_server_payload_ms == 0) {
                trace.first_server_payload_ms = tick;
                PacketTunnelDebugLog("TCP服务跟踪 首个服务端负载 流=" + flow +
                                     " 来源=" + origin +
                                     " 字节=" + std::to_string(info.payload_len) +
                                     " 距SYN=" + FormatWatchedTcpElapsed(trace.syn_ms, tick) + "ms" +
                                     " 距首个客户端负载=" +
                                     FormatWatchedTcpElapsed(trace.first_client_payload_ms, tick) + "ms");
            } else if (trace.pending_request_ms != 0 &&
                       tick >= trace.pending_request_ms &&
                       (tick - trace.pending_request_ms) >= kWatchedTcpServerWaitLogMs) {
                PacketTunnelDebugLog("TCP服务跟踪 服务端回复等待 流=" + flow +
                                     " 来源=" + origin +
                                     " 等待=" + std::to_string(tick - trace.pending_request_ms) + "ms" +
                                     " 字节=" + std::to_string(info.payload_len));
            }
            trace.last_server_payload_ms = tick;
            trace.pending_request_ms = 0;
        }
    }

    if ((info.fin || info.rst) && !trace.close_logged) {
        trace.close_logged = true;
        trace.closed_ms = tick;
        std::ostringstream close_ss;
        close_ss << "TCP服务跟踪 关闭 流=" << flow
                 << " 来源=" << origin
                 << " 标志=" << DescribeWatchedTcpFlags(info.flags)
                 << " 生命周期=" << FormatWatchedTcpElapsed(trace.created_ms, tick) << "ms"
                 << " 客户端负载数=" << trace.client_payload_count
                 << " 服务端负载数=" << trace.server_payload_count;
        if (trace.pending_request_ms != 0 && tick >= trace.pending_request_ms) {
            close_ss << " 未决等待=" << (tick - trace.pending_request_ms) << "ms";
        }
        PacketTunnelDebugLog(close_ss.str());
    }
}

void PacketTunnelClient::WintunWriteLoop() {
    while (true) {
        QueuedWintunPacket queued_packet;
        size_t pending_business_packets = 0;
        size_t pending_priority_packets = 0;
        size_t pending_normal_packets = 0;
        {
            std::unique_lock<std::mutex> lock(wintun_write_mutex_);
            wintun_write_cv_.wait(lock, [this]() {
                return stop_requested_ ||
                       !wintun_write_business_queue_.empty() ||
                       !wintun_write_priority_queue_.empty() ||
                       !wintun_write_queue_.empty();
            });
            if (wintun_write_business_queue_.empty() &&
                wintun_write_priority_queue_.empty() &&
                wintun_write_queue_.empty()) {
                if (stop_requested_) {
                    break;
                }
                continue;
            }
            if (!wintun_write_business_queue_.empty()) {
                queued_packet = std::move(wintun_write_business_queue_.front());
                wintun_write_business_queue_.pop_front();
            } else if (!wintun_write_priority_queue_.empty()) {
                queued_packet = std::move(wintun_write_priority_queue_.front());
                wintun_write_priority_queue_.pop_front();
            } else {
                queued_packet = std::move(wintun_write_queue_.front());
                wintun_write_queue_.pop_front();
            }
            pending_business_packets = wintun_write_business_queue_.size();
            pending_priority_packets = wintun_write_priority_queue_.size();
            pending_normal_packets = wintun_write_queue_.size();
        }

        if (!wintun_manager_ || queued_packet.payload.empty()) {
            if (stop_requested_) {
                break;
            }
            continue;
        }

        const unsigned long long queue_wait_elapsed =
            GetTickCount64() - queued_packet.enqueue_tick_ms;
        std::wstring wintun_write_error;
        const unsigned long long wintun_write_start = GetTickCount64();
        const bool wintun_write_ok =
            wintun_manager_->WritePacket(queued_packet.payload.data(),
                                         queued_packet.payload.size(),
                                         &wintun_write_error);
        const unsigned long long wintun_write_elapsed =
            GetTickCount64() - wintun_write_start;
        const unsigned long long total_elapsed =
            GetTickCount64() - queued_packet.enqueue_tick_ms;
        if (!wintun_write_ok ||
            queue_wait_elapsed >= kSlowWintunQueueWarnMs ||
            wintun_write_elapsed >= kSlowWintunWriteWarnMs ||
            total_elapsed >= kSlowPacketProcessWarnMs) {
            PacketTunnelWarnLog(std::string("排队的中转->Wintun写入缓慢或失败 排队耗时=") +
                                std::to_string(queue_wait_elapsed) +
                                " 写入耗时=" + std::to_string(wintun_write_elapsed) +
                                " 总耗时=" + std::to_string(total_elapsed) +
                                " 业务待处理=" + std::to_string(pending_business_packets) +
                                " 高优先待处理=" + std::to_string(pending_priority_packets) +
                                " 普通待处理=" + std::to_string(pending_normal_packets) +
                                " 方向=" +
                                (queued_packet.from_known_peer ? "对端->Wintun" : "中转->Wintun") +
                                " 优先级=" +
                                std::string(queued_packet.business_priority
                                                ? "业务TCP"
                                                : (queued_packet.high_priority ? "TCP" : "普通")) +
                                " 源=" + queued_packet.inner_src_virtual_ip + ":" +
                                std::to_string(queued_packet.inner_src_port) +
                                " 目标=" + queued_packet.inner_dst_virtual_ip + ":" +
                                std::to_string(queued_packet.inner_dst_port) +
                                " 长度=" + std::to_string(queued_packet.payload.size()) +
                                (wintun_write_ok ? "" : (" 错误=" + WideToUtf8(wintun_write_error))));
        }
        if (!wintun_write_ok) {
            connected_ = false;
            stop_requested_ = true;
            break;
        }
        if (PacketTunnelDebugEnabled()) {
            TraceWatchedTcpPacket(queued_packet.payload.data(),
                                  queued_packet.payload.size(),
                                  queued_packet.from_known_peer ? "对端->Wintun"
                                                                : "中转->Wintun");
        }
        const bool should_pace_business_tcp =
            queued_packet.from_known_peer &&
            queued_packet.business_priority &&
            pending_business_packets != 0 &&
            (queued_packet.inner_src_port == kPeerToWintunPacedBusinessTcpPort ||
             queued_packet.inner_dst_port == kPeerToWintunPacedBusinessTcpPort);
        if (should_pace_business_tcp) {
            BusyWaitMicroseconds(kPeerToWintunBusinessTcpPaceUs);
        }
    }
}

bool PacketTunnelClient::EnqueueWintunPacket(const uint8_t* payload,
                                             size_t payload_len,
                                             bool from_known_peer,
                                             const std::string& inner_src_virtual_ip,
                                             uint16_t inner_src_port,
                                             const std::string& inner_dst_virtual_ip,
                                             uint16_t inner_dst_port) {
    if (payload == NULL || payload_len == 0 || stop_requested_) {
        return false;
    }

    QueuedWintunPacket queued_packet;
    queued_packet.payload.assign(payload, payload + payload_len);
    queued_packet.from_known_peer = from_known_peer;
    queued_packet.inner_src_virtual_ip = inner_src_virtual_ip;
    queued_packet.inner_src_port = inner_src_port;
    queued_packet.inner_dst_virtual_ip = inner_dst_virtual_ip;
    queued_packet.inner_dst_port = inner_dst_port;
    queued_packet.enqueue_tick_ms = GetTickCount64();
    queued_packet.high_priority =
        payload_len >= 20 &&
        ((payload[0] >> 4) & 0x0F) == 4 &&
        payload[9] == IPPROTO_TCP;
    if (queued_packet.high_priority) {
        size_t ip_header_len = 0;
        size_t tcp_header_len = 0;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        if (TryParseTcpPacket(payload,
                              payload_len,
                              &ip_header_len,
                              &tcp_header_len,
                              &src_port,
                              &dst_port)) {
            queued_packet.business_priority =
                IsWatchedBusinessTcpPort(src_port) ||
                IsWatchedBusinessTcpPort(dst_port);
        }
    }

    {
        std::lock_guard<std::mutex> lock(wintun_write_mutex_);
        if (stop_requested_) {
            return false;
        }
        if (queued_packet.business_priority) {
            wintun_write_business_queue_.push_back(std::move(queued_packet));
        } else if (queued_packet.high_priority) {
            wintun_write_priority_queue_.push_back(std::move(queued_packet));
        } else {
            wintun_write_queue_.push_back(std::move(queued_packet));
        }
    }
    wintun_write_cv_.notify_one();
    return true;
}

void PacketTunnelClient::SocketReadLoop() {
    std::vector<uint8_t> buffer(65535);
    while (!stop_requested_) {
        std::wstring err;
        sockaddr_storage source_addr = {};
        int source_addr_len = 0;
        int received = RecvDatagramFrom(buffer.data(),
                                        buffer.size(),
                                        &source_addr,
                                        &source_addr_len,
                                        &err);
        if (received < 0) {
            if (!err.empty()) {
                PacketTunnelDebugLog("套接字读取循环已停止: " + WideToUtf8(err));
            }
            break;
        }
        if (received == 0) {
            continue;
        }

        if (received < (int)packet_tunnel::kFrameHeaderSize) {
            continue;
        }

        const bool from_server = IsServerEndpoint(source_addr, source_addr_len);
        std::string datagram_peer_virtual_ip;
        bool datagram_from_known_peer = !from_server &&
                                        TryResolvePeerBySource(source_addr,
                                                               source_addr_len,
                                                               &datagram_peer_virtual_ip);
        auto has_fresh_direct_route = [this](const std::string& candidate_peer_virtual_ip) -> bool {
            if (candidate_peer_virtual_ip.empty() ||
                peer_link_manager_ == NULL) {
                return false;
            }

            PeerRouteStatus route = {};
            const unsigned long long now_tick = GetTickCount64();
            if (!peer_link_manager_->TryGetDirectRoute(candidate_peer_virtual_ip,
                                                       now_tick,
                                                       kPeerDirectDataTimeoutMs,
                                                       kPeerDirectProbeGraceMs,
                                                       &route)) {
                return false;
            }
            return route.active_direct && IsDirectPathFresh(route, now_tick);
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
            bool learned_direct_endpoint = false;
            bool learned_direct_endpoint_changed = false;
            std::string learned_direct_reason;

            if (from_server) {
                last_receive_tick_ = GetTickCount64();
                MarkNetworkActivity();

                if (frame_type == packet_tunnel::kFrameHeartbeatAck) {
                    continue;
                }

                if (HandlePeerControlFrame(frame_type, payload, payload_len)) {
                    continue;
                }
            }

            if (frame_type == packet_tunnel::kFrameIpv4Packet && wintun_manager_ != NULL) {
                const unsigned long long frame_process_start = GetTickCount64();
                const bool debug_enabled = PacketTunnelDebugEnabled();
                const bool has_inner_ipv4 =
                payload_len >= 20 &&
                (((payload[0] >> 4) & 0x0F) == 4);
            const std::string inner_src_virtual_ip =
                has_inner_ipv4 ? Ipv4ToString(payload + 12) : "";
            const std::string inner_dst_virtual_ip =
                has_inner_ipv4 ? Ipv4ToString(payload + 16) : "";
            bool inner_is_udp = false;
            uint16_t inner_src_port = 0;
            uint16_t inner_dst_port = 0;
            if (has_inner_ipv4 && payload[9] == IPPROTO_UDP) {
                const size_t ip_header_len = static_cast<size_t>(payload[0] & 0x0F) * 4;
                if (ip_header_len >= 20 && payload_len >= ip_header_len + 8) {
                    inner_is_udp = true;
                    inner_src_port = ntohs(*(const uint16_t*)(payload + ip_header_len));
                    inner_dst_port = ntohs(*(const uint16_t*)(payload + ip_header_len + 2));
                    if (debug_enabled) {
                        MaybeLogDnfUdpSignature(from_server ? "中转->Wintun" : "对端->Wintun",
                                                inner_src_virtual_ip,
                                                inner_src_port,
                                                inner_dst_virtual_ip,
                                                inner_dst_port,
                                                payload + ip_header_len + 8,
                                                payload_len - ip_header_len - 8);
                    }
                }
            }

            uint8_t probe_type = 0;
            const bool is_direct_probe = ParsePeerDirectProbePacket(payload, payload_len, &probe_type);
            if (debug_enabled &&
                !from_server &&
                inner_is_udp &&
                (is_direct_probe || inner_src_port == 5063 || inner_dst_port == 5063) &&
                !IsNoisyUdpForLogging(payload, payload_len)) {
                const std::string probe_kind =
                    probe_type == kPeerDirectProbeRequest
                        ? "请求"
                        : (probe_type == kPeerDirectProbeResponse ? "响应" : "无");
                PT_DEBUG("收到非服务器IPv4 源=" +
                         SockaddrToString(source_addr, source_addr_len) +
                         " 已知对端=" + (from_known_peer ? "是" : "否") +
                         " 对端=" + (peer_virtual_ip.empty() ? "-" : peer_virtual_ip) +
                         " 内层源=" + inner_src_virtual_ip + ":" +
                         std::to_string(inner_src_port) +
                         " 内层目标=" + inner_dst_virtual_ip + ":" +
                         std::to_string(inner_dst_port) +
                         " 探测=" + probe_kind +
                         " 长度=" + std::to_string(payload_len));
            }
            if (!from_server && !from_known_peer && peer_link_manager_ != NULL &&
                payload_len >= 20 && inner_is_udp) {
                const std::string inferred_peer_virtual_ip = inner_src_virtual_ip;
                const std::string inferred_local_virtual_ip = inner_dst_virtual_ip;
                bool should_learn_direct_endpoint = is_direct_probe;
                if (!should_learn_direct_endpoint &&
                    inferred_local_virtual_ip == virtual_ip_ &&
                    !inferred_peer_virtual_ip.empty() &&
                    inferred_peer_virtual_ip != virtual_ip_ &&
                    !IsServerVirtualPeer(inferred_peer_virtual_ip)) {
                    const std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
                    should_learn_direct_endpoint =
                        IsKnownPeerVirtualIp(peers, inferred_peer_virtual_ip);
                }
                uint8_t endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
                uint16_t endpoint_port = 0;
                uint8_t endpoint_addr[16] = {};
                if (should_learn_direct_endpoint &&
                    !inferred_peer_virtual_ip.empty() &&
                    inferred_peer_virtual_ip != virtual_ip_ &&
                    !IsServerVirtualPeer(inferred_peer_virtual_ip) &&
                    inferred_local_virtual_ip == virtual_ip_ &&
                    TryExtractPeerEndpointFromSockaddr(source_addr,
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
                    learned_direct_endpoint = true;
                    learned_direct_reason = is_direct_probe ? "探测" : "负载";
                    const std::string probe_kind =
                        probe_type == kPeerDirectProbeRequest
                            ? "请求"
                            : (probe_type == kPeerDirectProbeResponse ? "响应" : "未知");
                    if (debug_enabled) {
                        PT_DEBUG("学习到直连端点 对端=" +
                                 peer_virtual_ip +
                                 " 原因=" + learned_direct_reason +
                                 " 探测类型=" + probe_kind +
                                 " 源虚拟IP=" + inferred_peer_virtual_ip +
                                 " 目标虚拟IP=" + inferred_local_virtual_ip +
                                 " 来源=" + SockaddrToString(source_addr, source_addr_len) +
                                 (learned_direct_endpoint_changed ? " 已变化=是" : " 已变化=否"));
                    }
                }
            }
            if (!from_server && !from_known_peer) {
                if (debug_enabled) {
                    PT_DEBUG("忽略来自未知端点的IPv4数据包 来源=" +
                             SockaddrToString(source_addr, source_addr_len));
                }
                continue;
            }
            if (from_known_peer &&
                (payload_len < 20 ||
                 Ipv4ToString(payload + 12) != peer_virtual_ip)) {
                if (debug_enabled) {
                    PT_DEBUG("忽略内层源地址不匹配的对端IPv4数据包 对端=" +
                             peer_virtual_ip);
                }
                continue;
            }

            std::string relay_peer_virtual_ip;
            if (from_server &&
                peer_link_manager_ != NULL &&
                inner_is_udp &&
                inner_dst_virtual_ip == virtual_ip_) {
                const std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
                if (!IsServerVirtualPeer(inner_src_virtual_ip) &&
                    IsKnownPeerVirtualIp(peers, inner_src_virtual_ip)) {
                    relay_peer_virtual_ip = inner_src_virtual_ip;
                }
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
                            ParseIpv4StringToBe(peer_virtual_ip, &peer_virtual_ip_be)) {
                            std::vector<uint8_t> probe_response;
                            if (BuildPeerDirectProbePacket(local_virtual_ip_be,
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
                                if (debug_enabled) {
                                    PT_DEBUG("回复直连探测 对端=" + peer_virtual_ip +
                                             " 端点=" +
                                             SockaddrToString(source_addr, source_addr_len));
                                }
                            }
                        }
                    }
                    if (learned_direct_endpoint) {
                        MaybeLogDirectRouteFallback(peer_virtual_ip,
                                                    learned_direct_endpoint_changed
                                                        ? (learned_direct_reason == "探测"
                                                               ? "探测端点已更新"
                                                               : "负载端点已更新")
                                                        : (learned_direct_reason == "探测"
                                                               ? "探测端点已确认"
                                                               : "负载端点已确认"));
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
            }
            if (!from_known_peer &&
                has_inner_ipv4 &&
                has_fresh_direct_route(inner_src_virtual_ip)) {
                continue;
            }
            std::string desc;
            if (debug_enabled &&
                !IsNoisyUdpForLogging(payload, payload_len) &&
                TryDescribeUdpPacket(payload, payload_len, &desc)) {
                PT_DEBUG(std::string(from_known_peer ? "UDP 对端->Wintun " : "UDP 中转->Wintun ") + desc);
            }
            if (debug_enabled) {
                MaybeLogTcpPayloadIpHints(from_known_peer ? "对端->Wintun" : "中转->Wintun",
                                          payload,
                                          payload_len);
                MaybeLogUdpPayloadIpHints(from_known_peer ? "对端->Wintun" : "中转->Wintun",
                                          payload,
                                          payload_len);
                MarkWatchedTcpEnqueue(payload,
                                      payload_len,
                                      from_known_peer ? "对端接收" : "中转接收");
            }
            if (!EnqueueWintunPacket(payload,
                                     payload_len,
                                     from_known_peer,
                                     inner_src_virtual_ip,
                                     inner_src_port,
                                     inner_dst_virtual_ip,
                                     inner_dst_port)) {
                if (!stop_requested_) {
                    PacketTunnelWarnLog(std::string("中转->Wintun入队失败 方向=") +
                                        (from_known_peer ? "对端->Wintun" : "中转->Wintun") +
                                        " 源=" + inner_src_virtual_ip + ":" +
                                        std::to_string(inner_src_port) +
                                        " 目标=" + inner_dst_virtual_ip + ":" +
                                        std::to_string(inner_dst_port) +
                                        " 长度=" + std::to_string(payload_len));
                }
                datagram_valid = false;
                break;
            }
            const unsigned long long frame_process_elapsed =
                GetTickCount64() - frame_process_start;
            if (frame_process_elapsed >= kSlowPacketProcessWarnMs) {
                PacketTunnelWarnLog(std::string("套接字读取处理耗时偏长 elapsed_ms=") +
                                    std::to_string(frame_process_elapsed) +
                                    " 方向=" + (from_known_peer ? "对端->Wintun" : "中转->Wintun") +
                                    " 源=" + inner_src_virtual_ip + ":" + std::to_string(inner_src_port) +
                                    " 目标=" + inner_dst_virtual_ip + ":" + std::to_string(inner_dst_port) +
                                    " 长度=" + std::to_string(payload_len));
            }
            continue;
        }

            if (!from_server && !from_known_peer) {
                PT_DEBUG("ignore packet from unknown endpoint source=" +
                         SockaddrToString(source_addr, source_addr_len) +
                         " frame=" + PacketTunnelFrameName(frame_type));
            }
        }
        if (!datagram_valid) {
            continue;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void PacketTunnelClient::WintunReadLoop() {
    uint32_t virtual_ip_be = ParseVirtualIp(NULL);
    uint8_t leased_src_ip[4] = {};
    std::deque<std::vector<uint8_t>> deferred_packets;
    if (virtual_ip_be != 0) {
        memcpy(leased_src_ip, &virtual_ip_be, sizeof(leased_src_ip));
    }

    while (!stop_requested_) {
        std::vector<uint8_t> packet;
        std::wstring err;
        if (!deferred_packets.empty()) {
            packet = std::move(deferred_packets.front());
            deferred_packets.pop_front();
        } else if (!wintun_manager_ || !wintun_manager_->ReadPacket(&packet, kWintunReadWaitMs, &err)) {
            continue;
        }

        if (packet.empty()) {
            continue;
        }

        const unsigned long long frame_process_start = GetTickCount64();
        const bool debug_enabled = PacketTunnelDebugEnabled();

        uint8_t version = (packet[0] >> 4) & 0x0F;
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

        if (virtual_ip_be != 0 && packet.size() >= 20 &&
            memcmp(packet.data() + 12, leased_src_ip, sizeof(leased_src_ip)) != 0) {
            continue;
        }

        std::string desc;
        const bool has_desc =
            debug_enabled &&
            !IsNoisyUdpForLogging(packet.data(), packet.size()) &&
            TryDescribeUdpPacket(packet.data(), packet.size(), &desc);
        if (debug_enabled) {
            MaybeLogTcpPayloadIpHints("Wintun->中转", packet.data(), packet.size());
            MaybeLogUdpPayloadIpHints("Wintun->中转", packet.data(), packet.size());
        }
        const bool is_udp = packet.size() >= 20 && packet[9] == IPPROTO_UDP;
        const bool is_tcp = packet.size() >= 20 && packet[9] == IPPROTO_TCP;
        const std::string inner_proto_name = is_udp ? "udp" : (is_tcp ? "tcp" : "ip");
        std::string dst_virtual_ip = packet.size() >= 20 ? Ipv4ToString(packet.data() + 16) : "";
        std::string route_desc =
            "dst=" + dst_virtual_ip + " proto=" + inner_proto_name +
            " len=" + std::to_string(packet.size());
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        if (is_udp) {
            const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
            const std::string src_virtual_ip = Ipv4ToString(packet.data() + 12);
            if (ip_header_len >= 20 && packet.size() >= ip_header_len + 4) {
                src_port = ntohs(*(const uint16_t*)(packet.data() + ip_header_len));
                dst_port = ntohs(*(const uint16_t*)(packet.data() + ip_header_len + 2));
            }
            route_desc = has_desc
                            ? desc
                            : ("dst=" + dst_virtual_ip + ":" + std::to_string(dst_port) +
                               " len=" + std::to_string(packet.size()));
            if (debug_enabled) {
                MaybeLogWintunTargetIntent(dst_virtual_ip, dst_port, route_desc);
            }
            if (ip_header_len >= 20 && packet.size() >= ip_header_len + 8) {
                if (debug_enabled) {
                    MaybeLogDnfUdpSignature("Wintun->中转",
                                            src_virtual_ip,
                                            src_port,
                                            dst_virtual_ip,
                                            dst_port,
                                            packet.data() + ip_header_len + 8,
                                            packet.size() - ip_header_len - 8);
                }
            }
        }
        if (is_tcp) {
            size_t ip_header_len = 0;
            size_t tcp_header_len = 0;
            TryParseTcpPacket(packet.data(),
                              packet.size(),
                              &ip_header_len,
                              &tcp_header_len,
                              &src_port,
                              &dst_port);
        }
        if (is_udp &&
            IsMirrorEligibleUdpFlow(src_port, dst_port) &&
            peer_link_manager_ != NULL &&
            !dst_virtual_ip.empty()) {
            const std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
            const std::string udp_signature =
                BuildMirroredGatewayUdpSignature(packet.data(), packet.size());
            if (!udp_signature.empty()) {
                PruneMirroredGatewayUdpSignatureTicks(&mirrored_gateway_udp_signature_tick_,
                                                     frame_process_start);
                if (IsGatewayPeerResolveCandidate(virtual_ip_, dst_virtual_ip, peers)) {
                    mirrored_gateway_udp_signature_tick_[udp_signature] = frame_process_start;
                } else if (IsKnownPeerVirtualIp(peers, dst_virtual_ip)) {
                    std::map<std::string, unsigned long long>::iterator mirror_it =
                        mirrored_gateway_udp_signature_tick_.find(udp_signature);
                    if (mirror_it != mirrored_gateway_udp_signature_tick_.end() &&
                        frame_process_start >= mirror_it->second &&
                        (frame_process_start - mirror_it->second) <=
                            kMirroredGatewayUdpSignatureTtlMs) {
                        if (debug_enabled) {
                            PT_DEBUG("丢弃镜像网关UDP对端副本 " + route_desc +
                                     " 匹配耗时=" +
                                     std::to_string(frame_process_start - mirror_it->second));
                        }
                        continue;
                    }
                }
            }
        }
        if (is_udp && peer_direct_allowed_ && !dst_virtual_ip.empty()) {
            const std::string original_dst_virtual_ip = dst_virtual_ip;
            std::string target_peer_virtual_ip = dst_virtual_ip;
            std::string target_resolution = "直连IP";
            bool resolved_gateway_target = false;
            UdpEndpoint peer_endpoint;
            bool direct_path_fresh = false;
            bool active_direct = false;
            bool have_peer_endpoint =
                TryBuildPeerEndpoint(target_peer_virtual_ip,
                                     &peer_endpoint,
                                     &direct_path_fresh,
                                     &active_direct);
            if (!have_peer_endpoint && is_udp) {
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
                    if (resolved_gateway_target) {
                        if (debug_enabled) {
                            PT_DEBUG("UDP网关对端解析 目标=" +
                                     original_dst_virtual_ip + ":" +
                                     std::to_string(dst_port) +
                                     " -> 对端=" + target_peer_virtual_ip +
                                     " 解析器=" + target_resolution);
                        }
                    }
                }
            }

            std::vector<uint8_t> direct_packet;
            const std::vector<uint8_t>* direct_packet_view = &packet;
            bool direct_payload_ready = true;
            if (have_peer_endpoint && resolved_gateway_target && is_udp) {
                uint32_t original_dst_ip_be = 0;
                uint32_t target_peer_ip_be = 0;
                memcpy(&original_dst_ip_be, packet.data() + 16, sizeof(original_dst_ip_be));
                direct_packet = packet;
                if (!ParseIpv4StringToBe(target_peer_virtual_ip, &target_peer_ip_be) ||
                    !RewriteIpv4UdpDestinationIp(&direct_packet,
                                                original_dst_ip_be,
                                                target_peer_ip_be)) {
                    direct_payload_ready = false;
                    if (debug_enabled) {
                        PT_DEBUG("UDP网关对端改写失败 目标=" +
                                 original_dst_virtual_ip + ":" +
                                 std::to_string(dst_port) +
                                 " 对端=" + target_peer_virtual_ip +
                                 " 解析器=" + target_resolution);
                    }
                } else {
                    direct_packet_view = &direct_packet;
                }
            }

            PacketFlowRouterInput udp_flow_input;
            udp_flow_input.is_udp = true;
            udp_flow_input.has_udp_peer_endpoint = have_peer_endpoint;
            udp_flow_input.direct_path_fresh = direct_path_fresh;
            udp_flow_input.active_direct = active_direct;
            udp_flow_input.resolved_gateway_target = resolved_gateway_target;
            udp_flow_input.direct_payload_ready = direct_payload_ready;
            udp_flow_input.route_desc_seed = route_desc;
            udp_flow_input.target_peer_virtual_ip = target_peer_virtual_ip;
            udp_flow_input.original_dst_virtual_ip = original_dst_virtual_ip;
            udp_flow_input.target_resolution = target_resolution;
            udp_flow_input.can_shadow_payload =
                direct_payload_ready &&
                !resolved_gateway_target &&
                target_peer_virtual_ip == original_dst_virtual_ip &&
                (src_port == 5063 || dst_port == 5063);
            const PacketFlowRouterDecision udp_flow_decision =
                PacketFlowRouter::Decide(udp_flow_input);
            const std::string direct_route_desc = udp_flow_decision.route_desc;

            if (have_peer_endpoint) {
                if (udp_flow_decision.primary_route == PacketFlowRoute::UdpDirect) {
                    if (udp_flow_decision.try_udp_direct_now) {
                        if (!direct_path_fresh && active_direct && resolved_gateway_target) {
                            if (debug_enabled) {
                                PT_DEBUG("udp stale active direct send " + direct_route_desc);
                            }
                        }
                        if (SendFrameToEndpoint(peer_endpoint,
                                                packet_tunnel::kFrameIpv4Packet,
                                                direct_packet_view->data(),
                                                direct_packet_view->size(),
                                                NULL)) {
                            const unsigned long long frame_process_elapsed =
                                GetTickCount64() - frame_process_start;
                            if (frame_process_elapsed >= kSlowPacketProcessWarnMs) {
                                PacketTunnelWarnLog(std::string("Wintun直连发送处理耗时偏长 elapsed_ms=") +
                                                    std::to_string(frame_process_elapsed) +
                                                    " 目标=" + target_peer_virtual_ip + ":" +
                                                    std::to_string(dst_port) +
                                                    " 长度=" + std::to_string(direct_packet_view->size()));
                            }
                            if (debug_enabled) {
                                TraceWatchedTcpPacket(direct_packet_view->data(),
                                                      direct_packet_view->size(),
                                                      "Wintun->对端");
                                PT_DEBUG(inner_proto_name + " Wintun->对端 " + direct_route_desc);
                            }
                            continue;
                        }
                        PeerRouteStatus failed_status = {};
                        const bool state_changed =
                            peer_link_manager_ != NULL &&
                            peer_link_manager_->RecordDirectSendFailure(target_peer_virtual_ip,
                                                                        0,
                                                                        active_direct,
                                                                        &failed_status);
                        if (debug_enabled) {
                            PT_DEBUG(inner_proto_name +
                                     " 当前直连发送失败，回退到中转 " +
                                     direct_route_desc);
                        }
                        if (debug_enabled &&
                            state_changed &&
                            failed_status.state == PeerRouteState::Cooldown) {
                            PT_DEBUG("UDP直连进入冷却 对端=" +
                                     failed_status.peer_virtual_ip);
                        }
                    } else {
                        MaybeLogDirectRouteFallback(target_peer_virtual_ip, "目标改写失败");
                    }
                } else {
                    const unsigned long long now_tick = GetTickCount64();
                    std::map<std::string, unsigned long long>::iterator probe_it =
                        peer_probe_send_tick_.find(target_peer_virtual_ip);
                    const bool should_send_probe =
                        probe_it == peer_probe_send_tick_.end() ||
                        now_tick < probe_it->second ||
                        (now_tick - probe_it->second) >= kPeerDirectProbeIntervalMs;
                    bool sent_shadow_payload = false;
                    const bool can_shadow_send_payload =
                        should_send_probe &&
                        udp_flow_decision.try_udp_shadow_payload;
                    if (can_shadow_send_payload &&
                        SendFrameToEndpoint(peer_endpoint,
                                            packet_tunnel::kFrameIpv4Packet,
                                            direct_packet_view->data(),
                                            direct_packet_view->size(),
                                            NULL)) {
                        peer_probe_send_tick_[target_peer_virtual_ip] = now_tick;
                        sent_shadow_payload = true;
                        if (debug_enabled) {
                            PT_DEBUG("UDP直连影子发送 " + direct_route_desc +
                                     " 端点=" +
                                     SockaddrToString(peer_endpoint.addr,
                                                      peer_endpoint.addr_len));
                        }
                    } else if (can_shadow_send_payload) {
                        PeerRouteStatus failed_status = {};
                        const bool state_changed =
                            peer_link_manager_ != NULL &&
                            peer_link_manager_->RecordDirectSendFailure(target_peer_virtual_ip,
                                                                        0,
                                                                        active_direct,
                                                                        &failed_status);
                        if (debug_enabled) {
                            PT_DEBUG("UDP直连影子发送失败，继续以中转为主 " +
                                     direct_route_desc);
                        }
                        if (debug_enabled &&
                            state_changed &&
                            failed_status.state == PeerRouteState::Cooldown) {
                            PT_DEBUG("UDP直连进入冷却 对端=" +
                                     failed_status.peer_virtual_ip);
                        }
                    }
                    if (should_send_probe) {
                        uint32_t target_peer_ip_be = 0;
                        std::vector<uint8_t> probe_packet;
                        if (virtual_ip_be != 0 &&
                            ParseIpv4StringToBe(target_peer_virtual_ip, &target_peer_ip_be) &&
                            BuildPeerDirectProbePacket(virtual_ip_be,
                                                       target_peer_ip_be,
                                                       kPeerDirectProbeRequest,
                                                       &probe_packet) &&
                            SendFrameToEndpoint(peer_endpoint,
                                                packet_tunnel::kFrameIpv4Packet,
                                                probe_packet.data(),
                                                probe_packet.size(),
                                                NULL)) {
                            peer_probe_send_tick_[target_peer_virtual_ip] = now_tick;
                            if (debug_enabled) {
                                PT_DEBUG(std::string(inner_proto_name + " 直连探测请求 ") +
                                         direct_route_desc +
                                         (sent_shadow_payload ? " 同时发送=影子负载" : ""));
                            }
                        } else {
                            PeerRouteStatus failed_status = {};
                            const bool state_changed =
                                peer_link_manager_ != NULL &&
                                peer_link_manager_->RecordDirectSendFailure(target_peer_virtual_ip,
                                                                            0,
                                                                            active_direct,
                                                                            &failed_status);
                            if (debug_enabled) {
                                if (active_direct) {
                                    PT_DEBUG(inner_proto_name +
                                             " 当前直连探测失败，回退到中转 " +
                                             direct_route_desc);
                                } else {
                                    PT_DEBUG(inner_proto_name +
                                             " 直连探测发送失败，继续以中转为主 " +
                                             direct_route_desc);
                                }
                            }
                            if (debug_enabled &&
                                state_changed &&
                                failed_status.state == PeerRouteState::Cooldown) {
                                PT_DEBUG("UDP直连进入冷却 对端=" +
                                         failed_status.peer_virtual_ip);
                            }
                        }
                    }
                }
            } else {
                MaybeLogDirectRouteFallback(target_peer_virtual_ip,
                                            target_peer_virtual_ip != original_dst_virtual_ip
                                                ? ("路由不可用_" + target_resolution)
                                                : "路由不可用");
            }
        }

        PacketFlowRouterInput flow_input;
        flow_input.is_tcp = is_tcp;
        flow_input.has_tcp_direct_target = !dst_virtual_ip.empty();
        flow_input.tcp_relay_available = tcp_connected_ && tcp_sock_ != INVALID_SOCKET;
        flow_input.udp_relay_batch_eligible =
            kPacketTunnelEnableWinRelayTcpMicroBatch &&
            IsPacketTunnelMicroBatchEligibleTcpPacket(packet.data(), packet.size());
        const PacketFlowRouterDecision flow_decision = PacketFlowRouter::Decide(flow_input);

        if (flow_decision.try_tcp_direct_now &&
            TrySendTcpDirectPacket(dst_virtual_ip, packet.data(), packet.size())) {
            const unsigned long long frame_process_elapsed =
                GetTickCount64() - frame_process_start;
            if (frame_process_elapsed >= kSlowPacketProcessWarnMs) {
                                PacketTunnelWarnLog(std::string("Wintun TCP直连处理耗时偏长 elapsed_ms=") +
                                                    std::to_string(frame_process_elapsed) +
                                                    " 目标=" + dst_virtual_ip + ":" +
                                                    std::to_string(dst_port) +
                                                    " 长度=" + std::to_string(packet.size()));
            }
            if (debug_enabled) {
                TraceWatchedTcpPacket(packet.data(), packet.size(), "Wintun->TCP对端");
                PT_DEBUG("TCP Wintun->TCP对端 目标=" + dst_virtual_ip + ":" +
                         std::to_string(dst_port) +
                         " 长度=" + std::to_string(packet.size()));
            }
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
                PacketTunnelWarnLog("TCP中转载体发送失败，回退到UDP中转");
                tcp_connected_ = false;
                SOCKET stale_tcp_sock = tcp_sock_;
                tcp_sock_ = INVALID_SOCKET;
                if (stale_tcp_sock != INVALID_SOCKET) {
                    closesocket(stale_tcp_sock);
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
                    std::wstring next_err;
                    if (!wintun_manager_ ||
                        !wintun_manager_->ReadPacket(&next_packet, 0, &next_err) ||
                        next_packet.empty()) {
                        break;
                    }

                    if (!IsPacketTunnelRelayBatchEligibleWintunPacket(next_packet,
                                                                      leased_src_ip,
                                                                      virtual_ip_be != 0)) {
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

                EnterCriticalSection(&send_lock_);
                relay_send_ok = SendDatagramToEndpoint(server_endpoint_,
                                                       relay_datagram.data(),
                                                       relay_datagram.size(),
                                                       NULL);
                LeaveCriticalSection(&send_lock_);
                if (debug_enabled && relay_batch_frames > 1) {
                    PT_DEBUG("TCP Wintun->中转 批量帧数=" +
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
            if (debug_enabled) {
                PT_DEBUG("Wintun读取循环发送失败");
            }
            break;
        }
        if (debug_enabled) {
            TraceWatchedTcpPacket(packet.data(), packet.size(), "Wintun->中转");
        }
        const unsigned long long frame_process_elapsed = GetTickCount64() - frame_process_start;
        if (frame_process_elapsed >= kSlowPacketProcessWarnMs) {
            PacketTunnelWarnLog(std::string("Wintun中转发送处理耗时偏长 elapsed_ms=") +
                                std::to_string(frame_process_elapsed) +
                                " 目标=" + dst_virtual_ip + ":" + std::to_string(dst_port) +
                                " 长度=" + std::to_string(packet.size()));
        }

        if (debug_enabled && has_desc) {
            PT_DEBUG("UDP Wintun->中转 " + desc);
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void PacketTunnelClient::TcpSocketReadLoop() {
    while (!stop_requested_ && tcp_connected_) {
        uint8_t header[packet_tunnel::kFrameHeaderSize] = {};
        std::wstring err;
        if (!RecvTcpExact(header, sizeof(header), &err)) {
            if (!stop_requested_ && tcp_connected_ && !err.empty()) {
                PacketTunnelWarnLog("TCP中转载体读取结束: " + WideToUtf8(err));
            }
            break;
        }

        const uint8_t frame_type = header[0];
        const uint16_t payload_len = ntohs(*(const uint16_t*)(&header[1]));
        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0 &&
            !RecvTcpExact(payload.data(), payload_len, &err)) {
            if (!stop_requested_ && tcp_connected_ && !err.empty()) {
                PacketTunnelWarnLog("TCP中转载体负载读取结束: " + WideToUtf8(err));
            }
            break;
        }

        if (frame_type == packet_tunnel::kFrameHeartbeatAck) {
            continue;
        }
        if (HandlePeerControlFrame(frame_type, payload.data(), payload.size())) {
            continue;
        }
        if (frame_type != packet_tunnel::kFrameIpv4Packet || wintun_manager_ == NULL) {
            PacketTunnelDebugLog("忽略TCP中转载体帧 " + PacketTunnelFrameName(frame_type) +
                                 " 长度=" + std::to_string(payload.size()));
            continue;
        }

        const bool has_inner_ipv4 =
            payload.size() >= 20 &&
            (((payload[0] >> 4) & 0x0F) == 4);
        const std::string inner_src_virtual_ip =
            has_inner_ipv4 ? Ipv4ToString(payload.data() + 12) : "";
        const std::string inner_dst_virtual_ip =
            has_inner_ipv4 ? Ipv4ToString(payload.data() + 16) : "";
        uint16_t inner_src_port = 0;
        uint16_t inner_dst_port = 0;
        if (has_inner_ipv4 && payload[9] == IPPROTO_UDP) {
            const size_t ip_header_len = static_cast<size_t>(payload[0] & 0x0F) * 4;
            if (ip_header_len >= 20 && payload.size() >= ip_header_len + 8) {
                inner_src_port = ntohs(*(const uint16_t*)(payload.data() + ip_header_len));
                inner_dst_port = ntohs(*(const uint16_t*)(payload.data() + ip_header_len + 2));
            }
        } else if (has_inner_ipv4 && payload[9] == IPPROTO_TCP) {
            size_t ip_header_len = 0;
            size_t tcp_header_len = 0;
            TryParseTcpPacket(payload.data(),
                              payload.size(),
                              &ip_header_len,
                              &tcp_header_len,
                              &inner_src_port,
                              &inner_dst_port);
        }

        if (!EnqueueWintunPacket(payload.data(),
                                 payload.size(),
                                 false,
                                 inner_src_virtual_ip,
                                 inner_src_port,
                                 inner_dst_virtual_ip,
                                 inner_dst_port)) {
            if (!stop_requested_) {
                PacketTunnelWarnLog("TCP中转载体数据写入Wintun队列失败");
            }
            break;
        }
    }

    SOCKET stale_sock = tcp_sock_;
    tcp_connected_ = false;
    if (stale_sock != INVALID_SOCKET) {
        closesocket(stale_sock);
        if (tcp_sock_ == stale_sock) {
            tcp_sock_ = INVALID_SOCKET;
        }
    }
}

bool PacketTunnelClient::RecvFrameFromSocket(SOCKET sock,
                                             uint8_t* frame_type,
                                             std::vector<uint8_t>* payload,
                                             std::wstring* error_msg) {
    if (sock == INVALID_SOCKET || frame_type == NULL || payload == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP直连接收参数无效";
        }
        return false;
    }

    auto recv_exact = [&](uint8_t* data, size_t length) -> bool {
        size_t received = 0;
        while (received < length && !stop_requested_) {
            int n = recv(sock,
                         reinterpret_cast<char*>(data + received),
                         static_cast<int>(length - received),
                         0);
            if (n > 0) {
                received += static_cast<size_t>(n);
                continue;
            }
            if (n == 0) {
                if (error_msg != NULL) {
                    *error_msg = L"IP Tunnel TCP直连对端已关闭";
                }
                return false;
            }
            int err = WSAGetLastError();
            if ((err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) && !stop_requested_) {
                continue;
            }
            if (error_msg != NULL) {
                *error_msg = BuildSocketError(L"IP Tunnel TCP direct recv failed", err);
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

bool PacketTunnelClient::SendFrameOverSocket(SOCKET sock,
                                             CRITICAL_SECTION* send_lock,
                                             uint8_t frame_type,
                                             const uint8_t* data,
                                             size_t length,
                                             std::wstring* error_msg) {
    if (sock == INVALID_SOCKET || length > 0xFFFFu) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP直连发送参数无效";
        }
        return false;
    }

    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons(static_cast<uint16_t>(length));
    if (length > 0 && data != NULL) {
        memcpy(frame.data() + packet_tunnel::kFrameHeaderSize, data, length);
    }

    if (send_lock != NULL) {
        EnterCriticalSection(send_lock);
    }
    size_t sent = 0;
    int transient_retries = 0;
    int last_error = 0;
    while (sent < frame.size() && !stop_requested_) {
        int n = send(sock,
                     reinterpret_cast<const char*>(frame.data() + sent),
                     static_cast<int>(frame.size() - sent),
                     0);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            transient_retries = 0;
            continue;
        }
        last_error = WSAGetLastError();
        if (IsTransientSocketSendError(last_error) &&
            transient_retries + 1 < kSocketSendRetryCount) {
            ++transient_retries;
            Sleep(kSocketSendRetryDelayMs);
            continue;
        }
        break;
    }
    if (send_lock != NULL) {
        LeaveCriticalSection(send_lock);
    }

    if (sent == frame.size()) {
        return true;
    }
    if (error_msg != NULL) {
        if (last_error != 0) {
            *error_msg = BuildSocketError(L"IP Tunnel TCP直连发送失败", last_error);
        } else {
            *error_msg = L"IP Tunnel TCP直连发送被中断";
        }
    }
    return false;
}

void PacketTunnelClient::TcpDirectAcceptLoop() {
    while (!stop_requested_) {
        SOCKET listen_sock = tcp_direct_listen_sock_;
        if (listen_sock == INVALID_SOCKET) {
            break;
        }

        sockaddr_storage peer_addr = {};
        int peer_addr_len = sizeof(peer_addr);
        SOCKET accepted = accept(listen_sock,
                                 reinterpret_cast<sockaddr*>(&peer_addr),
                                 &peer_addr_len);
        if (accepted == INVALID_SOCKET) {
            if (!stop_requested_) {
                int err = WSAGetLastError();
                if (err != WSAENOTSOCK &&
                    err != WSAEINTR &&
                    err != WSAEWOULDBLOCK &&
                    err != WSAETIMEDOUT) {
                    PacketTunnelWarnLog("接受TCP直连接入失败: " +
                                        WideToUtf8(BuildSocketError(L"accept", err)));
                }
            }
            continue;
        }

        if (stop_requested_) {
            closesocket(accepted);
            break;
        }

        ConfigureTcpStreamSocket(accepted);
        std::shared_ptr<TcpDirectConnection> connection =
            std::make_shared<TcpDirectConnection>();
        connection->sock = accepted;
        connection->active = true;
        connection->read_thread =
            std::thread(&PacketTunnelClient::TcpDirectReadLoop, this, connection, true);
        connection->read_thread.detach();
        PacketTunnelDebugLog("已接受TCP直连接入，来源=" +
                             SockaddrToString(peer_addr, peer_addr_len));
    }
}

void PacketTunnelClient::TcpDirectReadLoop(const std::shared_ptr<TcpDirectConnection>& connection,
                                           bool expect_open_frame) {
    if (!connection) {
        return;
    }

    SOCKET socket_for_remove = connection->sock;
    std::string peer_virtual_ip = connection->peer_virtual_ip;

    if (expect_open_frame) {
        uint8_t open_frame_type = 0;
        std::vector<uint8_t> open_payload;
        std::wstring open_error;
        if (!RecvFrameFromSocket(connection->sock,
                                 &open_frame_type,
                                 &open_payload,
                                 &open_error) ||
            open_frame_type != packet_tunnel::kFrameTcpDirectOpen ||
            open_payload.size() != packet_tunnel::kTcpDirectOpenPayloadSize) {
            if (!stop_requested_) {
                PacketTunnelDebugLog("TCP直连入站打开失败: " +
                                     WideToUtf8(open_error));
            }
            CloseSocketQuiet(&connection->sock);
            connection->active = false;
            return;
        }

        const std::string src_virtual_ip = Ipv4ToString(open_payload.data());
        const std::string dst_virtual_ip = Ipv4ToString(open_payload.data() + 4);
        if (src_virtual_ip.empty() ||
            src_virtual_ip == virtual_ip_ ||
            dst_virtual_ip != virtual_ip_) {
            PacketTunnelDebugLog("拒绝TCP直连接入，源=" +
                                 src_virtual_ip +
                                 " 目标=" + dst_virtual_ip);
            CloseSocketQuiet(&connection->sock);
            connection->active = false;
            return;
        }

        connection->peer_virtual_ip = src_virtual_ip;
        peer_virtual_ip = src_virtual_ip;
        RegisterTcpDirectConnection(peer_virtual_ip, connection, true);
    }

    while (!stop_requested_ && connection->active && connection->sock != INVALID_SOCKET) {
        uint8_t frame_type = 0;
        std::vector<uint8_t> payload;
        std::wstring err;
        if (!RecvFrameFromSocket(connection->sock, &frame_type, &payload, &err)) {
            if (!stop_requested_ && !err.empty()) {
                PacketTunnelDebugLog("TCP直连读取结束，对端=" +
                                     (peer_virtual_ip.empty() ? std::string("?") : peer_virtual_ip) +
                                     " 原因=" + WideToUtf8(err));
            }
            break;
        }

        connection->last_rx_tick_ms = GetTickCount64();
        if (frame_type == packet_tunnel::kFrameHeartbeat && payload.empty()) {
            if (SendFrameOverSocket(connection->sock,
                                    &connection->send_lock,
                                    packet_tunnel::kFrameHeartbeatAck,
                                    NULL,
                                    0,
                                    NULL)) {
                connection->last_tx_tick_ms = GetTickCount64();
            }
            continue;
        }
        if (frame_type == packet_tunnel::kFrameHeartbeatAck && payload.empty()) {
            continue;
        }

        if (frame_type != packet_tunnel::kFrameIpv4Packet || payload.size() < 20 ||
            (((payload[0] >> 4) & 0x0F) != 4)) {
            PacketTunnelDebugLog("忽略TCP直连帧，类型=" +
                                 PacketTunnelFrameName(frame_type) +
                                 " 长度=" + std::to_string(payload.size()));
            continue;
        }

        const std::string inner_src_virtual_ip = Ipv4ToString(payload.data() + 12);
        const std::string inner_dst_virtual_ip = Ipv4ToString(payload.data() + 16);
        if (!peer_virtual_ip.empty() && inner_src_virtual_ip != peer_virtual_ip) {
            PacketTunnelDebugLog("忽略源地址不匹配的TCP直连包，对端=" +
                                 peer_virtual_ip +
                                 " 包内源=" + inner_src_virtual_ip);
            continue;
        }

        uint16_t inner_src_port = 0;
        uint16_t inner_dst_port = 0;
        if (payload[9] == IPPROTO_UDP) {
            const size_t ip_header_len = static_cast<size_t>(payload[0] & 0x0F) * 4;
            if (ip_header_len >= 20 && payload.size() >= ip_header_len + 8) {
                inner_src_port = ntohs(*(const uint16_t*)(payload.data() + ip_header_len));
                inner_dst_port = ntohs(*(const uint16_t*)(payload.data() + ip_header_len + 2));
            }
        } else if (payload[9] == IPPROTO_TCP) {
            size_t ip_header_len = 0;
            size_t tcp_header_len = 0;
            TryParseTcpPacket(payload.data(),
                              payload.size(),
                              &ip_header_len,
                              &tcp_header_len,
                              &inner_src_port,
                              &inner_dst_port);
        }

        MarkNetworkActivity();
        if (PacketTunnelDebugEnabled()) {
            TraceWatchedTcpPacket(payload.data(), payload.size(), "TCP对端->Wintun");
        }
        if (!EnqueueWintunPacket(payload.data(),
                                 payload.size(),
                                 true,
                                 inner_src_virtual_ip,
                                 inner_src_port,
                                 inner_dst_virtual_ip,
                                 inner_dst_port)) {
            if (!stop_requested_) {
                PacketTunnelWarnLog("写入Wintun失败，TCP直连数据入队失败，对端=" +
                                    peer_virtual_ip);
            }
            break;
        }
    }

    RemoveTcpDirectConnection(peer_virtual_ip, socket_for_remove, true);
}

void PacketTunnelClient::RegisterTcpDirectConnection(
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
        const unsigned long long now_tick = GetTickCount64();
        connection->last_rx_tick_ms = now_tick;
        connection->last_tx_tick_ms = now_tick;
        TcpDirectOffer& offer = tcp_direct_offers_[peer_virtual_ip];
        offer.connecting = false;
        offer.cooldown_until_tick_ms = 0;
    }

    if (old_connection) {
        old_connection->active = false;
        CloseSocketQuiet(&old_connection->sock);
    }

    PacketTunnelInfoLog(std::string("TCP直连已激活，方向=") +
                        (incoming ? "入站" : "出站") +
                        " 对端=" + peer_virtual_ip);
}

void PacketTunnelClient::RemoveTcpDirectConnection(const std::string& peer_virtual_ip,
                                                   SOCKET sock,
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
            (sock != INVALID_SOCKET && it->second->sock != sock)) {
            return;
        }
        removed = it->second;
        tcp_direct_connections_.erase(it);

        std::map<std::string, TcpDirectOffer>::iterator offer_it =
            tcp_direct_offers_.find(peer_virtual_ip);
        if (offer_it != tcp_direct_offers_.end()) {
            offer_it->second.connecting = false;
            if (enter_cooldown) {
                offer_it->second.cooldown_until_tick_ms =
                    GetTickCount64() + kTcpDirectRetryCooldownMs;
            }
        }
    }

    if (removed) {
        removed->active = false;
        CloseSocketQuiet(&removed->sock);
    }
}

void PacketTunnelClient::MaintainTcpDirectConnections(unsigned long long now_tick) {
    std::vector<std::pair<std::string, SOCKET>> stale_connections;
    std::vector<std::shared_ptr<TcpDirectConnection>> heartbeat_connections;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        for (std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator it =
                 tcp_direct_connections_.begin();
             it != tcp_direct_connections_.end();
             ++it) {
            const std::shared_ptr<TcpDirectConnection>& connection = it->second;
            if (!connection || !connection->active || connection->sock == INVALID_SOCKET) {
                stale_connections.push_back(std::make_pair(it->first, INVALID_SOCKET));
                continue;
            }

            const unsigned long long last_rx = connection->last_rx_tick_ms.load();
            const unsigned long long last_tx = connection->last_tx_tick_ms.load();
            if (last_rx != 0 &&
                now_tick >= last_rx &&
                (now_tick - last_rx) > kTcpDirectIdleTimeoutMs) {
                stale_connections.push_back(std::make_pair(it->first, connection->sock));
                continue;
            }
            if (last_tx == 0 ||
                now_tick < last_tx ||
                (now_tick - last_tx) >= kTcpDirectHeartbeatIntervalMs) {
                heartbeat_connections.push_back(connection);
            }
        }
    }

    for (size_t i = 0; i < stale_connections.size(); ++i) {
        PacketTunnelDebugLog("TCP直连空闲超时，对端=" + stale_connections[i].first);
        RemoveTcpDirectConnection(stale_connections[i].first,
                                  stale_connections[i].second,
                                  true);
    }

    for (size_t i = 0; i < heartbeat_connections.size(); ++i) {
        const std::shared_ptr<TcpDirectConnection>& connection = heartbeat_connections[i];
        if (!connection || !connection->active || connection->sock == INVALID_SOCKET) {
            continue;
        }
        if (SendFrameOverSocket(connection->sock,
                                &connection->send_lock,
                                packet_tunnel::kFrameHeartbeat,
                                NULL,
                                0,
                                NULL)) {
            connection->last_tx_tick_ms = now_tick;
        } else {
            RemoveTcpDirectConnection(connection->peer_virtual_ip,
                                      connection->sock,
                                      true);
        }
    }
}

void PacketTunnelClient::RecordTcpDirectCandidateResult(
    const std::string& peer_virtual_ip,
    const TcpDirectCandidate& candidate,
    bool success,
    unsigned long long connect_ms) {
    if (peer_virtual_ip.empty()) {
        return;
    }

    const unsigned long long now_tick = GetTickCount64();
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
            existing.last_success_tick_ms = now_tick;
            existing.last_connect_ms = connect_ms;
            offer_it->second.next_candidate_index = i;
        } else {
            ++existing.failure_count;
            existing.last_failure_tick_ms = now_tick;
        }
        return;
    }
}

std::vector<PacketTunnelClient::TcpDirectCandidate>
PacketTunnelClient::BuildOrderedTcpDirectCandidates(const TcpDirectOffer& offer,
                                                    unsigned long long now_tick) const {
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
                     [now_tick](const TcpDirectCandidate& left,
                                const TcpDirectCandidate& right) {
                         const bool left_recent_fail =
                             left.last_failure_tick_ms != 0 &&
                             now_tick >= left.last_failure_tick_ms &&
                             (now_tick - left.last_failure_tick_ms) <
                                 kTcpDirectRetryCooldownMs;
                         const bool right_recent_fail =
                             right.last_failure_tick_ms != 0 &&
                             now_tick >= right.last_failure_tick_ms &&
                             (now_tick - right.last_failure_tick_ms) <
                                 kTcpDirectRetryCooldownMs;
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

bool PacketTunnelClient::TrySendTcpDirectPacket(const std::string& peer_virtual_ip,
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
            it->second->sock != INVALID_SOCKET) {
            connection = it->second;
        }
    }

    if (!connection) {
        MaybeStartTcpDirectConnect(peer_virtual_ip);
        return false;
    }

    if (SendFrameOverSocket(connection->sock,
                            &connection->send_lock,
                            packet_tunnel::kFrameIpv4Packet,
                            data,
                            length,
                            NULL)) {
        connection->last_tx_tick_ms = GetTickCount64();
        return true;
    }

    PacketTunnelWarnLog("TCP直连发送失败，回退到中转，对端=" + peer_virtual_ip);
    RecordTcpDirectCandidateResult(peer_virtual_ip, connection->candidate, false, 0);
    RemoveTcpDirectConnection(peer_virtual_ip, connection->sock, true);
    MaybeStartTcpDirectConnect(peer_virtual_ip);
    return false;
}

void PacketTunnelClient::MaybeStartTcpDirectConnect(const std::string& peer_virtual_ip) {
    if (stop_requested_ || peer_virtual_ip.empty() || peer_virtual_ip == virtual_ip_) {
        return;
    }

    const unsigned long long now_tick = GetTickCount64();
    const uint32_t local_virtual_ip_be = ParseVirtualIp(NULL);
    uint32_t peer_virtual_ip_be = 0;
    const bool have_virtual_ip_order =
        local_virtual_ip_be != 0 &&
        ParseIpv4StringToBe(peer_virtual_ip, &peer_virtual_ip_be) &&
        peer_virtual_ip_be != 0;
    {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, TcpDirectOffer>::iterator offer_it =
            tcp_direct_offers_.find(peer_virtual_ip);
        if (offer_it == tcp_direct_offers_.end() ||
            (offer_it->second.candidates.empty() &&
             offer_it->second.endpoint_port == 0) ||
            offer_it->second.connecting ||
            (offer_it->second.cooldown_until_tick_ms != 0 &&
             now_tick < offer_it->second.cooldown_until_tick_ms)) {
            return;
        }
        if (have_virtual_ip_order &&
            local_virtual_ip_be > peer_virtual_ip_be &&
            offer_it->second.last_offer_tick_ms != 0 &&
            now_tick >= offer_it->second.last_offer_tick_ms &&
            (now_tick - offer_it->second.last_offer_tick_ms) < kTcpDirectPassiveWaitMs) {
            return;
        }
        std::map<std::string, std::shared_ptr<TcpDirectConnection>>::iterator conn_it =
            tcp_direct_connections_.find(peer_virtual_ip);
        if (conn_it != tcp_direct_connections_.end() &&
            conn_it->second &&
            conn_it->second->active &&
            conn_it->second->sock != INVALID_SOCKET) {
            return;
        }
        offer_it->second.connecting = true;
        tcp_direct_connect_threads_.push_back(
            std::thread(&PacketTunnelClient::TcpDirectConnectWorker, this, peer_virtual_ip));
    }
}

void PacketTunnelClient::TcpDirectConnectWorker(const std::string& peer_virtual_ip) {
    auto finish_connect_attempt = [&](bool cooldown) {
        std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
        std::map<std::string, TcpDirectOffer>::iterator it =
            tcp_direct_offers_.find(peer_virtual_ip);
        if (it != tcp_direct_offers_.end()) {
            it->second.connecting = false;
            if (cooldown) {
                it->second.cooldown_until_tick_ms =
                    GetTickCount64() + kTcpDirectRetryCooldownMs;
            }
        }
    };

    uint32_t local_virtual_ip_be = ParseVirtualIp(NULL);
    uint32_t peer_virtual_ip_be = 0;
    if (local_virtual_ip_be == 0 ||
        !ParseIpv4StringToBe(peer_virtual_ip, &peer_virtual_ip_be)) {
        finish_connect_attempt(true);
        return;
    }

    std::vector<TcpDirectCandidate> attempted_candidates;
    const auto same_candidate =
        [](const TcpDirectCandidate& left, const TcpDirectCandidate& right) -> bool {
            const size_t left_addr_len =
                left.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16;
            const size_t right_addr_len =
                right.endpoint_family == packet_tunnel::kPeerEndpointFamilyIpv4 ? 4 : 16;
            return left.endpoint_family == right.endpoint_family &&
                   left.endpoint_port == right.endpoint_port &&
                   left_addr_len == right_addr_len &&
                   memcmp(left.endpoint_addr, right.endpoint_addr, left_addr_len) == 0;
        };

    while (!stop_requested_) {
        TcpDirectOffer offer;
        {
            std::lock_guard<std::mutex> lock(tcp_direct_mutex_);
            std::map<std::string, TcpDirectOffer>::const_iterator it =
                tcp_direct_offers_.find(peer_virtual_ip);
            if (it == tcp_direct_offers_.end()) {
                finish_connect_attempt(true);
                return;
            }
            offer = it->second;
        }

        std::vector<TcpDirectCandidate> candidates =
            BuildOrderedTcpDirectCandidates(offer, GetTickCount64());
        if (candidates.empty()) {
            finish_connect_attempt(true);
            return;
        }

        size_t candidate_index = candidates.size();
        TcpDirectCandidate candidate;
        for (size_t i = 0; i < candidates.size(); ++i) {
            bool already_attempted = false;
            for (size_t tried = 0; tried < attempted_candidates.size(); ++tried) {
                if (same_candidate(candidates[i], attempted_candidates[tried])) {
                    already_attempted = true;
                    break;
                }
            }
            if (!already_attempted) {
                candidate = candidates[i];
                candidate_index = i;
                break;
            }
        }
        if (candidate_index >= candidates.size()) {
            break;
        }
        attempted_candidates.push_back(candidate);
        const size_t candidate_count = candidates.size();

        sockaddr_storage peer_addr = {};
        int peer_addr_len = 0;
        if (!BuildTcpDirectSockaddr(candidate.endpoint_family,
                                    candidate.endpoint_addr,
                                    candidate.endpoint_port,
                                    &peer_addr,
                                    &peer_addr_len)) {
            continue;
        }

        SOCKET direct_sock = socket(peer_addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (direct_sock == INVALID_SOCKET) {
            continue;
        }
        ConfigureTcpStreamSocket(direct_sock);

        int connect_error = 0;
        const unsigned long long connect_start_tick = GetTickCount64();
        if (!ConnectSocketWithTimeout(direct_sock,
                                      peer_addr,
                                      peer_addr_len,
                                      kTcpDirectConnectTimeoutMs,
                                      &connect_error)) {
            if (!stop_requested_) {
                PacketTunnelDebugLog("TCP直连候选连接失败，对端=" + peer_virtual_ip +
                                     " 端点=" + SockaddrToString(peer_addr, peer_addr_len) +
                                     " 错误=" + std::to_string(connect_error));
            }
            closesocket(direct_sock);
            RecordTcpDirectCandidateResult(peer_virtual_ip, candidate, false, 0);
            continue;
        }
        const unsigned long long connect_end_tick = GetTickCount64();
        const unsigned long long connect_elapsed =
            connect_end_tick >= connect_start_tick
                ? (connect_end_tick - connect_start_tick)
                : 0;

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
                                 &connection->send_lock,
                                 packet_tunnel::kFrameTcpDirectOpen,
                                 open_payload.data(),
                                 open_payload.size(),
                                 NULL)) {
            CloseSocketQuiet(&connection->sock);
            RecordTcpDirectCandidateResult(peer_virtual_ip, candidate, false, 0);
            continue;
        }
        if (stop_requested_) {
            CloseSocketQuiet(&connection->sock);
            finish_connect_attempt(false);
            return;
        }

        RecordTcpDirectCandidateResult(peer_virtual_ip, candidate, true, connect_elapsed);
        RegisterTcpDirectConnection(peer_virtual_ip, connection, false);
        connection->read_thread =
            std::thread(&PacketTunnelClient::TcpDirectReadLoop, this, connection, false);
        connection->read_thread.detach();
        PacketTunnelInfoLog("TCP直连已连接，对端=" + peer_virtual_ip +
                            " 端点=" + SockaddrToString(peer_addr, peer_addr_len) +
                            " 候选=" + std::to_string(candidate_index + 1) +
                            "/" + std::to_string(candidate_count));
        return;
    }

    finish_connect_attempt(!stop_requested_);
}

void PacketTunnelClient::HeartbeatLoop() {
    unsigned long long last_peer_snapshot_log_tick = 0;
    while (!stop_requested_) {
        for (DWORD waited = 0; waited < kHeartbeatIntervalMs && !stop_requested_; waited += 200) {
            Sleep(200);
        }
        if (stop_requested_) {
            break;
        }

        if (!SendFrame(packet_tunnel::kFrameHeartbeat, NULL, 0, NULL)) {
            PacketTunnelDebugLog("发送心跳失败");
            break;
        }

        unsigned long long now_tick = GetTickCount64();
        MaintainTcpDirectConnections(now_tick);

        if (peer_direct_allowed_ && peer_link_manager_ != NULL) {
            std::vector<PeerRouteStatus> expired = peer_link_manager_->ExpireStalePeers(
                now_tick,
                kPeerOfferTimeoutMs,
                kPeerDirectReadyTimeoutMs,
                kPeerCooldownTimeoutMs);
            for (size_t i = 0; i < expired.size(); ++i) {
                PacketTunnelDebugLog("对等控制状态切换: 对端=" +
                                     expired[i].peer_virtual_ip +
                                     " 状态=" + PeerRouteStateName(expired[i].state) +
                                     " 版本=" + std::to_string(expired[i].endpoint_version));
            }

            std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
            if (!peers.empty() &&
                (last_peer_snapshot_log_tick == 0 ||
                 now_tick < last_peer_snapshot_log_tick ||
                 (now_tick - last_peer_snapshot_log_tick) >= kPeerSnapshotLogIntervalMs)) {
                PacketTunnelDebugLog("对等控制快照: " +
                                     BuildPeerRouteSnapshotSummary(peers, now_tick));
                last_peer_snapshot_log_tick = now_tick;
            }
            uint32_t local_virtual_ip_be = 0;
            const bool has_local_virtual_ip =
                ParseIpv4StringToBe(virtual_ip_, &local_virtual_ip_be);
            for (size_t i = 0; i < peers.size(); ++i) {
                if (peers[i].direct_ready &&
                    peers[i].endpoint_version != 0 &&
                    has_local_virtual_ip) {
                    UdpEndpoint peer_endpoint;
                    bool direct_path_fresh = false;
                    bool active_direct = false;
                    if (TryBuildPeerEndpoint(peers[i].peer_virtual_ip,
                                             &peer_endpoint,
                                             &direct_path_fresh,
                                             &active_direct)) {
                        std::map<std::string, unsigned long long>::iterator probe_it =
                            peer_probe_send_tick_.find(peers[i].peer_virtual_ip);
                        const bool should_send_probe =
                            probe_it == peer_probe_send_tick_.end() ||
                            now_tick < probe_it->second ||
                            (now_tick - probe_it->second) >= kPeerDirectProbeIntervalMs;
                        // Keep the direct route warm even during short idle gaps so
                        // the next TCP business flow does not fall back to relay
                        // before we have a chance to refresh freshness again.
                        if (should_send_probe) {
                            uint32_t target_peer_ip_be = 0;
                            std::vector<uint8_t> probe_packet;
                            if (ParseIpv4StringToBe(peers[i].peer_virtual_ip, &target_peer_ip_be) &&
                                BuildPeerDirectProbePacket(local_virtual_ip_be,
                                                           target_peer_ip_be,
                                                           kPeerDirectProbeRequest,
                                                           &probe_packet) &&
                                SendFrameToEndpoint(peer_endpoint,
                                                    packet_tunnel::kFrameIpv4Packet,
                                                    probe_packet.data(),
                                                    probe_packet.size(),
                                                    NULL)) {
                                peer_probe_send_tick_[peers[i].peer_virtual_ip] = now_tick;
                                PacketTunnelDebugLog("主动发送直连探测: 对端=" +
                                                     peers[i].peer_virtual_ip +
                                                     " 状态=" + PeerRouteStateName(peers[i].state) +
                                                     " 当前直连=" + (active_direct ? std::string("是")
                                                                                   : std::string("否")));
                            } else {
                                PeerRouteStatus failed_status = {};
                                const bool state_changed =
                                    peer_link_manager_->RecordDirectSendFailure(
                                        peers[i].peer_virtual_ip,
                                        peers[i].endpoint_version,
                                        active_direct,
                                        &failed_status);
                                PacketTunnelDebugLog("主动直连探测失败: 对端=" +
                                                     peers[i].peer_virtual_ip);
                                if (state_changed &&
                                    failed_status.state == PeerRouteState::Cooldown) {
                                    PacketTunnelDebugLog("UDP直连进入冷却: 对端=" +
                                                         failed_status.peer_virtual_ip);
                                }
                            }
                        }
                    }
                }
                if (!peers[i].active_direct || peers[i].endpoint_version == 0) {
                    continue;
                }
                const uint32_t nonce = peer_signal_nonce_.fetch_add(1);
                if (SendPeerSignalFrame(packet_tunnel::kFramePeerKeepalive,
                                        peers[i].peer_virtual_ip,
                                        peers[i].endpoint_version,
                                        nonce)) {
                    PacketTunnelDebugLog("发送对等端保活: 对端=" +
                                         peers[i].peer_virtual_ip +
                                         " 版本=" + std::to_string(peers[i].endpoint_version) +
                                         " 随机数=" + std::to_string(nonce));
                }
            }
        }

        unsigned long long last_tick = last_network_activity_tick_.load();
        if (last_tick != 0 && now_tick > last_tick && (now_tick - last_tick) > kHeartbeatTimeoutMs) {
            PacketTunnelDebugLog("心跳超时，空闲=" + std::to_string(now_tick - last_tick) + "ms");
            break;
        }
    }

    connected_ = false;
    stop_requested_ = true;
}

void PacketTunnelClient::MaybeLogDirectRouteFallback(const std::string& peer_virtual_ip,
                                                     const std::string& reason) {
    if (!PacketTunnelDebugEnabled()) {
        return;
    }

    if (peer_link_manager_ == NULL || peer_virtual_ip.empty()) {
        return;
    }

    const unsigned long long now_tick = GetTickCount64();
    std::map<std::string, unsigned long long>::iterator it = peer_route_debug_log_tick_.find(peer_virtual_ip);
    if (it != peer_route_debug_log_tick_.end() &&
        now_tick >= it->second &&
        (now_tick - it->second) < kPeerRouteDebugLogIntervalMs) {
        return;
    }

    const std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
    const std::string detail = DescribeSinglePeerRoute(peers, peer_virtual_ip, now_tick);
    if (detail.empty()) {
        return;
    }

    peer_route_debug_log_tick_[peer_virtual_ip] = now_tick;
    PacketTunnelDebugLog("UDP直连回退: 原因=" + reason + " 对端=" + detail);
}

void PacketTunnelClient::MaybeLogWintunTargetIntent(const std::string& dst_virtual_ip,
                                                    uint16_t dst_port,
                                                    const std::string& route_desc) {
    if (!PacketTunnelDebugEnabled()) {
        return;
    }

    if (dst_virtual_ip.empty()) {
        return;
    }

    const unsigned long long now_tick = GetTickCount64();
    const std::string flow_key = dst_virtual_ip + ":" + std::to_string(dst_port);
    std::map<std::string, unsigned long long>::iterator it =
        wintun_target_debug_log_tick_.find(flow_key);
    if (it != wintun_target_debug_log_tick_.end() &&
        now_tick >= it->second &&
        (now_tick - it->second) < kPeerRouteDebugLogIntervalMs) {
        return;
    }

    std::string direct_target = "无";
    std::string peers_summary = "无";
    std::string resolution = "无";
    if (peer_link_manager_ != NULL) {
        const std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
        const std::string detail = DescribeSinglePeerRoute(peers, dst_virtual_ip, now_tick);
        if (!detail.empty()) {
            direct_target = detail;
            resolution = "直连IP";
        } else {
            std::string resolved_peer_virtual_ip;
            if (TryResolveGatewayUdpPeerTarget(dst_virtual_ip,
                                               dst_port,
                                               &resolved_peer_virtual_ip,
                                               &resolution) &&
                !resolved_peer_virtual_ip.empty()) {
                const std::string resolved_detail =
                    DescribeSinglePeerRoute(peers, resolved_peer_virtual_ip, now_tick);
                direct_target = !resolved_detail.empty()
                                    ? resolved_detail
                                    : resolved_peer_virtual_ip;
            }
        }
        peers_summary = BuildPeerRouteSnapshotSummary(peers, now_tick);
    }

    wintun_target_debug_log_tick_[flow_key] = now_tick;
    PacketTunnelDebugLog("Wintun发送意图 " + route_desc +
                         " 直连目标=" + direct_target +
                         " 解析方式=" + resolution +
                         " 对端快照=" + peers_summary);
}

void PacketTunnelClient::MaybeLogTcpPayloadIpHints(const std::string& direction,
                                                   const uint8_t* packet,
                                                   size_t packet_len) {
    if (!PacketTunnelDebugEnabled()) {
        return;
    }

    size_t ip_header_len = 0;
    size_t tcp_header_len = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (!TryParseTcpPacket(packet,
                           packet_len,
                           &ip_header_len,
                           &tcp_header_len,
                           &src_port,
                           &dst_port)) {
        return;
    }

    if (!IsWatchedBusinessTcpPort(src_port) && !IsWatchedBusinessTcpPort(dst_port)) {
        return;
    }

    if (packet_len < ip_header_len + tcp_header_len) {
        return;
    }

    const uint8_t* tcp_payload = packet + ip_header_len + tcp_header_len;
    const size_t tcp_payload_len = packet_len - ip_header_len - tcp_header_len;
    if (tcp_payload_len < 4) {
        return;
    }

    const std::vector<TcpPayloadVirtualIpHit> hits =
        FindVirtualSubnetIpHits(tcp_payload, tcp_payload_len, 6);
    if (hits.empty()) {
        return;
    }

    const std::string inner_src_ip = Ipv4ToString(packet + 12);
    const std::string inner_dst_ip = Ipv4ToString(packet + 16);

    std::vector<PeerRouteStatus> peers;
    if (peer_link_manager_ != NULL) {
        peers = peer_link_manager_->Snapshot();
    }

    const unsigned long long now_tick = GetTickCount64();
    for (size_t i = 0; i < hits.size(); ++i) {
        const std::string role =
            DescribeVirtualIpRole(hits[i].ip, virtual_ip_, inner_src_ip, inner_dst_ip, peers);
        const std::string flow_key =
            "tcp|" +
            direction + "|" +
            inner_src_ip + ":" + std::to_string(src_port) + ">" +
            inner_dst_ip + ":" + std::to_string(dst_port) + "|" +
            hits[i].ip + "|" +
            (hits[i].little_endian ? "le" : "be") + "|" +
            role;
        std::map<std::string, unsigned long long>::iterator it =
            payload_ip_debug_log_tick_.find(flow_key);
        if (it != payload_ip_debug_log_tick_.end() &&
            now_tick >= it->second &&
            (now_tick - it->second) < kPeerRouteDebugLogIntervalMs) {
            continue;
        }

        payload_ip_debug_log_tick_[flow_key] = now_tick;

        std::ostringstream ss;
        ss << "tcp payload virtual-ip hit dir=" << direction
           << " flow=" << inner_src_ip << ":" << src_port
           << "->" << inner_dst_ip << ":" << dst_port
           << " hit=" << hits[i].ip
           << " order=" << (hits[i].little_endian ? "le" : "be")
           << " role=" << role
           << " payload_off=" << hits[i].offset;
        if (hits[i].has_next_port) {
            ss << " next_port_le=" << hits[i].next_port_le
               << " next_port_be=" << hits[i].next_port_be;
        }
        ss << " ctx=" << hits[i].context_hex;
        PacketTunnelDebugLog(ss.str());
    }
}

void PacketTunnelClient::MaybeLogUdpPayloadIpHints(const std::string& direction,
                                                   const uint8_t* packet,
                                                   size_t packet_len) {
    if (!PacketTunnelDebugEnabled()) {
        return;
    }

    if (packet == NULL || packet_len < 28 || ((packet[0] >> 4) & 0x0F) != 4 || packet[9] != IPPROTO_UDP) {
        return;
    }

    if (IsNoisyUdpForLogging(packet, packet_len)) {
        return;
    }

    const size_t ip_header_len = static_cast<size_t>(packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8) {
        return;
    }

    const uint16_t src_port = ntohs(*(const uint16_t*)(packet + ip_header_len));
    const uint16_t dst_port = ntohs(*(const uint16_t*)(packet + ip_header_len + 2));
    const uint8_t* udp_payload = packet + ip_header_len + 8;
    const size_t udp_payload_len = packet_len - ip_header_len - 8;
    if (udp_payload_len < 4) {
        return;
    }

    const std::vector<TcpPayloadVirtualIpHit> hits =
        FindVirtualSubnetIpHits(udp_payload, udp_payload_len, 6);
    if (hits.empty()) {
        return;
    }

    const std::string inner_src_ip = Ipv4ToString(packet + 12);
    const std::string inner_dst_ip = Ipv4ToString(packet + 16);

    std::vector<PeerRouteStatus> peers;
    if (peer_link_manager_ != NULL) {
        peers = peer_link_manager_->Snapshot();
    }

    const unsigned long long now_tick = GetTickCount64();
    for (size_t i = 0; i < hits.size(); ++i) {
        const std::string role =
            DescribeVirtualIpRole(hits[i].ip, virtual_ip_, inner_src_ip, inner_dst_ip, peers);
        const std::string flow_key =
            "udp|" +
            direction + "|" +
            inner_src_ip + ":" + std::to_string(src_port) + ">" +
            inner_dst_ip + ":" + std::to_string(dst_port) + "|" +
            hits[i].ip + "|" +
            (hits[i].little_endian ? "le" : "be") + "|" +
            role;
        std::map<std::string, unsigned long long>::iterator it =
            payload_ip_debug_log_tick_.find(flow_key);
        if (it != payload_ip_debug_log_tick_.end() &&
            now_tick >= it->second &&
            (now_tick - it->second) < kPeerRouteDebugLogIntervalMs) {
            continue;
        }

        payload_ip_debug_log_tick_[flow_key] = now_tick;

        std::ostringstream ss;
        ss << "udp payload virtual-ip hit dir=" << direction
           << " flow=" << inner_src_ip << ":" << src_port
           << "->" << inner_dst_ip << ":" << dst_port
           << " hit=" << hits[i].ip
           << " order=" << (hits[i].little_endian ? "le" : "be")
           << " role=" << role
           << " payload_off=" << hits[i].offset;
        if (hits[i].has_next_port) {
            ss << " next_port_le=" << hits[i].next_port_le
               << " next_port_be=" << hits[i].next_port_be;
        }
        ss << " ctx=" << hits[i].context_hex;
        PacketTunnelDebugLog(ss.str());
    }
}

bool PacketTunnelClient::HandlePeerControlFrame(uint8_t frame_type,
                                                const uint8_t* payload,
                                                size_t length) {
    if (frame_type == packet_tunnel::kFrameTcpPeerOffer) {
        ParsedPeerOffer offer = {};
        if (!ParsePeerOfferPayload(payload, length, &offer)) {
            PacketTunnelDebugLog("忽略无效的TCP对等提议帧，长度=" +
                                 std::to_string(length));
            return true;
        }
        if (offer.peer_virtual_ip.empty() ||
            offer.peer_virtual_ip == virtual_ip_ ||
            offer.endpoint_port == 0) {
            PacketTunnelDebugLog("忽略不可用的TCP对等提议，对端=" +
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
                PacketTunnelDebugLog("忽略过期的TCP对等提议，对端=" +
                                     offer.peer_virtual_ip +
                                     " 版本=" +
                                     std::to_string(offer.endpoint_version));
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
                    candidate.last_success_tick_ms = previous.last_success_tick_ms;
                    candidate.last_failure_tick_ms = previous.last_failure_tick_ms;
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
            stored.last_offer_tick_ms = GetTickCount64();
            if (changed) {
                stored.cooldown_until_tick_ms = 0;
            }
        }

        PacketTunnelDebugLog("收到TCP对等提议: 对端=" +
                             offer.peer_virtual_ip +
                             " 版本=" +
                             std::to_string(offer.endpoint_version) +
                             " 端点=" + offer.endpoint +
                             (changed ? " 已变更=是" : " 已变更=否"));
        MaybeStartTcpDirectConnect(offer.peer_virtual_ip);
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerOffer) {
        ParsedPeerOffer offer = {};
        if (!ParsePeerOfferPayload(payload, length, &offer)) {
            PacketTunnelDebugLog("忽略无效的对等提议帧，长度=" + std::to_string(length));
            return true;
        }
        if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("忽略对等提议: 当前仅中转模式，对端=" +
                                 offer.peer_virtual_ip +
                                 " 端点=" + offer.endpoint);
            if (offer.endpoint_version != 0) {
                SendPeerDisableFrame(offer.peer_virtual_ip,
                                     offer.endpoint_version,
                                     packet_tunnel::kPeerDisableReasonCooldown);
            }
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
        PacketTunnelDebugLog("收到对等提议: 对端=" + offer.peer_virtual_ip +
                             " 版本=" + std::to_string(offer.endpoint_version) +
                             " 端点=" + offer.endpoint);
        if (!should_send_hello) {
            PacketTunnelDebugLog("忽略稳定未变化的对等提议: 对端=" + offer.peer_virtual_ip +
                                 " 版本=" + std::to_string(offer.endpoint_version));
            return true;
        }
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
            PacketTunnelDebugLog("发送对等端问候: 对端=" + offer.peer_virtual_ip +
                                 " 版本=" + std::to_string(offer.endpoint_version) +
                                 " 随机数=" + std::to_string(nonce));
        } else {
            PacketTunnelDebugLog("发送对等端问候失败: 对端=" + offer.peer_virtual_ip +
                                 " 版本=" + std::to_string(offer.endpoint_version) +
                                 " 随机数=" + std::to_string(nonce));
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerHello ||
        frame_type == packet_tunnel::kFramePeerAck ||
        frame_type == packet_tunnel::kFramePeerKeepalive) {
        ParsedPeerSignal signal = {};
        if (!ParsePeerSignalPayload(payload, length, &signal)) {
            PacketTunnelDebugLog("忽略无效的" + PacketTunnelFrameName(frame_type) +
                                 "，长度=" + std::to_string(length));
            return true;
        }

        if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("忽略" + PacketTunnelFrameName(frame_type) +
                                 ": 当前仅中转模式，对端=" + signal.peer_virtual_ip +
                                 " 版本=" + std::to_string(signal.endpoint_version) +
                                 " 随机数=" + std::to_string(signal.nonce));
            if (frame_type != packet_tunnel::kFramePeerAck && signal.endpoint_version != 0) {
                SendPeerDisableFrame(signal.peer_virtual_ip,
                                     signal.endpoint_version,
                                     packet_tunnel::kPeerDisableReasonCooldown);
            }
            return true;
        }
        if (peer_link_manager_ != NULL) {
            if (frame_type == packet_tunnel::kFramePeerHello) {
                peer_link_manager_->MarkPeerProbing(signal.peer_virtual_ip, signal.endpoint_version);
            } else if (frame_type == packet_tunnel::kFramePeerAck) {
                if (!peer_link_manager_->TryPromotePeerDirectReady(signal.peer_virtual_ip,
                                                                   signal.endpoint_version,
                                                                   signal.nonce)) {
                    PacketTunnelDebugLog("忽略非预期的对等端确认: 对端=" +
                                         signal.peer_virtual_ip +
                                         " 版本=" + std::to_string(signal.endpoint_version) +
                                         " 随机数=" + std::to_string(signal.nonce));
                    return true;
                }
            } else {
                peer_link_manager_->TouchPeer(signal.peer_virtual_ip, signal.endpoint_version);
            }
        }

        PacketTunnelDebugLog("收到" + PacketTunnelFrameName(frame_type) +
                             ": 对端=" + signal.peer_virtual_ip +
                             " 版本=" + std::to_string(signal.endpoint_version) +
                             " 随机数=" + std::to_string(signal.nonce));

        if (frame_type == packet_tunnel::kFramePeerHello) {
            if (SendPeerSignalFrame(packet_tunnel::kFramePeerAck,
                                    signal.peer_virtual_ip,
                                    signal.endpoint_version,
                                    signal.nonce)) {
                PacketTunnelDebugLog("发送对等端确认: 对端=" + signal.peer_virtual_ip +
                                     " 版本=" + std::to_string(signal.endpoint_version) +
                                     " 随机数=" + std::to_string(signal.nonce));
            } else {
                PacketTunnelDebugLog("发送对等端确认失败: 对端=" + signal.peer_virtual_ip +
                                     " 版本=" + std::to_string(signal.endpoint_version) +
                                     " 随机数=" + std::to_string(signal.nonce));
            }
        }
        return true;
    }

    if (frame_type == packet_tunnel::kFramePeerDisable) {
        ParsedPeerDisable disable = {};
        if (!ParsePeerDisablePayload(payload, length, &disable)) {
            PacketTunnelDebugLog("忽略无效的对等端禁用帧，长度=" + std::to_string(length));
            return true;
        }
        if (!peer_direct_allowed_) {
            PacketTunnelDebugLog("忽略对等端禁用: 当前仅中转模式，对端=" +
                                 disable.peer_virtual_ip +
                                 " 版本=" + std::to_string(disable.endpoint_version) +
                                 " 原因=" + std::to_string(disable.reason));
            return true;
        }
        if (peer_link_manager_ != NULL) {
            peer_link_manager_->MarkPeerCooldown(disable.peer_virtual_ip,
                                                 disable.endpoint_version);
        }
        PacketTunnelDebugLog("收到对等端禁用: 对端=" + disable.peer_virtual_ip +
                             " 版本=" + std::to_string(disable.endpoint_version) +
                             " 原因=" + std::to_string(disable.reason));
        return true;
    }

    return false;
}

bool PacketTunnelClient::SendPeerSignalFrame(uint8_t frame_type,
                                             const std::string& target_peer_virtual_ip,
                                             uint64_t endpoint_version,
                                             uint32_t nonce) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerSignalPayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    packet_tunnel::write_u32_be(payload.data() + 12, nonce);
    return SendFrame(frame_type, payload.data(), payload.size(), NULL);
}

bool PacketTunnelClient::SendPeerDisableFrame(const std::string& target_peer_virtual_ip,
                                              uint64_t endpoint_version,
                                              uint8_t reason) {
    uint32_t peer_virtual_ip_be = 0;
    if (!ParseIpv4StringToBe(target_peer_virtual_ip, &peer_virtual_ip_be)) {
        return false;
    }

    std::vector<uint8_t> payload(packet_tunnel::kPeerDisablePayloadSize, 0);
    packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
    packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
    payload[12] = reason;
    return SendFrame(packet_tunnel::kFramePeerDisable, payload.data(), payload.size(), NULL);
}

bool PacketTunnelClient::TryBuildPeerEndpoint(const std::string& peer_virtual_ip,
                                              UdpEndpoint* endpoint,
                                              bool* direct_path_fresh,
                                              bool* active_direct) const {
    if (endpoint == NULL || peer_link_manager_ == NULL) {
        return false;
    }

    PeerRouteStatus route = {};
    if (!peer_link_manager_->TryGetDirectRoute(peer_virtual_ip,
                                               GetTickCount64(),
                                               kPeerDirectDataTimeoutMs,
                                               kPeerDirectProbeGraceMs,
                                               &route)) {
        return false;
    }
    if (direct_path_fresh != NULL) {
        *direct_path_fresh = IsDirectPathFresh(route, GetTickCount64());
    }
    if (active_direct != NULL) {
        *active_direct = route.active_direct;
    }

    ZeroMemory(&endpoint->addr, sizeof(endpoint->addr));
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
            addr6->sin6_addr.u.Word[5] = 0xFFFF;
            memcpy(&addr6->sin6_addr.u.Byte[12], route.endpoint_addr, 4);
            endpoint->addr_len = sizeof(sockaddr_in6);
            endpoint->valid = true;
            return true;
        }
    }

    return false;
}

bool PacketTunnelClient::TryResolvePeerBySource(const sockaddr_storage& source_addr,
                                                int source_addr_len,
                                                std::string* peer_virtual_ip) const {
    (void)source_addr_len;
    if (peer_link_manager_ == NULL) {
        return false;
    }

    uint8_t endpoint_family = packet_tunnel::kPeerEndpointFamilyUnknown;
    uint16_t endpoint_port = 0;
    uint8_t endpoint_addr[16] = {};
    if (!TryExtractPeerEndpointFromSockaddr(source_addr,
                                            &endpoint_family,
                                            endpoint_addr,
                                            &endpoint_port)) {
        return false;
    }

    PeerRouteStatus route = {};
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

bool PacketTunnelClient::IsServerEndpoint(const sockaddr_storage& source_addr,
                                          int source_addr_len) const {
    if (!server_endpoint_.valid) {
        return false;
    }
    return SockaddrEquals(source_addr,
                          source_addr_len,
                          server_endpoint_.addr,
                          server_endpoint_.addr_len);
}

void PacketTunnelClient::LearnPeerUdpPortOwner(const std::string& peer_virtual_ip,
                                               uint16_t src_port) {
    if (peer_virtual_ip.empty() ||
        peer_virtual_ip == virtual_ip_ ||
        IsServerVirtualPeer(peer_virtual_ip) ||
        src_port == 0 ||
        IsKnownGameUdpPort(src_port) ||
        IsReservedPeerDirectPort(src_port)) {
        return;
    }

    const unsigned long long now_tick = GetTickCount64();
    std::string previous_owner;
    bool owner_changed = false;

    PeerUdpPortOwner& owner = peer_udp_port_owners_[src_port];
    previous_owner = owner.peer_virtual_ip;
    owner_changed = !previous_owner.empty() && previous_owner != peer_virtual_ip;
    owner.peer_virtual_ip = peer_virtual_ip;
    owner.last_seen_ms = now_tick;

    if (owner_changed) {
        PacketTunnelDebugLog("udp gateway owner update port=" + std::to_string(src_port) +
                             " owner=" + previous_owner + "->" + peer_virtual_ip);
    }
}

bool PacketTunnelClient::TryResolveGatewayUdpPeerTarget(const std::string& dst_virtual_ip,
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
    if (!kEnableGatewayUdpPeerHeuristics) {
        if (resolution != NULL) {
            *resolution = "仅按路由";
        }
        return false;
    }

    const unsigned long long now_tick = GetTickCount64();
    const std::vector<PeerRouteStatus> peers = peer_link_manager_->Snapshot();
    if (!IsGatewayPeerResolveCandidate(virtual_ip_, dst_virtual_ip, peers)) {
        if (resolution != NULL) {
            *resolution = "目标不适用";
        }
        return false;
    }

    auto can_route_peer = [this](const PeerRouteStatus& peer) -> bool {
        return !peer.peer_virtual_ip.empty() &&
               peer.peer_virtual_ip != virtual_ip_ &&
               !IsServerVirtualPeer(peer.peer_virtual_ip) &&
               peer.state != PeerRouteState::Cooldown &&
               peer.direct_ready &&
               peer.endpoint_family != packet_tunnel::kPeerEndpointFamilyUnknown &&
               peer.endpoint_port != 0;
    };

    std::string selected_peer_virtual_ip;
    std::string selected_resolution;
    size_t candidate_count = 0;

    for (size_t i = 0; i < peers.size(); ++i) {
        if (!can_route_peer(peers[i])) {
            continue;
        }
        ++candidate_count;
    }

    std::map<uint16_t, PeerUdpPortOwner>::const_iterator owner_it =
        peer_udp_port_owners_.find(dst_port);
    if (owner_it != peer_udp_port_owners_.end()) {
        const PeerUdpPortOwner& owner = owner_it->second;
        const bool owner_stale =
            owner.last_seen_ms == 0 ||
            now_tick < owner.last_seen_ms ||
            (now_tick - owner.last_seen_ms) > kGatewayUdpPortOwnerTtlMs;
        if (!owner_stale &&
            !owner.peer_virtual_ip.empty() &&
            owner.peer_virtual_ip != virtual_ip_) {
            for (size_t i = 0; i < peers.size(); ++i) {
                if (!can_route_peer(peers[i]) ||
                    peers[i].peer_virtual_ip != owner.peer_virtual_ip) {
                    continue;
                }
                selected_peer_virtual_ip = owner.peer_virtual_ip;
                selected_resolution = "端口归属";
                break;
            }
        }
    }

    if (selected_peer_virtual_ip.empty()) {
        if (resolution != NULL) {
            *resolution = "未解析候选数=" + std::to_string(candidate_count);
        }
        return false;
    }

    if (peer_virtual_ip != NULL) {
        *peer_virtual_ip = selected_peer_virtual_ip;
    }
    if (resolution != NULL) {
        *resolution = selected_resolution;
    }
    return true;
}

bool PacketTunnelClient::SendFrameToEndpoint(const UdpEndpoint& endpoint,
                                             uint8_t frame_type,
                                             const uint8_t* data,
                                             size_t length,
                                             std::wstring* error_msg) {
    const unsigned long long send_start = GetTickCount64();
    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons((uint16_t)length);
    if (length > 0 && data != NULL) {
        memcpy(&frame[packet_tunnel::kFrameHeaderSize], data, length);
    }

    EnterCriticalSection(&send_lock_);
    bool ok = SendDatagramToEndpoint(endpoint, frame.data(), frame.size(), error_msg);
    LeaveCriticalSection(&send_lock_);
    const unsigned long long send_elapsed = GetTickCount64() - send_start;
    if (send_elapsed >= kSlowSocketSendWarnMs) {
        PacketTunnelWarnLog("帧发送耗时偏长 elapsed_ms=" +
                            std::to_string(send_elapsed) +
                            " 帧类型=" + PacketTunnelFrameName(frame_type) +
                            " 端点=" + SockaddrToString(endpoint.addr, endpoint.addr_len) +
                            " 负载长度=" + std::to_string(length) +
                            " 成功=" + (ok ? std::string("是") : std::string("否")));
    }
    return ok;
}

bool PacketTunnelClient::SendDatagramToEndpoint(const UdpEndpoint& endpoint,
                                                const uint8_t* data,
                                                size_t length,
                                                std::wstring* error_msg) {
    if (!endpoint.valid) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel send target is invalid";
        }
        return false;
    }

    int last_error = 0;
    for (int attempt = 0; attempt < kSocketSendRetryCount; ++attempt) {
        int n = sendto(sock_,
                       reinterpret_cast<const char*>(data),
                       static_cast<int>(length),
                       0,
                       reinterpret_cast<const sockaddr*>(&endpoint.addr),
                       endpoint.addr_len);
        if (n == (int)length) {
            MarkNetworkActivity();
            return true;
        }

        last_error = WSAGetLastError();
        if (IsTransientSocketSendError(last_error) && attempt + 1 < kSocketSendRetryCount) {
            Sleep(kSocketSendRetryDelayMs);
            continue;
        }
        if (!IsTransientSocketSendError(last_error)) {
            if (error_msg != NULL) {
                *error_msg = BuildSocketError(L"IP Tunnel发送失败", last_error);
            }
            return false;
        }
        break;
    }

    PacketTunnelWarnLog("IP Tunnel send dropped after transient stall error=" +
                        std::to_string(last_error) +
                        " endpoint=" + SockaddrToString(endpoint.addr, endpoint.addr_len) +
                        " len=" + std::to_string(length));
    if (error_msg != NULL) {
        *error_msg = BuildSocketError(L"IP Tunnel send dropped", last_error);
    }
    return true;
}

int PacketTunnelClient::RecvDatagramFrom(uint8_t* data,
                                         size_t length,
                                         sockaddr_storage* source_addr,
                                         int* source_addr_len,
                                         std::wstring* error_msg) {
    int addr_len = static_cast<int>(sizeof(sockaddr_storage));
    if (source_addr_len != NULL && *source_addr_len > 0) {
        addr_len = *source_addr_len;
    }
    int n = recvfrom(sock_,
                     reinterpret_cast<char*>(data),
                     static_cast<int>(length),
                     0,
                     (source_addr != NULL) ? reinterpret_cast<sockaddr*>(source_addr) : NULL,
                     (source_addr_len != NULL) ? &addr_len : NULL);
    if (source_addr_len != NULL) {
        *source_addr_len = addr_len;
    }
    if (n == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAETIMEDOUT || err == WSAECONNRESET) {
            return 0;
        }
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel recv failed", err);
        }
        return -1;
    }
    if (n == 0) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel对端已关闭";
        }
        return -1;
    }
    return n;
}

bool PacketTunnelClient::RecvTcpExact(uint8_t* data,
                                      size_t length,
                                      std::wstring* error_msg) {
    size_t received = 0;
    while (received < length && !stop_requested_ && tcp_connected_) {
        if (tcp_sock_ == INVALID_SOCKET) {
            break;
        }
        int n = recv(tcp_sock_,
                     reinterpret_cast<char*>(data + received),
                     static_cast<int>(length - received),
                     0);
        if (n > 0) {
            received += static_cast<size_t>(n);
            continue;
        }
        if (n == 0) {
            if (error_msg != NULL) {
                *error_msg = L"IP Tunnel TCP中转载体已关闭";
            }
            return false;
        }

        const int err = WSAGetLastError();
        if ((err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) &&
            !stop_requested_ &&
            tcp_connected_) {
            continue;
        }
        if (error_msg != NULL) {
            *error_msg = BuildSocketError(L"IP Tunnel TCP接收失败", err);
        }
        return false;
    }

    if (received == length) {
        return true;
    }
    if (error_msg != NULL && error_msg->empty() && !stop_requested_) {
        *error_msg = L"IP Tunnel TCP recv interrupted";
    }
    return false;
}

bool PacketTunnelClient::SendFrame(uint8_t frame_type, const uint8_t* data, size_t length, std::wstring* error_msg) {
    return SendFrameToEndpoint(server_endpoint_, frame_type, data, length, error_msg);
}

bool PacketTunnelClient::SendFrameOverTcp(uint8_t frame_type,
                                          const uint8_t* data,
                                          size_t length,
                                          std::wstring* error_msg) {
    if (!tcp_connected_ || tcp_sock_ == INVALID_SOCKET) {
        if (error_msg != NULL) {
            *error_msg = L"IP Tunnel TCP relay is not connected";
        }
        return false;
    }

    std::vector<uint8_t> frame(packet_tunnel::kFrameHeaderSize + length, 0);
    frame[0] = frame_type;
    *(uint16_t*)(&frame[1]) = htons(static_cast<uint16_t>(length));
    if (length > 0 && data != NULL) {
        memcpy(&frame[packet_tunnel::kFrameHeaderSize], data, length);
    }

    EnterCriticalSection(&tcp_send_lock_);
    size_t sent = 0;
    int transient_retries = 0;
    int last_error = 0;
    while (sent < frame.size() && tcp_connected_ && tcp_sock_ != INVALID_SOCKET) {
        int n = send(tcp_sock_,
                     reinterpret_cast<const char*>(frame.data() + sent),
                     static_cast<int>(frame.size() - sent),
                     0);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            transient_retries = 0;
            continue;
        }

        last_error = WSAGetLastError();
        if (IsTransientSocketSendError(last_error) &&
            transient_retries + 1 < kSocketSendRetryCount) {
            ++transient_retries;
            Sleep(kSocketSendRetryDelayMs);
            continue;
        }
        break;
    }
    LeaveCriticalSection(&tcp_send_lock_);

    if (sent == frame.size()) {
        return true;
    }
    if (error_msg != NULL) {
        if (last_error != 0) {
            *error_msg = BuildSocketError(L"IP Tunnel TCP发送失败", last_error);
        } else {
            *error_msg = L"IP Tunnel TCP发送被中断";
        }
    }
    return false;
}

bool PacketTunnelClient::SendDatagram(const uint8_t* data, size_t length, std::wstring* error_msg) {
    return SendDatagramToEndpoint(server_endpoint_, data, length, error_msg);
}

int PacketTunnelClient::RecvDatagram(uint8_t* data, size_t length, std::wstring* error_msg) {
    sockaddr_storage source_addr = {};
    int source_addr_len = 0;
    return RecvDatagramFrom(data, length, &source_addr, &source_addr_len, error_msg);
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
