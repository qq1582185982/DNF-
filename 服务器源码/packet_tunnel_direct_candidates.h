#ifndef PACKET_TUNNEL_DIRECT_CANDIDATES_H_
#define PACKET_TUNNEL_DIRECT_CANDIDATES_H_

#include "packet_tunnel_protocol.h"

#include <stdint.h>
#include <sys/socket.h>

#include <string>
#include <vector>

struct TcpDirectCandidate {
    uint8_t endpoint_family;
    uint16_t endpoint_port;
    uint8_t endpoint_addr[16];

    TcpDirectCandidate();
};

struct PacketTunnelCandidateOwnerView {
    std::string client_endpoint;
    bool use_udp;
    sockaddr_storage udp_addr;
    socklen_t udp_addr_len;
    uint16_t tcp_direct_listen_port;
    std::vector<TcpDirectCandidate> udp_direct_candidates;
    std::vector<TcpDirectCandidate> tcp_direct_candidates;

    PacketTunnelCandidateOwnerView();
};

bool ParsePacketTunnelClientEndpointString(const std::string& client_str,
                                          sockaddr_storage* out_addr,
                                          socklen_t* out_addr_len);
bool BuildPacketTunnelDirectCandidateFromSockaddr(const sockaddr_storage& addr,
                                                  uint16_t port_override,
                                                  TcpDirectCandidate* out_candidate);
bool PacketTunnelDirectCandidateEquals(const TcpDirectCandidate& left,
                                      const TcpDirectCandidate& right);
void AppendUniquePacketTunnelDirectCandidate(std::vector<TcpDirectCandidate>* candidates,
                                             const TcpDirectCandidate& candidate);
std::string PacketTunnelDirectCandidateToString(const TcpDirectCandidate& candidate);
std::vector<TcpDirectCandidate> BuildTcpDirectCandidatesForOwner(
    const PacketTunnelCandidateOwnerView& owner);
std::vector<TcpDirectCandidate> BuildUdpDirectCandidatesForOwner(
    const PacketTunnelCandidateOwnerView& owner);

#endif
