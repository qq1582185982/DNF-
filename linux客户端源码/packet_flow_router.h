#ifndef PACKET_FLOW_ROUTER_H_
#define PACKET_FLOW_ROUTER_H_

#include <cstddef>
#include <cstdint>
#include <string>

enum class PacketFlowRoute : uint8_t {
    RelayOnly = 0,
    UdpDirect,
    UdpProbe,
    TcpDirect,
    TcpRelay,
    UdpRelay
};

struct PacketFlowRouterInput {
    bool is_udp;
    bool is_tcp;
    bool has_udp_peer_endpoint;
    bool direct_path_fresh;
    bool active_direct;
    bool resolved_gateway_target;
    bool direct_payload_ready;
    bool has_tcp_direct_target;
    bool tcp_relay_available;
    bool udp_relay_batch_eligible;
    bool can_shadow_payload;
    std::string route_desc_seed;
    std::string target_peer_virtual_ip;
    std::string original_dst_virtual_ip;
    std::string target_resolution;

    PacketFlowRouterInput()
        : is_udp(false),
          is_tcp(false),
          has_udp_peer_endpoint(false),
          direct_path_fresh(false),
          active_direct(false),
          resolved_gateway_target(false),
          direct_payload_ready(false),
          has_tcp_direct_target(false),
          tcp_relay_available(false),
          udp_relay_batch_eligible(false),
          can_shadow_payload(false) {
    }
};

struct PacketFlowRouterDecision {
    PacketFlowRoute primary_route;
    PacketFlowRoute relay_fallback_route;
    bool try_udp_direct_now;
    bool try_udp_probe;
    bool try_udp_shadow_payload;
    bool try_tcp_direct_now;
    bool try_tcp_relay_now;
    bool try_udp_relay_now;
    bool allow_udp_relay_batch;
    std::string route_desc;

    PacketFlowRouterDecision()
        : primary_route(PacketFlowRoute::RelayOnly),
          relay_fallback_route(PacketFlowRoute::UdpRelay),
          try_udp_direct_now(false),
          try_udp_probe(false),
          try_udp_shadow_payload(false),
          try_tcp_direct_now(false),
          try_tcp_relay_now(false),
          try_udp_relay_now(false),
          allow_udp_relay_batch(false) {
    }
};

class PacketFlowRouter {
public:
    static PacketFlowRouterDecision Decide(const PacketFlowRouterInput& input) {
        PacketFlowRouterDecision decision;
        decision.route_desc = BuildRouteDesc(input);
        decision.relay_fallback_route =
            (input.is_tcp && input.tcp_relay_available)
                ? PacketFlowRoute::TcpRelay
                : PacketFlowRoute::UdpRelay;
        decision.try_tcp_relay_now = input.is_tcp && input.tcp_relay_available;
        decision.try_udp_relay_now = !input.is_tcp;
        decision.allow_udp_relay_batch =
            input.udp_relay_batch_eligible &&
            decision.relay_fallback_route == PacketFlowRoute::UdpRelay;

        if (input.is_udp) {
            if (!input.has_udp_peer_endpoint) {
                decision.primary_route = PacketFlowRoute::UdpRelay;
                return decision;
            }

            if (input.direct_path_fresh ||
                (input.active_direct && input.resolved_gateway_target)) {
                decision.primary_route = PacketFlowRoute::UdpDirect;
                decision.try_udp_direct_now = input.direct_payload_ready;
                return decision;
            }

            decision.primary_route = PacketFlowRoute::UdpProbe;
            decision.try_udp_probe = true;
            decision.try_udp_shadow_payload = input.can_shadow_payload;
            return decision;
        }

        if (input.is_tcp) {
            if (input.has_tcp_direct_target) {
                decision.primary_route = PacketFlowRoute::TcpDirect;
                decision.try_tcp_direct_now = true;
            } else if (input.tcp_relay_available) {
                decision.primary_route = PacketFlowRoute::TcpRelay;
            } else {
                decision.primary_route = PacketFlowRoute::UdpRelay;
                decision.try_tcp_relay_now = false;
                decision.try_udp_relay_now = true;
            }
            return decision;
        }

        decision.primary_route = PacketFlowRoute::UdpRelay;
        decision.try_tcp_relay_now = false;
        decision.try_udp_relay_now = true;
        return decision;
    }

private:
    static std::string BuildRouteDesc(const PacketFlowRouterInput& input) {
        std::string route_desc = input.route_desc_seed;
        if (!input.target_peer_virtual_ip.empty() &&
            !input.original_dst_virtual_ip.empty() &&
            input.target_peer_virtual_ip != input.original_dst_virtual_ip) {
            route_desc += " resolved_peer=" + input.target_peer_virtual_ip;
            if (!input.target_resolution.empty()) {
                route_desc += " resolver=" + input.target_resolution;
            }
        }
        return route_desc;
    }
};

#endif
